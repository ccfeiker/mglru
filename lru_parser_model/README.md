# Traditional LRU eBPF Instrumentation and Parser Model

## 1. Overview

This directory is used to collect and analyze the behavior of `shrink_lruvec()` on the Linux traditional LRU reclaim path.

The overall workflow has two parts:

- use eBPF to capture one `shrink_lruvec()` execution summary
- use `lru_executor.py` to construct a parser model from the captured summary and predict anon/file reclaim counts

## 2. Directory Layout

The main files in this directory are:

- `lru_monitor.bpf.c`
  Attaches tracepoints and kprobes to collect observable signals along the traditional LRU reclaim path.
- `lru_monitor.c`
  Loads the eBPF program, reads the ring buffer, and exports `lru_output.csv`.
- `lru_monitor.h`
  Defines the summary event structure `struct lru_event` shared between eBPF and user space.
- `lru_executor.py`
  The executor of the traditional LRU parser model. It takes one case as input and produces prediction results plus an execution trace.
- `validate_lru_executor.py`
  Batch validation script. It reads `lru_output.csv`, invokes `lru_executor.py` row by row, and aggregates validation metrics.
- `Makefile`
  Generates `vmlinux.h`, builds the BPF object, generates the skeleton, and links the user-space program.

## 3. Quick Start

To execute a single case:
`python lru_executor.py lru_template_case/lru_case_sw100.json`

To analyze a case captured from eBPF data:
1. Modify and rebuild the kernel-side tracepoints.
2. Run `make` in the `lru_parser_model` directory.
3. Run `sudo ./lru_monitor lru_output.csv`.
4. Run `python validate_lru_executor.py --csv lru_output.csv --trigger-comm kswapd0`.

To analyze one specific sample from the captured eBPF dataset:
`python lru_executor.py --csv lru_output.csv --line <line_no> --json`

## 4. Modify the Linux Kernel and Add Tracepoints

The current traditional LRU parser model requires additional planning information and proportional-adjust information. Therefore, two extra tracepoints need to be added to the Linux kernel reclaim path in `vmscan`:

- `mm_vmscan_lru_plan`
- `mm_vmscan_lru_adjust`

### 4.1 Modify `vmscan.h`

File location:

```text
[kernel-source]/include/trace/events/vmscan.h
```

1. Add the following macro definitions after `#define trace_reclaim_flags(file)`:

```c
#define TRACE_LRU_PLAN_FLAG_MAY_DEACTIVATE_ANON (1U << 0)
#define TRACE_LRU_PLAN_FLAG_MAY_DEACTIVATE_FILE (1U << 1)
#define TRACE_LRU_PLAN_FLAG_FORCE_DEACTIVATE    (1U << 2)
#define TRACE_LRU_PLAN_FLAG_SKIPPED_DEACTIVATE  (1U << 3)
#define TRACE_LRU_PLAN_FLAG_MAY_WRITEPAGE       (1U << 4)
#define TRACE_LRU_PLAN_FLAG_MAY_UNMAP           (1U << 5)
#define TRACE_LRU_PLAN_FLAG_MAY_SWAP            (1U << 6)

#define TRACE_LRU_SCAN_STATE_CGROUP_RECLAIM     (1U << 0)
#define TRACE_LRU_SCAN_STATE_CAN_RECLAIM_ANON   (1U << 1)
#define TRACE_LRU_SCAN_STATE_CACHE_TRIM_MODE    (1U << 2)
#define TRACE_LRU_SCAN_STATE_FILE_IS_TINY       (1U << 3)
#define TRACE_LRU_SCAN_STATE_MEMCG_LOW_RECLAIM  (1U << 4)
#define TRACE_LRU_SCAN_STATE_PROPORTIONAL       (1U << 5)
```

2. Add the following block after `TRACE_EVENT(mm_vmscan_lru_shrink_active, ...)`:

```c
TRACE_EVENT(mm_vmscan_lru_plan,

    TP_PROTO(int nid, int memcg_id, int priority, int reclaim_idx,
        int order, unsigned long nr_to_reclaim, int swappiness,
        unsigned int plan_flags, unsigned int scan_state_flags,
        const unsigned long *before, const unsigned long *targets),

    TP_ARGS(nid, memcg_id, priority, reclaim_idx, order, nr_to_reclaim,
        swappiness, plan_flags, scan_state_flags, before, targets),

    TP_STRUCT__entry(
        __field(int, nid)
        __field(int, memcg_id)
        __field(int, priority)
        __field(int, reclaim_idx)
        __field(int, order)
        __field(unsigned long, nr_to_reclaim)
        __field(int, swappiness)
        __field(unsigned int, plan_flags)
        __field(unsigned int, scan_state_flags)
        __array(unsigned long, before, NR_LRU_LISTS)
        __array(unsigned long, targets, NR_LRU_LISTS)
    ),

    TP_fast_assign(
        __entry->nid = nid;
        __entry->memcg_id = memcg_id;
        __entry->priority = priority;
        __entry->reclaim_idx = reclaim_idx;
        __entry->order = order;
        __entry->nr_to_reclaim = nr_to_reclaim;
        __entry->swappiness = swappiness;
        __entry->plan_flags = plan_flags;
        __entry->scan_state_flags = scan_state_flags;
        memcpy(__entry->before, before, sizeof(__entry->before));
        memcpy(__entry->targets, targets, sizeof(__entry->targets));
    ),

    TP_printk("nid=%d memcg_id=%d priority=%d reclaim_idx=%d order=%d nr_to_reclaim=%lu swappiness=%d plan_flags=0x%x scan_state_flags=0x%x",
        __entry->nid,
        __entry->memcg_id,
        __entry->priority,
        __entry->reclaim_idx,
        __entry->order,
        __entry->nr_to_reclaim,
        __entry->swappiness,
        __entry->plan_flags,
        __entry->scan_state_flags)
);

TRACE_EVENT(mm_vmscan_lru_adjust,

    TP_PROTO(int nid, int memcg_id, int lru,
        unsigned long nr_to_scan, unsigned long percentage,
        unsigned long nr_reclaimed, unsigned long nr_to_reclaim,
        const unsigned long *remaining, const unsigned long *targets),

    TP_ARGS(nid, memcg_id, lru, nr_to_scan, percentage,
        nr_reclaimed, nr_to_reclaim, remaining, targets),

    TP_STRUCT__entry(
        __field(int, nid)
        __field(int, memcg_id)
        __field(int, lru)
        __field(unsigned long, nr_to_scan)
        __field(unsigned long, percentage)
        __field(unsigned long, nr_reclaimed)
        __field(unsigned long, nr_to_reclaim)
        __array(unsigned long, remaining, NR_LRU_LISTS)
        __array(unsigned long, targets, NR_LRU_LISTS)
    ),

    TP_fast_assign(
        __entry->nid = nid;
        __entry->memcg_id = memcg_id;
        __entry->lru = lru;
        __entry->nr_to_scan = nr_to_scan;
        __entry->percentage = percentage;
        __entry->nr_reclaimed = nr_reclaimed;
        __entry->nr_to_reclaim = nr_to_reclaim;
        memcpy(__entry->remaining, remaining, sizeof(__entry->remaining));
        memcpy(__entry->targets, targets, sizeof(__entry->targets));
    ),

    TP_printk("nid=%d memcg_id=%d lru=%s nr_to_scan=%lu percentage=%lu nr_reclaimed=%lu nr_to_reclaim=%lu",
        __entry->nid,
        __entry->memcg_id,
        __print_symbolic(__entry->lru, LRU_NAMES),
        __entry->nr_to_scan,
        __entry->percentage,
        __entry->nr_reclaimed,
        __entry->nr_to_reclaim)
);
```

### 4.2 Modify `vmscan.c`

File location:

```text
[kernel-source]/mm/vmscan.c
```

1. Add the following two helper functions:

```c
static unsigned int trace_lru_plan_flags(struct scan_control *sc)
{
    unsigned int flags = 0;

    if (sc->may_deactivate & DEACTIVATE_ANON)
        flags |= TRACE_LRU_PLAN_FLAG_MAY_DEACTIVATE_ANON;
    if (sc->may_deactivate & DEACTIVATE_FILE)
        flags |= TRACE_LRU_PLAN_FLAG_MAY_DEACTIVATE_FILE;
    if (sc->force_deactivate)
        flags |= TRACE_LRU_PLAN_FLAG_FORCE_DEACTIVATE;
    if (sc->skipped_deactivate)
        flags |= TRACE_LRU_PLAN_FLAG_SKIPPED_DEACTIVATE;
    if (sc->may_writepage)
        flags |= TRACE_LRU_PLAN_FLAG_MAY_WRITEPAGE;
    if (sc->may_unmap)
        flags |= TRACE_LRU_PLAN_FLAG_MAY_UNMAP;
    if (sc->may_swap)
        flags |= TRACE_LRU_PLAN_FLAG_MAY_SWAP;

    return flags;
}

static unsigned int trace_lru_scan_state_flags(struct scan_control *sc,
                           bool cgroup_reclaiming,
                           bool can_reclaim_anon,
                           bool proportional_reclaim)
{
    unsigned int flags = 0;

    if (cgroup_reclaiming)
        flags |= TRACE_LRU_SCAN_STATE_CGROUP_RECLAIM;
    if (can_reclaim_anon)
        flags |= TRACE_LRU_SCAN_STATE_CAN_RECLAIM_ANON;
    if (sc->cache_trim_mode)
        flags |= TRACE_LRU_SCAN_STATE_CACHE_TRIM_MODE;
    if (sc->file_is_tiny)
        flags |= TRACE_LRU_SCAN_STATE_FILE_IS_TINY;
    if (sc->memcg_low_reclaim)
        flags |= TRACE_LRU_SCAN_STATE_MEMCG_LOW_RECLAIM;
    if (proportional_reclaim)
        flags |= TRACE_LRU_SCAN_STATE_PROPORTIONAL;

    return flags;
}
```

2. Add local variables and collected metrics inside `shrink_lruvec()`. First locate:

```c
static void shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
    unsigned long nr[NR_LRU_LISTS];
    unsigned long targets[NR_LRU_LISTS];
    unsigned long nr_to_scan;
    enum lru_list lru;
    unsigned long nr_reclaimed = 0;
    unsigned long nr_to_reclaim = sc->nr_to_reclaim;
    bool proportional_reclaim;
    struct blk_plug plug;
    .....
}
```

Then add the following immediately afterward:

```c
    unsigned long before[NR_LRU_LISTS] = { 0 };
    struct pglist_data *pgdat = lruvec_pgdat(lruvec);
    struct mem_cgroup *memcg = lruvec_memcg(lruvec);
    int swappiness;
    bool cgroup_reclaiming;
    bool can_reclaim_anon;
    unsigned int plan_flags;
    unsigned int scan_state_flags;

    swappiness = sc_swappiness(sc, memcg);
    cgroup_reclaiming = cgroup_reclaim(sc);
    can_reclaim_anon = can_reclaim_anon_pages(memcg, pgdat->node_id, sc);
```

3. Add `mm_vmscan_lru_plan` after `get_scan_count()` and `memcpy(targets, nr, sizeof(nr));`. First locate:

```c
        get_scan_count(lruvec, sc, nr);

        /* Record the original scan target for proportional adjustments later */
        memcpy(targets, nr, sizeof(nr));

        /*
         * Global reclaiming within direct reclaim at DEF_PRIORITY is a normal
         * event that can occur when there is little memory pressure e.g.
         * multiple streaming readers/writers. Hence, we do not abort scanning
         * when the requested number of pages are reclaimed when scanning at
         * DEF_PRIORITY on the assumption that the fact we are direct
         * reclaiming implies that kswapd is not keeping up and it is best to
         * do a batch of work at once. For memcg reclaim one check is made to
         * abort proportional reclaim if either the file or anon lru has already
         * dropped to zero at the first pass.
         */
        proportional_reclaim = (!cgroup_reclaim(sc) && !current_is_kswapd() &&
                                sc->priority == DEF_PRIORITY);
```

Then add:

```c
    for_each_evictable_lru(lru)
        before[lru] = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);

    plan_flags = trace_lru_plan_flags(sc);
    scan_state_flags = trace_lru_scan_state_flags(sc, cgroup_reclaiming,
                              can_reclaim_anon,
                              proportional_reclaim);
    trace_mm_vmscan_lru_plan(pgdat->node_id,
                 memcg ? mem_cgroup_id(memcg) : 0,
                 sc->priority, sc->reclaim_idx, sc->order,
                 sc->nr_to_reclaim, swappiness, plan_flags,
                 scan_state_flags, before, targets);
```

4. Add `mm_vmscan_lru_adjust` in the proportional reclaim branch. Replace the current block:

```c
    while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
                    nr[LRU_INACTIVE_FILE]) {
        unsigned long nr_anon, nr_file, percentage;
        unsigned long nr_scanned;

        for_each_evictable_lru(lru) {
            if (nr[lru]) {
                nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
                nr[lru] -= nr_to_scan;

                nr_reclaimed += shrink_list(lru, nr_to_scan,
                                lruvec, sc);
            }
        }

        cond_resched();

        if (nr_reclaimed < nr_to_reclaim || proportional_reclaim)
            continue;

        /*
         * For kswapd and memcg, reclaim at least the number of pages
         * requested. Ensure that the anon and file LRUs are scanned
         * proportionally what was requested by get_scan_count(). We
         * stop reclaiming one LRU and reduce the amount scanning
         * proportional to the original scan target.
         */
        nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
        nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];

        /*
         * It's just vindictive to attack the larger once the smaller
         * has gone to zero.  And given the way we stop scanning the
         * smaller below, this makes sure that we only make one nudge
         * towards proportionality once we've got nr_to_reclaim.
         */
        if (!nr_file || !nr_anon)
            break;

        if (nr_file > nr_anon) {
            unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
                        targets[LRU_ACTIVE_ANON] + 1;
            lru = LRU_BASE;

            percentage = nr_anon * 100 / scan_target;
        } else {
            unsigned long scan_target = targets[LRU_INACTIVE_FILE] +
                        targets[LRU_ACTIVE_FILE] + 1;
            lru = LRU_FILE;
            percentage = nr_file * 100 / scan_target;
        }

        /* Stop scanning the smaller of the LRU */
        nr[lru] = 0;
        nr[lru + LRU_ACTIVE] = 0;

        /*
         * Recalculate the other LRU scan count based on its original
         * scan target and the percentage scanning already complete
         */
        lru = (lru == LRU_FILE) ? LRU_BASE : LRU_FILE;
        nr_scanned = targets[lru] - nr[lru];
        nr[lru] = targets[lru] * (100 - percentage) / 100;
        nr[lru] -= min(nr[lru], nr_scanned);

        lru += LRU_ACTIVE;
        nr_scanned = targets[lru] - nr[lru];
        nr[lru] = targets[lru] * (100 - percentage) / 100;
        nr[lru] -= min(nr[lru], nr_scanned);
    }
```

with:

```c
    while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
                    nr[LRU_INACTIVE_FILE]) {
        unsigned long nr_anon, nr_file, percentage;
        unsigned long nr_scanned;
        unsigned long adjust_nr_to_scan;
        enum lru_list stopped_lru;

        for_each_evictable_lru(lru) {
            if (nr[lru]) {
                nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
                nr[lru] -= nr_to_scan;

                nr_reclaimed += shrink_list(lru, nr_to_scan,
                                lruvec, sc);
            }
        }

        cond_resched();

        if (nr_reclaimed < nr_to_reclaim || proportional_reclaim)
            continue;

        /*
         * For kswapd and memcg, reclaim at least the number of pages
         * requested. Ensure that the anon and file LRUs are scanned
         * proportionally what was requested by get_scan_count(). We
         * stop reclaiming one LRU and reduce the amount scanning
         * proportional to the original scan target.
         */
        nr_file = nr[LRU_INACTIVE_FILE] + nr[LRU_ACTIVE_FILE];
        nr_anon = nr[LRU_INACTIVE_ANON] + nr[LRU_ACTIVE_ANON];

        /*
         * It's just vindictive to attack the larger once the smaller
         * has gone to zero.  And given the way we stop scanning the
         * smaller below, this makes sure that we only make one nudge
         * towards proportionality once we've got nr_to_reclaim.
         */
        if (!nr_file || !nr_anon)
            break;

        if (nr_file > nr_anon) {
            unsigned long scan_target = targets[LRU_INACTIVE_ANON] +
                        targets[LRU_ACTIVE_ANON] + 1;
            lru = LRU_BASE;
            stopped_lru = lru;
            adjust_nr_to_scan = nr_anon;
            percentage = nr_anon * 100 / scan_target;
        } else {
            unsigned long scan_target = targets[LRU_INACTIVE_FILE] +
                        targets[LRU_ACTIVE_FILE] + 1;
            lru = LRU_FILE;
            stopped_lru = lru;
            adjust_nr_to_scan = nr_file;
            percentage = nr_file * 100 / scan_target;
        }

        /* Stop scanning the smaller of the LRU */
        nr[lru] = 0;
        nr[lru + LRU_ACTIVE] = 0;

        /*
         * Recalculate the other LRU scan count based on its original
         * scan target and the percentage scanning already complete
         */
        lru = (lru == LRU_FILE) ? LRU_BASE : LRU_FILE;
        nr_scanned = targets[lru] - nr[lru];
        nr[lru] = targets[lru] * (100 - percentage) / 100;
        nr[lru] -= min(nr[lru], nr_scanned);

        lru += LRU_ACTIVE;
        nr_scanned = targets[lru] - nr[lru];
        nr[lru] = targets[lru] * (100 - percentage) / 100;
        nr[lru] -= min(nr[lru], nr_scanned);

        trace_mm_vmscan_lru_adjust(pgdat->node_id,
                       memcg ? mem_cgroup_id(memcg) : 0,
                       stopped_lru,
                       adjust_nr_to_scan, percentage,
                       nr_reclaimed, nr_to_reclaim,
                       nr, targets);
    }
```

### 4.3 Rebuild the Kernel and Verify the Changes

Rebuild the kernel:

```bash
make -j`nproc`
```

Check whether the new tracepoints appear in the running system:

```bash
root@syzkaller:~# cat /sys/kernel/tracing/available_events | grep mm_vmscan_lru_
vmscan:mm_vmscan_lru_adjust
vmscan:mm_vmscan_lru_plan
vmscan:mm_vmscan_lru_shrink_active
vmscan:mm_vmscan_lru_shrink_inactive
vmscan:mm_vmscan_lru_isolate
```

If the following entries are present:

- `vmscan:mm_vmscan_lru_adjust`
- `vmscan:mm_vmscan_lru_plan`

then the new hooks have been added successfully.

### 4.4 Regenerate `vmlinux.h` and Rebuild eBPF

After the kernel is updated, you need to regenerate `vmlinux.h` and rebuild the eBPF program in this directory.

For example:

```bash
root@syzkaller:~/libbpf-bootstrap/examples/lru_monitor# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Then return to this directory and run:

```bash
make clean
make
```

## 5. eBPF Data Collection

### 5.1 Collected Information

The summary data mainly contains the following categories:

- reclaim control inputs
  - `swappiness`
  - `priority`
  - `reclaim_idx`
  - `order`
  - `nr_to_reclaim`
  - `may_deactivate`
  - `may_writepage`
  - `may_unmap`
  - `may_swap`
- traced `scan_control` states
  - `cgroup_reclaim`
  - `can_reclaim_anon`
  - `cache_trim_mode`
  - `file_is_tiny`
  - `memcg_low_reclaim`
- before-state / target information
  - `before_*`
  - `target_*`
- observed path activity
  - `observed_scanned_*`
  - `observed_taken_*`
  - `observed_deactivated_*`
  - `observed_reclaimed_*`
  - `observed_ref_keep_*`
  - `observed_dirty_*`
  - `observed_writeback_*`
- proportional-adjust information
  - `observed_proportional_adjust_count`
  - `observed_proportional_adjust_percentage`
  - `observed_proportional_stopped_lru`
  - `observed_remaining_*`

### 5.2 Dependencies

The current `Makefile` assumes `libbpf-bootstrap` is available at:

- `LIBBPF_BOOTSTRAP_ROOT := /root/libbpf-bootstrap`

If your environment uses a different path, update this entry in the `Makefile` first.

### 5.3 Build

Enter the current directory:

```bash
cd lru_parser_model
```

Then run:

```bash
make
```

To regenerate all derived files:

```bash
make clean
make
```

`make` performs the following steps:

- generate `vmlinux.h` from `/sys/kernel/btf/vmlinux` using `bpftool`
- compile `lru_monitor.bpf.c`
- generate `lru_monitor.skel.h`
- link the user-space program `lru_monitor`

### 5.4 Run

Start the monitor directly:

```bash
sudo ./lru_monitor
```

Export the output to CSV:

```bash
sudo ./lru_monitor lru_output.csv
```

The command-line format of `lru_monitor` is:

```bash
./lru_monitor [lru_output.csv]
```

## 6. Kernel-Side Requirements

This traditional LRU collection pipeline depends on two classes of kernel events:

- existing events
  - `mm_vmscan_lru_isolate`
  - `mm_vmscan_lru_shrink_inactive`
  - `mm_vmscan_lru_shrink_active`
- custom events
  - `mm_vmscan_lru_plan`
  - `mm_vmscan_lru_adjust`

Specifically:

- `mm_vmscan_lru_plan` exports the planning state after `get_scan_count()` and before entering the scan loop
- `mm_vmscan_lru_adjust` exports the result of proportional reclaim adjustment

If you modify `[kernel-source]/mm/vmscan.c` or `[kernel-source]/include/trace/events/vmscan.h`, you usually need to do the following three things together:

1. rebuild the kernel
2. regenerate `vmlinux.h` in this directory
3. run `make` again

Otherwise, the BPF-side structure definitions may become inconsistent with the ABI of the running kernel.

## 7. `lru_executor.py`

### 7.1 Functionality

`lru_executor.py` analyzes one case at a time.

It does not replay the internal `shrink_lruvec()` loop step by step. Instead, it reconstructs the following logic from summary-level data:

- `get_scan_count()`-style scan target allocation
- active/inactive path budgeting
- interpretation of the remaining work after proportional reclaim adjustment
- final anon/file reclaim prediction

Its outputs include:

- `predicted_anon_pages`
- `predicted_file_pages`
- error analysis
- detailed trace

### 7.2 Usage

Analyze a single JSON case directly:

```bash
python lru_executor.py lru_template_case/lru_case_sw100.json
```

Output JSON:

```bash
python lru_executor.py lru_template_case/lru_case_sw100.json --json
```

Read from standard input:

```bash
python lru_executor.py --stdin --json < lru_template_case/lru_case_sw100.json
```

Read a specific line from a CSV file:

```bash
python lru_executor.py --csv lru_output.csv --line 2 --json
```

Read by `session_id`:

```bash
python lru_executor.py --csv lru_output.csv --session-id 123 --json
```

Print a template case:

```bash
python lru_executor.py --template
```

More options:

```bash
python lru_executor.py --help
```

## 8. `validate_lru_executor.py`

### 8.1 Functionality

`validate_lru_executor.py` performs batch validation.

It:

- reads `lru_output.csv`
- rebuilds each row into a case
- invokes `lru_executor.py` to analyze each case
- outputs a per-row result CSV
- outputs a summary JSON
- saves a representative case
- saves the top-error cases

### 8.2 Output Files

By default, it generates:

- `lru_executor_validation_results.csv`
  Validation result for each sample.
- `lru_executor_validation_summary.json`
  Aggregated metrics.
- `lru_template_case/lru_case_sw100.json`
  Representative case.
- `lru_executor_top_error_cases.json`
  List of cases with the largest prediction errors.

### 8.3 Usage

Use the default input files:

```bash
python validate_lru_executor.py
```

Validate a specific CSV file:

```bash
python validate_lru_executor.py --csv lru_output.csv
```

Validate only `kswapd0`:

```bash
python validate_lru_executor.py --csv lru_output.csv --trigger-comm kswapd0
```

Validate all triggering processes:

```bash
python validate_lru_executor.py --csv lru_output.csv --trigger-comm all
```

Limit the number of samples:

```bash
python validate_lru_executor.py --csv lru_output.csv --limit 1000
```

Include `top_error_cases` in the summary:

```bash
python validate_lru_executor.py \
  --csv lru_output.csv \
  --include-top-error-cases
```

More options:

```bash
python validate_lru_executor.py --help
```
