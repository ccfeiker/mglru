# Traditional LRU eBPF 与解析模型说明

## 1. 功能

本目录用于采集和解析 Linux 传统 LRU 路径上的 `shrink_lruvec()` 行为。

整体目标分成两部分：

- 用 eBPF 采集一次 `shrink_lruvec()` 的 summary 级信息
- 用 `lru_executor.py` 根据这些信息对传统 LRU 路径进行解析建模，并预测 anon / file reclaim 数量

当前模型的定位是：

- `one CSV row == one shrink_lruvec() summary`
- 面向传统 LRU 路径
- 是源码驱动的 summary 级解析模型

## 2. 说明

本目录下的核心文件包括：

- `lru_monitor.bpf.c`
  负责挂载 tracepoint / kprobe，采集传统 LRU reclaim 过程中的观测信息
- `lru_monitor.c`
  负责加载 eBPF、读取 ring buffer、导出 `lru_output.csv`
- `lru_monitor.h`
  定义 eBPF 与用户态共享的 summary 事件结构 `struct lru_event`
- `lru_executor.py`
  传统 LRU 解析模型执行器。输入单条 case，输出预测结果和解析 trace
- `validate_lru_executor.py`
  批量验证脚本。读取 `lru_output.csv`，逐行调用 `lru_executor.py` 做验证并汇总指标
- `Makefile`
  用于生成 `vmlinux.h`、编译 BPF 对象、生成 skeleton、链接用户态程序
- `lru_output.csv`
  monitor 导出的 summary 数据

## 3. 修改 Linux 内核代码并添加 tracepoint

由于当前传统 LRU 解析模型需要额外的计划信息和 proportional adjust 信息，因此需要修改 Linux 内核代码，在 `vmscan` 路径中增加两个 tracepoint：

- `mm_vmscan_lru_plan`
- `mm_vmscan_lru_adjust`

### 3.1 修改 `vmscan.h`

文件位置：

```text
kernel-source/include/trace/events/vmscan.h
```

1. 在 `#define trace_reclaim_flags(file)` 后添加以下宏定义：

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

2. 在 `TRACE_EVENT(mm_vmscan_lru_shrink_active, ...)` 结束后添加：

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

### 3.2 修改 `vmscan.c`

文件位置：

```text
kernel-source/mm/vmscan.c
```

1. 添加两个辅助函数：

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

2. 在 `shrink_lruvec()` 中新增局部变量和采集指标。先找到这段：

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

在这段后面添加：

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

3. 在 `get_scan_count()` 和 `memcpy(targets, nr, sizeof(nr));` 后，新增 `mm_vmscan_lru_plan`。先找到：

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

在这段后面添加：

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

4. 在 proportional reclaim 分支里，新增 `mm_vmscan_lru_adjust`。将当前这段：

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

替换成：

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

### 3.3 重新编译内核并检查是否成功

重新编译内核：

```bash
make -j`nproc`
```

检查 tracepoint 是否已经出现在系统中：

```bash
root@syzkaller:~# cat /sys/kernel/tracing/available_events | grep mm_vmscan_lru_
vmscan:mm_vmscan_lru_adjust
vmscan:mm_vmscan_lru_plan
vmscan:mm_vmscan_lru_shrink_active
vmscan:mm_vmscan_lru_shrink_inactive
vmscan:mm_vmscan_lru_isolate
```

如果存在：

- `vmscan:mm_vmscan_lru_adjust`
- `vmscan:mm_vmscan_lru_plan`

则说明新增 hook 成功。

### 3.4 重新生成 `vmlinux.h` 并编译 eBPF

内核更新后，需要重新生成 `vmlinux.h`，然后重新编译本目录下的 eBPF 程序。

例如：

```bash
root@syzkaller:~/libbpf-bootstrap/examples/lru_monitor# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

随后回到本目录重新执行：

```bash
make clean
make
```

## 4. eBPF 采集

### 4.1 采集内容

当前 summary case 主要包含以下几类信息：

- reclaim 控制输入
  - `swappiness`
  - `priority`
  - `reclaim_idx`
  - `order`
  - `nr_to_reclaim`
  - `may_deactivate`
  - `may_writepage`
  - `may_unmap`
  - `may_swap`
- traced `scan_control` 状态
  - `cgroup_reclaim`
  - `can_reclaim_anon`
  - `cache_trim_mode`
  - `file_is_tiny`
  - `memcg_low_reclaim`
- before-state / target
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
- proportional adjust 信息
  - `observed_proportional_adjust_count`
  - `observed_proportional_adjust_percentage`
  - `observed_proportional_stopped_lru`
  - `observed_remaining_*`

### 4.2 依赖

当前 `Makefile` 默认依赖 `libbpf-bootstrap`：

- `LIBBPF_BOOTSTRAP_ROOT := /root/libbpf-bootstrap`

如果你的环境路径不同，需要先调整 `Makefile` 中这一项。

### 4.3 编译

先进入当前目录：

```bash
cd lru_eBPF
```

然后执行：

```bash
make
```

如需重新生成：

```bash
make clean
make
```

`make` 会完成这些工作：

- 用 `bpftool` 从 `/sys/kernel/btf/vmlinux` 生成 `vmlinux.h`
- 编译 `lru_monitor.bpf.c`
- 生成 `lru_monitor.skel.h`
- 链接得到用户态程序 `lru_monitor`

### 4.4 运行

直接启动 monitor：

```bash
sudo ./lru_monitor
```

导出到 CSV：

```bash
sudo ./lru_monitor lru_output.csv
```

当前 `lru_monitor` 的命令格式是：

```bash
./lru_monitor [lru_output.csv]
```

## 5. 内核侧配合

当前这套传统 LRU 采集依赖两类内核事件：

- 已有事件
  - `mm_vmscan_lru_isolate`
  - `mm_vmscan_lru_shrink_inactive`
  - `mm_vmscan_lru_shrink_active`
- 自定义事件
  - `mm_vmscan_lru_plan`
  - `mm_vmscan_lru_adjust`

其中：

- `mm_vmscan_lru_plan` 用来导出 `get_scan_count()` 之后、进入扫描循环之前的计划信息
- `mm_vmscan_lru_adjust` 用来导出 proportional reclaim adjust 的结果

如果你修改了 `kernel-source/mm/vmscan.c` 或 `kernel-source/include/trace/events/vmscan.h`，通常需要同步做三件事：

1. 重编内核
2. 重新生成本目录下的 `vmlinux.h`
3. 重新执行 `make`

否则 BPF 侧结构和运行内核 ABI 可能不一致。

## 6. `lru_executor.py`

### 6.1 功能

`lru_executor.py` 用来解析单条 case。

它不会逐次重放 `shrink_lruvec()` 内部循环，而是基于 summary 级数据重建以下逻辑：

- `get_scan_count()` 风格的 scan target 分配
- active / inactive 路径预算
- proportional reclaim adjust 的剩余量解释
- anon / file reclaim 的最终预测

输出包括：

- `predicted_anon_pages`
- `predicted_file_pages`
- 误差分析
- 详细 trace

### 6.2 运行方式

直接解析单个 JSON case：

```bash
python lru_executor.py selected_lru_case.json
```

输出 JSON：

```bash
python lru_executor.py selected_lru_case.json --json
```

从标准输入读取：

```bash
python lru_executor.py --stdin --json < selected_lru_case.json
```

从 CSV 的指定行读取：

```bash
python lru_executor.py --csv lru_output.csv --line 2 --json
```

按 `session_id` 读取：

```bash
python lru_executor.py --csv lru_output.csv --session-id 123 --json
```

打印模板 case：

```bash
python lru_executor.py --template
```

更多参数：

```bash
python lru_executor.py --help
```

## 7. `validate_lru_executor.py`

### 7.1 功能

`validate_lru_executor.py` 用来做批量验证。

它会：

- 读取 `lru_output.csv`
- 每一行重建成 case
- 调用 `lru_executor.py` 执行解析
- 输出逐行结果 CSV
- 输出汇总 JSON
- 保存代表性 case
- 保存 top error case

### 7.2 输出文件

默认会生成：

- `lru_executor_validation_results.csv`
  每条样本的验证结果
- `lru_executor_validation_summary.json`
  汇总指标
- `selected_lru_case.json`
  代表性 case
- `lru_executor_top_error_cases.json`
  误差最大的 case 列表

注意：

- 默认终端输出和 `summary.json` 不再内嵌 `top_error_cases`
- 如需在 summary 中显式包含它们，请加 `--include-top-error-cases`

### 7.3 运行方式

使用默认文件：

```bash
python validate_lru_executor.py
```

验证指定 CSV：

```bash
python validate_lru_executor.py --csv lru_output.csv
```

只验证 `kswapd0`：

```bash
python validate_lru_executor.py --csv lru_output.csv --trigger-comm kswapd0
```

验证全部触发进程：

```bash
python validate_lru_executor.py --csv lru_output.csv --trigger-comm all
```

限制样本数：

```bash
python validate_lru_executor.py --csv lru_output.csv --limit 1000
```

在 summary 中包含 `top_error_cases`：

```bash
python validate_lru_executor.py \
  --csv lru_output.csv \
  --include-top-error-cases
```

更多参数：

```bash
python validate_lru_executor.py --help
```

## 8. 推荐工作流

推荐按这个顺序使用：

1. 修改并编译内核侧 tracepoint
2. 在 `lru_eBPF` 目录执行 `make`
3. 运行 `sudo ./lru_monitor lru_output.csv`
4. 执行 `python validate_lru_executor.py --csv lru_output.csv --trigger-comm kswapd0`
5. 如需深入分析单条样本，再执行 `python lru_executor.py --csv lru_output.csv --line <line_no> --json`
