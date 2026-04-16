#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "lru_monitor.h"

char LICENSE[] SEC("license") = "GPL";

#define RECLAIM_WB_FILE 0x0002u
#define LRU_FILE_IDX 1
#define DEACTIVATE_ANON 1
#define DEACTIVATE_FILE 2
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

struct mem_cgroup_id___local {
    int id;
};

struct mem_cgroup___local {
    struct cgroup_subsys_state css;
    struct mem_cgroup_id___local id;
};

struct active_session {
    struct lruvec *lruvec;
    struct scan_control *sc;
    unsigned long long session_id;
    unsigned long long memcg_id;
    unsigned int trigger_tgid;
    unsigned int trigger_tid;
    char trigger_comm[LRU_COMM_LEN];
    int node_id;
    int swappiness;
    int priority;
    int reclaim_idx;
    int order;
    unsigned int may_deactivate;
    unsigned int force_deactivate;
    unsigned int skipped_deactivate;
    unsigned int may_writepage;
    unsigned int may_unmap;
    unsigned int may_swap;
    unsigned long long gfp_mask;
    unsigned long long nr_to_reclaim;
    unsigned long long anon_cost;
    unsigned long long file_cost;
    unsigned long long refaults_anon;
    unsigned long long refaults_file;
    unsigned int proportional_reclaim;
    unsigned int cgroup_reclaim;
    unsigned int can_reclaim_anon;
    unsigned int cache_trim_mode;
    unsigned int file_is_tiny;
    unsigned int memcg_low_reclaim;
    unsigned long long before_inactive_anon;
    unsigned long long before_active_anon;
    unsigned long long before_inactive_file;
    unsigned long long before_active_file;
    unsigned long long target_inactive_anon;
    unsigned long long target_active_anon;
    unsigned long long target_inactive_file;
    unsigned long long target_active_file;
    unsigned long long observed_scanned_inactive_anon_pages;
    unsigned long long observed_taken_active_anon_pages;
    unsigned long long observed_scanned_inactive_file_pages;
    unsigned long long observed_taken_active_file_pages;
    unsigned int observed_isolate_calls_inactive_anon;
    unsigned int observed_isolate_calls_active_anon;
    unsigned int observed_isolate_calls_inactive_file;
    unsigned int observed_isolate_calls_active_file;
    unsigned long long observed_isolated_pages_inactive_anon;
    unsigned long long observed_isolated_pages_active_anon;
    unsigned long long observed_isolated_pages_inactive_file;
    unsigned long long observed_isolated_pages_active_file;
    unsigned long long observed_reclaimed_anon_pages;
    unsigned long long observed_reclaimed_file_pages;
    unsigned long long observed_activated_anon_pages;
    unsigned long long observed_activated_file_pages;
    unsigned long long observed_deactivated_anon_pages;
    unsigned long long observed_deactivated_file_pages;
    unsigned long long observed_active_retained_anon_pages;
    unsigned long long observed_active_retained_file_pages;
    unsigned long long observed_referenced_anon_pages;
    unsigned long long observed_referenced_file_pages;
    unsigned long long observed_ref_keep_anon_pages;
    unsigned long long observed_ref_keep_file_pages;
    unsigned long long observed_dirty_file_pages;
    unsigned long long observed_writeback_file_pages;
    unsigned long long observed_congested_file_pages;
    unsigned long long observed_immediate_file_pages;
    unsigned long long observed_unmap_fail_anon_pages;
    unsigned long long observed_unmap_fail_file_pages;
    unsigned int observed_proportional_adjust_count;
    unsigned long long observed_proportional_adjust_percentage;
    int observed_proportional_stopped_lru;
    unsigned long long observed_remaining_inactive_anon_pages;
    unsigned long long observed_remaining_active_anon_pages;
    unsigned long long observed_remaining_inactive_file_pages;
    unsigned long long observed_remaining_active_file_pages;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct active_session);
} active_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct active_session);
} session_scratch SEC(".maps");

static __always_inline unsigned long long get_memcg_id(struct mem_cgroup *memcg)
{
    struct mem_cgroup___local *m;
    int id = 0;

    if (!memcg)
        return 0;

    m = (void *)memcg;
    if (bpf_probe_read_kernel(&id, sizeof(id), &m->id.id))
        return 0;

    return (unsigned long long)id;
}

static __always_inline void account_isolate(struct active_session *sample, int lru, unsigned long long nr_taken)
{
    if (!sample)
        return;

    switch (lru) {
    case LRU_LIST_INACTIVE_ANON:
        sample->observed_isolate_calls_inactive_anon += 1;
        sample->observed_isolated_pages_inactive_anon += nr_taken;
        break;
    case LRU_LIST_ACTIVE_ANON:
        sample->observed_isolate_calls_active_anon += 1;
        sample->observed_isolated_pages_active_anon += nr_taken;
        break;
    case LRU_LIST_INACTIVE_FILE:
        sample->observed_isolate_calls_inactive_file += 1;
        sample->observed_isolated_pages_inactive_file += nr_taken;
        break;
    case LRU_LIST_ACTIVE_FILE:
        sample->observed_isolate_calls_active_file += 1;
        sample->observed_isolated_pages_active_file += nr_taken;
        break;
    default:
        break;
    }
}

static __always_inline void account_scan_work(struct active_session *sample, int lru, unsigned long long pages)
{
    if (!sample)
        return;

    switch (lru) {
    case LRU_LIST_INACTIVE_ANON:
        sample->observed_scanned_inactive_anon_pages += pages;
        break;
    case LRU_LIST_ACTIVE_ANON:
        sample->observed_taken_active_anon_pages += pages;
        break;
    case LRU_LIST_INACTIVE_FILE:
        sample->observed_scanned_inactive_file_pages += pages;
        break;
    case LRU_LIST_ACTIVE_FILE:
        sample->observed_taken_active_file_pages += pages;
        break;
    default:
        break;
    }
}

SEC("kprobe/shrink_lruvec")
int BPF_KPROBE(shrink_lruvec_enter, struct lruvec *lruvec, struct scan_control *sc)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 zero = 0;
    struct active_session *sample;
    struct mem_cgroup *target_memcg;

    if (!lruvec || !sc)
        return 0;

    sample = bpf_map_lookup_elem(&session_scratch, &zero);
    if (!sample)
        return 0;

    __builtin_memset(sample, 0, sizeof(*sample));
    sample->lruvec = lruvec;
    sample->sc = sc;
    sample->session_id = bpf_ktime_get_ns();
    sample->trigger_tgid = pid_tgid >> 32;
    sample->trigger_tid = tid;
    bpf_get_current_comm(sample->trigger_comm, sizeof(sample->trigger_comm));
    sample->priority = BPF_CORE_READ(sc, priority);
    sample->reclaim_idx = BPF_CORE_READ(sc, reclaim_idx);
    sample->order = BPF_CORE_READ(sc, order);
    sample->may_deactivate = BPF_CORE_READ_BITFIELD_PROBED(sc, may_deactivate);
    sample->force_deactivate = BPF_CORE_READ_BITFIELD_PROBED(sc, force_deactivate);
    sample->skipped_deactivate = BPF_CORE_READ_BITFIELD_PROBED(sc, skipped_deactivate);
    sample->may_writepage = BPF_CORE_READ_BITFIELD_PROBED(sc, may_writepage);
    sample->may_unmap = BPF_CORE_READ_BITFIELD_PROBED(sc, may_unmap);
    sample->may_swap = BPF_CORE_READ_BITFIELD_PROBED(sc, may_swap);
    sample->gfp_mask = BPF_CORE_READ(sc, gfp_mask);
    sample->nr_to_reclaim = BPF_CORE_READ(sc, nr_to_reclaim);
    sample->swappiness = sample->may_swap ? -1 : 0;
    sample->anon_cost = BPF_CORE_READ(lruvec, anon_cost);
    sample->file_cost = BPF_CORE_READ(lruvec, file_cost);
    sample->refaults_anon = BPF_CORE_READ(lruvec, refaults[0]);
    sample->refaults_file = BPF_CORE_READ(lruvec, refaults[LRU_FILE_IDX]);

    target_memcg = BPF_CORE_READ(sc, target_mem_cgroup);
    sample->memcg_id = get_memcg_id(target_memcg);
    sample->node_id = -1;

    bpf_map_update_elem(&active_sessions, &tid, sample, BPF_ANY);
    return 0;
}

SEC("kretprobe/get_swappiness")
int BPF_KRETPROBE(get_swappiness_exit, int ret)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct active_session *sample;

    sample = bpf_map_lookup_elem(&active_sessions, &tid);
    if (!sample)
        return 0;

    sample->swappiness = ret;
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_lru_plan")
int lru_plan_tp(struct trace_event_raw_mm_vmscan_lru_plan *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct active_session *sample;
    unsigned int plan_flags;
    unsigned int scan_state_flags;

    sample = bpf_map_lookup_elem(&active_sessions, &tid);
    if (!sample)
        return 0;

    sample->node_id = ctx->nid;
    sample->memcg_id = (unsigned long long)ctx->memcg_id;
    sample->priority = ctx->priority;
    sample->reclaim_idx = ctx->reclaim_idx;
    sample->order = ctx->order;
    sample->nr_to_reclaim = ctx->nr_to_reclaim;
    sample->swappiness = ctx->swappiness;
    scan_state_flags = ctx->scan_state_flags;
    sample->proportional_reclaim = !!(scan_state_flags & TRACE_LRU_SCAN_STATE_PROPORTIONAL);
    sample->cgroup_reclaim = !!(scan_state_flags & TRACE_LRU_SCAN_STATE_CGROUP_RECLAIM);
    sample->can_reclaim_anon = !!(scan_state_flags & TRACE_LRU_SCAN_STATE_CAN_RECLAIM_ANON);
    sample->cache_trim_mode = !!(scan_state_flags & TRACE_LRU_SCAN_STATE_CACHE_TRIM_MODE);
    sample->file_is_tiny = !!(scan_state_flags & TRACE_LRU_SCAN_STATE_FILE_IS_TINY);
    sample->memcg_low_reclaim = !!(scan_state_flags & TRACE_LRU_SCAN_STATE_MEMCG_LOW_RECLAIM);

    plan_flags = ctx->plan_flags;
    sample->may_deactivate = 0;
    if (plan_flags & TRACE_LRU_PLAN_FLAG_MAY_DEACTIVATE_ANON)
        sample->may_deactivate |= DEACTIVATE_ANON;
    if (plan_flags & TRACE_LRU_PLAN_FLAG_MAY_DEACTIVATE_FILE)
        sample->may_deactivate |= DEACTIVATE_FILE;
    sample->force_deactivate = !!(plan_flags & TRACE_LRU_PLAN_FLAG_FORCE_DEACTIVATE);
    sample->skipped_deactivate = !!(plan_flags & TRACE_LRU_PLAN_FLAG_SKIPPED_DEACTIVATE);
    sample->may_writepage = !!(plan_flags & TRACE_LRU_PLAN_FLAG_MAY_WRITEPAGE);
    sample->may_unmap = !!(plan_flags & TRACE_LRU_PLAN_FLAG_MAY_UNMAP);
    sample->may_swap = !!(plan_flags & TRACE_LRU_PLAN_FLAG_MAY_SWAP);

    sample->before_inactive_anon = ctx->before[LRU_LIST_INACTIVE_ANON];
    sample->before_active_anon = ctx->before[LRU_LIST_ACTIVE_ANON];
    sample->before_inactive_file = ctx->before[LRU_LIST_INACTIVE_FILE];
    sample->before_active_file = ctx->before[LRU_LIST_ACTIVE_FILE];

    sample->target_inactive_anon = ctx->targets[LRU_LIST_INACTIVE_ANON];
    sample->target_active_anon = ctx->targets[LRU_LIST_ACTIVE_ANON];
    sample->target_inactive_file = ctx->targets[LRU_LIST_INACTIVE_FILE];
    sample->target_active_file = ctx->targets[LRU_LIST_ACTIVE_FILE];

    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_lru_adjust")
int lru_adjust_tp(struct trace_event_raw_mm_vmscan_lru_adjust *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct active_session *sample;

    sample = bpf_map_lookup_elem(&active_sessions, &tid);
    if (!sample)
        return 0;

    sample->node_id = ctx->nid;
    sample->memcg_id = (unsigned long long)ctx->memcg_id;
    sample->nr_to_reclaim = ctx->nr_to_reclaim;
    sample->observed_remaining_inactive_anon_pages = ctx->remaining[LRU_LIST_INACTIVE_ANON];
    sample->observed_remaining_active_anon_pages = ctx->remaining[LRU_LIST_ACTIVE_ANON];
    sample->observed_remaining_inactive_file_pages = ctx->remaining[LRU_LIST_INACTIVE_FILE];
    sample->observed_remaining_active_file_pages = ctx->remaining[LRU_LIST_ACTIVE_FILE];

    sample->observed_proportional_adjust_count += 1;
    sample->observed_proportional_adjust_percentage = ctx->percentage;
    sample->observed_proportional_stopped_lru = ctx->lru;

    return 0;
}

SEC("kretprobe/shrink_lruvec")
int BPF_KRETPROBE(shrink_lruvec_exit)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct active_session *sample;
    struct lru_event *event;

    sample = bpf_map_lookup_elem(&active_sessions, &tid);
    if (!sample)
        return 0;

    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        goto out;

    __builtin_memset(event, 0, sizeof(*event));
    event->kind = LRU_EVENT_SUMMARY;
    event->session_id = sample->session_id;
    event->memcg_id = sample->memcg_id;
    event->trigger_tgid = sample->trigger_tgid;
    event->trigger_tid = sample->trigger_tid;
    __builtin_memcpy(event->trigger_comm, sample->trigger_comm, sizeof(event->trigger_comm));
    event->node_id = sample->node_id;
    event->swappiness = sample->swappiness;
    event->priority = sample->priority;
    event->reclaim_idx = sample->reclaim_idx;
    event->order = sample->order;
    event->may_deactivate = sample->may_deactivate;
    event->force_deactivate = sample->force_deactivate;
    event->skipped_deactivate = sample->skipped_deactivate;
    event->may_writepage = sample->may_writepage;
    event->may_unmap = sample->may_unmap;
    event->may_swap = sample->may_swap;
    event->gfp_mask = sample->gfp_mask;
    event->nr_to_reclaim = sample->nr_to_reclaim;
    event->anon_cost = sample->anon_cost;
    event->file_cost = sample->file_cost;
    event->refaults_anon = sample->refaults_anon;
    event->refaults_file = sample->refaults_file;
    event->proportional_reclaim = sample->proportional_reclaim;
    event->cgroup_reclaim = sample->cgroup_reclaim;
    event->can_reclaim_anon = sample->can_reclaim_anon;
    event->cache_trim_mode = sample->cache_trim_mode;
    event->file_is_tiny = sample->file_is_tiny;
    event->memcg_low_reclaim = sample->memcg_low_reclaim;
    event->before_inactive_anon = sample->before_inactive_anon;
    event->before_active_anon = sample->before_active_anon;
    event->before_inactive_file = sample->before_inactive_file;
    event->before_active_file = sample->before_active_file;
    event->target_inactive_anon = sample->target_inactive_anon;
    event->target_active_anon = sample->target_active_anon;
    event->target_inactive_file = sample->target_inactive_file;
    event->target_active_file = sample->target_active_file;
    event->observed_scanned_inactive_anon_pages = sample->observed_scanned_inactive_anon_pages;
    event->observed_taken_active_anon_pages = sample->observed_taken_active_anon_pages;
    event->observed_scanned_inactive_file_pages = sample->observed_scanned_inactive_file_pages;
    event->observed_taken_active_file_pages = sample->observed_taken_active_file_pages;
    event->observed_isolate_calls_inactive_anon = sample->observed_isolate_calls_inactive_anon;
    event->observed_isolate_calls_active_anon = sample->observed_isolate_calls_active_anon;
    event->observed_isolate_calls_inactive_file = sample->observed_isolate_calls_inactive_file;
    event->observed_isolate_calls_active_file = sample->observed_isolate_calls_active_file;
    event->observed_isolated_pages_inactive_anon = sample->observed_isolated_pages_inactive_anon;
    event->observed_isolated_pages_active_anon = sample->observed_isolated_pages_active_anon;
    event->observed_isolated_pages_inactive_file = sample->observed_isolated_pages_inactive_file;
    event->observed_isolated_pages_active_file = sample->observed_isolated_pages_active_file;
    event->observed_reclaimed_anon_pages = sample->observed_reclaimed_anon_pages;
    event->observed_reclaimed_file_pages = sample->observed_reclaimed_file_pages;
    event->observed_activated_anon_pages = sample->observed_activated_anon_pages;
    event->observed_activated_file_pages = sample->observed_activated_file_pages;
    event->observed_deactivated_anon_pages = sample->observed_deactivated_anon_pages;
    event->observed_deactivated_file_pages = sample->observed_deactivated_file_pages;
    event->observed_active_retained_anon_pages = sample->observed_active_retained_anon_pages;
    event->observed_active_retained_file_pages = sample->observed_active_retained_file_pages;
    event->observed_referenced_anon_pages = sample->observed_referenced_anon_pages;
    event->observed_referenced_file_pages = sample->observed_referenced_file_pages;
    event->observed_ref_keep_anon_pages = sample->observed_ref_keep_anon_pages;
    event->observed_ref_keep_file_pages = sample->observed_ref_keep_file_pages;
    event->observed_dirty_file_pages = sample->observed_dirty_file_pages;
    event->observed_writeback_file_pages = sample->observed_writeback_file_pages;
    event->observed_congested_file_pages = sample->observed_congested_file_pages;
    event->observed_immediate_file_pages = sample->observed_immediate_file_pages;
    event->observed_unmap_fail_anon_pages = sample->observed_unmap_fail_anon_pages;
    event->observed_unmap_fail_file_pages = sample->observed_unmap_fail_file_pages;
    event->observed_proportional_adjust_count = sample->observed_proportional_adjust_count;
    event->observed_proportional_adjust_percentage = sample->observed_proportional_adjust_percentage;
    event->observed_proportional_stopped_lru = sample->observed_proportional_stopped_lru;
    event->observed_remaining_inactive_anon_pages = sample->observed_remaining_inactive_anon_pages;
    event->observed_remaining_active_anon_pages = sample->observed_remaining_active_anon_pages;
    event->observed_remaining_inactive_file_pages = sample->observed_remaining_inactive_file_pages;
    event->observed_remaining_active_file_pages = sample->observed_remaining_active_file_pages;
    bpf_ringbuf_submit(event, 0);

out:
    bpf_map_delete_elem(&active_sessions, &tid);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_lru_isolate")
int lru_isolate_tp(struct trace_event_raw_mm_vmscan_lru_isolate *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct active_session *sample;
    int lru;
    unsigned long long nr_taken;

    sample = bpf_map_lookup_elem(&active_sessions, &tid);
    if (!sample)
        return 0;

    lru = ctx->lru;
    nr_taken = ctx->nr_taken;
    account_isolate(sample, lru, nr_taken);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_lru_shrink_inactive")
int lru_shrink_inactive_tp(struct trace_event_raw_mm_vmscan_lru_shrink_inactive *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct active_session *sample;
    bool file;
    int nid;
    int reclaim_flags;
    unsigned long long nr_reclaimed;
    unsigned long long nr_scanned;
    unsigned long long nr_ref_keep;
    unsigned long long nr_dirty;
    unsigned long long nr_writeback;
    unsigned long long nr_unmap_fail;
    unsigned int nr_activate0;
    unsigned int nr_activate1;

    sample = bpf_map_lookup_elem(&active_sessions, &tid);
    if (!sample)
        return 0;

    nid = ctx->nid;
    reclaim_flags = ctx->reclaim_flags;
    nr_reclaimed = ctx->nr_reclaimed;
    nr_scanned = ctx->nr_scanned;
    nr_ref_keep = ctx->nr_ref_keep;
    nr_dirty = ctx->nr_dirty;
    nr_writeback = ctx->nr_writeback;
    nr_unmap_fail = ctx->nr_unmap_fail;
    nr_activate0 = ctx->nr_activate0;
    nr_activate1 = ctx->nr_activate1;

    if (sample->node_id < 0)
        sample->node_id = nid;

    file = (reclaim_flags & RECLAIM_WB_FILE) != 0;
    if (file) {
        account_scan_work(sample, LRU_LIST_INACTIVE_FILE, nr_scanned);
        sample->observed_reclaimed_file_pages += nr_reclaimed;
        sample->observed_ref_keep_file_pages += nr_ref_keep;
        sample->observed_dirty_file_pages += nr_dirty;
        sample->observed_writeback_file_pages += nr_writeback;
        sample->observed_congested_file_pages += ctx->nr_congested;
        sample->observed_immediate_file_pages += ctx->nr_immediate;
        sample->observed_unmap_fail_file_pages += nr_unmap_fail;
    } else {
        account_scan_work(sample, LRU_LIST_INACTIVE_ANON, nr_scanned);
        sample->observed_reclaimed_anon_pages += nr_reclaimed;
        sample->observed_ref_keep_anon_pages += nr_ref_keep;
        sample->observed_unmap_fail_anon_pages += nr_unmap_fail;
    }

    sample->observed_activated_anon_pages += nr_activate0;
    sample->observed_activated_file_pages += nr_activate1;
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_lru_shrink_active")
int lru_shrink_active_tp(struct trace_event_raw_mm_vmscan_lru_shrink_active *ctx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct active_session *sample;
    bool file;
    int nid;
    int reclaim_flags;
    unsigned long long nr_taken;
    unsigned long long nr_active;
    unsigned long long nr_deactivated;
    unsigned long long nr_referenced;

    sample = bpf_map_lookup_elem(&active_sessions, &tid);
    if (!sample)
        return 0;

    nid = ctx->nid;
    reclaim_flags = ctx->reclaim_flags;
    nr_taken = ctx->nr_taken;
    nr_active = ctx->nr_active;
    nr_deactivated = ctx->nr_deactivated;
    nr_referenced = ctx->nr_referenced;

    if (sample->node_id < 0)
        sample->node_id = nid;

    file = (reclaim_flags & RECLAIM_WB_FILE) != 0;
    if (file) {
        account_scan_work(sample, LRU_LIST_ACTIVE_FILE, nr_taken);
        sample->observed_deactivated_file_pages += nr_deactivated;
        sample->observed_active_retained_file_pages += nr_active;
        sample->observed_referenced_file_pages += nr_referenced;
    } else {
        account_scan_work(sample, LRU_LIST_ACTIVE_ANON, nr_taken);
        sample->observed_deactivated_anon_pages += nr_deactivated;
        sample->observed_active_retained_anon_pages += nr_active;
        sample->observed_referenced_anon_pages += nr_referenced;
    }

    return 0;
}
