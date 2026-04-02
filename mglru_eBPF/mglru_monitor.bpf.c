#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "mglru_monitor.h"

char LICENSE[] SEC("license") = "GPL";

struct try_sample {
    struct lruvec *lruvec;
    struct scan_control *sc;
    u64 memcg_id;
    u32 trigger_tgid;
    u32 trigger_tid;
    char trigger_comm[MGLRU_COMM_LEN];
    int swappiness;
    u32 evict_folios_calls;
    unsigned long long reclaimed_pages[MGLRU_MAX_TYPES];
    struct mglru_lru_gen_folio_snapshot before;
};

struct evict_state {
    struct lruvec *lruvec;
    struct scan_control *sc;
    int *type_scanned;
    long nr_reclaimed_before;
    int type;
};

struct mem_cgroup_id___local {
    int id;
};

struct mem_cgroup___local {
    struct cgroup_subsys_state css;
    struct mem_cgroup_id___local id;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct try_sample);
} active_tries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct evict_state);
} active_evictions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct try_sample);
} try_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct evict_state);
} evict_scratch SEC(".maps");

static __always_inline u64 get_memcg_id(struct mem_cgroup *memcg)
{
    struct mem_cgroup___local *m;
    int id = 0;

    if (!memcg)
        return 0;

    m = (void *)memcg;
    if (bpf_probe_read_kernel(&id, sizeof(id), &m->id.id))
        return 0;

    return (u64)id;
}

static __always_inline void copy_snapshot(struct mglru_lru_gen_folio_snapshot *dst,
                                          const struct mglru_lru_gen_folio_snapshot *src)
{
    int i;

    dst->max_seq = src->max_seq;

#pragma unroll
    for (i = 0; i < MGLRU_MAX_TYPES; i++)
        dst->min_seq[i] = src->min_seq[i];

#pragma unroll
    for (i = 0; i < MGLRU_NR_PAGE_BINS; i++)
        dst->nr_pages[i] = src->nr_pages[i];

#pragma unroll
    for (i = 0; i < MGLRU_NR_TYPE_TIER_BINS; i++)
        dst->avg_refaulted[i] = src->avg_refaulted[i];

#pragma unroll
    for (i = 0; i < MGLRU_NR_TYPE_TIER_BINS; i++)
        dst->avg_total[i] = src->avg_total[i];

#pragma unroll
    for (i = 0; i < MGLRU_NR_PROTECTED_BINS; i++)
        dst->protected[i] = src->protected[i];

#pragma unroll
    for (i = 0; i < MGLRU_NR_HIST_TIER_BINS; i++)
        dst->evicted[i] = src->evicted[i];

#pragma unroll
    for (i = 0; i < MGLRU_NR_HIST_TIER_BINS; i++)
        dst->refaulted[i] = src->refaulted[i];
}

static __always_inline void snapshot_lru_gen_folio(
    struct mglru_lru_gen_folio_snapshot *dst, struct lruvec *lruvec)
{
    struct lru_gen_folio *lrugen = &lruvec->lrugen;

    dst->max_seq = BPF_CORE_READ(lruvec, lrugen.max_seq);
    bpf_core_read(dst->min_seq, sizeof(dst->min_seq), &lrugen->min_seq);
    bpf_core_read(dst->nr_pages, sizeof(dst->nr_pages), &lrugen->nr_pages);
    bpf_core_read(dst->avg_refaulted, sizeof(dst->avg_refaulted),
                  &lrugen->avg_refaulted);
    bpf_core_read(dst->avg_total, sizeof(dst->avg_total), &lrugen->avg_total);
    bpf_core_read(dst->protected, sizeof(dst->protected), &lrugen->protected);
    bpf_core_read(dst->evicted, sizeof(dst->evicted), &lrugen->evicted);
    bpf_core_read(dst->refaulted, sizeof(dst->refaulted), &lrugen->refaulted);
}

SEC("kprobe/try_to_shrink_lruvec")
int BPF_KPROBE(try_to_shrink_lruvec_enter, struct lruvec *lruvec, struct scan_control *sc)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u32 zero = 0;
    struct mem_cgroup *target_memcg;
    struct try_sample *sample;

    if (!lruvec || !sc)
        return 0;

    sample = bpf_map_lookup_elem(&try_scratch, &zero);
    if (!sample)
        return 0;

    target_memcg = BPF_CORE_READ(sc, target_mem_cgroup);
    sample->lruvec = lruvec;
    sample->sc = sc;
    sample->memcg_id = get_memcg_id(target_memcg);
    sample->trigger_tgid = (u32)(pid_tgid >> 32);
    sample->trigger_tid = tid;
    bpf_get_current_comm(sample->trigger_comm, sizeof(sample->trigger_comm));
    sample->swappiness = -1;
    sample->evict_folios_calls = 0;
    sample->reclaimed_pages[0] = 0;
    sample->reclaimed_pages[1] = 0;
    snapshot_lru_gen_folio(&sample->before, lruvec);

    bpf_map_update_elem(&active_tries, &tid, sample, BPF_ANY);
    return 0;
}

SEC("kretprobe/try_to_shrink_lruvec")
int BPF_KRETPROBE(try_to_shrink_lruvec_exit)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct try_sample *sample;
    struct mglru_event *e;

    sample = bpf_map_lookup_elem(&active_tries, &tid);
    if (!sample)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_tries, &tid);
        bpf_map_delete_elem(&active_evictions, &tid);
        return 0;
    }

    e->memcg_id = sample->memcg_id;
    e->trigger_tgid = sample->trigger_tgid;
    e->trigger_tid = sample->trigger_tid;
    __builtin_memcpy(e->trigger_comm, sample->trigger_comm, sizeof(e->trigger_comm));
    e->swappiness = sample->swappiness;
    e->evict_folios_calls = sample->evict_folios_calls;
    e->target_reclaimed_anon_pages = sample->reclaimed_pages[0];
    e->target_reclaimed_file_pages = sample->reclaimed_pages[1];
    copy_snapshot(&e->before, &sample->before);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&active_tries, &tid);
    bpf_map_delete_elem(&active_evictions, &tid);
    return 0;
}

SEC("kretprobe/get_swappiness")
int BPF_KRETPROBE(get_swappiness_exit, int ret)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct try_sample *sample;

    sample = bpf_map_lookup_elem(&active_tries, &tid);
    if (!sample)
        return 0;

    sample->swappiness = ret;
    return 0;
}

SEC("kprobe/evict_folios")
int BPF_KPROBE(evict_folios_enter, struct lruvec *lruvec, struct scan_control *sc,
               int swappiness)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u32 zero = 0;
    struct try_sample *sample;
    struct evict_state *state;

    (void)swappiness;

    sample = bpf_map_lookup_elem(&active_tries, &tid);
    if (!sample)
        return 0;

    if (sample->lruvec != lruvec || sample->sc != sc)
        return 0;

    sample->evict_folios_calls++;

    state = bpf_map_lookup_elem(&evict_scratch, &zero);
    if (!state)
        return 0;

    state->lruvec = lruvec;
    state->sc = sc;
    state->type_scanned = NULL;
    state->nr_reclaimed_before = BPF_CORE_READ(sc, nr_reclaimed);
    state->type = -1;
    bpf_map_update_elem(&active_evictions, &tid, state, BPF_ANY);
    return 0;
}

SEC("kprobe/isolate_folios")
int BPF_KPROBE(isolate_folios_enter, struct lruvec *lruvec, struct scan_control *sc,
               int swappiness, int *type_scanned, struct list_head *list)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct evict_state *state;

    (void)swappiness;
    (void)list;

    state = bpf_map_lookup_elem(&active_evictions, &tid);
    if (!state)
        return 0;

    if (state->lruvec != lruvec || state->sc != sc)
        return 0;

    state->type_scanned = type_scanned;
    return 0;
}

SEC("kretprobe/isolate_folios")
int BPF_KRETPROBE(isolate_folios_exit, int ret)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct evict_state *state;
    int type = -1;

    (void)ret;

    state = bpf_map_lookup_elem(&active_evictions, &tid);
    if (!state || !state->type_scanned)
        return 0;

    if (bpf_probe_read_kernel(&type, sizeof(type), state->type_scanned))
        return 0;

    state->type = type;
    return 0;
}

SEC("kretprobe/evict_folios")
int BPF_KRETPROBE(evict_folios_exit)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct evict_state *state;
    struct try_sample *sample;
    struct scan_control *sc;
    long nr_reclaimed_after;
    unsigned long long delta;

    state = bpf_map_lookup_elem(&active_evictions, &tid);
    if (!state)
        return 0;

    sample = bpf_map_lookup_elem(&active_tries, &tid);
    if (!sample) {
        bpf_map_delete_elem(&active_evictions, &tid);
        return 0;
    }

    sc = state->sc;
    nr_reclaimed_after = BPF_CORE_READ(sc, nr_reclaimed);
    if (nr_reclaimed_after < state->nr_reclaimed_before) {
        bpf_map_delete_elem(&active_evictions, &tid);
        return 0;
    }

    delta = (unsigned long long)(nr_reclaimed_after - state->nr_reclaimed_before);
    if (delta && state->type >= 0 && state->type < MGLRU_MAX_TYPES)
        sample->reclaimed_pages[state->type] += delta;

    bpf_map_delete_elem(&active_evictions, &tid);
    return 0;
}
