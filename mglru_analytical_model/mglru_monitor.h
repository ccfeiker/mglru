#ifndef __MGLRU_MONITOR_H
#define __MGLRU_MONITOR_H

#define MGLRU_MAX_NR_GENS 4
#define MGLRU_MAX_TYPES 2
#define MGLRU_MAX_NR_ZONES 4
#define MGLRU_MAX_NR_TIERS 4
#define MGLRU_NR_HIST_GENS 1
#define MGLRU_COMM_LEN 16

#define MGLRU_NR_PAGE_BINS \
    (MGLRU_MAX_NR_GENS * MGLRU_MAX_TYPES * MGLRU_MAX_NR_ZONES)
#define MGLRU_NR_TYPE_TIER_BINS (MGLRU_MAX_TYPES * MGLRU_MAX_NR_TIERS)
#define MGLRU_NR_PROTECTED_BINS \
    (MGLRU_NR_HIST_GENS * MGLRU_MAX_TYPES * (MGLRU_MAX_NR_TIERS - 1))
#define MGLRU_NR_HIST_TIER_BINS \
    (MGLRU_NR_HIST_GENS * MGLRU_MAX_TYPES * MGLRU_MAX_NR_TIERS)

enum mglru_ringbuf_event_kind {
    MGLRU_EVENT_SUMMARY = 1,
};

struct mglru_lru_gen_folio_snapshot {
    unsigned long long max_seq;
    unsigned long long min_seq[MGLRU_MAX_TYPES];
    long long nr_pages[MGLRU_NR_PAGE_BINS];
    unsigned long long avg_refaulted[MGLRU_NR_TYPE_TIER_BINS];
    unsigned long long avg_total[MGLRU_NR_TYPE_TIER_BINS];
    unsigned long long protected[MGLRU_NR_PROTECTED_BINS];
    long long evicted[MGLRU_NR_HIST_TIER_BINS];
    long long refaulted[MGLRU_NR_HIST_TIER_BINS];
};

struct mglru_event {
    unsigned int kind;
    unsigned long long session_id;
    unsigned long long memcg_id;
    unsigned int trigger_tgid;
    unsigned int trigger_tid;
    char trigger_comm[MGLRU_COMM_LEN];
    int swappiness;
    int priority;
    int reclaim_idx;
    int order;
    unsigned int may_writepage;
    unsigned int may_unmap;
    unsigned long long gfp_mask;
    unsigned long long nr_to_reclaim;
    unsigned long long nr_scanned_before;
    unsigned long long nr_scanned_after;
    unsigned long long nr_scanned_delta;
    unsigned long long nr_reclaimed_before;
    unsigned long long nr_reclaimed_after;
    unsigned int evict_folios_calls;
    unsigned long long evict_folios_return_sum;
    unsigned int evict_folios_calls_by_type[MGLRU_MAX_TYPES];
    unsigned long long evict_folios_return_sum_by_type[MGLRU_MAX_TYPES];
    unsigned long long evict_scanned_delta_pages[MGLRU_MAX_TYPES];
    unsigned int isolate_calls[MGLRU_MAX_TYPES];
    unsigned long long isolate_scanned_pages[MGLRU_MAX_TYPES];
    unsigned long long label_reclaimed_anon_pages;
    unsigned long long label_reclaimed_file_pages;
    struct mglru_lru_gen_folio_snapshot before;
    struct mglru_lru_gen_folio_snapshot after;
};

#endif
