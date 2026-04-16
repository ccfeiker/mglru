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
    MGLRU_EVENT_REPLAY_STEP = 2,
};

enum mglru_replay_step_kind {
    MGLRU_STEP_TRY_TO_SHRINK_ENTER = 1,
    MGLRU_STEP_GET_SWAPPINESS_EXIT = 2,
    MGLRU_STEP_EVICT_FOLIOS_ENTER = 3,
    MGLRU_STEP_ISOLATE_FOLIOS_EXIT = 4,
    MGLRU_STEP_EVICT_FOLIOS_EXIT = 5,
    MGLRU_STEP_TRY_TO_SHRINK_EXIT = 6,
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
    unsigned int evict_folios_calls;
    unsigned int isolate_calls[MGLRU_MAX_TYPES];
    unsigned long long isolated_pages[MGLRU_MAX_TYPES];
    unsigned long long target_reclaimed_anon_pages;
    unsigned long long target_reclaimed_file_pages;
    struct mglru_lru_gen_folio_snapshot before;
    struct mglru_lru_gen_folio_snapshot after;
};

struct mglru_replay_event {
    unsigned int kind;
    unsigned int step_kind;
    unsigned long long session_id;
    unsigned long long ts_ns;
    unsigned long long memcg_id;
    unsigned int trigger_tgid;
    unsigned int trigger_tid;
    char trigger_comm[MGLRU_COMM_LEN];
    unsigned int seq_no;
    unsigned int evict_round;
    int swappiness;
    int priority;
    int reclaim_idx;
    int order;
    unsigned int may_writepage;
    unsigned int may_unmap;
    unsigned long long gfp_mask;
    unsigned long long nr_to_reclaim;
    long long nr_reclaimed_before;
    long long nr_reclaimed_after;
    unsigned long long reclaimed_delta;
    int type;
    int isolate_ret;
    unsigned long long min_seq_anon;
    unsigned long long min_seq_file;
    unsigned long long max_seq;
};

#endif
