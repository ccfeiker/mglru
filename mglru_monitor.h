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
    unsigned long long memcg_id;
    unsigned int trigger_tgid;
    unsigned int trigger_tid;
    char trigger_comm[MGLRU_COMM_LEN];
    int swappiness;
    unsigned int evict_folios_calls;
    unsigned long long target_reclaimed_anon_pages;
    unsigned long long target_reclaimed_file_pages;
    struct mglru_lru_gen_folio_snapshot before;
};

#endif
