#ifndef __LRU_MONITOR_H
#define __LRU_MONITOR_H

#define LRU_COMM_LEN 16
#define LRU_NR_LISTS 4

enum lru_event_kind {
    LRU_EVENT_SUMMARY = 1,
};

enum lru_list_kind {
    LRU_LIST_INACTIVE_ANON = 0,
    LRU_LIST_ACTIVE_ANON = 1,
    LRU_LIST_INACTIVE_FILE = 2,
    LRU_LIST_ACTIVE_FILE = 3,
};

struct lru_event {
    unsigned int kind;
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
    unsigned long long observed_shrink_input_anon_pages;
    unsigned long long observed_shrink_input_file_pages;
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
    unsigned long long observed_dirty_anon_pages;
    unsigned long long observed_dirty_file_pages;
    unsigned long long observed_writeback_anon_pages;
    unsigned long long observed_writeback_file_pages;
    unsigned long long observed_congested_anon_pages;
    unsigned long long observed_congested_file_pages;
    unsigned long long observed_immediate_anon_pages;
    unsigned long long observed_immediate_file_pages;
    unsigned long long observed_unmap_fail_anon_pages;
    unsigned long long observed_unmap_fail_file_pages;
    unsigned long long observed_putback_anon_pages;
    unsigned long long observed_putback_file_pages;
    unsigned int observed_proportional_adjust_count;
    unsigned long long observed_proportional_adjust_percentage;
    int observed_proportional_stopped_lru;
    unsigned long long observed_remaining_inactive_anon_pages;
    unsigned long long observed_remaining_active_anon_pages;
    unsigned long long observed_remaining_inactive_file_pages;
    unsigned long long observed_remaining_active_file_pages;
};

#endif
