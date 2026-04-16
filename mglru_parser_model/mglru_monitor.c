#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>

#include "mglru_monitor.h"
#include "mglru_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;
static FILE *csv_fp = NULL;
static FILE *replay_fp = NULL;
static bool csv_header_written = false;

struct feature_summary {
    unsigned long long anon_gen_span;
    unsigned long long file_gen_span;
    unsigned long long after_anon_gen_span;
    unsigned long long after_file_gen_span;
    long long anon_total_pages;
    long long file_total_pages;
    long long after_anon_total_pages;
    long long after_file_total_pages;
    long long anon_oldest_gen_pages;
    long long anon_second_oldest_gen_pages;
    long long anon_second_youngest_gen_pages;
    long long anon_youngest_gen_pages;
    long long file_oldest_gen_pages;
    long long file_second_oldest_gen_pages;
    long long file_second_youngest_gen_pages;
    long long file_youngest_gen_pages;
    unsigned long long avg_refaulted_anon;
    unsigned long long avg_refaulted_file;
    unsigned long long avg_total_anon;
    unsigned long long avg_total_file;
    unsigned long long protected_anon_pages;
    unsigned long long protected_file_pages;
    long long evicted_anon_pages;
    long long evicted_file_pages;
    long long refaulted_anon_pages;
    long long refaulted_file_pages;
    long long isolated_anon_pages;
    long long isolated_file_pages;
    unsigned int isolate_calls_anon;
    unsigned int isolate_calls_file;
    long long reclaimed_over_isolated_anon_pct;
    long long reclaimed_over_isolated_file_pct;
    unsigned long long avg_refaulted_tiers[MGLRU_MAX_TYPES][MGLRU_MAX_NR_TIERS];
    unsigned long long avg_total_tiers[MGLRU_MAX_TYPES][MGLRU_MAX_NR_TIERS];
    unsigned long long protected_tiers[MGLRU_MAX_TYPES][MGLRU_MAX_NR_TIERS - 1];
    long long evicted_tiers[MGLRU_MAX_TYPES][MGLRU_MAX_NR_TIERS];
    long long refaulted_tiers[MGLRU_MAX_TYPES][MGLRU_MAX_NR_TIERS];
};

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static int page_bin_idx(int gen_idx, int type, int zone)
{
    return gen_idx * (MGLRU_MAX_TYPES * MGLRU_MAX_NR_ZONES) +
           type * MGLRU_MAX_NR_ZONES + zone;
}

static int protected_idx(int hist, int type, int tier)
{
    return hist * (MGLRU_MAX_TYPES * (MGLRU_MAX_NR_TIERS - 1)) +
           type * (MGLRU_MAX_NR_TIERS - 1) + tier;
}

static int hist_tier_idx(int hist, int type, int tier)
{
    return hist * (MGLRU_MAX_TYPES * MGLRU_MAX_NR_TIERS) +
           type * MGLRU_MAX_NR_TIERS + tier;
}

static long long seq_type_total(const struct mglru_lru_gen_folio_snapshot *snap,
                                unsigned long long seq, int type);

static long long total_pages_for_type(const struct mglru_lru_gen_folio_snapshot *snap, int type)
{
    long long total = 0;
    unsigned long long seq;

    if (snap->max_seq < snap->min_seq[type])
        return 0;

    for (seq = snap->min_seq[type]; seq <= snap->max_seq; seq++)
        total += seq_type_total(snap, seq, type);

    return total;
}

static unsigned long long gen_span_for_type(const struct mglru_lru_gen_folio_snapshot *snap, int type)
{
    if (snap->max_seq < snap->min_seq[type])
        return 0;

    return snap->max_seq - snap->min_seq[type];
}

static unsigned long long gen_count_for_type(const struct mglru_lru_gen_folio_snapshot *snap, int type)
{
    if (snap->max_seq < snap->min_seq[type])
        return 0;

    return snap->max_seq - snap->min_seq[type] + 1;
}

static long long seq_type_total(const struct mglru_lru_gen_folio_snapshot *snap,
                                unsigned long long seq, int type)
{
    long long total = 0;
    int gen_idx;
    int zone;

    if (seq > snap->max_seq || seq < snap->min_seq[type])
        return 0;

    gen_idx = (int)(seq % MGLRU_MAX_NR_GENS);
    for (zone = 0; zone < MGLRU_MAX_NR_ZONES; zone++)
        total += snap->nr_pages[page_bin_idx(gen_idx, type, zone)];

    return total;
}

static long long ranked_seq_total_from_oldest(const struct mglru_lru_gen_folio_snapshot *snap,
                                              int type, unsigned long long rank)
{
    unsigned long long seq = snap->min_seq[type] + rank;

    if (snap->max_seq < seq)
        return 0;

    return seq_type_total(snap, seq, type);
}

static long long ranked_seq_total_from_youngest(const struct mglru_lru_gen_folio_snapshot *snap,
                                                int type, unsigned long long rank)
{
    if (snap->max_seq < rank || snap->max_seq - rank < snap->min_seq[type])
        return 0;

    return seq_type_total(snap, snap->max_seq - rank, type);
}

static void distinct_window_totals(const struct mglru_lru_gen_folio_snapshot *snap, int type,
                                   long long *oldest, long long *second_oldest,
                                   long long *second_youngest, long long *youngest)
{
    unsigned long long count = gen_count_for_type(snap, type);

    *oldest = 0;
    *second_oldest = 0;
    *second_youngest = 0;
    *youngest = 0;

    if (!count)
        return;

    *oldest = ranked_seq_total_from_oldest(snap, type, 0);

    if (count >= 2)
        *youngest = ranked_seq_total_from_youngest(snap, type, 0);

    if (count >= 3)
        *second_oldest = ranked_seq_total_from_oldest(snap, type, 1);

    if (count >= 4)
        *second_youngest = ranked_seq_total_from_youngest(snap, type, 1);
}

static unsigned long long sum_protected_bins(const struct mglru_lru_gen_folio_snapshot *snap, int type)
{
    unsigned long long total = 0;
    int hist;
    int tier;

    for (hist = 0; hist < MGLRU_NR_HIST_GENS; hist++) {
        for (tier = 0; tier < MGLRU_MAX_NR_TIERS - 1; tier++)
            total += snap->protected[protected_idx(hist, type, tier)];
    }

    return total;
}

static long long sum_hist_tier_bins(const long long *values, int type)
{
    long long total = 0;
    int hist;
    int tier;

    for (hist = 0; hist < MGLRU_NR_HIST_GENS; hist++) {
        for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++)
            total += values[hist_tier_idx(hist, type, tier)];
    }

    return total;
}

static unsigned long long sum_type_tier_bins(const unsigned long long *values, int type)
{
    unsigned long long total = 0;
    int tier;

    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++)
        total += values[type * MGLRU_MAX_NR_TIERS + tier];

    return total;
}

static unsigned long long type_tier_value(const unsigned long long *values, int type, int tier)
{
    return values[type * MGLRU_MAX_NR_TIERS + tier];
}

static long long hist_tier_value(const long long *values, int type, int tier)
{
    return values[hist_tier_idx(0, type, tier)];
}

static unsigned long long protected_value(const struct mglru_lru_gen_folio_snapshot *snap,
                                          int type, int tier)
{
    return snap->protected[protected_idx(0, type, tier)];
}

static void compute_feature_summary(const struct mglru_event *event, struct feature_summary *summary)
{
    const struct mglru_lru_gen_folio_snapshot *before = &event->before;
    const struct mglru_lru_gen_folio_snapshot *after = &event->after;

    memset(summary, 0, sizeof(*summary));

    summary->anon_gen_span = gen_span_for_type(before, 0);
    summary->file_gen_span = gen_span_for_type(before, 1);
    summary->after_anon_gen_span = gen_span_for_type(after, 0);
    summary->after_file_gen_span = gen_span_for_type(after, 1);
    summary->anon_total_pages = total_pages_for_type(before, 0);
    summary->file_total_pages = total_pages_for_type(before, 1);
    summary->after_anon_total_pages = total_pages_for_type(after, 0);
    summary->after_file_total_pages = total_pages_for_type(after, 1);

    distinct_window_totals(before, 0,
                           &summary->anon_oldest_gen_pages,
                           &summary->anon_second_oldest_gen_pages,
                           &summary->anon_second_youngest_gen_pages,
                           &summary->anon_youngest_gen_pages);
    distinct_window_totals(before, 1,
                           &summary->file_oldest_gen_pages,
                           &summary->file_second_oldest_gen_pages,
                           &summary->file_second_youngest_gen_pages,
                           &summary->file_youngest_gen_pages);

    summary->avg_refaulted_anon = sum_type_tier_bins(before->avg_refaulted, 0);
    summary->avg_refaulted_file = sum_type_tier_bins(before->avg_refaulted, 1);
    summary->avg_total_anon = sum_type_tier_bins(before->avg_total, 0);
    summary->avg_total_file = sum_type_tier_bins(before->avg_total, 1);
    summary->protected_anon_pages = sum_protected_bins(before, 0);
    summary->protected_file_pages = sum_protected_bins(before, 1);
    summary->evicted_anon_pages = sum_hist_tier_bins(before->evicted, 0);
    summary->evicted_file_pages = sum_hist_tier_bins(before->evicted, 1);
    summary->refaulted_anon_pages = sum_hist_tier_bins(before->refaulted, 0);
    summary->refaulted_file_pages = sum_hist_tier_bins(before->refaulted, 1);
    summary->isolated_anon_pages = event->isolated_pages[0];
    summary->isolated_file_pages = event->isolated_pages[1];
    summary->isolate_calls_anon = event->isolate_calls[0];
    summary->isolate_calls_file = event->isolate_calls[1];
    if (event->isolated_pages[0] > 0)
        summary->reclaimed_over_isolated_anon_pct =
            (long long)(event->target_reclaimed_anon_pages * 100 / event->isolated_pages[0]);
    if (event->isolated_pages[1] > 0)
        summary->reclaimed_over_isolated_file_pct =
            (long long)(event->target_reclaimed_file_pages * 100 / event->isolated_pages[1]);

    for (int type = 0; type < MGLRU_MAX_TYPES; type++) {
        for (int tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
            summary->avg_refaulted_tiers[type][tier] =
                type_tier_value(before->avg_refaulted, type, tier);
            summary->avg_total_tiers[type][tier] =
                type_tier_value(before->avg_total, type, tier);
            summary->evicted_tiers[type][tier] =
                hist_tier_value(before->evicted, type, tier);
            summary->refaulted_tiers[type][tier] =
                hist_tier_value(before->refaulted, type, tier);
            if (tier < MGLRU_MAX_NR_TIERS - 1) {
                summary->protected_tiers[type][tier] =
                    protected_value(before, type, tier);
            }
        }
    }
}

static void write_csv_header(FILE *fp)
{
    int tier;

    fprintf(fp, "memcg_id,trigger_tgid,trigger_tid,trigger_comm");
    fprintf(fp, ",anon_min_gen_seq,file_min_gen_seq,max_gen_seq");
    fprintf(fp, ",feature_swappiness,feature_priority,feature_reclaim_idx,feature_order");
    fprintf(fp, ",feature_may_writepage,feature_may_unmap,feature_gfp_mask,feature_nr_to_reclaim");
    fprintf(fp, ",feature_evict_folios_calls");
    fprintf(fp, ",feature_isolate_calls_anon,feature_isolate_calls_file");
    fprintf(fp, ",feature_isolated_anon_pages,feature_isolated_file_pages");
    fprintf(fp, ",feature_reclaimed_over_isolated_anon_pct,feature_reclaimed_over_isolated_file_pct");
    fprintf(fp, ",feature_anon_gen_span,feature_file_gen_span");
    fprintf(fp, ",feature_after_anon_gen_span,feature_after_file_gen_span");
    fprintf(fp, ",feature_anon_total_pages,feature_file_total_pages");
    fprintf(fp, ",feature_after_anon_total_pages,feature_after_file_total_pages");
    fprintf(fp, ",feature_after_anon_min_gen_seq,feature_after_file_min_gen_seq,feature_after_max_gen_seq");
    fprintf(fp, ",feature_anon_oldest_gen_pages");
    fprintf(fp, ",feature_anon_second_oldest_gen_pages");
    fprintf(fp, ",feature_anon_second_youngest_gen_pages");
    fprintf(fp, ",feature_anon_youngest_gen_pages");
    fprintf(fp, ",feature_file_oldest_gen_pages");
    fprintf(fp, ",feature_file_second_oldest_gen_pages");
    fprintf(fp, ",feature_file_second_youngest_gen_pages");
    fprintf(fp, ",feature_file_youngest_gen_pages");
    fprintf(fp, ",feature_avg_refaulted_anon,feature_avg_refaulted_file");
    fprintf(fp, ",feature_avg_total_anon,feature_avg_total_file");
    fprintf(fp, ",feature_protected_anon_pages,feature_protected_file_pages");
    fprintf(fp, ",feature_evicted_anon_pages,feature_evicted_file_pages");
    fprintf(fp, ",feature_refaulted_anon_pages,feature_refaulted_file_pages");
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
        fprintf(fp, ",feature_avg_refaulted_anon_tier%d", tier);
        fprintf(fp, ",feature_avg_refaulted_file_tier%d", tier);
    }
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
        fprintf(fp, ",feature_avg_total_anon_tier%d", tier);
        fprintf(fp, ",feature_avg_total_file_tier%d", tier);
    }
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS - 1; tier++) {
        fprintf(fp, ",feature_protected_anon_tier%d", tier);
        fprintf(fp, ",feature_protected_file_tier%d", tier);
    }
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
        fprintf(fp, ",feature_evicted_anon_tier%d", tier);
        fprintf(fp, ",feature_evicted_file_tier%d", tier);
    }
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
        fprintf(fp, ",feature_refaulted_anon_tier%d", tier);
        fprintf(fp, ",feature_refaulted_file_tier%d", tier);
    }
    fprintf(fp, ",target_reclaimed_anon_pages,target_reclaimed_file_pages");
    fputc('\n', fp);
}

static void write_csv_event(FILE *fp, const struct mglru_event *event)
{
    struct feature_summary summary;
    int tier;

    compute_feature_summary(event, &summary);

    fprintf(fp, "%llu,%u,%u,%s",
            event->memcg_id,
            event->trigger_tgid,
            event->trigger_tid,
            event->trigger_comm);
    fprintf(fp, ",%llu,%llu,%llu",
            event->before.min_seq[0],
            event->before.min_seq[1],
            event->before.max_seq);
    fprintf(fp, ",%d,%d,%d,%d,%u,%u,%llu,%llu,%u",
            event->swappiness,
            event->priority,
            event->reclaim_idx,
            event->order,
            event->may_writepage,
            event->may_unmap,
            event->gfp_mask,
            event->nr_to_reclaim,
            event->evict_folios_calls);
    fprintf(fp, ",%u,%u,%llu,%llu,%lld,%lld",
            event->isolate_calls[0],
            event->isolate_calls[1],
            event->isolated_pages[0],
            event->isolated_pages[1],
            summary.reclaimed_over_isolated_anon_pct,
            summary.reclaimed_over_isolated_file_pct);
    fprintf(fp, ",%llu,%llu",
            summary.anon_gen_span,
            summary.file_gen_span);
    fprintf(fp, ",%llu,%llu",
            summary.after_anon_gen_span,
            summary.after_file_gen_span);
    fprintf(fp, ",%lld,%lld",
            summary.anon_total_pages,
            summary.file_total_pages);
    fprintf(fp, ",%lld,%lld,%llu,%llu,%llu",
            summary.after_anon_total_pages,
            summary.after_file_total_pages,
            event->after.min_seq[0],
            event->after.min_seq[1],
            event->after.max_seq);
    fprintf(fp, ",%lld,%lld,%lld,%lld",
            summary.anon_oldest_gen_pages,
            summary.anon_second_oldest_gen_pages,
            summary.anon_second_youngest_gen_pages,
            summary.anon_youngest_gen_pages);
    fprintf(fp, ",%lld,%lld,%lld,%lld",
            summary.file_oldest_gen_pages,
            summary.file_second_oldest_gen_pages,
            summary.file_second_youngest_gen_pages,
            summary.file_youngest_gen_pages);
    fprintf(fp, ",%llu,%llu,%llu,%llu",
            summary.avg_refaulted_anon,
            summary.avg_refaulted_file,
            summary.avg_total_anon,
            summary.avg_total_file);
    fprintf(fp, ",%llu,%llu",
            summary.protected_anon_pages,
            summary.protected_file_pages);
    fprintf(fp, ",%lld,%lld",
            summary.evicted_anon_pages,
            summary.evicted_file_pages);
    fprintf(fp, ",%lld,%lld",
            summary.refaulted_anon_pages,
            summary.refaulted_file_pages);
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
        fprintf(fp, ",%llu,%llu",
                summary.avg_refaulted_tiers[0][tier],
                summary.avg_refaulted_tiers[1][tier]);
    }
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
        fprintf(fp, ",%llu,%llu",
                summary.avg_total_tiers[0][tier],
                summary.avg_total_tiers[1][tier]);
    }
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS - 1; tier++) {
        fprintf(fp, ",%llu,%llu",
                summary.protected_tiers[0][tier],
                summary.protected_tiers[1][tier]);
    }
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
        fprintf(fp, ",%lld,%lld",
                summary.evicted_tiers[0][tier],
                summary.evicted_tiers[1][tier]);
    }
    for (tier = 0; tier < MGLRU_MAX_NR_TIERS; tier++) {
        fprintf(fp, ",%lld,%lld",
                summary.refaulted_tiers[0][tier],
                summary.refaulted_tiers[1][tier]);
    }
    fprintf(fp, ",%llu,%llu",
            event->target_reclaimed_anon_pages,
            event->target_reclaimed_file_pages);
    fputc('\n', fp);
    fflush(fp);
}

static const char *step_kind_name(unsigned int step_kind)
{
    switch (step_kind) {
    case MGLRU_STEP_TRY_TO_SHRINK_ENTER:
        return "try_to_shrink_lruvec.enter";
    case MGLRU_STEP_GET_SWAPPINESS_EXIT:
        return "get_swappiness.exit";
    case MGLRU_STEP_EVICT_FOLIOS_ENTER:
        return "evict_folios.enter";
    case MGLRU_STEP_ISOLATE_FOLIOS_EXIT:
        return "isolate_folios.exit";
    case MGLRU_STEP_EVICT_FOLIOS_EXIT:
        return "evict_folios.exit";
    case MGLRU_STEP_TRY_TO_SHRINK_EXIT:
        return "try_to_shrink_lruvec.exit";
    default:
        return "unknown";
    }
}

static const char *type_name(int type)
{
    if (type == 0)
        return "anon";
    if (type == 1)
        return "file";
    return "unknown";
}

static void write_replay_event(FILE *fp, const struct mglru_replay_event *event)
{
    fprintf(fp,
            "{"
            "\"session_id\":%llu,"
            "\"ts_ns\":%llu,"
            "\"seq_no\":%u,"
            "\"step_kind\":\"%s\","
            "\"memcg_id\":%llu,"
            "\"trigger_tgid\":%u,"
            "\"trigger_tid\":%u,"
            "\"trigger_comm\":\"%s\","
            "\"evict_round\":%u,"
            "\"swappiness\":%d,"
            "\"priority\":%d,"
            "\"reclaim_idx\":%d,"
            "\"order\":%d,"
            "\"may_writepage\":%u,"
            "\"may_unmap\":%u,"
            "\"gfp_mask\":%llu,"
            "\"nr_to_reclaim\":%llu,"
            "\"nr_reclaimed_before\":%lld,"
            "\"nr_reclaimed_after\":%lld,"
            "\"reclaimed_delta\":%llu,"
            "\"type\":\"%s\","
            "\"isolate_ret\":%d,"
            "\"min_seq_anon\":%llu,"
            "\"min_seq_file\":%llu,"
            "\"max_seq\":%llu"
            "}\n",
            event->session_id,
            event->ts_ns,
            event->seq_no,
            step_kind_name(event->step_kind),
            event->memcg_id,
            event->trigger_tgid,
            event->trigger_tid,
            event->trigger_comm,
            event->evict_round,
            event->swappiness,
            event->priority,
            event->reclaim_idx,
            event->order,
            event->may_writepage,
            event->may_unmap,
            event->gfp_mask,
            event->nr_to_reclaim,
            event->nr_reclaimed_before,
            event->nr_reclaimed_after,
            event->reclaimed_delta,
            type_name(event->type),
            event->isolate_ret,
            event->min_seq_anon,
            event->min_seq_file,
            event->max_seq);
    fflush(fp);
}

static void print_event_summary(const struct mglru_event *event)
{
    printf("memcg_id=%llu trigger_comm=%s anon_min_gen_seq=%llu file_min_gen_seq=%llu max_gen_seq=%llu after_anon_min_gen_seq=%llu after_file_min_gen_seq=%llu after_max_gen_seq=%llu swappiness=%d priority=%d reclaim_idx=%d may_writepage=%u may_unmap=%u evict_folios_calls=%u isolate_calls_anon=%u isolate_calls_file=%u isolated_anon_pages=%llu isolated_file_pages=%llu target_reclaimed_anon_pages=%llu target_reclaimed_file_pages=%llu\n",
           event->memcg_id,
           event->trigger_comm,
           event->before.min_seq[0],
           event->before.min_seq[1],
           event->before.max_seq,
           event->after.min_seq[0],
           event->after.min_seq[1],
           event->after.max_seq,
           event->swappiness,
           event->priority,
           event->reclaim_idx,
           event->may_writepage,
           event->may_unmap,
           event->evict_folios_calls,
           event->isolate_calls[0],
           event->isolate_calls[1],
           event->isolated_pages[0],
           event->isolated_pages[1],
           event->target_reclaimed_anon_pages,
           event->target_reclaimed_file_pages);
    fflush(stdout);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const unsigned int *kind = data;

    (void)ctx;
    (void)data_sz;

    if (*kind == MGLRU_EVENT_SUMMARY) {
        const struct mglru_event *event = data;

        print_event_summary(event);

        if (csv_fp) {
            if (!csv_header_written) {
                write_csv_header(csv_fp);
                csv_header_written = true;
            }
            write_csv_event(csv_fp, event);
        }
    } else if (*kind == MGLRU_EVENT_REPLAY_STEP) {
        const struct mglru_replay_event *event = data;

        if (replay_fp)
            write_replay_event(replay_fp, event);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct mglru_monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    const char *csv_path = NULL;
    const char *replay_path = NULL;
    int err = 0;

    if (argc > 3) {
        fprintf(stderr, "Usage: %s [output.csv] [replay.jsonl]\n", argv[0]);
        return 1;
    }

    if (argc == 2)
        csv_path = argv[1];
    if (argc == 3) {
        csv_path = argv[1];
        replay_path = argv[2];
    }

    if (csv_path) {
        csv_fp = fopen(csv_path, "w");
        if (!csv_fp) {
            fprintf(stderr, "Failed to open %s\n", csv_path);
            return 1;
        }
        csv_header_written = false;
    }

    if (replay_path) {
        replay_fp = fopen(replay_path, "w");
        if (!replay_fp) {
            fprintf(stderr, "Failed to open %s\n", replay_path);
            err = 1;
            goto out;
        }
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = mglru_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        err = 1;
        goto out;
    }

    err = mglru_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto out;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = 1;
        goto out;
    }

    printf("Attached to try_to_shrink_lruvec/evict_folios");
    if (csv_path)
        printf(", writing CSV to %s", csv_path);
    if (replay_path)
        printf(", writing replay JSONL to %s", replay_path);
    printf("\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 20);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }
    }

out:
    ring_buffer__free(rb);
    mglru_monitor_bpf__destroy(skel);

    if (csv_fp)
        fclose(csv_fp);
    if (replay_fp)
        fclose(replay_fp);

    return err < 0 ? 1 : err;
}
