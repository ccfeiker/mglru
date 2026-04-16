#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/libbpf.h>

#include "lru_monitor.h"
#include "lru_monitor.skel.h"

static volatile sig_atomic_t exiting = 0;
static FILE *csv_fp = NULL;
static bool csv_header_written = false;

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static const char *reclaim_context_for(const struct lru_event *event)
{
    if (!strncmp(event->trigger_comm, "kswapd", 6))
        return "kswapd";
    return "direct reclaim";
}

static void write_csv_header(FILE *fp)
{
    fprintf(
        fp,
        "session_id,memcg_id,node_id,trigger_tgid,trigger_tid,trigger_comm,reclaim_context,"
        "feature_swappiness,feature_priority,feature_reclaim_idx,feature_order,"
        "feature_may_deactivate,feature_force_deactivate,feature_skipped_deactivate,"
        "feature_may_writepage,feature_may_unmap,feature_may_swap,feature_gfp_mask,feature_nr_to_reclaim,"
        "feature_anon_cost,feature_file_cost,feature_refaults_anon,feature_refaults_file,feature_proportional_reclaim,"
        "feature_cgroup_reclaim,feature_can_reclaim_anon,feature_cache_trim_mode,feature_file_is_tiny,feature_memcg_low_reclaim,"
        "feature_before_inactive_anon,feature_before_active_anon,feature_before_inactive_file,feature_before_active_file,"
        "feature_target_inactive_anon,feature_target_active_anon,feature_target_inactive_file,feature_target_active_file,"
        "observed_scanned_inactive_anon_pages,observed_taken_active_anon_pages,"
        "observed_scanned_inactive_file_pages,observed_taken_active_file_pages,"
        "observed_isolate_calls_inactive_anon,observed_isolate_calls_active_anon,"
        "observed_isolate_calls_inactive_file,observed_isolate_calls_active_file,"
        "observed_isolated_pages_inactive_anon,observed_isolated_pages_active_anon,"
        "observed_isolated_pages_inactive_file,observed_isolated_pages_active_file,"
        "observed_reclaimed_anon_pages,observed_reclaimed_file_pages,"
        "observed_activated_anon_pages,observed_activated_file_pages,"
        "observed_deactivated_anon_pages,observed_deactivated_file_pages,"
        "observed_active_retained_anon_pages,observed_active_retained_file_pages,"
        "observed_referenced_anon_pages,observed_referenced_file_pages,"
        "observed_ref_keep_anon_pages,observed_ref_keep_file_pages,"
        "observed_dirty_file_pages,observed_writeback_file_pages,observed_congested_file_pages,observed_immediate_file_pages,"
        "observed_unmap_fail_anon_pages,observed_unmap_fail_file_pages,"
        "observed_proportional_adjust_count,observed_proportional_adjust_percentage,observed_proportional_stopped_lru,"
        "observed_remaining_inactive_anon_pages,observed_remaining_active_anon_pages,"
        "observed_remaining_inactive_file_pages,observed_remaining_active_file_pages,"
        "target_reclaimed_anon_pages,target_reclaimed_file_pages\n");
}

static void write_csv_event(FILE *fp, const struct lru_event *event)
{
    fprintf(
        fp,
        "%llu,%llu,%d,%u,%u,%s,%s,"
        "%d,%d,%d,%d,"
        "%u,%u,%u,"
        "%u,%u,%u,%llu,%llu,"
        "%llu,%llu,%llu,%llu,%u,"
        "%u,%u,%u,%u,%u,"
        "%llu,%llu,%llu,%llu,"
        "%llu,%llu,%llu,%llu,"
        "%llu,%llu,%llu,%llu,"
        "%u,%u,%u,%u,"
        "%llu,%llu,%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,"
        "%llu,%llu,"
        "%u,%llu,%d,"
        "%llu,%llu,%llu,%llu,"
        "%llu,%llu\n",
        event->session_id,
        event->memcg_id,
        event->node_id,
        event->trigger_tgid,
        event->trigger_tid,
        event->trigger_comm,
        reclaim_context_for(event),
        event->swappiness,
        event->priority,
        event->reclaim_idx,
        event->order,
        event->may_deactivate,
        event->force_deactivate,
        event->skipped_deactivate,
        event->may_writepage,
        event->may_unmap,
        event->may_swap,
        event->gfp_mask,
        event->nr_to_reclaim,
        event->anon_cost,
        event->file_cost,
        event->refaults_anon,
        event->refaults_file,
        event->proportional_reclaim,
        event->cgroup_reclaim,
        event->can_reclaim_anon,
        event->cache_trim_mode,
        event->file_is_tiny,
        event->memcg_low_reclaim,
        event->before_inactive_anon,
        event->before_active_anon,
        event->before_inactive_file,
        event->before_active_file,
        event->target_inactive_anon,
        event->target_active_anon,
        event->target_inactive_file,
        event->target_active_file,
        event->observed_scanned_inactive_anon_pages,
        event->observed_taken_active_anon_pages,
        event->observed_scanned_inactive_file_pages,
        event->observed_taken_active_file_pages,
        event->observed_isolate_calls_inactive_anon,
        event->observed_isolate_calls_active_anon,
        event->observed_isolate_calls_inactive_file,
        event->observed_isolate_calls_active_file,
        event->observed_isolated_pages_inactive_anon,
        event->observed_isolated_pages_active_anon,
        event->observed_isolated_pages_inactive_file,
        event->observed_isolated_pages_active_file,
        event->observed_reclaimed_anon_pages,
        event->observed_reclaimed_file_pages,
        event->observed_activated_anon_pages,
        event->observed_activated_file_pages,
        event->observed_deactivated_anon_pages,
        event->observed_deactivated_file_pages,
        event->observed_active_retained_anon_pages,
        event->observed_active_retained_file_pages,
        event->observed_referenced_anon_pages,
        event->observed_referenced_file_pages,
        event->observed_ref_keep_anon_pages,
        event->observed_ref_keep_file_pages,
        event->observed_dirty_file_pages,
        event->observed_writeback_file_pages,
        event->observed_congested_file_pages,
        event->observed_immediate_file_pages,
        event->observed_unmap_fail_anon_pages,
        event->observed_unmap_fail_file_pages,
        event->observed_proportional_adjust_count,
        event->observed_proportional_adjust_percentage,
        event->observed_proportional_stopped_lru,
        event->observed_remaining_inactive_anon_pages,
        event->observed_remaining_active_anon_pages,
        event->observed_remaining_inactive_file_pages,
        event->observed_remaining_active_file_pages,
        event->observed_reclaimed_anon_pages,
        event->observed_reclaimed_file_pages);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct lru_event *event = data;

    (void)ctx;
    if (data_sz < sizeof(*event))
        return 0;
    if (event->kind != LRU_EVENT_SUMMARY)
        return 0;

    if (csv_fp) {
        if (!csv_header_written) {
            write_csv_header(csv_fp);
            csv_header_written = true;
        }
        write_csv_event(csv_fp, event);
        fflush(csv_fp);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct lru_monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    const char *csv_path = NULL;
    int err = 0;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [lru_output.csv]\n", argv[0]);
        return 1;
    }

    if (argc == 2)
        csv_path = argv[1];

    if (csv_path) {
        csv_fp = fopen(csv_path, "w");
        if (!csv_fp) {
            fprintf(stderr, "Failed to open %s\n", csv_path);
            return 1;
        }
        csv_header_written = false;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = lru_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        err = 1;
        goto out;
    }

    err = lru_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto out;
    }

    err = lru_monitor_bpf__attach(skel);
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

    printf("Attached to shrink_lruvec and vmscan tracepoints, get_swappiness kretprobe enabled");
    if (csv_path)
        printf(", writing CSV to %s", csv_path);
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
    lru_monitor_bpf__destroy(skel);
    if (csv_fp)
        fclose(csv_fp);
    return err < 0 ? 1 : err;
}
