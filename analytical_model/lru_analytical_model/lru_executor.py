#!/usr/bin/env python3
"""Standalone whitebox traditional-LRU executor.

This executor is intentionally self-contained and session-oriented:

  one CSV row == one shrink_lruvec() summary

It does not try to replay every loop iteration inside shrink_lruvec(). Instead,
it reconstructs the reclaim decision at the summary level from:

- initial control inputs (`swappiness`, `nr_to_reclaim`, gating flags)
- traced `scan_control` state (`cgroup_reclaim`, `can_reclaim_anon`, `file_is_tiny`, ...)
- before-state / scan targets (`before_*`, `target_*`)
- proportional reclaim signals (`observed_proportional_*`, `observed_remaining_*`)
- observed path activity (`observed_scanned_*`, `observed_taken_*`, ...)

This is a whitebox parser, not a fitted predictor.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_CSV = Path(__file__).resolve().parent / "lru_output.csv"

MAX_SWAPPINESS = 200
DEACTIVATE_ANON = 1
DEACTIVATE_FILE = 2
LRU_BASE = 0
LRU_FILE = 2


TEMPLATE: Dict[str, Any] = {
    "session_id": 0,
    "memcg_id": 0,
    "node_id": 0,
    "trigger_tgid": 0,
    "trigger_tid": 0,
    "trigger_comm": "kswapd0",
    "reclaim_context": "kswapd",
    "swappiness": 60,
    "priority": 12,
    "reclaim_idx": 0,
    "order": 0,
    "may_deactivate": 3,
    "force_deactivate": 0,
    "skipped_deactivate": 0,
    "may_writepage": 1,
    "may_unmap": 1,
    "may_swap": 1,
    "gfp_mask": 0,
    "nr_to_reclaim": 128,
    "anon_cost": 1000,
    "file_cost": 1000,
    "refaults_anon": 0,
    "refaults_file": 0,
    "proportional_reclaim": 0,
    "cgroup_reclaim": 0,
    "can_reclaim_anon": 1,
    "cache_trim_mode": 0,
    "file_is_tiny": 0,
    "memcg_low_reclaim": 0,
    "before_inactive_anon": 4096,
    "before_active_anon": 8192,
    "before_inactive_file": 16384,
    "before_active_file": 8192,
    "target_inactive_anon": 64,
    "target_active_anon": 32,
    "target_inactive_file": 128,
    "target_active_file": 64,
    "observed_scanned_inactive_anon_pages": 48,
    "observed_taken_active_anon_pages": 16,
    "observed_scanned_inactive_file_pages": 96,
    "observed_taken_active_file_pages": 32,
    "observed_isolate_calls_inactive_anon": 1,
    "observed_isolate_calls_active_anon": 1,
    "observed_isolate_calls_inactive_file": 2,
    "observed_isolate_calls_active_file": 1,
    "observed_isolated_pages_inactive_anon": 48,
    "observed_isolated_pages_active_anon": 16,
    "observed_isolated_pages_inactive_file": 96,
    "observed_isolated_pages_active_file": 32,
    "observed_shrink_input_anon_pages": 48,
    "observed_shrink_input_file_pages": 96,
    "observed_reclaimed_anon_pages": 24,
    "observed_reclaimed_file_pages": 40,
    "observed_activated_anon_pages": 8,
    "observed_activated_file_pages": 6,
    "observed_deactivated_anon_pages": 10,
    "observed_deactivated_file_pages": 12,
    "observed_active_retained_anon_pages": 4,
    "observed_active_retained_file_pages": 5,
    "observed_referenced_anon_pages": 7,
    "observed_referenced_file_pages": 9,
    "observed_ref_keep_anon_pages": 12,
    "observed_ref_keep_file_pages": 18,
    "observed_dirty_anon_pages": 0,
    "observed_dirty_file_pages": 6,
    "observed_writeback_anon_pages": 0,
    "observed_writeback_file_pages": 4,
    "observed_congested_anon_pages": 0,
    "observed_congested_file_pages": 0,
    "observed_immediate_anon_pages": 0,
    "observed_immediate_file_pages": 0,
    "observed_unmap_fail_anon_pages": 2,
    "observed_unmap_fail_file_pages": 0,
    "observed_putback_anon_pages": 0,
    "observed_putback_file_pages": 0,
    "observed_proportional_adjust_count": 0,
    "observed_proportional_adjust_percentage": 0,
    "observed_proportional_stopped_lru": -1,
    "observed_remaining_inactive_anon_pages": 0,
    "observed_remaining_active_anon_pages": 0,
    "observed_remaining_inactive_file_pages": 0,
    "observed_remaining_active_file_pages": 0,
    "target_reclaimed_anon_pages": 24,
    "target_reclaimed_file_pages": 40,
}


@dataclass
class CaseInput:
    session_id: int
    memcg_id: int
    node_id: int
    trigger_tgid: int
    trigger_tid: int
    trigger_comm: str
    reclaim_context: str
    swappiness: int
    priority: int
    reclaim_idx: int
    order: int
    may_deactivate: int
    force_deactivate: bool
    skipped_deactivate: bool
    may_writepage: bool
    may_unmap: bool
    may_swap: bool
    gfp_mask: int
    nr_to_reclaim: int
    anon_cost: int
    file_cost: int
    refaults_anon: int
    refaults_file: int
    proportional_reclaim: bool
    cgroup_reclaim: bool
    can_reclaim_anon: bool
    cache_trim_mode: bool
    file_is_tiny: bool
    memcg_low_reclaim: bool
    before_inactive_anon: int
    before_active_anon: int
    before_inactive_file: int
    before_active_file: int
    target_inactive_anon: int
    target_active_anon: int
    target_inactive_file: int
    target_active_file: int
    observed_scanned_inactive_anon_pages: int
    observed_taken_active_anon_pages: int
    observed_scanned_inactive_file_pages: int
    observed_taken_active_file_pages: int
    observed_isolate_calls_inactive_anon: int
    observed_isolate_calls_active_anon: int
    observed_isolate_calls_inactive_file: int
    observed_isolate_calls_active_file: int
    observed_isolated_pages_inactive_anon: int
    observed_isolated_pages_active_anon: int
    observed_isolated_pages_inactive_file: int
    observed_isolated_pages_active_file: int
    observed_shrink_input_anon_pages: int
    observed_shrink_input_file_pages: int
    observed_reclaimed_anon_pages: int
    observed_reclaimed_file_pages: int
    observed_activated_anon_pages: int
    observed_activated_file_pages: int
    observed_deactivated_anon_pages: int
    observed_deactivated_file_pages: int
    observed_active_retained_anon_pages: int
    observed_active_retained_file_pages: int
    observed_referenced_anon_pages: int
    observed_referenced_file_pages: int
    observed_ref_keep_anon_pages: int
    observed_ref_keep_file_pages: int
    observed_dirty_anon_pages: int
    observed_dirty_file_pages: int
    observed_writeback_anon_pages: int
    observed_writeback_file_pages: int
    observed_congested_anon_pages: int
    observed_congested_file_pages: int
    observed_immediate_anon_pages: int
    observed_immediate_file_pages: int
    observed_unmap_fail_anon_pages: int
    observed_unmap_fail_file_pages: int
    observed_putback_anon_pages: int
    observed_putback_file_pages: int
    observed_proportional_adjust_count: int
    observed_proportional_adjust_percentage: int
    observed_proportional_stopped_lru: int
    observed_remaining_inactive_anon_pages: int
    observed_remaining_active_anon_pages: int
    observed_remaining_inactive_file_pages: int
    observed_remaining_active_file_pages: int
    target_reclaimed_anon_pages: int
    target_reclaimed_file_pages: int


@dataclass(frozen=True)
class ExecutorConfig:
    anon_unmap_fail_weight: float = 0.50
    anon_ref_keep_weight: float = 1.00
    anon_activate_weight: float = 1.00
    anon_reference_weight: float = 0.25
    anon_dirty_weight: float = 0.35
    anon_writeback_weight: float = 0.60
    anon_congested_weight: float = 0.35
    anon_immediate_weight: float = 0.50
    anon_putback_weight: float = 1.00
    file_ref_keep_weight: float = 1.00
    file_activate_weight: float = 1.00
    file_reference_weight: float = 0.15
    file_dirty_weight: float = 0.35
    file_writeback_weight: float = 0.60
    file_congested_weight: float = 0.35
    file_immediate_weight: float = 0.50
    file_unmap_fail_weight: float = 0.20
    file_putback_weight: float = 1.00
    blocked_path_discount: float = 0.35
    direct_reclaim_overshoot_ratio: float = 0.15
    anon_observed_scan_success_ceiling: float = 0.50


@dataclass
class TraceStep:
    fn: str
    branch: str
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute a whitebox traditional-LRU parser")
    parser.add_argument("input", nargs="?", help="Path to case JSON")
    parser.add_argument("--stdin", action="store_true", help="Read case JSON from stdin")
    parser.add_argument("--template", action="store_true", help="Print a case JSON template")
    parser.add_argument("--csv", default=str(DEFAULT_CSV), help="Path to lru_output.csv")
    parser.add_argument("--line", type=int, help="Physical CSV line number to load (header is line 1)")
    parser.add_argument("--session-id", type=int, help="Load the first CSV row with this session_id")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser.parse_args()


def as_int(mapping: Dict[str, Any], key: str, default: int = 0) -> int:
    value = mapping.get(key)
    if value is None or value == "":
        return default
    return int(value)


def as_bool_from_int(mapping: Dict[str, Any], key: str, default: bool = False) -> bool:
    return bool(as_int(mapping, key, int(default)))


def load_case(data: Dict[str, Any]) -> CaseInput:
    return CaseInput(
        session_id=as_int(data, "session_id"),
        memcg_id=as_int(data, "memcg_id"),
        node_id=as_int(data, "node_id", -1),
        trigger_tgid=as_int(data, "trigger_tgid"),
        trigger_tid=as_int(data, "trigger_tid"),
        trigger_comm=str(data.get("trigger_comm", "unknown")),
        reclaim_context=str(data.get("reclaim_context", "unknown")),
        swappiness=as_int(data, "swappiness"),
        priority=as_int(data, "priority"),
        reclaim_idx=as_int(data, "reclaim_idx"),
        order=as_int(data, "order"),
        may_deactivate=as_int(data, "may_deactivate"),
        force_deactivate=as_bool_from_int(data, "force_deactivate"),
        skipped_deactivate=as_bool_from_int(data, "skipped_deactivate"),
        may_writepage=as_bool_from_int(data, "may_writepage", True),
        may_unmap=as_bool_from_int(data, "may_unmap", True),
        may_swap=as_bool_from_int(data, "may_swap", True),
        gfp_mask=as_int(data, "gfp_mask"),
        nr_to_reclaim=as_int(data, "nr_to_reclaim"),
        anon_cost=as_int(data, "anon_cost"),
        file_cost=as_int(data, "file_cost"),
        refaults_anon=as_int(data, "refaults_anon"),
        refaults_file=as_int(data, "refaults_file"),
        proportional_reclaim=as_bool_from_int(data, "proportional_reclaim"),
        cgroup_reclaim=as_bool_from_int(data, "cgroup_reclaim"),
        can_reclaim_anon=as_bool_from_int(data, "can_reclaim_anon", True),
        cache_trim_mode=as_bool_from_int(data, "cache_trim_mode"),
        file_is_tiny=as_bool_from_int(data, "file_is_tiny"),
        memcg_low_reclaim=as_bool_from_int(data, "memcg_low_reclaim"),
        before_inactive_anon=as_int(data, "before_inactive_anon"),
        before_active_anon=as_int(data, "before_active_anon"),
        before_inactive_file=as_int(data, "before_inactive_file"),
        before_active_file=as_int(data, "before_active_file"),
        target_inactive_anon=as_int(data, "target_inactive_anon"),
        target_active_anon=as_int(data, "target_active_anon"),
        target_inactive_file=as_int(data, "target_inactive_file"),
        target_active_file=as_int(data, "target_active_file"),
        observed_scanned_inactive_anon_pages=as_int(data, "observed_scanned_inactive_anon_pages"),
        observed_taken_active_anon_pages=as_int(data, "observed_taken_active_anon_pages"),
        observed_scanned_inactive_file_pages=as_int(data, "observed_scanned_inactive_file_pages"),
        observed_taken_active_file_pages=as_int(data, "observed_taken_active_file_pages"),
        observed_isolate_calls_inactive_anon=as_int(data, "observed_isolate_calls_inactive_anon"),
        observed_isolate_calls_active_anon=as_int(data, "observed_isolate_calls_active_anon"),
        observed_isolate_calls_inactive_file=as_int(data, "observed_isolate_calls_inactive_file"),
        observed_isolate_calls_active_file=as_int(data, "observed_isolate_calls_active_file"),
        observed_isolated_pages_inactive_anon=as_int(data, "observed_isolated_pages_inactive_anon"),
        observed_isolated_pages_active_anon=as_int(data, "observed_isolated_pages_active_anon"),
        observed_isolated_pages_inactive_file=as_int(data, "observed_isolated_pages_inactive_file"),
        observed_isolated_pages_active_file=as_int(data, "observed_isolated_pages_active_file"),
        observed_shrink_input_anon_pages=as_int(
            data,
            "observed_shrink_input_anon_pages",
            as_int(data, "observed_isolated_pages_inactive_anon"),
        ),
        observed_shrink_input_file_pages=as_int(
            data,
            "observed_shrink_input_file_pages",
            as_int(data, "observed_isolated_pages_inactive_file"),
        ),
        observed_reclaimed_anon_pages=as_int(data, "observed_reclaimed_anon_pages"),
        observed_reclaimed_file_pages=as_int(data, "observed_reclaimed_file_pages"),
        observed_activated_anon_pages=as_int(data, "observed_activated_anon_pages"),
        observed_activated_file_pages=as_int(data, "observed_activated_file_pages"),
        observed_deactivated_anon_pages=as_int(data, "observed_deactivated_anon_pages"),
        observed_deactivated_file_pages=as_int(data, "observed_deactivated_file_pages"),
        observed_active_retained_anon_pages=as_int(data, "observed_active_retained_anon_pages"),
        observed_active_retained_file_pages=as_int(data, "observed_active_retained_file_pages"),
        observed_referenced_anon_pages=as_int(data, "observed_referenced_anon_pages"),
        observed_referenced_file_pages=as_int(data, "observed_referenced_file_pages"),
        observed_ref_keep_anon_pages=as_int(data, "observed_ref_keep_anon_pages"),
        observed_ref_keep_file_pages=as_int(data, "observed_ref_keep_file_pages"),
        observed_dirty_anon_pages=as_int(data, "observed_dirty_anon_pages"),
        observed_dirty_file_pages=as_int(data, "observed_dirty_file_pages"),
        observed_writeback_anon_pages=as_int(data, "observed_writeback_anon_pages"),
        observed_writeback_file_pages=as_int(data, "observed_writeback_file_pages"),
        observed_congested_anon_pages=as_int(data, "observed_congested_anon_pages"),
        observed_congested_file_pages=as_int(data, "observed_congested_file_pages"),
        observed_immediate_anon_pages=as_int(data, "observed_immediate_anon_pages"),
        observed_immediate_file_pages=as_int(data, "observed_immediate_file_pages"),
        observed_unmap_fail_anon_pages=as_int(data, "observed_unmap_fail_anon_pages"),
        observed_unmap_fail_file_pages=as_int(data, "observed_unmap_fail_file_pages"),
        observed_putback_anon_pages=as_int(data, "observed_putback_anon_pages"),
        observed_putback_file_pages=as_int(data, "observed_putback_file_pages"),
        observed_proportional_adjust_count=as_int(data, "observed_proportional_adjust_count"),
        observed_proportional_adjust_percentage=as_int(data, "observed_proportional_adjust_percentage"),
        observed_proportional_stopped_lru=as_int(data, "observed_proportional_stopped_lru", -1),
        observed_remaining_inactive_anon_pages=as_int(data, "observed_remaining_inactive_anon_pages"),
        observed_remaining_active_anon_pages=as_int(data, "observed_remaining_active_anon_pages"),
        observed_remaining_inactive_file_pages=as_int(data, "observed_remaining_inactive_file_pages"),
        observed_remaining_active_file_pages=as_int(data, "observed_remaining_active_file_pages"),
        target_reclaimed_anon_pages=as_int(data, "target_reclaimed_anon_pages"),
        target_reclaimed_file_pages=as_int(data, "target_reclaimed_file_pages"),
    )


def build_case_from_csv_row(row: Dict[str, str]) -> Dict[str, Any]:
    return {
        "session_id": as_int(row, "session_id"),
        "memcg_id": as_int(row, "memcg_id"),
        "node_id": as_int(row, "node_id", -1),
        "trigger_tgid": as_int(row, "trigger_tgid"),
        "trigger_tid": as_int(row, "trigger_tid"),
        "trigger_comm": row.get("trigger_comm", "unknown"),
        "reclaim_context": row.get("reclaim_context", "unknown"),
        "swappiness": as_int(row, "feature_swappiness"),
        "priority": as_int(row, "feature_priority"),
        "reclaim_idx": as_int(row, "feature_reclaim_idx"),
        "order": as_int(row, "feature_order"),
        "may_deactivate": as_int(row, "feature_may_deactivate"),
        "force_deactivate": as_int(row, "feature_force_deactivate"),
        "skipped_deactivate": as_int(row, "feature_skipped_deactivate"),
        "may_writepage": as_int(row, "feature_may_writepage"),
        "may_unmap": as_int(row, "feature_may_unmap"),
        "may_swap": as_int(row, "feature_may_swap"),
        "gfp_mask": as_int(row, "feature_gfp_mask"),
        "nr_to_reclaim": as_int(row, "feature_nr_to_reclaim"),
        "anon_cost": as_int(row, "feature_anon_cost"),
        "file_cost": as_int(row, "feature_file_cost"),
        "refaults_anon": as_int(row, "feature_refaults_anon"),
        "refaults_file": as_int(row, "feature_refaults_file"),
        "proportional_reclaim": as_int(row, "feature_proportional_reclaim"),
        "cgroup_reclaim": as_int(row, "feature_cgroup_reclaim"),
        "can_reclaim_anon": as_int(row, "feature_can_reclaim_anon", 1),
        "cache_trim_mode": as_int(row, "feature_cache_trim_mode"),
        "file_is_tiny": as_int(row, "feature_file_is_tiny"),
        "memcg_low_reclaim": as_int(row, "feature_memcg_low_reclaim"),
        "before_inactive_anon": as_int(row, "feature_before_inactive_anon"),
        "before_active_anon": as_int(row, "feature_before_active_anon"),
        "before_inactive_file": as_int(row, "feature_before_inactive_file"),
        "before_active_file": as_int(row, "feature_before_active_file"),
        "target_inactive_anon": as_int(row, "feature_target_inactive_anon"),
        "target_active_anon": as_int(row, "feature_target_active_anon"),
        "target_inactive_file": as_int(row, "feature_target_inactive_file"),
        "target_active_file": as_int(row, "feature_target_active_file"),
        "observed_scanned_inactive_anon_pages": as_int(row, "observed_scanned_inactive_anon_pages"),
        "observed_taken_active_anon_pages": as_int(row, "observed_taken_active_anon_pages"),
        "observed_scanned_inactive_file_pages": as_int(row, "observed_scanned_inactive_file_pages"),
        "observed_taken_active_file_pages": as_int(row, "observed_taken_active_file_pages"),
        "observed_isolate_calls_inactive_anon": as_int(row, "observed_isolate_calls_inactive_anon"),
        "observed_isolate_calls_active_anon": as_int(row, "observed_isolate_calls_active_anon"),
        "observed_isolate_calls_inactive_file": as_int(row, "observed_isolate_calls_inactive_file"),
        "observed_isolate_calls_active_file": as_int(row, "observed_isolate_calls_active_file"),
        "observed_isolated_pages_inactive_anon": as_int(row, "observed_isolated_pages_inactive_anon"),
        "observed_isolated_pages_active_anon": as_int(row, "observed_isolated_pages_active_anon"),
        "observed_isolated_pages_inactive_file": as_int(row, "observed_isolated_pages_inactive_file"),
        "observed_isolated_pages_active_file": as_int(row, "observed_isolated_pages_active_file"),
        "observed_shrink_input_anon_pages": as_int(
            row,
            "observed_shrink_input_anon_pages",
            as_int(row, "observed_isolated_pages_inactive_anon"),
        ),
        "observed_shrink_input_file_pages": as_int(
            row,
            "observed_shrink_input_file_pages",
            as_int(row, "observed_isolated_pages_inactive_file"),
        ),
        "observed_reclaimed_anon_pages": as_int(row, "observed_reclaimed_anon_pages"),
        "observed_reclaimed_file_pages": as_int(row, "observed_reclaimed_file_pages"),
        "observed_activated_anon_pages": as_int(row, "observed_activated_anon_pages"),
        "observed_activated_file_pages": as_int(row, "observed_activated_file_pages"),
        "observed_deactivated_anon_pages": as_int(row, "observed_deactivated_anon_pages"),
        "observed_deactivated_file_pages": as_int(row, "observed_deactivated_file_pages"),
        "observed_active_retained_anon_pages": as_int(row, "observed_active_retained_anon_pages"),
        "observed_active_retained_file_pages": as_int(row, "observed_active_retained_file_pages"),
        "observed_referenced_anon_pages": as_int(row, "observed_referenced_anon_pages"),
        "observed_referenced_file_pages": as_int(row, "observed_referenced_file_pages"),
        "observed_ref_keep_anon_pages": as_int(row, "observed_ref_keep_anon_pages"),
        "observed_ref_keep_file_pages": as_int(row, "observed_ref_keep_file_pages"),
        "observed_dirty_anon_pages": as_int(row, "observed_dirty_anon_pages"),
        "observed_dirty_file_pages": as_int(row, "observed_dirty_file_pages"),
        "observed_writeback_anon_pages": as_int(row, "observed_writeback_anon_pages"),
        "observed_writeback_file_pages": as_int(row, "observed_writeback_file_pages"),
        "observed_congested_anon_pages": as_int(row, "observed_congested_anon_pages"),
        "observed_congested_file_pages": as_int(row, "observed_congested_file_pages"),
        "observed_immediate_anon_pages": as_int(row, "observed_immediate_anon_pages"),
        "observed_immediate_file_pages": as_int(row, "observed_immediate_file_pages"),
        "observed_unmap_fail_anon_pages": as_int(row, "observed_unmap_fail_anon_pages"),
        "observed_unmap_fail_file_pages": as_int(row, "observed_unmap_fail_file_pages"),
        "observed_putback_anon_pages": as_int(row, "observed_putback_anon_pages"),
        "observed_putback_file_pages": as_int(row, "observed_putback_file_pages"),
        "observed_proportional_adjust_count": as_int(row, "observed_proportional_adjust_count"),
        "observed_proportional_adjust_percentage": as_int(row, "observed_proportional_adjust_percentage"),
        "observed_proportional_stopped_lru": as_int(row, "observed_proportional_stopped_lru", -1),
        "observed_remaining_inactive_anon_pages": as_int(row, "observed_remaining_inactive_anon_pages"),
        "observed_remaining_active_anon_pages": as_int(row, "observed_remaining_active_anon_pages"),
        "observed_remaining_inactive_file_pages": as_int(row, "observed_remaining_inactive_file_pages"),
        "observed_remaining_active_file_pages": as_int(row, "observed_remaining_active_file_pages"),
        "target_reclaimed_anon_pages": as_int(row, "target_reclaimed_anon_pages"),
        "target_reclaimed_file_pages": as_int(row, "target_reclaimed_file_pages"),
    }


def iter_csv_rows(csv_path: Path) -> Iterable[Tuple[int, Dict[str, str]]]:
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for line_no, row in enumerate(reader, start=2):
            yield line_no, row


def load_case_from_args(args: argparse.Namespace) -> CaseInput:
    if args.template:
        print(json.dumps(TEMPLATE, indent=2, ensure_ascii=False))
        raise SystemExit(0)
    if args.stdin:
        return load_case(json.load(sys.stdin))
    if args.line is not None or args.session_id is not None:
        csv_path = Path(args.csv).resolve()
        for line_no, row in iter_csv_rows(csv_path):
            if args.line is not None and line_no != args.line:
                continue
            if args.session_id is not None and as_int(row, "session_id") != args.session_id:
                continue
            return load_case(build_case_from_csv_row(row))
        if args.line is not None:
            raise SystemExit(f"no CSV row found at physical line {args.line}")
        raise SystemExit(f"no CSV row found for session_id={args.session_id}")
    if not args.input:
        raise SystemExit("missing case JSON path, or use --csv with --line/--session-id")
    with open(args.input, "r", encoding="utf-8") as fh:
        return load_case(json.load(fh))


def to_range_label(value: int) -> str:
    if value <= 0:
        return "0"
    if value <= 16:
        return "1-16"
    if value <= 64:
        return "17-64"
    if value <= 256:
        return "65-256"
    if value <= 1024:
        return "257-1024"
    if value <= 4096:
        return "1025-4096"
    return "4097+"


def append_step(trace: List[TraceStep], fn: str, branch: str, reason: str, **details: Any) -> None:
    trace.append(TraceStep(fn=fn, branch=branch, reason=reason, details=details))


def total_before_anon(case: CaseInput) -> int:
    return case.before_inactive_anon + case.before_active_anon


def total_before_file(case: CaseInput) -> int:
    return case.before_inactive_file + case.before_active_file


def total_target_anon(case: CaseInput) -> int:
    return case.target_inactive_anon + case.target_active_anon


def total_target_file(case: CaseInput) -> int:
    return case.target_inactive_file + case.target_active_file


def total_remaining_anon(case: CaseInput) -> int:
    return case.observed_remaining_inactive_anon_pages + case.observed_remaining_active_anon_pages


def total_remaining_file(case: CaseInput) -> int:
    return case.observed_remaining_inactive_file_pages + case.observed_remaining_active_file_pages


def scaled_lru_size(value: int, priority: int) -> int:
    if value <= 0:
        return 0
    if priority <= 0:
        return value
    return max(value >> priority, 1)


def synthetic_scan_balance(case: CaseInput) -> str:
    if not case.may_swap or not case.can_reclaim_anon:
        return "SCAN_FILE"
    if case.cgroup_reclaim and case.swappiness <= 0:
        return "SCAN_FILE"
    if case.priority == 0 and case.swappiness > 0:
        return "SCAN_EQUAL"
    if case.file_is_tiny:
        return "SCAN_ANON"
    if case.cache_trim_mode:
        return "SCAN_FILE"
    return "SCAN_FRACT"


def scan_fraction_weights(case: CaseInput) -> Tuple[int, int]:
    total_cost = max(case.anon_cost + case.file_cost, 0)
    anon_cost = total_cost + case.anon_cost
    file_cost = total_cost + case.file_cost
    total_cost = anon_cost + file_cost
    swappiness = max(0, min(case.swappiness, MAX_SWAPPINESS))

    ap = swappiness * (total_cost + 1)
    ap //= anon_cost + 1

    fp = (MAX_SWAPPINESS - swappiness) * (total_cost + 1)
    fp //= file_cost + 1
    return max(ap, 0), max(fp, 0)


def synthesize_targets(case: CaseInput, config: ExecutorConfig) -> Dict[str, Any]:
    scan_balance = synthetic_scan_balance(case)
    ap, fp = scan_fraction_weights(case)
    denominator = max(ap + fp, 1)

    raw_weights = {
        "inactive_anon": scaled_lru_size(case.before_inactive_anon, case.priority),
        "active_anon": scaled_lru_size(case.before_active_anon, case.priority) if active_path_allowed(case, "anon") else 0,
        "inactive_file": scaled_lru_size(case.before_inactive_file, case.priority),
        "active_file": scaled_lru_size(case.before_active_file, case.priority) if active_path_allowed(case, "file") else 0,
    }

    if scan_balance == "SCAN_EQUAL":
        planned = dict(raw_weights)
        weighted = dict(raw_weights)
    elif scan_balance == "SCAN_FILE":
        weighted = {
            "inactive_anon": 0,
            "active_anon": 0,
            "inactive_file": raw_weights["inactive_file"],
            "active_file": raw_weights["active_file"],
        }
        planned = dict(weighted)
    elif scan_balance == "SCAN_ANON":
        weighted = {
            "inactive_anon": raw_weights["inactive_anon"],
            "active_anon": raw_weights["active_anon"],
            "inactive_file": 0,
            "active_file": 0,
        }
        planned = dict(weighted)
    else:
        weighted = {
            "inactive_anon": raw_weights["inactive_anon"] * ap,
            "active_anon": raw_weights["active_anon"] * ap,
            "inactive_file": raw_weights["inactive_file"] * fp,
            "active_file": raw_weights["active_file"] * fp,
        }
        planned = {
            "inactive_anon": int(round(weighted["inactive_anon"] / denominator)),
            "active_anon": int(round(weighted["active_anon"] / denominator)),
            "inactive_file": int(round(weighted["inactive_file"] / denominator)),
            "active_file": int(round(weighted["active_file"] / denominator)),
        }

    return {
        "planned": planned,
        "meta": {
            "scan_balance": scan_balance,
            "ap": ap,
            "fp": fp,
            "denominator": denominator,
            "scan_control": {
                "cgroup_reclaim": case.cgroup_reclaim,
                "can_reclaim_anon": case.can_reclaim_anon,
                "cache_trim_mode": case.cache_trim_mode,
                "file_is_tiny": case.file_is_tiny,
                "memcg_low_reclaim": case.memcg_low_reclaim,
            },
            "raw_weights": raw_weights,
            "weighted": weighted,
        },
    }


def reclaimable_cap_anon(case: CaseInput, config: ExecutorConfig, inactive_floor: int = 0) -> Tuple[int, Dict[str, int]]:
    shrink_input = case.observed_shrink_input_anon_pages
    if shrink_input <= 0:
        shrink_input = case.observed_isolated_pages_inactive_anon
    if shrink_input <= 0:
        shrink_input = case.observed_scanned_inactive_anon_pages
    if shrink_input <= 0:
        shrink_input = inactive_floor
    has_detailed_boundary = any(
        (
            case.observed_dirty_anon_pages,
            case.observed_writeback_anon_pages,
            case.observed_congested_anon_pages,
            case.observed_immediate_anon_pages,
            case.observed_putback_anon_pages,
        )
    )
    penalties = {
        "ref_keep": int(round(case.observed_ref_keep_anon_pages * config.anon_ref_keep_weight)),
        "activated": int(round(case.observed_activated_anon_pages * config.anon_activate_weight)),
        "referenced": int(round(case.observed_referenced_anon_pages * config.anon_reference_weight)),
        "dirty": int(round(case.observed_dirty_anon_pages * config.anon_dirty_weight)),
        "writeback": int(round(case.observed_writeback_anon_pages * config.anon_writeback_weight)),
        "congested": int(round(case.observed_congested_anon_pages * config.anon_congested_weight)),
        "immediate": int(round(case.observed_immediate_anon_pages * config.anon_immediate_weight)),
        "unmap_fail": int(round(case.observed_unmap_fail_anon_pages * config.anon_unmap_fail_weight)),
        "putback": int(round(case.observed_putback_anon_pages * config.anon_putback_weight)),
    }
    penalty_total = sum(penalties.values())
    cap = max(shrink_input - penalty_total, 0)
    if case.observed_isolated_pages_inactive_anon > 0 and not has_detailed_boundary:
        cap = min(cap, int(round(case.observed_isolated_pages_inactive_anon * config.anon_observed_scan_success_ceiling)))
    if not case.may_unmap:
        cap = int(round(cap * config.blocked_path_discount))
    if not case.may_swap or case.swappiness <= 0:
        cap = 0
    return cap, penalties


def reclaimable_cap_file(case: CaseInput, config: ExecutorConfig, inactive_floor: int = 0) -> Tuple[int, Dict[str, int]]:
    shrink_input = case.observed_shrink_input_file_pages
    if shrink_input <= 0:
        shrink_input = case.observed_isolated_pages_inactive_file
    if shrink_input <= 0:
        shrink_input = case.observed_scanned_inactive_file_pages
    if shrink_input <= 0:
        shrink_input = inactive_floor
    penalties = {
        "ref_keep": int(round(case.observed_ref_keep_file_pages * config.file_ref_keep_weight)),
        "activated": int(round(case.observed_activated_file_pages * config.file_activate_weight)),
        "referenced": int(round(case.observed_referenced_file_pages * config.file_reference_weight)),
        "dirty": int(round(case.observed_dirty_file_pages * config.file_dirty_weight)),
        "writeback": int(round(case.observed_writeback_file_pages * config.file_writeback_weight)),
        "congested": int(round(case.observed_congested_file_pages * config.file_congested_weight)),
        "immediate": int(round(case.observed_immediate_file_pages * config.file_immediate_weight)),
        "unmap_fail": int(round(case.observed_unmap_fail_file_pages * config.file_unmap_fail_weight)),
        "putback": int(round(case.observed_putback_file_pages * config.file_putback_weight)),
    }
    penalty_total = sum(penalties.values())
    cap = max(shrink_input - penalty_total, 0)
    if not case.may_writepage:
        cap = int(round(cap * config.blocked_path_discount))
    return cap, penalties


def active_path_allowed(case: CaseInput, type_name: str) -> bool:
    bit = DEACTIVATE_ANON if type_name == "anon" else DEACTIVATE_FILE
    if type_name == "anon":
        observed_active_work = any(
            (
                case.observed_taken_active_anon_pages,
                case.observed_deactivated_anon_pages,
                case.observed_active_retained_anon_pages,
                case.observed_referenced_anon_pages,
            )
        )
    else:
        observed_active_work = any(
            (
                case.observed_taken_active_file_pages,
                case.observed_deactivated_file_pages,
                case.observed_active_retained_file_pages,
                case.observed_referenced_file_pages,
            )
        )
    if observed_active_work:
        return True
    return bool(case.may_deactivate & bit) and not case.skipped_deactivate


def effective_targets(case: CaseInput, config: ExecutorConfig) -> Dict[str, Any]:
    traced_planned = {
        "inactive_anon": case.target_inactive_anon,
        "active_anon": case.target_active_anon,
        "inactive_file": case.target_inactive_file,
        "active_file": case.target_active_file,
    }
    synthesized = synthesize_targets(case, config)
    has_traced_targets = any(value > 0 for value in traced_planned.values())
    has_trace_activity = any(
        value > 0
        for value in (
            case.observed_scanned_inactive_anon_pages,
            case.observed_taken_active_anon_pages,
            case.observed_scanned_inactive_file_pages,
            case.observed_taken_active_file_pages,
            case.observed_isolate_calls_inactive_anon,
            case.observed_isolate_calls_active_anon,
            case.observed_isolate_calls_inactive_file,
            case.observed_isolate_calls_active_file,
        )
    )
    if has_traced_targets or has_trace_activity:
        planned = dict(traced_planned)
        source = "trace_target"
    else:
        planned = synthesized["planned"]
        source = "synthetic_get_scan_count"

    remaining = {
        "inactive_anon": case.observed_remaining_inactive_anon_pages,
        "active_anon": case.observed_remaining_active_anon_pages,
        "inactive_file": case.observed_remaining_inactive_file_pages,
        "active_file": case.observed_remaining_active_file_pages,
    }

    if case.observed_proportional_adjust_count > 0:
        executed = {
            name: max(planned[name] - remaining[name], 0)
            for name in planned
        }
    else:
        executed = dict(planned)

    return {
        "source": source,
        "observed_planned": traced_planned,
        "synthetic_meta": synthesized["meta"],
        "planned": planned,
        "remaining": remaining,
        "executed": executed,
    }


def reclaim_budget(case: CaseInput, type_name: str, targets: Dict[str, Any]) -> Dict[str, int]:
    executed = targets["executed"]
    if type_name == "anon":
        inactive_target = executed["inactive_anon"]
        active_target = executed["active_anon"]
        if targets["source"] == "trace_target":
            inactive_budget = case.observed_isolated_pages_inactive_anon
            if inactive_budget <= 0:
                inactive_budget = case.observed_scanned_inactive_anon_pages
            active_budget = case.observed_taken_active_anon_pages
        else:
            inactive_budget = inactive_target
            active_budget = active_target
        has_active_signal = any(
            (
                case.observed_taken_active_anon_pages,
                case.observed_deactivated_anon_pages,
                case.observed_active_retained_anon_pages,
                case.observed_referenced_anon_pages,
            )
        )
        if not active_path_allowed(case, "anon"):
            deactivated = 0
            deactivated_source = "blocked"
        elif case.observed_deactivated_anon_pages > 0 or has_active_signal:
            deactivated = case.observed_deactivated_anon_pages
            deactivated_source = "observed"
        else:
            deactivated = active_budget
            deactivated_source = "parsed"
    else:
        inactive_target = executed["inactive_file"]
        active_target = executed["active_file"]
        if targets["source"] == "trace_target":
            inactive_budget = case.observed_isolated_pages_inactive_file
            if inactive_budget <= 0:
                inactive_budget = case.observed_scanned_inactive_file_pages
            active_budget = case.observed_taken_active_file_pages
        else:
            inactive_budget = inactive_target
            active_budget = active_target
        has_active_signal = any(
            (
                case.observed_taken_active_file_pages,
                case.observed_deactivated_file_pages,
                case.observed_active_retained_file_pages,
                case.observed_referenced_file_pages,
            )
        )
        if not active_path_allowed(case, "file"):
            deactivated = 0
            deactivated_source = "blocked"
        elif case.observed_deactivated_file_pages > 0 or has_active_signal:
            deactivated = case.observed_deactivated_file_pages
            deactivated_source = "observed"
        else:
            deactivated = active_budget
            deactivated_source = "parsed"

    demoted_budget = min(active_budget, deactivated)
    total_budget = inactive_budget

    return {
        "inactive_target": inactive_target,
        "active_target": active_target,
        "inactive_budget": inactive_budget,
        "active_budget": active_budget,
        "deactivated_input": deactivated,
        "deactivated_source": deactivated_source,
        "demoted_budget": demoted_budget,
        "total_budget": total_budget,
    }


def apply_budget_cap(
    case: CaseInput,
    anon_cap: int,
    file_cap: int,
    anon_budget: Dict[str, int],
    file_budget: Dict[str, int],
    config: ExecutorConfig,
) -> Tuple[int, int]:
    anon_pred = min(anon_cap, anon_budget["total_budget"])
    file_pred = min(file_cap, file_budget["total_budget"])

    total_pred = anon_pred + file_pred
    if case.nr_to_reclaim > 0:
        overshoot_limit = int(round(case.nr_to_reclaim * config.direct_reclaim_overshoot_ratio))
        total_goal = case.nr_to_reclaim + overshoot_limit
    else:
        total_goal = total_pred

    if total_pred > total_goal and total_pred > 0:
        scale = total_goal / total_pred
        anon_pred = int(round(anon_pred * scale))
        file_pred = min(file_pred, max(total_goal - anon_pred, 0))

    return anon_pred, file_pred


def exec_shrink_lruvec(case: CaseInput, config: ExecutorConfig) -> Dict[str, Any]:
    trace: List[TraceStep] = []
    targets = effective_targets(case, config)

    append_step(
        trace,
        "shrink_lruvec",
        "enter",
        "entered shrink_lruvec() summary parser",
        session_id=case.session_id,
        trigger_comm=case.trigger_comm,
    )

    append_step(
        trace,
        "get_scan_count",
        "targets_loaded",
        "parsed scan targets from control inputs, traced scan_control state, and before-state, while keeping mm_vmscan_lru_plan targets for comparison",
        planned=targets["planned"],
        observed_planned=targets["observed_planned"],
        executed=targets["executed"],
        source=targets["source"],
        synthetic_meta=targets["synthetic_meta"],
    )

    if case.observed_proportional_adjust_count > 0:
        stopped = "anon" if case.observed_proportional_stopped_lru == LRU_BASE else "file"
        append_step(
            trace,
            "shrink_lruvec",
            "proportional_adjust",
            "proportional reclaim adjustment was observed",
            count=case.observed_proportional_adjust_count,
            percentage=case.observed_proportional_adjust_percentage,
            stopped_lru=stopped,
            remaining_anon=total_remaining_anon(case),
            remaining_file=total_remaining_file(case),
        )
    else:
        append_step(
            trace,
            "shrink_lruvec",
            "no_proportional_adjust",
            "no proportional reclaim adjustment was observed",
        )

    anon_budget = reclaim_budget(case, "anon", targets)
    file_budget = reclaim_budget(case, "file", targets)
    anon_cap, anon_penalties = reclaimable_cap_anon(case, config, anon_budget["inactive_budget"])
    file_cap, file_penalties = reclaimable_cap_file(case, config, file_budget["inactive_budget"])
    append_step(
        trace,
        "shrink_inactive_list",
        "anon_cap",
        "derived anon reclaimable cap from inactive scan and keep/fail signals, with synthetic fallback when observed scan is missing",
        scanned=case.observed_scanned_inactive_anon_pages or anon_budget["inactive_budget"],
        penalties=anon_penalties,
        cap=anon_cap,
    )
    append_step(
        trace,
        "shrink_inactive_list",
        "file_cap",
        "derived file reclaimable cap from inactive scan and dirty/writeback/keep signals, with synthetic fallback when observed scan is missing",
        scanned=case.observed_scanned_inactive_file_pages or file_budget["inactive_budget"],
        penalties=file_penalties,
        cap=file_cap,
    )
    append_step(
        trace,
        "budget_builder",
        "anon_budget",
        "built anon reclaim budget from executed inactive target plus active-to-inactive demotion",
        budget=anon_budget,
    )
    append_step(
        trace,
        "budget_builder",
        "file_budget",
        "built file reclaim budget from executed inactive target plus active-to-inactive demotion",
        budget=file_budget,
    )

    if active_path_allowed(case, "anon"):
        append_step(
            trace,
            "shrink_active_list",
            "anon_allowed",
            "active anon path was allowed and contributed deactivation/reference signals",
            taken=case.observed_taken_active_anon_pages,
            deactivated=case.observed_deactivated_anon_pages,
            retained=case.observed_active_retained_anon_pages,
        )
    else:
        append_step(
            trace,
            "shrink_active_list",
            "anon_blocked",
            "active anon path was gated off by may_deactivate/skipped_deactivate",
            may_deactivate=case.may_deactivate,
            skipped_deactivate=case.skipped_deactivate,
        )

    if active_path_allowed(case, "file"):
        append_step(
            trace,
            "shrink_active_list",
            "file_allowed",
            "active file path was allowed and contributed deactivation/reference signals",
            taken=case.observed_taken_active_file_pages,
            deactivated=case.observed_deactivated_file_pages,
            retained=case.observed_active_retained_file_pages,
        )
    else:
        append_step(
            trace,
            "shrink_active_list",
            "file_blocked",
            "active file path was gated off by may_deactivate/skipped_deactivate",
            may_deactivate=case.may_deactivate,
            skipped_deactivate=case.skipped_deactivate,
        )

    predicted_anon, predicted_file = apply_budget_cap(
        case=case,
        anon_cap=anon_cap,
        file_cap=file_cap,
        anon_budget=anon_budget,
        file_budget=file_budget,
        config=config,
    )
    append_step(
        trace,
        "shrink_lruvec",
        "predicted",
        "combined executed list budgets and inactive reclaim caps into final anon/file reclaim prediction",
        predicted_anon=predicted_anon,
        predicted_file=predicted_file,
        actual_anon=case.target_reclaimed_anon_pages,
        actual_file=case.target_reclaimed_file_pages,
    )

    append_step(trace, "shrink_lruvec", "exit", "leaving shrink_lruvec() summary parser")

    return {
        "input_summary": {
            "session_id": case.session_id,
            "trigger_comm": case.trigger_comm,
            "reclaim_context": case.reclaim_context,
            "swappiness": case.swappiness,
            "priority": case.priority,
            "reclaim_idx": case.reclaim_idx,
            "order": case.order,
            "nr_to_reclaim": case.nr_to_reclaim,
            "proportional_reclaim": case.proportional_reclaim,
            "cgroup_reclaim": case.cgroup_reclaim,
            "can_reclaim_anon": case.can_reclaim_anon,
            "cache_trim_mode": case.cache_trim_mode,
            "file_is_tiny": case.file_is_tiny,
        },
        "analysis": {
            "predicted_anon_pages": predicted_anon,
            "predicted_file_pages": predicted_file,
            "predicted_anon_range": to_range_label(predicted_anon),
            "predicted_file_range": to_range_label(predicted_file),
            "actual_anon_pages": case.target_reclaimed_anon_pages,
            "actual_file_pages": case.target_reclaimed_file_pages,
            "anon_abs_error": abs(predicted_anon - case.target_reclaimed_anon_pages),
            "file_abs_error": abs(predicted_file - case.target_reclaimed_file_pages),
        },
        "details": {
            "config": asdict(config),
            "derived": {
                "total_target_anon": total_target_anon(case),
                "total_target_file": total_target_file(case),
                "effective_targets": targets,
                "anon_budget": anon_budget,
                "file_budget": file_budget,
                "total_remaining_anon": total_remaining_anon(case),
                "total_remaining_file": total_remaining_file(case),
                "target_source": targets["source"],
                "observed_planned_targets": targets["observed_planned"],
                "active_anon_allowed": active_path_allowed(case, "anon"),
                "active_file_allowed": active_path_allowed(case, "file"),
                "memcg_low_reclaim": case.memcg_low_reclaim,
            },
            "trace": [asdict(step) for step in trace],
        },
    }


def render_text(result: Dict[str, Any]) -> str:
    analysis = result["analysis"]
    lines = [
        "Traditional LRU Whitebox Executor Result",
        f"session_id: {result['input_summary']['session_id']}",
        f"trigger_comm: {result['input_summary']['trigger_comm']}",
        f"reclaim_context: {result['input_summary']['reclaim_context']}",
        f"swappiness: {result['input_summary']['swappiness']}",
        f"nr_to_reclaim: {result['input_summary']['nr_to_reclaim']}",
        f"predicted reclaimed anon pages: {analysis['predicted_anon_pages']} ({analysis['predicted_anon_range']})",
        f"predicted reclaimed file pages: {analysis['predicted_file_pages']} ({analysis['predicted_file_range']})",
        f"actual reclaimed anon pages: {analysis['actual_anon_pages']}",
        f"actual reclaimed file pages: {analysis['actual_file_pages']}",
        f"anon abs error: {analysis['anon_abs_error']}",
        f"file abs error: {analysis['file_abs_error']}",
        "",
        "Trace:",
    ]
    for step in result["details"]["trace"]:
        lines.append(f"- {step['fn']} -> {step['branch']}: {step['reason']}")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    case = load_case_from_args(args)
    result = exec_shrink_lruvec(case, ExecutorConfig())
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
