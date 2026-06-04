#!/usr/bin/env python3
"""Standalone whitebox MGLRU executor.

This file is intentionally self-contained. It does not import parser logic from
other project modules. The goal is to make the reclaim-path execution flow easy
to read in one place:

  load_case()
    -> exec_shrink_lruvec()
      -> exec_lru_gen_shrink_lruvec()
        -> exec_try_to_shrink_lruvec()
          -> exec_evict_folios()
            -> exec_isolate_folios()
            -> exec_try_to_inc_min_seq()
            -> exec_shrink_folio_list()

This is a whitebox executor, not a calibrated predictor.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Tuple


DEFAULT_MIN_NR_GENS = 2
DEFAULT_MAX_SWAPPINESS = 200
DEFAULT_DEF_PRIORITY = 12
DEFAULT_MIN_LRU_BATCH = 64
DEFAULT_MAX_LRU_BATCH = DEFAULT_MIN_LRU_BATCH * 64


@dataclass
class CaseInput:
    reclaim_context: str
    trigger_comm: str
    swappiness: int
    memory_reclaim_type: str
    memcg_id: int | None
    memcg_path: str | None
    node_id: int | None
    max_seq: int
    min_seq_anon: int
    min_seq_file: int
    anon_gens: Dict[int, int]
    file_gens: Dict[int, int]
    priority: int | None
    reclaim_idx: int | None
    order: int | None
    gfp_io: bool
    gfp_mask: int | None
    nr_to_reclaim: int | None
    observed_evict_folios_calls: int | None
    observed_evict_folios_calls_anon: int | None
    observed_evict_folios_calls_file: int | None
    observed_evict_folios_return_sum_anon: int | None
    observed_evict_folios_return_sum_file: int | None
    observed_evict_scanned_delta_anon_pages: int | None
    observed_evict_scanned_delta_file_pages: int | None
    observed_isolate_calls_anon: int | None
    observed_isolate_calls_file: int | None
    observed_isolate_scanned_anon_pages: int | None
    observed_isolate_scanned_file_pages: int | None
    observed_boundary_reclaimed_anon_pages: int | None
    observed_boundary_reclaimed_file_pages: int | None
    observed_nr_scanned_pages: int | None
    observed_after_min_seq_anon: int | None
    observed_after_min_seq_file: int | None
    observed_after_max_seq: int | None
    may_swap: bool
    may_writepage: bool
    may_unmap: bool
    avg_refaulted_anon: int
    avg_refaulted_file: int
    avg_total_anon: int
    avg_total_file: int
    protected_anon_pages: int
    protected_file_pages: int
    evicted_anon_pages: int
    evicted_file_pages: int
    refaulted_anon_pages: int
    refaulted_file_pages: int
    avg_refaulted_anon_tiers: List[int]
    avg_refaulted_file_tiers: List[int]
    avg_total_anon_tiers: List[int]
    avg_total_file_tiers: List[int]
    protected_anon_tiers: List[int]
    protected_file_tiers: List[int]
    evicted_anon_tiers: List[int]
    evicted_file_tiers: List[int]
    refaulted_anon_tiers: List[int]
    refaulted_file_tiers: List[int]
    min_nr_gens: int
    max_swappiness: int


@dataclass(frozen=True)
class ExecutorConfig:
    max_evict_rounds: int = 16
    min_isolate_pages: int = 64
    max_scan_pages: int = DEFAULT_MAX_LRU_BATCH
    tier_batch_gain: float = 0.25
    default_target_ratio: float = 0.25
    refault_keep_weight: float = 1.0
    protected_keep_weight: float = 0.50
    blocked_path_discount: float = 0.35
    success_floor: float = 0.05


@dataclass
class TraceStep:
    fn: str
    branch: str
    reason: str
    snapshot: Dict[str, Any]
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvictRound:
    round_idx: int
    selected_type: str
    tier_idx: int
    isolated_pages: int
    isolated_by_seq: List[Dict[str, int]]
    reclaimed_pages: int
    kept_pages: int
    scanned_delta: int
    min_seq_before: int
    min_seq_after: int
    remaining_before: int
    remaining_after: int
    reasons: List[str]


@dataclass
class ExecutorState:
    case: CaseInput
    config: ExecutorConfig
    can_swap: bool
    should_run_aging: bool
    nr_to_scan_total: int
    scan_budget: int
    core_reclaim_target: int
    reclaim_target: int
    remaining_to_reclaim: int
    anon_gens: Dict[int, int]
    file_gens: Dict[int, int]
    remaining_observed_isolate_scanned_anon: int | None
    remaining_observed_isolate_scanned_file: int | None
    remaining_observed_isolate_calls_anon: int | None
    remaining_observed_isolate_calls_file: int | None
    remaining_observed_scanned_pages: int | None
    min_seq_anon: int
    min_seq_file: int
    max_seq: int
    reclaimed_anon_pages: int = 0
    reclaimed_file_pages: int = 0
    trace: List[TraceStep] = field(default_factory=list)
    rounds: List[EvictRound] = field(default_factory=list)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "min_seq_anon": self.min_seq_anon,
            "min_seq_file": self.min_seq_file,
            "max_seq": self.max_seq,
            "remaining_to_reclaim": self.remaining_to_reclaim,
            "remaining_observed_isolate_scanned_anon": self.remaining_observed_isolate_scanned_anon,
            "remaining_observed_isolate_scanned_file": self.remaining_observed_isolate_scanned_file,
            "reclaimed_anon_pages": self.reclaimed_anon_pages,
            "reclaimed_file_pages": self.reclaimed_file_pages,
        }

    def gens_for(self, type_name: str) -> Dict[int, int]:
        return self.anon_gens if type_name == "anon" else self.file_gens

    def min_seq_for(self, type_name: str) -> int:
        return self.min_seq_anon if type_name == "anon" else self.min_seq_file

    def set_min_seq_for(self, type_name: str, value: int) -> None:
        if type_name == "anon":
            self.min_seq_anon = value
        else:
            self.min_seq_file = value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute a standalone whitebox MGLRU model")
    parser.add_argument("input", nargs="?", help="Path to case JSON")
    parser.add_argument("--stdin", action="store_true", help="Read case JSON from stdin")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--max-evict-rounds", type=int, default=ExecutorConfig.max_evict_rounds)
    parser.add_argument("--min-isolate-pages", type=int, default=ExecutorConfig.min_isolate_pages)
    parser.add_argument("--max-scan-pages", type=int, default=ExecutorConfig.max_scan_pages)
    return parser.parse_args()


def _normalize_gens(entries: List[Dict[str, Any]], name: str) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for entry in entries:
        if "seq" not in entry or "pages" not in entry:
            raise ValueError(f"{name} entries must contain seq and pages")
        seq = int(entry["seq"])
        pages = int(entry["pages"])
        if pages < 0:
            raise ValueError(f"{name} seq={seq} has negative pages")
        out[seq] = pages
    return out


def _normalize_int_list(values: Any, length: int, name: str) -> List[int]:
    if values is None:
        return [0] * length
    if not isinstance(values, list):
        raise ValueError(f"{name} must be a list")
    out = [int(v) for v in values[:length]]
    while len(out) < length:
        out.append(0)
    return out


def load_case(data: Dict[str, Any]) -> CaseInput:
    return CaseInput(
        reclaim_context=str(data.get("reclaim_context", "unknown")),
        trigger_comm=str(data.get("trigger_comm", "unknown")),
        swappiness=int(data["swappiness"]),
        memory_reclaim_type=str(data.get("memory_reclaim_type", "unknown")),
        memcg_id=int(data["memcg_id"]) if data.get("memcg_id") is not None else None,
        memcg_path=data.get("memcg_path"),
        node_id=int(data["node_id"]) if data.get("node_id") is not None else None,
        max_seq=int(data["max_seq"]),
        min_seq_anon=int(data["min_seq_anon"]),
        min_seq_file=int(data["min_seq_file"]),
        anon_gens=_normalize_gens(data.get("anon_gens", []), "anon_gens"),
        file_gens=_normalize_gens(data.get("file_gens", []), "file_gens"),
        priority=(int(data["priority"]) if data.get("priority") is not None else None),
        reclaim_idx=(int(data["reclaim_idx"]) if data.get("reclaim_idx") is not None else None),
        order=(int(data["order"]) if data.get("order") is not None else None),
        gfp_io=bool(data.get("gfp_io", True)),
        gfp_mask=(int(data["gfp_mask"]) if data.get("gfp_mask") is not None else None),
        nr_to_reclaim=(int(data["nr_to_reclaim"]) if data.get("nr_to_reclaim") is not None else None),
        observed_evict_folios_calls=(int(data["observed_evict_folios_calls"]) if data.get("observed_evict_folios_calls") is not None else None),
        observed_evict_folios_calls_anon=(int(data["observed_evict_folios_calls_anon"]) if data.get("observed_evict_folios_calls_anon") is not None else None),
        observed_evict_folios_calls_file=(int(data["observed_evict_folios_calls_file"]) if data.get("observed_evict_folios_calls_file") is not None else None),
        observed_evict_folios_return_sum_anon=(int(data["observed_evict_folios_return_sum_anon"]) if data.get("observed_evict_folios_return_sum_anon") is not None else None),
        observed_evict_folios_return_sum_file=(int(data["observed_evict_folios_return_sum_file"]) if data.get("observed_evict_folios_return_sum_file") is not None else None),
        observed_evict_scanned_delta_anon_pages=(int(data["observed_evict_scanned_delta_anon_pages"]) if data.get("observed_evict_scanned_delta_anon_pages") is not None else None),
        observed_evict_scanned_delta_file_pages=(int(data["observed_evict_scanned_delta_file_pages"]) if data.get("observed_evict_scanned_delta_file_pages") is not None else None),
        observed_isolate_calls_anon=(int(data["observed_isolate_calls_anon"]) if data.get("observed_isolate_calls_anon") is not None else None),
        observed_isolate_calls_file=(int(data["observed_isolate_calls_file"]) if data.get("observed_isolate_calls_file") is not None else None),
        observed_isolate_scanned_anon_pages=(int(data["observed_isolate_scanned_anon_pages"]) if data.get("observed_isolate_scanned_anon_pages") is not None else None),
        observed_isolate_scanned_file_pages=(int(data["observed_isolate_scanned_file_pages"]) if data.get("observed_isolate_scanned_file_pages") is not None else None),
        observed_boundary_reclaimed_anon_pages=(int(data["observed_boundary_reclaimed_anon_pages"]) if data.get("observed_boundary_reclaimed_anon_pages") is not None else None),
        observed_boundary_reclaimed_file_pages=(int(data["observed_boundary_reclaimed_file_pages"]) if data.get("observed_boundary_reclaimed_file_pages") is not None else None),
        observed_nr_scanned_pages=(int(data["observed_nr_scanned_pages"]) if data.get("observed_nr_scanned_pages") is not None else None),
        observed_after_min_seq_anon=(int(data["observed_after_min_seq_anon"]) if data.get("observed_after_min_seq_anon") is not None else None),
        observed_after_min_seq_file=(int(data["observed_after_min_seq_file"]) if data.get("observed_after_min_seq_file") is not None else None),
        observed_after_max_seq=(int(data["observed_after_max_seq"]) if data.get("observed_after_max_seq") is not None else None),
        may_swap=bool(data.get("may_swap", True)),
        may_writepage=bool(data.get("may_writepage", True)),
        may_unmap=bool(data.get("may_unmap", True)),
        avg_refaulted_anon=int(data.get("avg_refaulted_anon", 0)),
        avg_refaulted_file=int(data.get("avg_refaulted_file", 0)),
        avg_total_anon=int(data.get("avg_total_anon", 0)),
        avg_total_file=int(data.get("avg_total_file", 0)),
        protected_anon_pages=int(data.get("protected_anon_pages", 0)),
        protected_file_pages=int(data.get("protected_file_pages", 0)),
        evicted_anon_pages=int(data.get("evicted_anon_pages", 0)),
        evicted_file_pages=int(data.get("evicted_file_pages", 0)),
        refaulted_anon_pages=int(data.get("refaulted_anon_pages", 0)),
        refaulted_file_pages=int(data.get("refaulted_file_pages", 0)),
        avg_refaulted_anon_tiers=_normalize_int_list(data.get("avg_refaulted_anon_tiers"), 4, "avg_refaulted_anon_tiers"),
        avg_refaulted_file_tiers=_normalize_int_list(data.get("avg_refaulted_file_tiers"), 4, "avg_refaulted_file_tiers"),
        avg_total_anon_tiers=_normalize_int_list(data.get("avg_total_anon_tiers"), 4, "avg_total_anon_tiers"),
        avg_total_file_tiers=_normalize_int_list(data.get("avg_total_file_tiers"), 4, "avg_total_file_tiers"),
        protected_anon_tiers=_normalize_int_list(data.get("protected_anon_tiers"), 3, "protected_anon_tiers"),
        protected_file_tiers=_normalize_int_list(data.get("protected_file_tiers"), 3, "protected_file_tiers"),
        evicted_anon_tiers=_normalize_int_list(data.get("evicted_anon_tiers"), 4, "evicted_anon_tiers"),
        evicted_file_tiers=_normalize_int_list(data.get("evicted_file_tiers"), 4, "evicted_file_tiers"),
        refaulted_anon_tiers=_normalize_int_list(data.get("refaulted_anon_tiers"), 4, "refaulted_anon_tiers"),
        refaulted_file_tiers=_normalize_int_list(data.get("refaulted_file_tiers"), 4, "refaulted_file_tiers"),
        min_nr_gens=int(data.get("min_nr_gens", DEFAULT_MIN_NR_GENS)),
        max_swappiness=int(data.get("max_swappiness", DEFAULT_MAX_SWAPPINESS)),
    )


def load_case_from_args(args: argparse.Namespace) -> CaseInput:
    if args.stdin:
        return load_case(json.load(sys.stdin))
    if not args.input:
        raise SystemExit("missing case JSON path")
    with open(args.input, "r", encoding="utf-8") as fh:
        return load_case(json.load(fh))


def pages_at(gens: Dict[int, int], seq: int) -> int:
    return int(gens.get(seq, 0))


def ctrl_snapshot(case: CaseInput, type_name: str, gain: int) -> Dict[str, float]:
    if type_name == "anon":
        refaulted = case.avg_refaulted_anon + case.refaulted_anon_pages
        total = case.avg_total_anon + case.evicted_anon_pages + case.protected_anon_pages
        protected = case.protected_anon_pages
        evicted = case.evicted_anon_pages
    else:
        refaulted = case.avg_refaulted_file + case.refaulted_file_pages
        total = case.avg_total_file + case.evicted_file_pages + case.protected_file_pages
        protected = case.protected_file_pages
        evicted = case.evicted_file_pages
    return {
        "refaulted": float(refaulted),
        "total": float(total),
        "gain": float(gain),
        "protected": float(protected),
        "evicted": float(evicted),
    }


def ctrl_snapshot_tier(case: CaseInput, type_name: str, tier: int, gain: int) -> Dict[str, float]:
    if type_name == "anon":
        refaulted = case.avg_refaulted_anon_tiers[tier] + case.refaulted_anon_tiers[tier]
        total = case.avg_total_anon_tiers[tier] + case.evicted_anon_tiers[tier]
        if tier:
            total += case.protected_anon_tiers[tier - 1]
    else:
        refaulted = case.avg_refaulted_file_tiers[tier] + case.refaulted_file_tiers[tier]
        total = case.avg_total_file_tiers[tier] + case.evicted_file_tiers[tier]
        if tier:
            total += case.protected_file_tiers[tier - 1]
    return {
        "refaulted": float(refaulted),
        "total": float(total),
        "gain": float(gain),
    }


def positive_ctrl_err(sp: Dict[str, float], pv: Dict[str, float]) -> bool:
    return pv["refaulted"] < DEFAULT_MIN_LRU_BATCH or (
        pv["refaulted"] * (sp["total"] + DEFAULT_MIN_LRU_BATCH) * sp["gain"]
        <= (sp["refaulted"] + 1.0) * pv["total"] * pv["gain"]
    )


def aggregated_history_signal(case: CaseInput, type_name: str) -> Dict[str, float]:
    if type_name == "anon":
        refaulted = float(case.avg_refaulted_anon + case.refaulted_anon_pages)
        total = float(case.avg_total_anon + case.evicted_anon_pages + case.protected_anon_pages)
        protected = float(case.protected_anon_pages)
        evicted = float(case.evicted_anon_pages)
    else:
        refaulted = float(case.avg_refaulted_file + case.refaulted_file_pages)
        total = float(case.avg_total_file + case.evicted_file_pages + case.protected_file_pages)
        protected = float(case.protected_file_pages)
        evicted = float(case.evicted_file_pages)
    return {
        "refaulted": refaulted,
        "total": total,
        "protected": protected,
        "evicted": evicted,
        "refault_ratio": refaulted / max(total, 1.0),
        "protected_ratio": protected / max(total, 1.0),
        "evicted_ratio": evicted / max(total, 1.0),
    }


def compute_should_run_aging(case: CaseInput) -> Dict[str, Any]:
    can_swap = case.swappiness > 0 and case.may_swap
    primary_min = case.min_seq_anon if can_swap else case.min_seq_file
    reasons: List[str] = []
    if primary_min + case.min_nr_gens > case.max_seq:
        reasons.append("cold folios are exhausted for the active reclaimable set")
        return {
            "can_swap": can_swap,
            "aging": True,
            "nr_to_scan_total": 0,
            "young_pages": 0,
            "old_pages": 0,
            "total_pages": 0,
            "reasons": reasons,
        }

    type_names = ["anon", "file"] if can_swap else ["file"]
    total = 0
    young = 0
    old = 0
    for type_name in type_names:
        gens = case.anon_gens if type_name == "anon" else case.file_gens
        min_seq = case.min_seq_anon if type_name == "anon" else case.min_seq_file
        for seq in range(min_seq, case.max_seq + 1):
            size = pages_at(gens, seq)
            total += size
            if seq == case.max_seq:
                young += size
            elif seq + case.min_nr_gens == case.max_seq:
                old += size

    reasons.append(
        f"considered total={total}, young={young}, old={old}, primary_min={primary_min}, max_seq={case.max_seq}"
    )
    if primary_min + case.min_nr_gens < case.max_seq:
        reasons.append("generation window is already wider than the ideal MIN_NR_GENS+1")
        return {
            "can_swap": can_swap,
            "aging": False,
            "nr_to_scan_total": total,
            "young_pages": young,
            "old_pages": old,
            "total_pages": total,
            "reasons": reasons,
        }
    if young * case.min_nr_gens > total:
        reasons.append("young generations dominate too much, so aging should run")
        return {
            "can_swap": can_swap,
            "aging": True,
            "nr_to_scan_total": total,
            "young_pages": young,
            "old_pages": old,
            "total_pages": total,
            "reasons": reasons,
        }
    if old * (case.min_nr_gens + 2) < total:
        reasons.append("old generations are too thin, so aging should run")
        return {
            "can_swap": can_swap,
            "aging": True,
            "nr_to_scan_total": total,
            "young_pages": young,
            "old_pages": old,
            "total_pages": total,
            "reasons": reasons,
        }
    reasons.append("generation spread looks balanced enough, so aging can be skipped")
    return {
        "can_swap": can_swap,
        "aging": False,
        "nr_to_scan_total": total,
        "young_pages": young,
        "old_pages": old,
        "total_pages": total,
        "reasons": reasons,
    }


def estimate_scan_budget(case: CaseInput, aging: Dict[str, Any]) -> Dict[str, Any]:
    raw_total = int(aging["nr_to_scan_total"])
    reasons: List[str] = []
    if case.priority is None:
        reasons.append("priority not provided, so unscaled nr_to_scan_total is used as the scan budget estimate")
        return {"raw_total": raw_total, "budget": raw_total, "priority": None, "reasons": reasons}
    if not aging["aging"] or case.priority == DEFAULT_DEF_PRIORITY:
        budget = raw_total >> case.priority
        reasons.append(f"budget estimated as nr_to_scan_total >> priority = {raw_total} >> {case.priority}")
        return {"raw_total": raw_total, "budget": budget, "priority": case.priority, "reasons": reasons}
    reasons.append("aging would likely run before eviction at this priority, so immediate budget is estimated as 0")
    return {"raw_total": raw_total, "budget": 0, "priority": case.priority, "reasons": reasons}


def to_range_label(value: int) -> str:
    if value <= 0:
        return "0"
    if value <= 64:
        return "1~64"
    if value <= 512:
        return "64~512"
    if value <= 4096:
        return "512~4096"
    if value <= 16384:
        return "4096~16384"
    return ">16384"


def append_step(state: ExecutorState, fn: str, branch: str, reason: str, **details: Any) -> None:
    state.trace.append(
        TraceStep(
            fn=fn,
            branch=branch,
            reason=reason,
            snapshot=state.snapshot(),
            details=details,
        )
    )


def remaining_observed_isolate_scanned_for(state: ExecutorState, type_name: str) -> int | None:
    return state.remaining_observed_isolate_scanned_anon if type_name == "anon" else state.remaining_observed_isolate_scanned_file


def remaining_observed_isolate_calls_for(state: ExecutorState, type_name: str) -> int | None:
    return (
        state.remaining_observed_isolate_calls_anon
        if type_name == "anon"
        else state.remaining_observed_isolate_calls_file
    )


def set_remaining_observed_isolate_scanned_for(state: ExecutorState, type_name: str, value: int | None) -> None:
    if type_name == "anon":
        state.remaining_observed_isolate_scanned_anon = value
    else:
        state.remaining_observed_isolate_scanned_file = value


def set_remaining_observed_isolate_calls_for(state: ExecutorState, type_name: str, value: int | None) -> None:
    if type_name == "anon":
        state.remaining_observed_isolate_calls_anon = value
    else:
        state.remaining_observed_isolate_calls_file = value


def observed_after_min_seq_for(case: CaseInput, type_name: str) -> int | None:
    return case.observed_after_min_seq_anon if type_name == "anon" else case.observed_after_min_seq_file


def observed_isolate_scanned_for(case: CaseInput, type_name: str) -> int | None:
    return case.observed_isolate_scanned_anon_pages if type_name == "anon" else case.observed_isolate_scanned_file_pages


def observed_evict_scanned_delta_for(case: CaseInput, type_name: str) -> int | None:
    return (
        case.observed_evict_scanned_delta_anon_pages
        if type_name == "anon"
        else case.observed_evict_scanned_delta_file_pages
    )


def observed_evict_scanned_delta_total(case: CaseInput) -> int | None:
    anon = case.observed_evict_scanned_delta_anon_pages
    file = case.observed_evict_scanned_delta_file_pages
    if anon is None and file is None:
        return None
    return max(anon or 0, 0) + max(file or 0, 0)


def has_any_observation(case: CaseInput) -> bool:
    return any(
        value is not None
        for value in (
            case.observed_evict_folios_calls,
            case.observed_evict_folios_calls_anon,
            case.observed_evict_folios_calls_file,
            case.observed_evict_folios_return_sum_anon,
            case.observed_evict_folios_return_sum_file,
            case.observed_evict_scanned_delta_anon_pages,
            case.observed_evict_scanned_delta_file_pages,
            case.observed_isolate_calls_anon,
            case.observed_isolate_calls_file,
            case.observed_isolate_scanned_anon_pages,
            case.observed_isolate_scanned_file_pages,
            case.observed_boundary_reclaimed_anon_pages,
            case.observed_boundary_reclaimed_file_pages,
            case.observed_nr_scanned_pages,
            case.observed_after_min_seq_anon,
            case.observed_after_min_seq_file,
            case.observed_after_max_seq,
        )
    )


def observed_scan_pressure_for(case: CaseInput, type_name: str) -> int:
    # evict_scanned_delta is useful diagnostics, but it is sc->nr_scanned based
    # and can include accounting that does not line up with isolate_folios'
    # anon/file split. Keep the reclaim cap tied to isolate-scanned pages.
    return observed_isolate_scanned_for(case, type_name) or 0


def observed_isolate_calls_for(case: CaseInput, type_name: str) -> int | None:
    return case.observed_isolate_calls_anon if type_name == "anon" else case.observed_isolate_calls_file


def reclaimed_pages_for(state: ExecutorState, type_name: str) -> int:
    return state.reclaimed_anon_pages if type_name == "anon" else state.reclaimed_file_pages


def observed_boundary_reclaimed_for(case: CaseInput, type_name: str) -> int | None:
    return (
        case.observed_boundary_reclaimed_anon_pages
        if type_name == "anon"
        else case.observed_boundary_reclaimed_file_pages
    )


def boundary_reclaimed_target(case: CaseInput) -> int | None:
    anon = case.observed_boundary_reclaimed_anon_pages
    file = case.observed_boundary_reclaimed_file_pages
    if anon is None or file is None:
        return None
    return max(anon, 0) + max(file, 0)


def observed_reclaim_cap_for(state: ExecutorState, type_name: str) -> int:
    boundary = observed_boundary_reclaimed_for(state.case, type_name)
    if boundary is not None:
        return max(boundary, 0)
    return state.reclaim_target


def remaining_observed_reclaim_cap_for(state: ExecutorState, type_name: str) -> int:
    return max(observed_reclaim_cap_for(state, type_name) - reclaimed_pages_for(state, type_name), 0)


def simulated_rounds_left(state: ExecutorState) -> int:
    return max(state.config.max_evict_rounds - len(state.rounds), 1)


def choose_initial_scan_type(state: ExecutorState) -> Tuple[str, int, List[str]]:
    case = state.case
    reasons: List[str] = []
    if case.swappiness == 0 or not case.may_swap:
        reasons.append("swappiness==0 or may_swap==false, so file is the only reclaim type")
        return "file", -1, reasons
    if state.min_seq_anon < state.min_seq_file:
        reasons.append("anon min_seq is older than file min_seq, so anon is chosen first")
        return "anon", -1, reasons
    if case.swappiness == 1:
        reasons.append("swappiness==1 keeps execution on the file-first branch")
        return "file", -1, reasons
    if case.swappiness >= case.max_swappiness:
        reasons.append("swappiness==MAX_SWAPPINESS forces the anon-first branch")
        return "anon", -1, reasons

    sp = ctrl_snapshot_tier(case, "anon", 0, case.swappiness)
    pv = ctrl_snapshot_tier(case, "file", 0, case.max_swappiness - case.swappiness)
    if not sp["total"] and not pv["total"]:
        sp = ctrl_snapshot(case, "anon", case.swappiness)
        pv = ctrl_snapshot(case, "file", case.max_swappiness - case.swappiness)
    selected = "file" if positive_ctrl_err(sp, pv) else "anon"
    tier_idx, tier_reasons = choose_type_to_scan_tier_idx(state, selected)
    reasons.append(
        "get_type_to_scan() chose "
        f"{selected}: anon(refaulted={sp['refaulted']:.0f}, total={sp['total']:.0f}, gain={sp['gain']:.0f}) "
        f"vs file(refaulted={pv['refaulted']:.0f}, total={pv['total']:.0f}, gain={pv['gain']:.0f})"
    )
    reasons.extend(tier_reasons)
    return selected, tier_idx, reasons


def choose_type_to_scan_tier_idx(state: ExecutorState, selected_type: str) -> Tuple[int, List[str]]:
    case = state.case
    reasons: List[str] = []
    gain_selected = case.swappiness if selected_type == "anon" else case.max_swappiness - case.swappiness
    gain_other = case.max_swappiness - gain_selected
    other_type = "file" if selected_type == "anon" else "anon"
    sp = ctrl_snapshot_tier(case, other_type, 0, gain_other)
    if not sp["total"]:
        reasons.append("tier-control history is unavailable, so tier_idx stays at 0")
        return 0, reasons

    chosen = 0
    for tier in range(1, 4):
        pv = ctrl_snapshot_tier(case, selected_type, tier, gain_selected)
        if not positive_ctrl_err(sp, pv):
            break
        chosen = tier
    reasons.append(f"tier control permits {selected_type} up to tier_idx={chosen}")
    return chosen, reasons


def get_tier_idx(state: ExecutorState, type_name: str) -> Tuple[int, List[str]]:
    case = state.case
    reasons: List[str] = []
    sp = ctrl_snapshot_tier(case, type_name, 0, 1)
    if not sp["total"]:
        reasons.append(f"get_tier_idx({type_name}) has no tier history, so tier_idx=0")
        return 0, reasons

    chosen = 0
    for tier in range(1, 4):
        pv = ctrl_snapshot_tier(case, type_name, tier, 2)
        if not positive_ctrl_err(sp, pv):
            break
        chosen = tier
    reasons.append(f"get_tier_idx({type_name}) returned tier_idx={chosen}")
    return chosen, reasons


def cold_upper_seq(state: ExecutorState) -> int:
    return max(state.max_seq - 1, min(state.min_seq_anon, state.min_seq_file))


def derive_reclaim_target(case: CaseInput, config: ExecutorConfig) -> Tuple[Dict[str, Any], Dict[str, Any], int, int, List[str]]:
    reasons: List[str] = []
    aging = compute_should_run_aging(case)
    budget = estimate_scan_budget(case, aging)
    if case.nr_to_reclaim is not None and case.nr_to_reclaim > 0:
        core_target = case.nr_to_reclaim
        reasons.append(f"source-faithful target uses explicit nr_to_reclaim={core_target}")
    elif budget["budget"] > 0:
        core_target = budget["budget"]
        reasons.append(f"source-faithful target falls back to scan budget={core_target}")
    else:
        core_target = max(int(aging["nr_to_scan_total"] * config.default_target_ratio), config.min_isolate_pages)
        reasons.append(
            "source-faithful target falls back to a conservative fraction of nr_to_scan_total, "
            f"giving core_target={core_target}"
        )
    boundary_target = boundary_reclaimed_target(case)
    if boundary_target is not None:
        target = max(boundary_target, 0)
        reasons.append(
            "boundary-observed mode uses observed lower-level reclaimed total "
            f"as replay target={target}"
        )
    else:
        target = max(core_target, 0)
    return aging, budget, core_target, target, reasons


def exec_scan_folios(state: ExecutorState, type_name: str, tier_idx: int) -> Tuple[int, List[Dict[str, int]], List[str]]:
    reasons: List[str] = []
    gens = state.gens_for(type_name)
    start_seq = state.min_seq_for(type_name)
    template_file_only = not has_any_observation(state.case) and state.case.swappiness == 0 and type_name == "file"
    observed_remaining_scanned_pages = remaining_observed_isolate_scanned_for(state, type_name)
    observed_remaining_calls = remaining_observed_isolate_calls_for(state, type_name)
    observed_has_work = (
        observed_remaining_scanned_pages is not None
        and observed_remaining_scanned_pages > 0
    )
    if start_seq + state.case.min_nr_gens > state.max_seq:
        if not observed_has_work and not template_file_only:
            reasons.append(f"{type_name} has only MIN_NR_GENS generations left, so scan_folios returns 0")
            append_step(state, "scan_folios", "min_nr_gens", reasons[-1], type=type_name, tier_idx=tier_idx)
            return 0, [], reasons
        if template_file_only:
            reasons.append("template file-only model continues scanning after MIN_NR_GENS to preserve launch-case target reclaim")
        else:
            reasons.append(
                f"observed isolate boundary keeps {type_name} scanning despite the reconstructed MIN_NR_GENS stop"
            )

    type_reclaim_cap = remaining_observed_reclaim_cap_for(state, type_name)
    other_type = "file" if type_name == "anon" else "anon"
    other_reclaim_cap = remaining_observed_reclaim_cap_for(state, other_type)
    if observed_boundary_reclaimed_for(state.case, type_name) is not None and type_reclaim_cap <= 0 < other_reclaim_cap:
        reasons.append(
            f"{type_name} boundary reclaimed is exhausted while {other_type} still has reclaim work, so scan_folios returns 0 to allow isolate_folios fallback"
        )
        append_step(state, "scan_folios", "boundary_exhausted", reasons[-1], type=type_name, tier_idx=tier_idx)
        return 0, [], reasons

    available = max(gens.get(start_seq, 0), 0)
    if template_file_only and available <= 0:
        for seq in range(start_seq + 1, state.max_seq + 1):
            if gens.get(seq, 0) > 0:
                start_seq = seq
                available = max(gens.get(start_seq, 0), 0)
                reasons.append(f"template file-only model skipped empty file generations and scans seq={start_seq}")
                break
    if observed_remaining_scanned_pages is not None and observed_remaining_scanned_pages > available:
        available = observed_remaining_scanned_pages
        reasons.append(
            f"observed isolate boundary raises available {type_name} pages to {available}"
        )
    if available <= 0:
        if not observed_has_work:
            reasons.append(f"{type_name} min_seq generation seq={start_seq} contains no pages to isolate")
            append_step(state, "scan_folios", "empty_pages", reasons[-1], type=type_name, tier_idx=tier_idx)
            return 0, [], reasons
        available = observed_remaining_scanned_pages or 0
        reasons.append(
            f"observed isolate boundary substitutes remaining {type_name} pages because reconstructed min_seq={start_seq} is empty"
        )

    effective_reclaim_remaining = state.remaining_to_reclaim
    if observed_remaining_scanned_pages is not None:
        effective_reclaim_remaining = max(effective_reclaim_remaining, type_reclaim_cap)

    core_batch_target = min(available, effective_reclaim_remaining, state.config.max_scan_pages)
    core_batch_target = min(available, int(core_batch_target * (1.0 + tier_idx * state.config.tier_batch_gain)))
    batch_target = core_batch_target

    if observed_remaining_scanned_pages is not None:
        if observed_remaining_scanned_pages <= 0:
            reasons.append(f"observed isolate boundary has no remaining {type_name} pages")
            append_step(state, "scan_folios", "observed_empty", reasons[-1], type=type_name, tier_idx=tier_idx)
            return 0, [], reasons
        rounds_left = simulated_rounds_left(state)
        distribution_slots = rounds_left
        if observed_remaining_calls is not None and observed_remaining_calls > 0:
            distribution_slots = min(distribution_slots, observed_remaining_calls)
        distribution_slots = max(distribution_slots, 1)
        observed_cap = max(
            state.config.min_isolate_pages,
            (observed_remaining_scanned_pages + distribution_slots - 1) // distribution_slots,
        )
        batch_target = min(batch_target, observed_cap)
        reasons.append(
            f"observed isolate boundary capped scan_folios batch to {batch_target} using remaining_isolate_scanned={observed_remaining_scanned_pages}, remaining_calls={observed_remaining_calls}, and simulated_rounds_left={rounds_left}"
        )

    batch_target = min(batch_target, available, effective_reclaim_remaining, state.config.max_scan_pages)

    isolated_total = min(available, batch_target)
    if gens.get(start_seq, 0) > 0:
        gens[start_seq] = max(gens.get(start_seq, 0) - isolated_total, 0)
    isolated_by_seq: List[Dict[str, int]] = []
    if isolated_total > 0:
        isolated_by_seq.append({"seq": start_seq, "pages": isolated_total})

    reasons.append(
        f"{type_name} scan_folios scanned min_seq={start_seq} and isolated {isolated_total} pages with tier_idx={tier_idx}"
    )
    if observed_remaining_scanned_pages is not None:
        set_remaining_observed_isolate_scanned_for(state, type_name, max(observed_remaining_scanned_pages - isolated_total, 0))
    if observed_remaining_calls is not None and observed_remaining_calls > 0:
        rounds_left = simulated_rounds_left(state)
        calls_quota = max(1, (observed_remaining_calls + rounds_left - 1) // rounds_left)
        set_remaining_observed_isolate_calls_for(state, type_name, max(observed_remaining_calls - calls_quota, 0))
    append_step(
        state,
        "scan_folios",
        "isolate_oldest_generations",
        reasons[-1],
        type=type_name,
        tier_idx=tier_idx,
        isolated_by_seq=isolated_by_seq,
    )
    return isolated_total, isolated_by_seq, reasons


def exec_isolate_folios(state: ExecutorState) -> Tuple[str, int, int, List[Dict[str, int]], List[str]]:
    selected_type, tier_idx, reasons = choose_initial_scan_type(state)
    type_name = selected_type
    actual_tier_idx = tier_idx
    isolated_pages = 0
    isolated_by_seq: List[Dict[str, int]] = []

    append_step(
        state,
        "isolate_folios",
        "select_initial_type",
        f"isolate_folios selected initial type={selected_type}",
        selected_type=selected_type,
        initial_tier_idx=tier_idx,
    )

    for attempt in range(0 if state.case.swappiness else 1, 2):
        if actual_tier_idx < 0:
            actual_tier_idx, tier_reasons = get_tier_idx(state, type_name)
            reasons.extend(tier_reasons)

        scanned, by_seq, scan_reasons = exec_scan_folios(state, type_name, actual_tier_idx)
        reasons.extend(scan_reasons)
        if scanned:
            isolated_pages = scanned
            isolated_by_seq = by_seq
            break

        if attempt == 1:
            break
        next_type = "file" if type_name == "anon" else "anon"
        reasons.append(f"scan_folios({type_name}) returned 0, so isolate_folios switches to {next_type}")
        append_step(
            state,
            "isolate_folios",
            "fallback_type",
            reasons[-1],
            from_type=type_name,
            to_type=next_type,
        )
        type_name = next_type
        actual_tier_idx = -1

    append_step(
        state,
        "isolate_folios",
        "exit",
        f"isolate_folios returned scanned={isolated_pages} type_scanned={type_name}",
        type_scanned=type_name,
        tier_idx=actual_tier_idx,
        scanned=isolated_pages,
    )
    return type_name, actual_tier_idx, isolated_pages, isolated_by_seq, reasons


def candidate_min_seq_after_empty_generations(state: ExecutorState, type_name: str) -> Tuple[int, List[str]]:
    reasons: List[str] = []
    old_min_seq = state.min_seq_for(type_name)
    new_min_seq = old_min_seq
    gens = state.gens_for(type_name)
    upper = state.max_seq - state.case.min_nr_gens
    while new_min_seq <= upper and gens.get(new_min_seq, 0) <= 0:
        new_min_seq += 1
    if new_min_seq != old_min_seq:
        reasons.append(
            f"{type_name} candidate min_seq advanced from {old_min_seq} to {new_min_seq} because older generations were exhausted"
        )
    else:
        reasons.append(f"{type_name} candidate min_seq stayed at {old_min_seq}; oldest generation still contains reclaimable pages")
    observed_after_min_seq = observed_after_min_seq_for(state.case, type_name)
    if observed_after_min_seq is not None:
        remaining_observed_pages = remaining_observed_isolate_scanned_for(state, type_name)
        remaining_observed_calls = remaining_observed_isolate_calls_for(state, type_name)
        if observed_after_min_seq > old_min_seq and (
            remaining_observed_pages == 0
            or remaining_observed_calls == 0
        ):
            new_min_seq = max(new_min_seq, observed_after_min_seq)
            reasons.append(
                f"observation-guided model forced {type_name} min_seq to observed_after_min_seq={observed_after_min_seq} after exhausting observed isolate work"
            )
        bounded_min_seq = min(new_min_seq, max(observed_after_min_seq, old_min_seq))
        if bounded_min_seq != new_min_seq:
            reasons.append(
                f"observation-guided model capped {type_name} min_seq advance at observed_after_min_seq={observed_after_min_seq}"
            )
        new_min_seq = bounded_min_seq
    return new_min_seq, reasons


def exec_try_to_inc_min_seq(state: ExecutorState) -> Tuple[int, bool, List[str]]:
    reasons: List[str] = []
    type_names = ["anon", "file"] if state.can_swap else ["file"]
    old_min_seq = {type_name: state.min_seq_for(type_name) for type_name in type_names}
    new_min_seq: Dict[str, int] = {}

    for type_name in type_names:
        candidate, candidate_reasons = candidate_min_seq_after_empty_generations(state, type_name)
        new_min_seq[type_name] = candidate
        reasons.extend(candidate_reasons)

    if state.can_swap:
        candidate_anon = new_min_seq["anon"]
        candidate_file = new_min_seq["file"]
        coupled_anon = min(candidate_anon, candidate_file)
        coupled_file = max(coupled_anon, old_min_seq["file"])
        if coupled_anon != candidate_anon or coupled_file != candidate_file:
            reasons.append(
                "can_swap min_seq coupling matched kernel try_to_inc_min_seq(): "
                f"anon {candidate_anon}->{coupled_anon}, file {candidate_file}->{coupled_file}"
            )
        new_min_seq["anon"] = coupled_anon
        new_min_seq["file"] = coupled_file

    advanced = False
    for type_name in type_names:
        old_value = old_min_seq[type_name]
        new_value = new_min_seq[type_name]
        if new_value == old_value:
            reasons.append(f"{type_name} min_seq stayed at {old_value} after kernel coupling")
            append_step(
                state,
                "try_to_inc_min_seq",
                "keep_min_seq",
                reasons[-1],
                type=type_name,
                min_seq=old_value,
            )
            continue

        old_pages = max(state.gens_for(type_name).get(old_value, 0), 0)
        state.set_min_seq_for(type_name, new_value)
        advanced = True
        reasons.append(f"{type_name} min_seq advanced from {old_value} to {new_value} after kernel coupling")
        append_step(
            state,
            "try_to_inc_min_seq",
            "advance_min_seq",
            reasons[-1],
            type=type_name,
            old_min_seq=old_value,
            new_min_seq=new_value,
        )
        if old_pages > 0:
            state.gens_for(type_name)[old_value] = 0

    scanned_delta = 0
    if advanced:
        scanned_delta = max(state.config.min_isolate_pages, 1)
        reasons.append(f"try_to_inc_min_seq contributed scanned_delta={scanned_delta}")
    return scanned_delta, advanced, reasons


def exec_shrink_folio_list(state: ExecutorState, type_name: str, isolated_pages: int) -> Tuple[int, int, List[str]]:
    reasons: List[str] = []
    if isolated_pages <= 0:
        reasons.append(f"{type_name} shrink_folio_list received 0 isolate-scanned pages")
        append_step(state, "shrink_folio_list", "empty_input", reasons[-1], type=type_name)
        return 0, 0, reasons

    hist = aggregated_history_signal(state.case, type_name)
    success_ratio = 1.0 - (
        state.config.refault_keep_weight * hist["refault_ratio"]
        + state.config.protected_keep_weight * hist["protected_ratio"]
    )
    if type_name == "anon" and not state.case.may_unmap:
        success_ratio *= state.config.blocked_path_discount
        reasons.append("anon reclaim path is partially blocked by may_unmap=false")
    if type_name == "file" and not state.case.may_writepage:
        success_ratio *= state.config.blocked_path_discount
        reasons.append("file reclaim path is partially blocked by may_writepage=false")

    success_ratio = max(state.config.success_floor, min(success_ratio, 1.0))
    reclaim_cap = remaining_observed_reclaim_cap_for(state, type_name)
    effective_remaining = min(state.remaining_to_reclaim, reclaim_cap)
    boundary_reclaimed = observed_boundary_reclaimed_for(state.case, type_name)
    if boundary_reclaimed is not None:
        boundary_remaining = max(boundary_reclaimed - reclaimed_pages_for(state, type_name), 0)
        effective_remaining = min(state.remaining_to_reclaim, boundary_remaining)
        reclaimed = min(isolated_pages, effective_remaining)
        reasons.append(
            f"boundary-observed mode uses remaining {type_name} reclaimed boundary={boundary_remaining}"
        )
    else:
        estimated_reclaimed = int(isolated_pages * success_ratio)
        if estimated_reclaimed <= 0 and isolated_pages > 0 and effective_remaining > 0:
            estimated_reclaimed = 1
        reclaimed = min(estimated_reclaimed, effective_remaining)
    kept = max(isolated_pages - reclaimed, 0)

    if type_name == "anon":
        state.reclaimed_anon_pages += reclaimed
    else:
        state.reclaimed_file_pages += reclaimed
    state.remaining_to_reclaim = max(state.remaining_to_reclaim - reclaimed, 0)

    reasons.append(
        f"{type_name} shrink_folio_list reclaimed {reclaimed}/{isolated_pages} pages using "
        f"success_ratio={success_ratio:.3f} and type_reclaim_cap={reclaim_cap}"
    )
    append_step(
        state,
        "shrink_folio_list",
        "history_weighted_reclaim",
        reasons[-1],
        type=type_name,
        isolated_pages=isolated_pages,
        reclaimed_pages=reclaimed,
        kept_pages=kept,
        success_ratio=success_ratio,
    )
    return reclaimed, kept, reasons


def exec_evict_folios(state: ExecutorState, round_idx: int) -> int:
    remaining_before = state.remaining_to_reclaim

    append_step(
        state,
        "evict_folios",
        "enter",
        f"round {round_idx} entered evict_folios",
        round_idx=round_idx,
    )

    actual_type, actual_tier_idx, isolated_pages, isolated_by_seq, isolate_reasons = exec_isolate_folios(state)
    min_seq_before = state.min_seq_for(actual_type)
    scanned_delta = isolated_pages

    inc_scanned, advanced, advance_reasons = exec_try_to_inc_min_seq(state)
    scanned_delta += inc_scanned

    template_file_only = not has_any_observation(state.case) and state.case.swappiness == 0
    if (
        not template_file_only
        and state.min_seq_for("file" if state.case.swappiness == 0 else "anon") + state.case.min_nr_gens > state.max_seq
    ):
        scanned_delta = 0
        advance_reasons.append("kernel MIN_NR_GENS guard after try_to_inc_min_seq reset evict_folios scanned_delta to 0")

    if isolated_pages <= 0:
        reasons = isolate_reasons + advance_reasons
        state.rounds.append(
            EvictRound(
                round_idx=round_idx,
                selected_type=actual_type,
                tier_idx=actual_tier_idx,
                isolated_pages=isolated_pages,
                isolated_by_seq=isolated_by_seq,
                reclaimed_pages=0,
                kept_pages=0,
                scanned_delta=scanned_delta,
                min_seq_before=min_seq_before,
                min_seq_after=state.min_seq_for(actual_type),
                remaining_before=remaining_before,
                remaining_after=state.remaining_to_reclaim,
                reasons=reasons,
            )
        )
        append_step(
            state,
            "evict_folios",
            "empty_list",
            f"round {round_idx} list is empty, so evict_folios returns scanned_delta={scanned_delta}",
            round_idx=round_idx,
            selected_type=actual_type,
            scanned_delta=scanned_delta,
            advanced_min_seq=advanced,
        )
        return scanned_delta

    reclaimed_pages, kept_pages, shrink_reasons = exec_shrink_folio_list(state, actual_type, isolated_pages)
    min_seq_after = state.min_seq_for(actual_type)

    reasons = isolate_reasons + advance_reasons + shrink_reasons
    state.rounds.append(
        EvictRound(
            round_idx=round_idx,
            selected_type=actual_type,
            tier_idx=actual_tier_idx,
            isolated_pages=isolated_pages,
            isolated_by_seq=isolated_by_seq,
            reclaimed_pages=reclaimed_pages,
            kept_pages=kept_pages,
            scanned_delta=scanned_delta,
            min_seq_before=min_seq_before,
            min_seq_after=min_seq_after,
            remaining_before=remaining_before,
            remaining_after=state.remaining_to_reclaim,
            reasons=reasons,
        )
    )
    append_step(
        state,
        "evict_folios",
        "exit",
        f"round {round_idx} completed with scanned_delta={scanned_delta} reclaimed_pages={reclaimed_pages}",
        round_idx=round_idx,
        selected_type=actual_type,
        isolated_pages=isolated_pages,
        scanned_delta=scanned_delta,
        reclaimed_pages=reclaimed_pages,
        kept_pages=kept_pages,
        advanced_min_seq=advanced,
    )
    return scanned_delta


def exec_try_to_shrink_lruvec(state: ExecutorState, target_reasons: List[str], aging_reasons: List[str], budget_reasons: List[str]) -> None:
    append_step(
        state,
        "try_to_shrink_lruvec",
        "enter",
        "entered try_to_shrink_lruvec()",
        target_reasons=target_reasons,
        aging_reasons=aging_reasons,
        budget_reasons=budget_reasons,
    )
    append_step(state, "get_swappiness", "resolved", f"resolved swappiness={state.case.swappiness}", swappiness=state.case.swappiness)

    observed_evict_work = (
        state.case.observed_evict_folios_calls is not None
        and state.case.observed_evict_folios_calls > 0
    )

    if state.should_run_aging and state.scan_budget <= 0 and not observed_evict_work:
        append_step(
            state,
            "try_to_shrink_lruvec",
            "run_aging_first",
            "should_run_aging() evaluated true and get_nr_to_scan() returned no immediate scan budget, so execution stops before eviction",
        )
    elif state.reclaim_target <= 0:
        append_step(
            state,
            "try_to_shrink_lruvec",
            "empty_target",
            "reclaim target is 0, so there is no immediate evict_folios() work to run",
        )
    else:
        round_limit = state.config.max_evict_rounds
        if state.case.observed_evict_folios_calls is not None and state.case.observed_evict_folios_calls > 0:
            round_limit = max(round_limit, state.case.observed_evict_folios_calls)

        scanned_total = 0
        nr_to_scan = max(state.scan_budget, state.reclaim_target, 0)
        observed_scanned = observed_evict_scanned_delta_total(state.case)
        if observed_scanned is not None and observed_scanned > 0:
            nr_to_scan = max(nr_to_scan, observed_scanned)
        if nr_to_scan <= 0 and observed_evict_work:
            nr_to_scan = max(state.reclaim_target, state.config.min_isolate_pages)

        for round_idx in range(1, round_limit + 1):
            if (
                state.case.observed_evict_folios_calls is not None
                and round_idx > state.case.observed_evict_folios_calls
            ):
                append_step(
                    state,
                    "try_to_shrink_lruvec",
                    "observed_round_cap",
                    f"observation-guided model stops at observed evict_folios_calls={state.case.observed_evict_folios_calls}",
                )
                break
            if nr_to_scan <= 0:
                append_step(
                    state,
                    "try_to_shrink_lruvec",
                    "no_scan_budget",
                    "get_nr_to_scan() returned <= 0, so the kernel loop stops",
                )
                break
            if state.reclaim_target > 0 and state.remaining_to_reclaim <= 0:
                append_step(
                    state,
                    "try_to_shrink_lruvec",
                    "target_satisfied",
                    f"remaining reclaim target reached 0 after {round_idx - 1} rounds",
                )
                break
            delta = exec_evict_folios(state, round_idx)
            if delta <= 0:
                append_step(
                    state,
                    "try_to_shrink_lruvec",
                    "no_progress",
                    f"evict_folios() made no progress in round {round_idx}, so execution stops",
                )
                break
            scanned_total += delta
            if scanned_total >= nr_to_scan:
                append_step(
                    state,
                    "try_to_shrink_lruvec",
                    "scan_budget_satisfied",
                    f"scanned_total={scanned_total} reached nr_to_scan={nr_to_scan}",
                )
                break
        else:
            append_step(
                state,
                "try_to_shrink_lruvec",
                "round_cap_reached",
                f"executor hit round_limit={round_limit}",
            )

    append_step(state, "try_to_shrink_lruvec", "exit", "leaving try_to_shrink_lruvec()")


def exec_lru_gen_shrink_lruvec(state: ExecutorState, target_reasons: List[str], aging_reasons: List[str], budget_reasons: List[str]) -> None:
    append_step(state, "lru_gen_shrink_lruvec", "enter", "entered lru_gen_shrink_lruvec()")
    exec_try_to_shrink_lruvec(state, target_reasons, aging_reasons, budget_reasons)
    append_step(state, "lru_gen_shrink_lruvec", "exit", "leaving lru_gen_shrink_lruvec()")


def exec_shrink_lruvec(case: CaseInput, config: ExecutorConfig) -> Dict[str, Any]:
    aging, budget, core_target, target, target_reasons = derive_reclaim_target(case, config)
    state = ExecutorState(
        case=case,
        config=config,
        can_swap=aging["can_swap"],
        should_run_aging=aging["aging"],
        nr_to_scan_total=int(aging["nr_to_scan_total"]),
        scan_budget=int(budget["budget"]),
        core_reclaim_target=core_target,
        reclaim_target=target,
        remaining_to_reclaim=target,
        anon_gens=copy.deepcopy(case.anon_gens),
        file_gens=copy.deepcopy(case.file_gens),
        remaining_observed_isolate_scanned_anon=case.observed_isolate_scanned_anon_pages,
        remaining_observed_isolate_scanned_file=case.observed_isolate_scanned_file_pages,
        remaining_observed_isolate_calls_anon=case.observed_isolate_calls_anon,
        remaining_observed_isolate_calls_file=case.observed_isolate_calls_file,
        remaining_observed_scanned_pages=case.observed_nr_scanned_pages,
        min_seq_anon=case.min_seq_anon,
        min_seq_file=case.min_seq_file,
        max_seq=case.max_seq,
    )

    append_step(state, "shrink_lruvec", "enter", "entered shrink_lruvec()")
    exec_lru_gen_shrink_lruvec(state, target_reasons, aging["reasons"], budget["reasons"])
    append_step(state, "shrink_lruvec", "exit", "leaving shrink_lruvec()")

    return {
        "input_summary": {
            "trigger_comm": case.trigger_comm,
            "reclaim_context": case.reclaim_context,
            "memory_reclaim_type": case.memory_reclaim_type,
            "swappiness": case.swappiness,
            "memcg_id": case.memcg_id,
            "memcg_path": case.memcg_path,
            "node_id": case.node_id,
            "max_seq": case.max_seq,
            "min_seq_anon": case.min_seq_anon,
            "min_seq_file": case.min_seq_file,
            "priority": case.priority,
            "reclaim_idx": case.reclaim_idx,
            "order": case.order,
            "nr_to_reclaim": case.nr_to_reclaim,
            "observed_evict_folios_calls": case.observed_evict_folios_calls,
            "observed_evict_folios_calls_anon": case.observed_evict_folios_calls_anon,
            "observed_evict_folios_calls_file": case.observed_evict_folios_calls_file,
            "observed_evict_folios_return_sum_anon": case.observed_evict_folios_return_sum_anon,
            "observed_evict_folios_return_sum_file": case.observed_evict_folios_return_sum_file,
            "observed_evict_scanned_delta_anon_pages": case.observed_evict_scanned_delta_anon_pages,
            "observed_evict_scanned_delta_file_pages": case.observed_evict_scanned_delta_file_pages,
            "observed_isolate_calls_anon": case.observed_isolate_calls_anon,
            "observed_isolate_calls_file": case.observed_isolate_calls_file,
            "observed_isolate_scanned_anon_pages": case.observed_isolate_scanned_anon_pages,
            "observed_isolate_scanned_file_pages": case.observed_isolate_scanned_file_pages,
            "observed_nr_scanned_pages": case.observed_nr_scanned_pages,
            "observed_after_min_seq_anon": case.observed_after_min_seq_anon,
            "observed_after_min_seq_file": case.observed_after_min_seq_file,
            "observed_after_max_seq": case.observed_after_max_seq,
            "may_swap": case.may_swap,
            "may_writepage": case.may_writepage,
            "may_unmap": case.may_unmap,
        },
        "analysis": {
            "can_swap": state.can_swap,
            "should_run_aging": state.should_run_aging,
            "nr_to_scan_total": state.nr_to_scan_total,
            "scan_budget_estimate": state.scan_budget,
            "core_reclaim_target": state.core_reclaim_target,
            "reclaim_target": state.reclaim_target,
            "remaining_to_reclaim": state.remaining_to_reclaim,
            "predicted_anon_pages": state.reclaimed_anon_pages,
            "predicted_file_pages": state.reclaimed_file_pages,
            "predicted_anon_range": to_range_label(state.reclaimed_anon_pages),
            "predicted_file_range": to_range_label(state.reclaimed_file_pages),
            "evict_rounds": len(state.rounds),
            "final_min_seq_anon": state.min_seq_anon,
            "final_min_seq_file": state.min_seq_file,
        },
        "details": {
            "config": asdict(config),
            "rounds": [asdict(item) for item in state.rounds],
            "trace": [asdict(step) for step in state.trace],
            "final_generations": {
                "anon_gens": state.anon_gens,
                "file_gens": state.file_gens,
            },
        },
    }


def render_text(result: Dict[str, Any]) -> str:
    analysis = result["analysis"]
    lines = [
        "MGLRU Whitebox Executor Result",
        f"trigger_comm: {result['input_summary']['trigger_comm']}",
        f"swappiness: {result['input_summary']['swappiness']}",
        f"should_run_aging: {'yes' if analysis['should_run_aging'] else 'no'}",
        f"reclaim_target: {analysis['reclaim_target']}",
        f"remaining_to_reclaim: {analysis['remaining_to_reclaim']}",
        f"predicted reclaimed anon pages: {analysis['predicted_anon_pages']} ({analysis['predicted_anon_range']})",
        f"predicted reclaimed file pages: {analysis['predicted_file_pages']} ({analysis['predicted_file_range']})",
        f"evict_rounds: {analysis['evict_rounds']}",
        f"final_min_seq_anon: {analysis['final_min_seq_anon']}",
        f"final_min_seq_file: {analysis['final_min_seq_file']}",
        "",
        "Trace:",
    ]
    for step in result["details"]["trace"]:
        lines.append(f"- {step['fn']} -> {step['branch']}: {step['reason']}")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    case = load_case_from_args(args)
    config = ExecutorConfig(
        max_evict_rounds=args.max_evict_rounds,
        min_isolate_pages=args.min_isolate_pages,
        max_scan_pages=args.max_scan_pages,
    )
    result = exec_shrink_lruvec(case, config)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

