#!/usr/bin/env python3
"""Validate lru_executor.py against lru_output.csv."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from lru_executor import ExecutorConfig, build_case_from_csv_row, exec_shrink_lruvec, load_case, to_range_label


DEFAULT_RELATIVE_TOLERANCE = 0.10
DEFAULT_ZERO_ABS_TOLERANCE = 64


def parse_args() -> argparse.Namespace:
    base = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Validate lru_executor.py against lru_output.csv")
    parser.add_argument("--csv", default=str(base / "lru_output.csv"), help="Path to lru_output.csv")
    parser.add_argument("--results-csv", default=str(base / "lru_executor_validation_results.csv"), help="Per-row validation results")
    parser.add_argument("--summary-json", default=str(base / "lru_executor_validation_summary.json"), help="Validation summary JSON")
    parser.add_argument("--case-out", default=str(base / "selected_lru_case.json"), help="Representative case JSON")
    parser.add_argument("--top-errors-json", default=str(base / "lru_executor_top_error_cases.json"), help="Highest-error cases JSON")
    parser.add_argument("--trigger-comm", default="all", help="Only validate rows whose trigger_comm matches this value; use 'all' to disable filtering")
    parser.add_argument("--relative-tolerance", type=float, default=DEFAULT_RELATIVE_TOLERANCE)
    parser.add_argument("--zero-abs-tolerance", type=int, default=DEFAULT_ZERO_ABS_TOLERANCE)
    parser.add_argument("--top-k", type=int, default=20, help="How many highest-error cases to retain")
    parser.add_argument("--include-top-error-cases", action="store_true", help="Embed top_error_cases in the printed/json summary")
    parser.add_argument(
        "--include-zero-label-cases",
        action="store_true",
        help="Include rows whose actual anon and file reclaimed pages are both 0",
    )
    parser.add_argument("--limit", type=int, default=0, help="Stop after validating this many filtered rows; 0 means no limit")
    return parser.parse_args()


def as_int(row: Dict[str, str], key: str, default: int = 0) -> int:
    value = row.get(key)
    if value is None or value == "":
        return default
    return int(value)


def trigger_comm_matches(row: Dict[str, str], trigger_comm: str) -> bool:
    if trigger_comm.lower() == "all":
        return True
    return row.get("trigger_comm") == trigger_comm


def page_relative_error(predicted: int, actual: int) -> float | None:
    if actual == 0:
        return None
    return abs(predicted - actual) / actual


def page_match(predicted: int, actual: int, relative_tolerance: float, zero_abs_tolerance: int) -> bool:
    if actual == 0:
        return abs(predicted) <= zero_abs_tolerance
    return abs(predicted - actual) <= max(zero_abs_tolerance, int(actual * relative_tolerance))


def safe_mean(values: List[int]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def better_representative(candidate: Tuple[int, int, int], incumbent: Tuple[int, int, int] | None) -> bool:
    if incumbent is None:
        return True
    return candidate > incumbent


def maybe_add_top_case(top_cases: List[Dict[str, Any]], candidate: Dict[str, Any], top_k: int) -> None:
    top_cases.append(candidate)
    top_cases.sort(
        key=lambda item: (
            int(item["combined_abs_error"]),
            int(item["file_abs_error"]),
            int(item["anon_abs_error"]),
        ),
        reverse=True,
    )
    del top_cases[top_k:]


def main() -> int:
    args = parse_args()
    csv_path = Path(args.csv).resolve()
    results_csv = Path(args.results_csv).resolve()
    summary_json = Path(args.summary_json).resolve()
    case_out = Path(args.case_out).resolve()
    top_errors_json = Path(args.top_errors_json).resolve()

    config = ExecutorConfig()

    results_csv.parent.mkdir(parents=True, exist_ok=True)
    summary_json.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    exact_both = 0
    tolerant_both = 0
    anon_exact = 0
    file_exact = 0
    anon_tolerant = 0
    file_tolerant = 0
    anon_range_hit = 0
    file_range_hit = 0
    combined_range_hit = 0
    anon_abs_errors: List[int] = []
    file_abs_errors: List[int] = []
    anon_signed_errors: List[int] = []
    file_signed_errors: List[int] = []
    anon_over = 0
    anon_under = 0
    file_over = 0
    file_under = 0
    top_cases: List[Dict[str, Any]] = []
    representative_score: Tuple[int, int, int] | None = None
    representative_case: Dict[str, Any] | None = None
    representative_result: Dict[str, Any] | None = None
    representative_line_no: int | None = None

    with csv_path.open("r", encoding="utf-8", newline="") as in_fh, results_csv.open("w", encoding="utf-8", newline="") as out_fh:
        reader = csv.DictReader(in_fh)
        writer: csv.DictWriter[str] | None = None

        for line_no, row in enumerate(reader, start=2):
            if not trigger_comm_matches(row, args.trigger_comm):
                continue
            actual_anon = as_int(row, "target_reclaimed_anon_pages")
            actual_file = as_int(row, "target_reclaimed_file_pages")
            if not args.include_zero_label_cases and actual_anon == 0 and actual_file == 0:
                continue
            if args.limit and total >= args.limit:
                break

            case_json = build_case_from_csv_row(row)
            result = exec_shrink_lruvec(load_case(case_json), config)

            predicted_anon = int(result["analysis"]["predicted_anon_pages"])
            predicted_file = int(result["analysis"]["predicted_file_pages"])
            anon_signed_error = predicted_anon - actual_anon
            file_signed_error = predicted_file - actual_file

            anon_exact_match = predicted_anon == actual_anon
            file_exact_match = predicted_file == actual_file
            anon_tol_match = page_match(predicted_anon, actual_anon, args.relative_tolerance, args.zero_abs_tolerance)
            file_tol_match = page_match(predicted_file, actual_file, args.relative_tolerance, args.zero_abs_tolerance)
            predicted_anon_range = to_range_label(predicted_anon)
            predicted_file_range = to_range_label(predicted_file)
            actual_anon_range = to_range_label(actual_anon)
            actual_file_range = to_range_label(actual_file)
            anon_range_match = predicted_anon_range == actual_anon_range
            file_range_match = predicted_file_range == actual_file_range

            total += 1
            anon_exact += int(anon_exact_match)
            file_exact += int(file_exact_match)
            anon_tolerant += int(anon_tol_match)
            file_tolerant += int(file_tol_match)
            exact_both += int(anon_exact_match and file_exact_match)
            tolerant_both += int(anon_tol_match and file_tol_match)
            anon_range_hit += int(anon_range_match)
            file_range_hit += int(file_range_match)
            combined_range_hit += int(anon_range_match and file_range_match)
            anon_abs_errors.append(abs(anon_signed_error))
            file_abs_errors.append(abs(file_signed_error))
            anon_signed_errors.append(anon_signed_error)
            file_signed_errors.append(file_signed_error)
            anon_over += int(anon_signed_error > 0)
            anon_under += int(anon_signed_error < 0)
            file_over += int(file_signed_error > 0)
            file_under += int(file_signed_error < 0)

            result_row = {
                "csv_line_no": line_no,
                "session_id": as_int(row, "session_id"),
                "memcg_id": as_int(row, "memcg_id"),
                "trigger_tgid": as_int(row, "trigger_tgid"),
                "trigger_tid": as_int(row, "trigger_tid"),
                "trigger_comm": row.get("trigger_comm", ""),
                "swappiness": as_int(row, "feature_swappiness"),
                "nr_to_reclaim": as_int(row, "feature_nr_to_reclaim"),
                "observed_shrink_input_anon_pages": as_int(row, "observed_shrink_input_anon_pages"),
                "observed_shrink_input_file_pages": as_int(row, "observed_shrink_input_file_pages"),
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
                "predicted_anon_pages": predicted_anon,
                "actual_anon_pages": actual_anon,
                "anon_abs_error": abs(anon_signed_error),
                "anon_signed_error": anon_signed_error,
                "anon_rel_error": page_relative_error(predicted_anon, actual_anon),
                "anon_exact_match": int(anon_exact_match),
                "anon_tolerant_match": int(anon_tol_match),
                "predicted_file_pages": predicted_file,
                "actual_file_pages": actual_file,
                "file_abs_error": abs(file_signed_error),
                "file_signed_error": file_signed_error,
                "file_rel_error": page_relative_error(predicted_file, actual_file),
                "file_exact_match": int(file_exact_match),
                "file_tolerant_match": int(file_tol_match),
                "predicted_anon_range": predicted_anon_range,
                "actual_anon_range": actual_anon_range,
                "anon_range_match": int(anon_range_match),
                "predicted_file_range": predicted_file_range,
                "actual_file_range": actual_file_range,
                "file_range_match": int(file_range_match),
                "combined_exact_match": int(anon_exact_match and file_exact_match),
                "combined_tolerant_match": int(anon_tol_match and file_tol_match),
                "combined_range_match": int(anon_range_match and file_range_match),
                "combined_abs_error": abs(anon_signed_error) + abs(file_signed_error),
            }

            if writer is None:
                writer = csv.DictWriter(out_fh, fieldnames=list(result_row.keys()))
                writer.writeheader()
            writer.writerow(result_row)

            maybe_add_top_case(top_cases, result_row, max(args.top_k, 1))

            rep_score = (
                min(actual_anon, actual_file),
                actual_anon + actual_file,
                as_int(row, "feature_nr_to_reclaim"),
            )
            if actual_anon > 0 and actual_file > 0 and better_representative(rep_score, representative_score):
                representative_score = rep_score
                representative_case = case_json
                representative_result = result_row
                representative_line_no = line_no

    if total == 0:
        raise SystemExit("no matching rows were validated")

    if representative_case is None:
        representative_case = TEMPLATE
        representative_result = None
        representative_line_no = None

    case_out.write_text(json.dumps(representative_case, indent=2, ensure_ascii=False), encoding="utf-8")
    top_errors_json.write_text(json.dumps(top_cases, indent=2, ensure_ascii=False), encoding="utf-8")

    summary = {
        "csv_path": str(csv_path),
        "results_csv": str(results_csv),
        "summary_json": str(summary_json),
        "case_out": str(case_out),
        "top_errors_json": str(top_errors_json),
        "trigger_comm_filter": args.trigger_comm,
        "validated_cases": total,
        "representative_case": {
            "csv_line_no": representative_line_no,
            "case_path": str(case_out),
            "predicted_anon_pages": (representative_result or {}).get("predicted_anon_pages"),
            "predicted_file_pages": (representative_result or {}).get("predicted_file_pages"),
            "actual_anon_pages": (representative_result or {}).get("actual_anon_pages"),
            "actual_file_pages": (representative_result or {}).get("actual_file_pages"),
        },
        "metrics": {
            "anon_exact_match_rate": anon_exact / total,
            "file_exact_match_rate": file_exact / total,
            "combined_exact_match_rate": exact_both / total,
            "anon_tolerant_match_rate": anon_tolerant / total,
            "file_tolerant_match_rate": file_tolerant / total,
            "combined_tolerant_match_rate": tolerant_both / total,
            "anon_range_hit_rate": anon_range_hit / total,
            "file_range_hit_rate": file_range_hit / total,
            "combined_range_hit_rate": combined_range_hit / total,
            "anon_mae": safe_mean(anon_abs_errors),
            "file_mae": safe_mean(file_abs_errors),
            "anon_mean_signed_error": safe_mean(anon_signed_errors),
            "file_mean_signed_error": safe_mean(file_signed_errors),
            "anon_overpredict_rate": anon_over / total,
            "anon_underpredict_rate": anon_under / total,
            "file_overpredict_rate": file_over / total,
            "file_underpredict_rate": file_under / total,
        },
        "tolerance": {
            "relative_tolerance": args.relative_tolerance,
            "zero_abs_tolerance": args.zero_abs_tolerance,
        },
    }

    if args.include_top_error_cases:
        summary["top_error_cases"] = top_cases

    summary_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
