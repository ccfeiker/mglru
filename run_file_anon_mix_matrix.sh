#!/usr/bin/env bash
set -euo pipefail

# Automated matrix runner for file_anon_mix_pressure.
# Assumptions:
# - Run this on the Linux guest, not on Windows.
# - file_anon_mix_pressure has been modified to use 5 rounds.
# - The caller has root privileges.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKLOAD_BIN="${WORKLOAD_BIN:-/root/emm-test-project/file-anon-mix-pressure/file_anon_mix_pressure}"
TEST_FILE="${TEST_FILE:-/root/mixfile.img}"
RESULT_DIR="${RESULT_DIR:-$SCRIPT_DIR/train_runs}"
TEST_FILE_SIZE_MB="${TEST_FILE_SIZE_MB:-1024}"
DEFAULT_WORKERS="${DEFAULT_WORKERS:-$(nproc)}"

require_file() {
    local path="$1"

    if [[ ! -e "$path" ]]; then
        echo "Missing required file: $path" >&2
        exit 1
    fi
}

setup_test_file() {
    mkdir -p "$(dirname "$TEST_FILE")"
    if [[ ! -f "$TEST_FILE" ]]; then
        echo "Creating test file: $TEST_FILE (${TEST_FILE_SIZE_MB}M)"
        fallocate -l "${TEST_FILE_SIZE_MB}M" "$TEST_FILE"
    fi
}

run_case() {
    local case_id="$1"
    local mem_mb="$2"
    local swappiness="$3"
    local anon_mb="$4"
    local file_mb="$5"
    local anon_workers="${6:-$DEFAULT_WORKERS}"
    local file_workers="${7:-$DEFAULT_WORKERS}"
    local reader_sleep_us="${8:-120000}"
    local anon_wait_s="${9:-1}"
    local log_path="$RESULT_DIR/${case_id}_mem${mem_mb}_sw${swappiness}_anon${anon_mb}_file${file_mb}_aw${anon_workers}_fw${file_workers}_rs${reader_sleep_us}_wait${anon_wait_s}.log"

    echo
    echo "=== [$case_id] qemu_mem_hint=${mem_mb}M swappiness=${swappiness} anon=${anon_mb}M file=${file_mb}M anon_workers=${anon_workers} file_workers=${file_workers} reader_sleep_us=${reader_sleep_us} anon_wait_s=${anon_wait_s} ==="

    sysctl -q -w "vm.swappiness=${swappiness}" >/dev/null

    "$WORKLOAD_BIN" "$TEST_FILE" "${anon_mb}m" "${file_mb}m" \
        "$anon_workers" "$file_workers" "$reader_sleep_us" "$anon_wait_s" \
        | tee "$log_path"
}

print_usage() {
    cat <<'EOF'
Usage:
  ./run_file_anon_mix_matrix.sh            # run all cases
  ./run_file_anon_mix_matrix.sh A01        # run a single case
  ./run_file_anon_mix_matrix.sh --list     # list all case IDs

Notes:
  - This script no longer applies any cgroup limits.
  - The mem_mb column is kept only as metadata/a QEMU memory hint.
EOF
}

main() {
    local case_line
    local selected_case="${1:-}"
    local matched=0

    require_file "$WORKLOAD_BIN"
    mkdir -p "$RESULT_DIR"
    setup_test_file

    if [[ "$selected_case" == "--help" || "$selected_case" == "-h" ]]; then
        print_usage
        exit 0
    fi

    while read -r case_line; do
        local case_id

        [[ -z "$case_line" ]] && continue
        case_id="${case_line%% *}"

        if [[ "$selected_case" == "--list" ]]; then
            echo "$case_id"
            continue
        fi

        if [[ -n "$selected_case" && "$case_id" != "$selected_case" ]]; then
            continue
        fi

        run_case $case_line
        matched=1
    done <<'EOF'
#case_id memory.max swappiness anon_mb file_mb anon_workers file_workers reader_sleep_us anon_wait_s
F01 1536 1 512 3072 2 1 1500000 1
F02 1536 5 768 3072 2 1 1200000 1
F03 2048 1 512 4096 2 1 1500000 1
F04 2048 5 768 4096 2 1 1000000 1
F05 2560 5 1024 4096 2 2 800000 1
F06 2560 10 1024 5120 2 2 800000 1
A01 1536 20 1024 512
A02 1536 60 1024 512
A03 1536 100 1024 512
A04 1536 20 1152 512
A05 1536 60 1152 512
A06 1536 100 1152 512
A07 1536 20 1024 768
A08 1536 60 1024 768
A09 1536 100 1024 768
A10 1536 60 1280 640
B01 2048 20 1280 512
B02 2048 60 1280 512
B03 2048 100 1280 512
B04 2048 20 1536 768
B05 2048 60 1536 768
B06 2048 100 1536 768
B07 2048 20 1792 768
B08 2048 60 1792 768
B09 2048 100 1792 768
B10 2048 60 1536 1024
C01 2560 20 1536 768
C02 2560 60 1536 768
C03 2560 100 1536 768
C04 2560 20 1792 1024
C05 2560 60 1792 1024
C06 2560 100 1792 1024
C07 2560 20 2048 1024
C08 2560 60 2048 1024
C09 2560 100 2048 1024
C10 2560 60 2304 1024
EOF

    if [[ "$selected_case" == "--list" ]]; then
        exit 0
    fi

    if [[ -n "$selected_case" && "$matched" -eq 0 ]]; then
        echo "Unknown case_id: $selected_case" >&2
        print_usage >&2
        exit 1
    fi

    echo
    if [[ -n "$selected_case" ]]; then
        echo "Case $selected_case completed. Logs are in: $RESULT_DIR"
    else
        echo "All runs completed. Logs are in: $RESULT_DIR"
    fi
}

main "$@"
