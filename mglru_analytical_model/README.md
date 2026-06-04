# MGLRU Analytical Model: Running Guide

This directory contains the MGLRU eBPF monitor, analytical-model executor,
template cases, and batch validation script.

All commands below should be run on the Linux test machine from this directory.

## Requirements

- A running Linux kernel with MGLRU and BTF available
- `/sys/kernel/btf/vmlinux`
- `clang`, `make`, `bpftool`, `libelf`, and `zlib`
- A `libbpf-bootstrap` checkout containing `libbpf/src` and `bpftool/src`
- Python 3.10 or newer

Confirm that MGLRU is available:

```bash
test -e /sys/kernel/mm/lru_gen/enabled
```

## Build the eBPF Monitor

The Makefile searches upward from the current directory for a compatible
`libbpf-bootstrap` checkout:

```bash
make clean
make
```

If auto-detection does not find the correct checkout, provide it explicitly:

```bash
make clean
make LIBBPF_BOOTSTRAP_ROOT=/path/to/libbpf-bootstrap
```

The build generates `vmlinux.h` and the `mglru_monitor` executable.

## Collect MGLRU Reclaim Data

Enable MGLRU before collection:

```bash
echo 0x0007 | sudo tee /sys/kernel/mm/lru_gen/enabled
```

Start the monitor and write samples to `output.csv`:

```bash
sudo ./mglru_monitor output.csv
```

Run the target workload in another terminal. Stop the monitor with `Ctrl-C`
after collection finishes.

Running the monitor without an output path prints events without writing CSV:

```bash
sudo ./mglru_monitor
```

## Run One Template Case

Human-readable output:

```bash
python mglru_executor.py \
  mglru_template_case/case2_launching_nrt20k/mglru_launching_anon_pid_sw100.json
```

JSON output:

```bash
python mglru_executor.py \
  mglru_template_case/case2_launching_nrt20k/mglru_launching_anon_pid_sw100.json \
  --json
```

Read a case from standard input:

```bash
python mglru_executor.py --stdin --json < case.json
```

Optional executor safety limits:

```bash
python mglru_executor.py case.json \
  --max-evict-rounds 16 \
  --min-isolate-pages 64 \
  --max-scan-pages 4096 \
  --json
```

## Batch Validation

Validate `kswapd0` samples:

```bash
python validate_mglru_executor.py --csv output.csv --trigger-comm kswapd0
```

Validate samples from all triggering processes:

```bash
python validate_mglru_executor.py --csv output.csv --trigger-comm all
```

Rows whose anon and file reclaim labels are both zero are excluded by default.
Include them only when explicitly needed:

```bash
python validate_mglru_executor.py \
  --csv output.csv \
  --trigger-comm kswapd0 \
  --include-zero-label-cases
```

Include the highest-error cases in the printed and JSON summary:

```bash
python validate_mglru_executor.py \
  --csv output.csv \
  --trigger-comm kswapd0 \
  --include-top-errors-in-summary
```

## Validation Outputs

The default batch-validation outputs are:

- `selected_kswapd0_case.json`
- `generated_cases/`
- `executor_validation_results.csv`
- `executor_validation_summary.json`
- `executor_top_error_cases.json`

Use `python mglru_executor.py --help` and
`python validate_mglru_executor.py --help` for all available options.
