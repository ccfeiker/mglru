# MGLRU Parser Model

## Overview

This directory contains the MGLRU parser model together with its eBPF-based data collection components.

The workflow has two stages:

- collect runtime reclaim signals from the Linux MGLRU path with eBPF
- reconstruct and analyze one reclaim instance with `mglru_executor.py`, and validate the model with `validate_mglru_executor.py`

The goal of this directory is to provide a structured and reproducible workflow for studying MGLRU reclaim behavior, including anon/file reclaim outcomes, `min_seq` transitions, and execution traces.

## 1. eBPF Data Collection

### 1.1 Directory Layout

The eBPF-related core files in this directory include:

- `mglru_monitor.bpf.c`
- `mglru_monitor.c`
- `mglru_monitor.h`
- `Makefile`

Specifically:

- `mglru_monitor.bpf.c` collects events along the kernel reclaim path
- `mglru_monitor.c` loads the eBPF program, reads the ring buffer, and exports CSV or JSONL outputs

### 1.2 Build

Enter the current directory first:

```bash
cd mglru_parser_model
```

Then run:

```bash
make
```

To rebuild from scratch:

```bash
make clean
make
```

### 1.3 Run

Start the monitor directly:

```bash
sudo ./mglru_monitor
```

Export `output.csv`:

```bash
sudo ./mglru_monitor output.csv
```

Export both `output.csv` and the replay trace:

```bash
sudo ./mglru_monitor output.csv replay.jsonl
```

The currently supported command-line format of `mglru_monitor.c` is:

```bash
./mglru_monitor [output.csv] [replay.jsonl]
```

## 2. Quick Start

To execute a single case:
`python mglru_executor.py mglru_template_case/mglru_image_case1_need_aging.json`

To analyze a case captured from eBPF data:
1. Run `make` in the `mglru_parser_model` directory.
2. Run `sudo ./mglru_monitor output.csv replay.jsonl`.
3. Run `python validate_mglru_executor.py --csv output.csv --trigger-comm kswapd0`.

To analyze one specific sample from the captured eBPF dataset:
`python mglru_executor.py --csv output.csv --line <line_no> --json`

## 3. MGLRU Parser Model Overview

This directory mainly contains two scripts:

- `mglru_executor.py`
- `validate_mglru_executor.py`

Together, they form the current MGLRU parser model and validation workflow.

### 3.1 Model Scope

`mglru_executor.py` is a parser model for the MGLRU reclaim path.

Its goal is to combine:

- reclaim context
- generation state
- historical anon/file statistics
- runtime observation signals collected by eBPF

to analyze what likely happened during one reclaim instance, and to infer:

- how many anonymous pages were reclaimed
- how many file-backed pages were reclaimed
- how `min_seq` changed
- which key steps occurred in each round of execution

### 3.2 Core Idea

The current model can be summarized as follows:

1. Use a case JSON file to describe the input state of one reclaim instance.
2. Parse the anon/file scanning and reclaim process according to the major MGLRU control logic.
3. Use eBPF observations to constrain the parsing process so that the result remains consistent with the observed execution.
4. Output the final reclaimed anon/file page counts together with a detailed trace.

This model is:

- interpretable
- structurally aligned with the MGLRU mechanism
- suitable for analyzing the source of prediction errors together with trace data

### 3.3 Inputs and Outputs

The input of `mglru_executor.py` is a case JSON file, which typically contains:

- reclaim context
- `min_seq` / `max_seq`
- anon / file generations
- control information such as swappiness, priority, and gfp flags
- historical refault / protected / evicted statistics
- isolate / evict / after-state observations collected by eBPF

Its outputs include:

- predicted reclaimed anonymous pages
- predicted reclaimed file-backed pages
- final `min_seq_anon` / `min_seq_file`
- per-round execution trace

If `--json` is specified, the script outputs structured results; otherwise it prints a human-readable text summary.

## 4. `mglru_executor.py`

### 4.1 Functionality

`mglru_executor.py` analyzes a single case.

Given one case JSON file, it outputs the parsing result of that reclaim instance, including:

- reclaimed anonymous pages
- reclaimed file-backed pages
- `min_seq` transitions
- execution trace

### 4.2 Usage

Analyze a single case directly:

```bash
python mglru_executor.py mglru_template_case/mglru_image_case1_need_aging.json
```

Output JSON:

```bash
python mglru_executor.py mglru_template_case/mglru_image_case1_need_aging.json --json
```

Read a case from standard input:

```bash
python mglru_executor.py --stdin --json < mglru_template_case/mglru_image_case1_need_aging.json
```

Print a template case:

```bash
python mglru_executor.py --template
```

For more options:

```bash
python mglru_executor.py --help
```

## 5. `validate_mglru_executor.py`

### 5.1 Functionality

`validate_mglru_executor.py` is used for batch validation.

It reads `output.csv` exported by the eBPF monitor, rebuilds each row into a case JSON file, invokes the parsing logic in `mglru_executor.py`, and then outputs aggregated validation results.

The main outputs include:

- one representative case JSON
- case JSON files for all filtered samples
- a per-sample validation result CSV
- a summary metrics JSON

### 5.2 Relationship to `mglru_executor.py`

Their relationship is straightforward:

- `mglru_executor.py` handles single-sample parsing
- `validate_mglru_executor.py` handles batch sample construction, batch execution, and result aggregation

The overall workflow is:

```text
output.csv
  -> validate_mglru_executor.py
    -> build_case_json()
    -> mglru_executor.py
    -> per-row result / summary
```

### 5.3 Usage

Run with the default filter:

```bash
python validate_mglru_executor.py --csv output.csv
```

Validate a specific `trigger_comm`:

```bash
python validate_mglru_executor.py --csv output.csv --trigger-comm kswapd0
```

Validate all samples:

```bash
python validate_mglru_executor.py --csv output.csv --trigger-comm all
```

If you want to export top-error cases, enable them explicitly:

```bash
python validate_mglru_executor.py \
  --csv output.csv \
  --write-top-errors-json \
  --include-top-errors-in-summary
```

For more options:

```bash
python validate_mglru_executor.py --help
```
