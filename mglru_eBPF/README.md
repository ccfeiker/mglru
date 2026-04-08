# MGLRU 解析模型说明

本目录主要包含两个脚本：

- `mglru_executor.py`
- `validate_mglru_executor.py`

它们共同组成了当前的 MGLRU 解析模型与验证流程。

## 1. 当前 MGLRU 解析模型

### 1.1 模型定位

`mglru_executor.py` 是一个面向 MGLRU reclaim 路径的解析模型。

它的目标是结合：

- reclaim 上下文
- generation 状态
- anon / file 历史统计信息
- eBPF 采集到的运行时观测信号

来解析一次 reclaim 过程中大致发生了什么，并推断：

- 回收了多少匿名页
- 回收了多少文件页
- `min_seq` 如何变化
- 每一轮执行过程中发生了哪些关键步骤

### 1.2 核心思想

当前模型的核心思路可以概括为：

1. 用 case JSON 描述一次 reclaim 的输入状态
2. 根据 MGLRU 的主要控制逻辑，逐步解析 anon / file 的扫描与回收过程
3. 利用 eBPF 观测值约束解析过程，避免结果明显偏离真实执行
4. 输出最终的匿名页 / 文件页回收量以及详细 trace

这个模型：

- 过程可解释
- 结构和 MGLRU 机制一致
- 可以结合 trace 分析误差来源

### 1.3 输入与输出

`mglru_executor.py` 的输入是一份 case JSON，里面通常包含：

- reclaim 上下文
- `min_seq` / `max_seq`
- anon / file generations
- swappiness、priority、gfp 等控制信息
- 历史 refault / protected / evicted 统计
- eBPF 观测到的 isolate / evict / after-state 信息

输出包括：

- 预测回收的匿名页数量
- 预测回收的文件页数量
- 最终 `min_seq_anon` / `min_seq_file`
- 每一轮解析过程的 trace

如果使用 `--json`，则会输出结构化结果；否则默认输出便于阅读的文本结果。

## 2. `mglru_executor.py`

### 2.1 功能

`mglru_executor.py` 用来解析单个 case。

给它一份 case JSON，它会输出这次 reclaim 的解析结果，包括：

- 匿名页回收量
- 文件页回收量
- `min_seq` 变化
- 执行 trace

### 2.2 运行方式

直接解析一个 case：

```bash
python mglru_executor.py selected_kswapd0_case.json
```

输出 JSON：

```bash
python mglru_executor.py selected_kswapd0_case.json --json
```

从标准输入读取 case：

```bash
python mglru_executor.py --stdin --json < selected_kswapd0_case.json
```

打印模板 case：

```bash
python mglru_executor.py --template
```

更多参数说明可以直接查看：

```bash
python mglru_executor.py --help
```

## 3. `validate_mglru_executor.py`

### 3.1 功能

`validate_mglru_executor.py` 用来做批量验证。

它会读取 eBPF monitor 导出的 `output.csv`，将每一行样本重建成 case JSON，再调用 `mglru_executor.py` 的解析逻辑，最后输出批量验证结果。

主要输出包括：

- 一个代表性 case JSON
- 所有过滤后样本对应的 case JSON
- 每条样本的验证结果 CSV
- 汇总指标 JSON

### 3.2 它和 `mglru_executor.py` 的关系

两者关系很简单：

- `mglru_executor.py` 负责单条样本的解析
- `validate_mglru_executor.py` 负责批量构造样本、批量运行、汇总统计

整体流程如下：

```text
output.csv
  -> validate_mglru_executor.py
    -> build_case_json()
    -> mglru_executor.py
    -> per-row result / summary
```

### 3.3 运行方式

使用默认过滤条件运行：

```bash
python validate_mglru_executor.py --csv output.csv
```

验证指定 `trigger_comm`：

```bash
python validate_mglru_executor.py --csv output.csv --trigger-comm kswapd1
```

验证全部样本：

```bash
python validate_mglru_executor.py --csv output.csv --trigger-comm all
```

如果你希望输出 top error case，可以显式开启：

```bash
python validate_mglru_executor.py \
  --csv output.csv \
  --write-top-errors-json \
  --include-top-errors-in-summary
```

更多参数说明可以直接查看：

```bash
python validate_mglru_executor.py --help
```


