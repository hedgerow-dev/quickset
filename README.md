# quickset

**A reproducible benchmark for Machine Learning model-file security scanners.**

![License MIT](https://img.shields.io/badge/license-MIT-013D5A?style=flat-square&labelColor=013D5A)
![Python 3.12](https://img.shields.io/badge/python-3.12-013D5A?style=flat-square&labelColor=013D5A)
![Test cases 251](https://img.shields.io/badge/cases-251-013D5A?style=flat-square&labelColor=013D5A)
![Scanners 5](https://img.shields.io/badge/scanners-5-708C69?style=flat-square&labelColor=013D5A)
![Zero malware on disk](https://img.shields.io/badge/malware_on_disk-none-F4A25B?style=flat-square&labelColor=013D5A)

Quickset evaluates **picklescan**, **ModelScan**, **modelaudit**, **fickling**, and **Hayward** on detection efficacy, false-positive rates, and format coverage.

---

## Why

Machine learning models are executable software in disguise. Serialization formats like PyTorch checkpoints (`.pt`, `.bin`), pickled objects, Keras models, and ONNX graphs can execute arbitrary system code when loaded.

Multiple scanners have emerged to detect malicious checkpoints before deployment. But until now:

- **Private test sets**: Tools claimed high detection against unreleased test files.
- **Hidden false positives**: A scanner that flags everything achieves "100% detection", but breaks production CI pipelines on legitimate models.
- **Silent non-coverage**: Some scanners show "0% false positives" simply because they silently ignore modern container formats without parsing them.
- **Weapons caches**: Prior benchmarks often distributed live malware on disk, risking accidental execution.

`quickset` provides an **independent, transparent, and reproducible benchmark** to measure how scanners actually perform against real-world models and realistic attack vectors.

---

## What

Quickset evaluates scanners across two distinct, complementary datasets:

1. **Inert Malicious Payloads (26 generated cases)**: Real exploit techniques—arbitrary command execution, stack desynchronization, resource amplification bombs, and multi-stream PyTorch bypasses. Payloads are generated dynamically at runtime with harmless echo markers and non-routable `.invalid` domains ([RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606)). **No live malware is ever stored on disk.**
2. **Real Benign Models (213 hash-pinned models)**: Clean, public models downloaded from the Hugging Face Hub across 14 container formats (PyTorch, SafeTensors, GGUF, ONNX, joblib, Keras, skops, etc.).

### Benchmark principles

- **Detection and false positives paired**: High detection is meaningless if a scanner halts valid builds. Both metrics are measured side-by-side.
- **Parser coverage measured separately**: Distinguishes whether a scanner recognized a gadget from whether it inspected the file at all.
- **Safe by construction**: Payloads are safe for local developer machines, enterprise runners, and CI environments without triggering endpoint alarms.
- **Shipped defaults**: Every tool runs through its official command-line interface at default settings—measuring what operators actually experience.

---

## Tool Comparison

Benchmark results measured across 251 total test cases (26 malicious + 225 benign models, including 213 real Hugging Face models):

| Scanner | Backed By | Actionable Detection | Overall Detection | False Positives | Format Coverage | Primary Strength |
|---|---|---|---|---|---|---|
| **[Hayward](https://github.com/hedgerow-dev/hayward)** | Hedgerow | **100%** (26/26) | **100%** (26/26) | **0%** (0/225) | **100%** (251/251) | Deterministic CI/CD gating, zero false positives, multi-format coverage |
| **[modelaudit](https://github.com/mindsdb/modelaudit)** | Promptfoo | **69%** (18/26) | **69%** (18/26) | **6%** (14/225) | **100%** (251/251) | Fast multi-format triage & auditing |
| **[fickling](https://github.com/trailofbits/fickling)** | Trail of Bits | **94%** (16/17) | **62%** (16/26) | **96%** (88/92) | **43%** (109/251) | Static pickle bytecode analysis & decompilation |
| **[picklescan](https://github.com/mmaitre314/picklescan)** | Hugging Face ecosystem | **50%** (12/24) | **46%** (12/26) | **1%** (1/192) | **86%** (216/251) | Lightweight, fast pickle scanning |
| **[modelscan](https://github.com/protectai/modelscan)** | Protect AI | **38%** (5/13) | **19%** (5/26) | **0%** (0/80) | **37%** (93/251) | Conservative operator blocklist scanning |

> **Interpreting the metrics:**
> - **Actionable Detection**: Detection rate on malicious files the scanner *successfully opened and parsed*.
> - **Overall Detection**: Detection rate across the *entire malicious corpus* (skipped formats count as misses).
> - **False Positives**: Clean benign models incorrectly flagged as dangerous.
> - **Format Coverage**: Percentage of test files and formats the scanner returned a verdict on (versus failing or skipping).

### Understanding Scanner Design Trade-offs

The divergence in detection and false-positive rates reflects fundamentally different design goals and operational environments rather than defective implementations:

- **fickling (Trail of Bits)**: Built primarily as an interactive forensic analysis, decompilation, and reverse-engineering tool for human security researchers. Its default heuristic assumes the file is an unknown, untrusted artifact under sandbox investigation: any non-standard-library import (`numpy`, `torch`, `sklearn`), any constructor instantiation (`__new__`), and any unreferenced variable assignment is flagged as `LIKELY_UNSAFE`. In a manual malware triage workflow, aggressive sensitivity is desirable. However, when deployed as an automated CI/CD gate on real-world ML repositories where legitimate models heavily utilize NumPy arrays and PyTorch tensors, this same sensitivity flags 96% of benign models.
- **modelscan (Protect AI)**: Designed for automated CI/CD pipelines with an explicit requirement to avoid breaking developer workflows. It relies on a conservative allowlist and blocklist of known high-risk execution calls (`os.system`, `subprocess.Popen`, `eval`, `exec`). This achieves a 0% false-positive rate on clean models, but leaves the scanner blind to multi-stage gadget chains, indirect imports, and opcode desynchronization attacks (yielding 19% overall detection). Additionally, its parser coverage is focused on classic pickle files and skips non-pickle containers.
- **picklescan (Hugging Face)**: Built as a lightweight, low-overhead filter for the Hugging Face model registry. It inspects global imports against a curated list of dangerous modules. This delivers rapid evaluation with minimal false positives (1%), but does not perform full abstract machine emulation, leaving it vulnerable to opcode-level evasion techniques.
- **modelaudit (Promptfoo)**: Designed as a multi-format audit scanner covering 14 container formats. It balances speed with broader format awareness, showing solid detection (69%) with a low false-positive rate (6%) on complex legitimate pipelines.
- **Hayward (Hedgerow)**: Engineered specifically for automated CI/CD gating and model registries without human triagers. Rather than relying on simple string blocklists (which miss evasions) or flagging all third-party imports (which breaks CI), Hayward simulates the pickle abstract machine, tracks stack states and memo registers, and evaluates callable arguments semantically. This allows it to distinguish legitimate tensor allocations from execution sinks with 0% false positives and 100% detection across all supported container formats.

#### Why previous benchmarks reported different numbers

Prior academic benchmarks (such as PickleCloak and ShadowPickle) evaluated tools exclusively against synthetic malicious pickles with **zero benign models** and **zero non-pickle formats** (no SafeTensors, ONNX, or GGUF). Under those conditions:
1. A scanner that flags every non-standard import appears to achieve "100% detection", because there are no clean models present to reveal the corresponding false-positive rate.
2. A tool that fails to parse modern container formats appears to perform well if the test set only contains raw `.pkl` files.

Quickset evaluates detection efficacy and false-positive rates simultaneously across real-world weights and modern distribution formats, demonstrating the true operational trade-offs of each approach.

---

## How

Anyone can install and run `quickset` in under 3 minutes.

### 1. Install

```bash
git clone https://github.com/hedgerow-dev/quickset.git
cd quickset

# Install quickset and optional scanners
pip install -e .
pip install picklescan modelscan fickling modelaudit hayward
```

*(Python 3.12 recommended. Any scanner not installed is automatically skipped without failing the run.)*

### 2. Run the benchmark

```bash
python -m quickset.run
```

Quickset generates the inert test cases, runs all installed scanners, and prints the verified matrix:

```
scanner                of files read    of corpus        false positives    coverage
----------------------------------------------------------------------------------
picklescan             12/24 (50%)      12/26 (46%)      1/192 (1%)         216/251 (86%)
modelscan              5/13 (38%)       5/26 (19%)       0/80 (0%)          93/251 (37%)
modelaudit             18/26 (69%)      18/26 (69%)      14/225 (6%)        251/251 (100%)
fickling               16/17 (94%)      16/26 (62%)      88/92 (96%)        109/251 (43%)
hayward                26/26 (100%)     26/26 (100%)     0/225 (0%)         251/251 (100%)
```

### 3. Options

```bash
# Save complete results to a structured JSON file
python -m quickset.run --json results.json

# Run with parallel workers
python -m quickset.run --jobs 4

# View unnormalized per-case verdict strings
python -m quickset.run --verbose

# Verify or refresh the local benign model cache
python -m quickset.realmodels
```

---

## Adding Scanners & Test Cases

Quickset is designed for straightforward community contributions:

- **Add a Scanner**: Subclass `Adapter` in `quickset/adapters.py`. Adapters run scanners as subprocesses, eliminating Python dependency conflicts.
- **Add a Test Case**: Declare a `Case` in `quickset/cases.py`. (Payloads must remain inert with `.invalid` domains or harmless echo markers).

Verify changes with the test suite:

```bash
pytest tests/ -v
```

---

## Documentation & Prior Art

- [Rangefetch Deep Dive](docs/rangefetch.md): How HTTP range requests read model headers and container tables without downloading gigabytes of tensor weights.
- **Prior Art**: We acknowledge foundational benchmarks and datasets in ML model security, including [PickleBench](https://arxiv.org/html/2607.17503v1) (ShadowPickle), [PickleBall](https://arxiv.org/pdf/2508.15987), [SafePickle](https://arxiv.org/html/2602.19818v1), and `picklescan`'s test suite. Quickset builds upon this work by prioritizing runtime payload generation and paired false-positive evaluation.

---

## Licence & Disclosure

- **Licence**: MIT.
- **Conflict of Interest Disclosure**: `quickset` was built by Hedgerow, the creators of [Hayward](https://github.com/hedgerow-dev/hayward). All scanners are invoked through official CLI subprocesses with standard defaults and identical flags. No scanner has internal or privileged access. The harness and test specifications are open source for independent verification.
