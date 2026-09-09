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
