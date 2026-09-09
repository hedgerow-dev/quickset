# quickset

**A reproducible benchmark for Machine Learning model-file security scanners.**

Quickset evaluates **picklescan**, **ModelScan**, **modelaudit**, **fickling**, and **Hayward** on detection efficacy, false-positive rates, and format coverage.

---

## Why

Machine learning models are executable programs in disguise. Formats like PyTorch checkpoints (`.pt`, `.bin`), pickled state dictionaries, Keras models, and ONNX files can execute arbitrary system commands when loaded.

Multiple scanners have emerged to detect malicious model files before deployment. But until now:
- **Private test claims**: Each tool claimed high detection against its own unreleased test set.
- **Hidden false positives**: A scanner that flags everything achieves "100% detection", but breaks CI/CD pipelines with false alarms on legitimate models.
- **Silent skips**: Some scanners report "0% false positives" simply because they silently skip modern model formats without parsing them.
- **Weapons caches**: Previous academic benchmarks often distributed live malware on disk, risking accidental execution.

`quickset` provides an **independent, transparent, reproducible benchmark** to help developers and security teams evaluate and select the right scanner for their pipelines.

---

## What

`quickset` evaluates scanners against two distinct, realistic datasets:

1. **Inert Malicious Payloads (26 generated test cases)**: Real-world exploit techniques (arbitrary command execution, stack desynchronization, resource amplification bombs, multi-stream legacy PyTorch bypasses). Payloads are synthesized dynamically at runtime with inert echo markers and non-routable `.invalid` domains (RFC 2606)—**no live malware is ever stored on disk**.
2. **Real Benign Models (213 hash-pinned models)**: Real, clean models downloaded from the Hugging Face Hub across 14 model formats (PyTorch, SafeTensors, GGUF, ONNX, joblib, Keras, skops, etc.).

### Benchmark Principles

- **Detection & False Positives Paired**: High detection is meaningless if a scanner produces false alarms on standard models. Both metrics are measured side-by-side.
- **Parser Coverage vs. Gadget Recognition**: Measures whether a tool actually parses the container format or silently ignores it.
- **Safe by Construction**: Payloads are safe for CI environments, enterprise runners, and developer laptops without triggering antivirus alarms.
- **Shipped Defaults**: All tools run through their official command-line interfaces at shipped defaults—measuring what users actually experience.

---

## Tool Comparison

Benchmark results measured across 251 total test cases (26 malicious + 225 benign models, including 213 real Hugging Face models):

| Scanner | Backed By | Actionable Detection | Overall Corpus Detection | False Positives | Format Coverage | Best For |
|---|---|---|---|---|---|---|
| **[Hayward](https://github.com/hedgerow-dev/open-rowan)** | Hedgerow | **100%** (26/26) | **100%** (26/26) | **0%** (0/225) | **100%** (251/251) | CI/CD pipelines, comprehensive multi-format scanning |
| **[modelaudit](https://github.com/mindsdb/modelaudit)** | Promptfoo | **69%** (18/26) | **69%** (18/26) | **6%** (14/225) | **100%** (251/251) | Fast multi-format triage & auditing |
| **[fickling](https://github.com/trailofbits/fickling)** | Trail of Bits | **94%** (16/17) | **62%** (16/26) | **96%** (88/92) | **43%** (109/251) | In-depth static pickle bytecode analysis & decompilation |
| **[picklescan](https://github.com/mmaitre314/picklescan)** | Hugging Face ecosystem | **50%** (12/24) | **46%** (12/26) | **1%** (1/192) | **86%** (216/251) | Lightweight, fast pickle scanning |
| **[modelscan](https://github.com/protectai/modelscan)** | Protect AI | **38%** (5/13) | **19%** (5/26) | **0%** (0/80) | **37%** (93/251) | Conservative operator blocklist scanning |

> **How to read this table:**
> - **Actionable Detection**: Catch rate on malicious files the scanner *successfully opened and parsed*.
> - **Overall Corpus Detection**: Catch rate across the *entire malicious corpus* (skipped formats count as misses).
> - **False Positives**: Clean benign models incorrectly flagged as malicious.
> - **Format Coverage**: Percentage of model formats and files the scanner returned a verdict on (versus skipping or failing to open).

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

### 2. Run the Benchmark

```bash
python -m quickset.run
```

Quickset will generate the inert test cases, evaluate installed scanners, and output the matrix:

```
scanner                of files read    of corpus        false positives    coverage
----------------------------------------------------------------------------------
picklescan             12/24 (50%)      12/26 (46%)      1/192 (1%)         216/251 (86%)
modelscan              5/13 (38%)       5/26 (19%)       0/80 (0%)          93/251 (37%)
modelaudit             18/26 (69%)      18/26 (69%)      14/225 (6%)        251/251 (100%)
fickling               16/17 (94%)      16/26 (62%)      88/92 (96%)        109/251 (43%)
hayward                26/26 (100%)     26/26 (100%)     0/225 (0%)         251/251 (100%)
```

### 3. Useful Commands

```bash
# Save results to a structured JSON file
python -m quickset.run --json results.json

# Speed up execution across multiple CPU cores
python -m quickset.run --jobs 4

# Show raw unnormalized verdicts per case
python -m quickset.run --verbose

# Pre-fetch or verify the pinned benign model cache
python -m quickset.realmodels
```

---

## Adding Scanners & Test Cases

Quickset is designed to be easily extended by the community:

- **Add a Scanner**: Subclass `Adapter` in `quickset/adapters.py`. Adapters run scanners as subprocesses, avoiding Python dependency conflicts.
- **Add a Test Case**: Add a `Case` to `MALICIOUS` or `BENIGN` in `quickset/cases.py`. (Payloads must remain inert by using `.invalid` domains or harmless echo markers).

Verify changes by running the test suite:

```bash
pytest tests/ -v
```

---

## Prior Art & Deep Dives

- [Rangefetch Deep Dive](docs/rangefetch.md): How HTTP range requests read model headers and container tables without downloading gigabytes of tensor weights.
- **Prior Art**: We acknowledge work on ML security benchmarks including [PickleBench](https://arxiv.org/html/2607.17503v1) (ShadowPickle), [PickleBall](https://arxiv.org/pdf/2508.15987), [SafePickle](https://arxiv.org/html/2602.19818v1), and `picklescan`'s test suite. Quickset builds upon this landscape by prioritizing zero-malware generation and paired false-positive evaluation.

---

## License & Conflict Disclosure

- **License**: MIT.
- **Conflict Disclosure**: `quickset` was built by Hedgerow, the creators of [Hayward](https://github.com/hedgerow-dev/open-rowan). All scanners are invoked strictly through official CLI subprocesses with identical flags and default settings. No scanner has internal or privileged access. The harness and cases are fully open source for independent verification.
