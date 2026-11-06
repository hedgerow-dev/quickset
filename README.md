# quickset

**A reproducible benchmark for Machine Learning model-file security scanners.**

![License MIT](https://img.shields.io/badge/license-MIT-013D5A?style=flat-square&labelColor=013D5A)
![Python 3.12](https://img.shields.io/badge/python-3.12-013D5A?style=flat-square&labelColor=013D5A)
![Test cases 248](https://img.shields.io/badge/cases-248-013D5A?style=flat-square&labelColor=013D5A)
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

`quickset` provides a **transparent and reproducible benchmark** to measure how scanners actually perform against real-world models and realistic attack vectors. It is built by Hedgerow, who also build Hayward, one of the scanners it measures: see the disclosure at the end.

---

## What

Quickset evaluates scanners across two distinct, complementary datasets:

1. **Inert Malicious Payloads (26 generated cases)**: Real exploit techniques—arbitrary command execution, stack desynchronization, resource amplification bombs, and multi-stream PyTorch bypasses. Payloads are generated dynamically at runtime with harmless echo markers and non-routable `.invalid` domains ([RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606)). **No live malware is ever stored on disk.**
2. **Real Benign Models (210 hash-pinned models)**: Clean, public models downloaded from the Hugging Face Hub across 14 container formats (PyTorch, SafeTensors, GGUF, ONNX, joblib, Keras, skops, etc.).

### Benchmark principles

- **Detection and false positives paired**: High detection is meaningless if a scanner halts valid builds. Both metrics are measured side-by-side.
- **Parser coverage measured separately**: Distinguishes whether a scanner recognized a gadget from whether it inspected the file at all.
- **Safe by construction**: Payloads are safe for local developer machines, enterprise runners, and CI environments without triggering endpoint alarms.
- **Shipped defaults**: Every tool runs through its official command-line interface at default settings—measuring what operators actually experience.

---

## Tool Comparison

Results from the run of 5 November 2026: 26 generated malicious cases and 222 benign files (210 real Hugging Face models, three of the 213 in the manifest no longer being downloadable, plus 12 generated benign cases). Raw per-file results, the run log and the environment are in [`evidence/2026-11-05-scanner-comparison/`](evidence/2026-11-05-scanner-comparison/).

Every rate is over the files that scanner returned a verdict on, so denominators differ between scanners. False positives are reported at **both thresholds**: the strict one counts only the tier each tool's author calls actionable, and the second adds the tool's own unknown or warning tier. Reporting only the first hides most of the difference between tools.

| Scanner | Backed By | Detection (of files read) | Detection (of corpus) | False positives, strict | Benign files flagged, incl. warnings | Coverage |
|---|---|---|---|---|---|---|
| **[Hayward](https://github.com/hedgerow-dev/hayward)** 1.16.1 | Hedgerow | 26/26 (100%) | 26/26 (100%) | 0/222 (0%) | 7/222 (3%) | 248/248 (100%) |
| **[modelaudit](https://github.com/promptfoo/promptfoo)** 0.2.54 | Promptfoo | 18/26 (69%) | 18/26 (69%) | 14/222 (6%) | 90/222 (41%) | 248/248 (100%) |
| **[fickling](https://github.com/trailofbits/fickling)** 0.1.13 | Trail of Bits | 16/17 (94%) | 16/26 (62%) | 90/94 (96%) | 90/94 (96%) | 111/248 (45%) |
| **[picklescan](https://github.com/mmaitre314/picklescan)** 1.0.5 | Hugging Face ecosystem | 12/24 (50%) | 12/26 (46%) | 1/192 (0.5%) | 38/192 (20%) | 216/248 (87%) |
| **[modelscan](https://github.com/protectai/modelscan)** 0.8.8 | Protect AI | 5/13 (38%) | 5/26 (19%) | 0/80 (0%) | 0/80 (0%) | 93/248 (38%) |

> **Interpreting the metrics:**
> - **Detection (of files read)**: detection rate on malicious files the scanner returned a verdict on.
> - **Detection (of corpus)**: detection rate across the whole malicious corpus, with files the scanner did not read counted as misses.
> - **False positives, strict**: benign files flagged at the tier each tool's author calls actionable.
> - **Benign files flagged, incl. warnings**: the same, adding each tool's unknown or warning tier (picklescan's suspicious, modelaudit's warning, fickling's SUSPICIOUS, Hayward's INFO). A warning asks a person to look; it is not an accusation of malware.
> - **Coverage**: share of all files the scanner returned any verdict on, versus failing or skipping.
>
> **Hayward's detection here counts findings from LOW up.** At its default build gate (HIGH and above) it blocks 22 of the 26 generated cases, 46/57 PickleCloak exploits and 56/97 PickleCloak chains; see `evidence/2026-11-05-scanner-comparison/hayward-high-rescore-2026-11-06.txt`.
>
> **The 26 malicious cases were written by us, alongside Hayward, so they flatter it.** The externally authored corpora (picklescan's tests, PickleCloak) are reported separately by `python -m quickset.run` and are the better detection evidence. These are self-measured numbers until someone else reproduces them.

### Understanding Scanner Design Trade-offs

The divergence in detection and flag rates reflects different design goals as well as implementation differences:

- **fickling (Trail of Bits)**: Focuses on pickle and pickle-based artifacts, with decompilation and forensic analysis as well as automated safety checks and import hooks. In the configuration tested here it rated 23 benign files LIKELY_OVERTLY_MALICIOUS and 67 more LIKELY_UNSAFE, and returned no verdict on non-pickle files.
- **modelscan (Protect AI)**: Uses a conservative list of known high-risk calls, which gives no false positives on the 80 benign files it read but low detection on the generated cases. With a default install it returned no verdict on most files; it reports this with a separate exit code (3) and a `--show-skipped` option, so pipelines should check for it.
- **picklescan (Hugging Face ecosystem)**: A lightweight check of pickle globals against curated lists. Its strict tier is very quiet (1 benign file); its suspicious tier flags 20%. When it cannot parse a file or has no reader for the format, its summary still reports zero infected files, so this harness counts those as no verdict.
- **modelaudit (Promptfoo)**: Broad format coverage, with a verdict on every file. Its warning tier, which it describes as potential issues that require review, flags 41% of benign files and fails a build by default.
- **Hayward (Hedgerow)**: Built for unattended CI gating. It simulates the pickle machine and judges callables by their arguments. It raised no strict-tier finding on any benign file and an INFO warning on 7 (3%); its default build gate fails on HIGH and above, so INFO does not fail a build.

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

Quickset generates the inert test cases, runs all installed scanners, and prints the matrix at both thresholds (this is the 5 November 2026 run; `+unknown` rows add each tool's warning tier):

```
scanner                of files read    of corpus        false positives    coverage         errors
----------------------------------------------------------------------------------------------
picklescan             12/24 (50%)      12/26 (46%)      1/192 (1%)         216/248 (87%)    32
picklescan +unknown    13/24 (54%)      13/26 (50%)      38/192 (20%)
modelscan              5/13 (38%)       5/26 (19%)       0/80 (0%)          93/248 (38%)     155
modelaudit             18/26 (69%)      18/26 (69%)      14/222 (6%)        248/248 (100%)   -
modelaudit +unknown    22/26 (85%)      22/26 (85%)      90/222 (41%)
fickling               16/17 (94%)      16/26 (62%)      90/94 (96%)        111/248 (45%)    137
hayward                26/26 (100%)     26/26 (100%)     0/222 (0%)         248/248 (100%)   -
hayward +unknown       26/26 (100%)     26/26 (100%)     7/222 (3%)
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
