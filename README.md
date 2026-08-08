# quickset

A benchmark for ML model-file scanners. Detection and false positives, scored separately, on a corpus that generates itself.

*Quickset* is the traditional term for living cuttings set in the ground to grow a hedge. The corpus here is grown the same way: nothing malicious is stored, only the cuttings it grows from.

## Prior art

An earlier version of this README claimed there was no shared corpus for this, and that this project was "an attempt at a public one". **That was wrong, and it was asserted without checking.** There is substantial prior work, including one benchmark whose name this project originally collided with:

| Corpus | Size / scope |
|---|---|
| [PickleBench](https://arxiv.org/html/2607.17503v1) (ShadowPickle) | Dynamic; injects attacks into arbitrary benign models, evaluates 5 scanners |
| [PickleBall](https://arxiv.org/pdf/2508.15987) | Compares PickleBall, ModelScan, ModelTRACER, PyTorch weights-only |
| [SafePickle](https://arxiv.org/html/2602.19818v1) | 727 labelled pickle files from HuggingFace |
| MalHug | 91 malicious HuggingFace models |
| PickleCloak | 57 malicious models |
| [picklescan `tests/data`](https://github.com/mmaitre314/picklescan/tree/main/tests/data) | 46 files, 35 malicious / 4 benign, public and labelled by filename |

Those results also disagree with the ones below in ways worth knowing before citing either. ShadowPickle reports **fickling at 100%** and **picklescan and ModelScan at 0%** against its attacks; this corpus ranks them close to the other way around. Different corpora measure different things, which is exactly why one benchmark's numbers should not be read as a scanner's general quality.

So this is not filling a vacuum. What it appears to do that the above do not:

- **Ships no malicious files.** MalHug and PickleCloak distribute real malicious models. Here payloads are generated at run time and are inert by construction.
- **Scores false positives against real benign models**, not detection alone. PickleBall's benign half is 2 models.
- **Treats parser coverage as a separate axis** from gadget recognition: whether a scanner reads the file at all (legacy multi-pickle layout, `.bin` dispatch, `EXT1` stack desync, `DUP` amplification). Four such bugs in Hayward (then named open-rowan) were found this way, and none are about which callables are on a list.
- **Runs the shipped CLIs at shipped defaults**, so it measures what a user actually gets.

Whether that justifies a separate project rather than contributing cases upstream to one of the above is open, and not something this README should pretend to have settled.

## What it does

```bash
pip install -e .
pip install picklescan          # or modelscan, fickling, ...
python -m quickset.run
```

**Python 3.12**, pinned deliberately: modelscan requires `<3.13`, so a newer
interpreter silently drops it and quietly turns a five-way comparison into a
four-way one. Any scanner you do not install is skipped rather than scored as
zero. A run takes a couple of minutes once the corpus is cached.

The malicious half is **generated at run time and never stored**, so a fresh
clone needs no network for it. The benign half is 215 real models fetched from
the HuggingFace Hub on first use and pinned by SHA-256; after that
`python -m quickset.realmodels` verifies the cache offline and re-fetches only
what is missing or has drifted from its hash.

Every scanner is scored at **two thresholds, always paired**: the strict tier (what the tool's own author calls actionable) and, as a `+unknown` row, the tier that includes its unknown bucket (picklescan's `suspicious`, modelaudit's `warning`, fickling's `SUSPICIOUS`, hayward's `INFO`). **Coverage** is the share of files the scanner returned any verdict on at all; errored files are excluded from every numerator and denominator. Measured 2026-08-06 on Python 3.12.13, with picklescan 1.0.5, modelscan 0.8.8, modelaudit 0.2.52, fickling 0.1.12 and hayward 1.0.0:

```
scanner                of files read    of corpus        false positives    coverage
----------------------------------------------------------------------------------
picklescan             12/24 (50%)      12/26 (46%)      1/192 (1%)         216/253 (85%)
picklescan +unknown    13/24 (54%)      13/26 (50%)      38/192 (20%)
modelscan              5/13 (38%)       5/26 (19%)       0/80 (0%)          93/253 (37%)
modelaudit             18/26 (69%)      18/26 (69%)      14/227 (6%)        253/253 (100%)
modelaudit +unknown    22/26 (85%)      22/26 (85%)      95/227 (42%)
fickling               16/17 (94%)      16/26 (62%)      90/94 (96%)        111/253 (44%)
hayward                26/26 (100%)     26/26 (100%)     0/227 (0%)         253/253 (100%)
hayward +unknown       26/26 (100%)     26/26 (100%)     7/227 (3%)
```

**Detection is given twice on purpose.** *Of files read* asks whether a scanner finds the payload once it has opened the file. *Of corpus* counts the files it never read as misses, which is what an operator actually gets. The two diverge sharply for tools with low coverage: fickling scores 94% on the first and 62% on the second, because it read 17 of the 26 malicious files. Quoting only the first column is how a scanner that reads very little comes to look accurate.

**Read the coverage column before either of them.** modelscan silently read zero files on 153 of 245 (mostly a removed private numpy API in its joblib path), fickling produced nothing on 138, and picklescan returned no verdict on 37. Only modelaudit and hayward returned a verdict on everything.

**Eight of the benign cases are traps built against specific detection signals**, not generic clean files: tensor names containing slashes, tensor spans that touch exactly, `external_data` naming a sibling shard, a Jinja chat template, a code-trained vocabulary containing `exec(` and `subprocess`, an xz-compressed sklearn payload, a weights blob whose first bytes coincide with a pickle PROTO marker, and two pickles separated by raw array data. Each one is legitimate and each one is what a plausible rule gets wrong. Three currently catch someone: modelaudit reports four issues on the coincidental PROTO marker, and fickling calls both the Jinja template and the code-trained vocabulary `LIKELY_UNSAFE`. The vocabulary case is not hypothetical, it caused two real false positives on unsloth releases before a Hub sweep found them.

**A corpus where the author's tool wins everything is a corpus that was written to let it, so treat the 26/26 with suspicion.** It was 25/26 until recently. `joblib-payload-after-raw-array` puts the gadget after raw ndarray bytes, where a walker that stops at the first unparseable byte never reaches it. That case was added marked as a known miss on the assumption nothing detected it; the first run reported that modelaudit did and hayward did not, and hayward was fixed in response. The mechanism worked, but it leaves this table without a case its author loses, which is a weakness in the corpus rather than a strength of the scanner. **A case hayward fails is the most valuable contribution anyone can make here.**

These numbers are not comparable to those published on 2026-08-04, for three reasons at once:

- The corpus grew by eleven cases drawn from published hub bypass proofs of concept, which lowered every detection rate.
- **picklescan had been credited with clean verdicts on files it never opened.** It declines to read a file in two ways and only one of them says so, printing `could not parse as pickle` for a malformed pickle but nothing at all for a format it has no reader for (measured: keras zip, tflite, skops). The adapter caught the first and read the second as a clean scan. Fourteen benign files moved from true negatives to errors, dropping coverage from 91% to 85% and the false-positive denominator from 198 to 184.
- **`open-rowan` is now `hayward`, and its adapter could not observe non-coverage at all.** It treated any written report as a verdict, so a file the scanner declined to read counted as covered, and since the coverage rules carry a severity, as a finding. That was the one asymmetry the coverage column exists to rule out, in the entrant this project's author ships. The adapter now reads the `coverage_gaps` array hayward puts in its own report, and `tests/test_adapters.py` pins it against an eight-byte file that triggers one. A perfect coverage column is not evidence the check works; it is what the bug looked like.

### Scored against externally-authored corpora

This corpus was written here, so its numbers flatter whatever it was written alongside. These were not, and they are now fetched and scored by the harness rather than by hand:

```bash
python -m quickset.external     # fetch
python -m quickset.run          # scores them alongside the built-in corpus
python -m quickset.external --purge   # delete; they are working exploits
```

They are gitignored, never committed, and never loaded or unpickled. Ground truth comes from each corpus author's own labelling; a file whose label the author does not state is excluded from scoring rather than assigned one. Each is **pinned to an upstream commit**, not to a branch head: these repositories keep moving, and an unpinned fetch meant the numbers below were measured on a snapshot nobody could name or get back. 
**The figures below are stale in three ways and should be re-run before anyone quotes them.** They were measured against unpinned branch heads, before the coverage-accounting fixes to the picklescan and hayward adapters, and while hayward was still called open-rowan. The rows are left labelled as they were measured rather than relabelled to a tool version that did not produce them.

```
picklescan tests/data (36 malicious):   picklescan 34 (94%) strict / 36 (100%) incl. unknown
                                        modelscan 24 (83%) | modelaudit 30 (83%) | fickling 29/29 | open-rowan 35 (97%)
PickleCloak exploits (57):              picklescan 27 (47%) strict / 57 (100%) incl. unknown
                                        modelscan 0 | modelaudit 51 (89%) | fickling 57 (100%) | open-rowan 49 (86%)
PickleCloak AEG chains (97):            picklescan 41 (42%) strict / 97 (100%) incl. unknown
                                        modelscan 0 | modelaudit 69 (71%) | fickling 97 (100%) | open-rowan 91 (94%)
```

**Neither PickleCloak set has a benign half**, so a scanner that flags every file scores 100% on both. The unknown-tier rows make that visible directly: picklescan and open-rowan both *see* 100% of PickleCloak files; the entire gap between 47%/42% and 86%/94% is which tool promotes what it saw to actionable. fickling's 100% at its actionable tier costs a 40% false-positive rate on real models: ShadowPickle measured it at 94.5% on 3000 benign models, and its 40% here is the same behaviour seen from the other side. Read those 100%s as "flags nearly everything", not as detection.

picklescan's own corpus is its own test suite, so its numbers there mean little; the informative columns are everyone else's.

The benign half is **215 real hash-pinned HuggingFace models** across 14 formats, 64 publishers and vintages 2020-2026, plus 4 hand-written pickles. The corpus is built by `scripts/build_benign_manifest.py` (HF API selection, security-rollup filter, magic-byte classification, SHA-256 pinning), and the cache is gitignored and never committed:

```bash
python -m quickset.realmodels
```

Run `--verbose` for each scanner's own verdict string per case, unnormalized.

Scanners are invoked through their command-line interfaces as subprocesses, never imported, and scored at their own shipped defaults. A scanner that is not installed is skipped, not failed.

**Read those columns carefully, because they are not measuring the same thing.** fickling grades on four severity levels and treats anything above `LIKELY_SAFE` as unsafe; it is built to be read by a human, not to gate a pipeline. Its false-positive column reflects that design goal, not a defect. It rates `OrderedDict.update(...)` as "can execute arbitrary code", which is *true* and also not what a CI gate wants. modelscan's low detection is the opposite trade: it is the most conservative of the four and missed every gadget that is not on its operator list, including cloudpickle (verified: 0 issues, 0 errors, not an adapter artifact).

Results worth singling out because they are about the tools, not the corpus:

- picklescan and fickling **both** rate an ordinary pickled `uuid.UUID` as dangerous, from independent causes (a `uuid: *` module wildcard, and an "overtly malicious" import rule).
- fickling rates three ordinary sklearn models (`sklearn-iris`, `mlewp-sklearn-wine`, `plain-sklearn`) as `LIKELY_OVERTLY_MALICIOUS`. Adding real models is what surfaced this; no hand-written benign pickle would have.
- fickling **errors on five cases**: it cannot open zip-format torch checkpoints or zlib-compressed joblib ("No pickle found"), and it **crashes** on the `EXT1` opcode. ColdwaterQ flagged this class in the DEFCON 30 talk: "Bugs prevent loading every pickle."
- fickling **times out** (120s) on the `DUP` amplification case. Counted as an error, never as a detection. A scanner that hangs has not detected anything, and crediting it would reward the failure.
- modelscan is the most conservative of the four and misses every gadget not on its operator list, including cloudpickle (verified: 0 issues, 0 errors, not an adapter artifact).

## Reading the Hub without downloading it

A Hub-scale false-positive measurement is bounded by download volume, not by
scan time. Scanning a large sample of public checkpoints the obvious way means
tens of terabytes. But a torch checkpoint is a zip whose tensor storage is
almost all of it, and the pickle that decides what executes on load is one
small member, so HTTP range requests can read that member and leave the
weights on the server. `quickset/rangefetch.py` does this;
`scripts/range_compare.py` is the reason to believe it.

What the fetcher writes is **not a fragment handed to the scanner**. It is a
sparse local copy of the remote file: the same filename, the same total
length, the fetched ranges written at their true offsets, and holes everywhere
else. The scanner is then pointed at that path and runs its ordinary code over
it. Nothing about zip parsing, magic sniffing, extension dispatch or the
scanner's own size limits is reimplemented in the fetcher, so none of it can
drift out of agreement with the scanner later.

| Format | What is read |
|---|---|
| torch zip (`PK`) | end-of-central-directory, the central directory, then per member its local header and first four bytes, then in full only the members the scanner parses |
| torch legacy (`\x80`) | a prefix grown until every pickle stream in it has reached STOP and the bytes after the last one are plainly not another pickle |
| SafeTensors | the 8-byte length prefix and the JSON header |
| GGUF | the header, the KV metadata and the tensor-info table |
| any flat format past hayward's 500 MB in-memory cap | nothing past the first 4 KB, because the scanner reads nothing either and reports non-coverage from the size alone |
| ONNX, Keras, TFLite, skops, npz, joblib, msgpack, ... | downloaded whole, or recorded as **not sampled** above the size limit |

**Counting pickle streams is the mistake the legacy strategy exists to avoid.**
`torch.save`'s legacy path writes *five* of them (magic number, protocol
version, `sys_info`, the object, and the sorted storage-key list) before a byte
of tensor data, not the four that a reading of the format suggests. A prefix
cut after the fourth ends mid-stream, and hayward 1.0.1 reports MFV-SKIP-003
when it sees one. So the fetcher does not count: it grows the prefix until the
bytes following the last completed stream are no longer a pickle. Any
unexplained MFV-SKIP-003 in a range-fetched run is a bug in the fetcher, not a
property of the model.

**A format with no range strategy is downloaded or recorded, never dropped.**
An omitted file does not lower a false-positive rate honestly, it corrupts the
denominator, which is the only thing the exercise produces.

### The gate

A fetcher that is 99% right is useless here, because the output is a rate and
the errors land directly in it rather than averaging out. So every sampled
file is scanned twice, once against the sparse range-fetched copy and once
against the whole file downloaded from the same URL in the same run, and the
two finding lists are compared verbatim: rule id, severity and message text,
which carries the zip member name and the resolved callables.

```bash
python scripts/range_compare.py --sample 260 --max-size 150000000
```

Measured 2026-08-08 against live Hub repositories with hayward 1.0.1, on 260
files from 178 repositories covering all fourteen formats the manifest records
by magic bytes:

```
compared    260
DIVERGED    0
not sampled 0
errored     0

strategy         files    read              of                share
------------------------------------------------------------------
full-small          77       2.5 MB          0.002 GB      100.00%
full                77    3026.2 MB          3.026 GB      100.00%
full-fallback        6     152.1 MB          0.152 GB      100.00%
torch-zip           27      98.5 MB          0.419 GB       23.50%
torch-legacy        22     126.6 MB          0.947 GB       13.37%
gguf                12      50.4 MB          0.649 GB        7.76%
safetensors         39       0.3 MB          0.855 GB        0.04%
------------------------------------------------------------------
range strategies   100     275.8 MB          2.870 GB        9.61%
```

**The whole-download rows are in that table on purpose.** They cannot diverge,
and they are still the majority of the sample, because the claim being made is
about the denominator and not about the saving.

**Read the percentages against the file sizes that produced them.** This
sample is capped at 150 MB per file, because the control half has to download
everything it compares, and at that size a "checkpoint" is often mostly
pickle: the smallest torch zips here are 99% pickle member and the strategy
saves nothing on them. The saving is a function of how much of a file is
tensor data, so the same fetcher over 48 large real files, from 400 MB to
165 GB, with no comparison half and therefore no cap, reads **805 MB of
1,242 GB, 0.065%**: 1.2% on multi-gigabyte torch shards (including a zip64
one), 0.001% on SafeTensors, and 4 KB flat on GGUF quantisations past the
scanner's in-memory cap.

The politeness cost is requests, not bytes. A member's first four bytes have
to be read to know whether the scanner will parse it, and those windows sit
megabytes apart, so a checkpoint with three hundred storages takes a few
hundred range requests however few bytes they carry. Narrow gaps are bridged
against a byte budget to cut that down; the run above averaged four requests
per file and peaked at 120.

**One gap is real and this design does not close it.** A whole-buffer pass
over a region that was never fetched reads zeros. Hayward has one, the
embedded-executable scan behind MFV-EXEC-001, which runs over every byte of
files under its in-memory cap. Ranges that *are* fetched (container headers,
pickle members, metadata) are covered normally, so a binary stapled into a
pickle member is still found; one buried in raw tensor data between two
fetched ranges is not. That is a property of range reading, not of this
implementation, and the comparison above is how often it costs anything rather
than an argument that it cannot.

## Design decisions

**No malicious files are committed.** Cases are specifications; bytes are generated into a temp directory at run time. A repository full of working pickle RCE payloads is a weapons cache, hazardous to contributors and likely to be flagged by the host.

**Payloads are inert by construction.** Each one resolves a genuinely dangerous callable, because that is what exercises the detection path, but the argument does nothing. Commands echo a marker string. Hosts and URLs use `.invalid`, the TLD RFC 2606 reserves as permanently non-resolvable, so even the DNS-exfiltration case cannot reach a network. A scanner reads the opcode stream and cannot tell the difference. A victim who actually loads one prints a marker.

**Detection and false positives are never combined into one score.** A scanner that flags every file has perfect detection; one that flags nothing has a perfect false-positive rate. Only the pair means anything, and single-number rankings are how benchmarks start lying.

**Case origins are declared.** `published-cve` and `published-technique` cases cite a source. Cases invented here are marked `quickset` and should be treated as the weakest evidence in the set: a benchmark whose author also writes the test cases can accidentally encode one scanner's detection logic as ground truth.

**Two distinct failure modes are scored separately.** Most cases test whether a scanner recognises a dangerous callable. Two (`legacy-layout-second-pickle`, `bin-extension-dispatch`) test whether it reads the file at all. A parser-coverage gap defeats every rule at once and deserves to be visible, not averaged away.

## Conflict of interest

This was built at Hedgerow, which makes Hayward, which is one of the entrants. That is a real conflict and pretending otherwise would be worse than disclosing it.

What is done about it: Hayward is invoked through the same subprocess adapter as everything else, with no import-level access and no special casing. Both parser-coverage cases were found by this corpus catching it missing them, and its failures are in the results above and in git history rather than fixed quietly before first publication. It is MIT and on PyPI, so unlike its predecessor a public CI runner can install it and every number above can be reproduced by someone who does not work here. The corpus is intended to be contributor-driven, and a case Hayward fails is the most valuable contribution anyone can make.

The most recent thing it caught is in the results table above: Hayward's adapter was the only one of the five with no way to observe the scanner declining to read a file, which flattered exactly the column it looked best in. That is what a conflict of interest looks like in practice. It does not arrive as a thumb on the scale, it arrives as the one adapter nobody thought to check.

If you do not trust the numbers, `run.py` and `adapters.py` are about 850 lines between them, `--json` records every scanner's version alongside the results, and you can run the whole thing yourself. That is the point of it being open.

## Adding a case

Add a `Case` to `MALICIOUS` or `BENIGN` in `quickset/cases.py`. Payload arguments must stay inert; `tests/test_corpus.py` enforces that and will fail on a live command or a resolvable host.

Useful cases are ones where scanners disagree. A case every scanner catches measures nothing except that the harness works.

## Adding a scanner

Add an `Adapter` to `quickset/adapters.py` implementing `scan(path) -> ScanOutcome`.

Then run `tests/test_adapters.py`, which is the most important file here. During development the Hayward adapter read a JSON field named `file_path` when the actual field was `file`. Every lookup returned nothing, and the harness confidently printed `0/9 (0%)` for a scanner that detects 9 of 9. Nothing crashed. A benchmark's characteristic failure is not a crash, it is a plausible number, so every adapter is pinned against a file its scanner certainly flags and one it certainly does not.

The same class of error bites at the build level: an editable install pointed at a different checkout than the one under test, and the first "real" result scored the wrong build of the scanner entirely. Check which build you are actually measuring before believing a number.

## Status

Early, and its premise needs revisiting in light of the prior art above. The corpus is still mostly pickle. Worth adding: Keras Lambda layers, ONNX custom operators, GGUF chat-template injection, and the ShadowPickle attack classes. [ModelAudit](https://www.promptfoo.dev/blog/open-sourcing-modelaudit/) (Promptfoo) now has an adapter and is in the table above.

The open item is the external-corpus block, which is stale on three counts and needs re-running. Beyond that, two of the five adapters have now been caught crediting their scanner for files it never read, both in the harness rather than in the scanners, which is not a count that suggests the answer is two. modelscan and fickling deserve the same audit.

## Licence

MIT, covering quickset's own code and case specifications.

It does not cover the models fetched by `quickset.realmodels`, which carry
their own licences (BSD-3-Clause, MIT, or unstated) and are downloaded to a
gitignored cache rather than redistributed here. Nor does it cover the scanners
under test, which are invoked as separate processes and never linked. That
matters for fickling in particular, which is LGPL-3.0.
