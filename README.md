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
- **Treats parser coverage as a separate axis** from gadget recognition: whether a scanner reads the file at all (legacy multi-pickle layout, `.bin` dispatch, `EXT1` stack desync, `DUP` amplification). Four such bugs in Rowan were found this way, and none are about which callables are on a list.
- **Runs the shipped CLIs at shipped defaults**, so it measures what a user actually gets.

Whether that justifies a separate project rather than contributing cases upstream to one of the above is open, and not something this README should pretend to have settled.

## What it does

```bash
pip install -e .
pip install picklescan          # or modelscan, fickling, ...
python -m quickset.run
```

```
scanner        detection        false positives    errors
--------------------------------------------------------------
picklescan     12/13 (92%)      1/12 (8%)          -
modelscan       5/13 (38%)      0/12 (0%)          -
modelaudit     13/13 (100%)     9/12 (75%)         -
fickling       12/13 (92%)      7/12 (58%)         5
open-rowan     13/13 (100%)     0/12 (0%)          -
```

### Scored against externally-authored corpora

This corpus was written here, so its numbers flatter whatever it was written alongside. These were not, and they are now fetched and scored by the harness rather than by hand:

```bash
python -m quickset.external     # fetch
python -m quickset.run          # scores them alongside the built-in corpus
python -m quickset.external --purge   # delete; they are working exploits
```

They are gitignored, never committed, and never loaded or unpickled. Ground truth comes from each corpus author's own labelling; a file whose label the author does not state is excluded from scoring rather than assigned one.

```
                              picklescan  modelscan  modelaudit  fickling  open-rowan
picklescan tests/data (35)       34 (97%)   24 (69%)      not run  28 (80%)   34 (97%)
PickleCloak exp_*.pkl (57)       27 (47%)    0 ( 0%)      not run  57 (100%)  45 (79%)
PickleCloak AEG chains (97)      41 (42%)    0 ( 0%)      not run  97 (100%)  75 (77%)
```

**Neither of those external sets has a benign half**, so a scanner that flags every file scores 100% on both. fickling does approximately that: ShadowPickle measured it at a **94.5% false-positive rate on 3000 benign models**, and its 58% here is the same behaviour seen from the other side. Read those 100%s as "flags everything", not as detection.

picklescan's own corpus is its own test suite, so its 97% there means little; the informative columns are everyone else's.

The benign half is 8 real hash-pinned HuggingFace models plus 4 hand-written pickles. Fetch the real ones first. Without them the false-positive column is measured against synthetic files only, which is much weaker evidence:

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

## Design decisions

**No malicious files are committed.** Cases are specifications; bytes are generated into a temp directory at run time. A repository full of working pickle RCE payloads is a weapons cache, hazardous to contributors and likely to be flagged by the host.

**Payloads are inert by construction.** Each one resolves a genuinely dangerous callable, because that is what exercises the detection path, but the argument does nothing. Commands echo a marker string. Hosts and URLs use `.invalid`, the TLD RFC 2606 reserves as permanently non-resolvable, so even the DNS-exfiltration case cannot reach a network. A scanner reads the opcode stream and cannot tell the difference. A victim who actually loads one prints a marker.

**Detection and false positives are never combined into one score.** A scanner that flags every file has perfect detection; one that flags nothing has a perfect false-positive rate. Only the pair means anything, and single-number rankings are how benchmarks start lying.

**Case origins are declared.** `published-cve` and `published-technique` cases cite a source. Cases invented here are marked `quickset` and should be treated as the weakest evidence in the set: a benchmark whose author also writes the test cases can accidentally encode one scanner's detection logic as ground truth.

**Two distinct failure modes are scored separately.** Most cases test whether a scanner recognises a dangerous callable. Two (`legacy-layout-second-pickle`, `bin-extension-dispatch`) test whether it reads the file at all. A parser-coverage gap defeats every rule at once and deserves to be visible, not averaged away.

## Conflict of interest

This was built at Hedgerow, which makes Rowan, which is one of the entrants. That is a real conflict and pretending otherwise would be worse than disclosing it.

What is done about it: Rowan is invoked through the same subprocess adapter as everything else, with no import-level access and no special casing. Both parser-coverage cases were found by this corpus catching Rowan missing them, and Rowan's failures are in the results above and in git history rather than fixed quietly before first publication. The corpus is intended to be contributor-driven, and a case that Rowan fails is the most valuable contribution anyone can make.

If you do not trust the numbers, the harness is thirty lines and you can run it yourself. That is the point of it being open.

## Adding a case

Add a `Case` to `MALICIOUS` or `BENIGN` in `quickset/cases.py`. Payload arguments must stay inert; `tests/test_corpus.py` enforces that and will fail on a live command or a resolvable host.

Useful cases are ones where scanners disagree. A case every scanner catches measures nothing except that the harness works.

## Adding a scanner

Add an `Adapter` to `quickset/adapters.py` implementing `scan(path) -> ScanOutcome`.

Then run `tests/test_adapters.py`, which is the most important file here. During development the Rowan adapter read a JSON field named `file_path` when the actual field was `file`. Every lookup returned nothing, and the harness confidently printed `0/9 (0%)` for a scanner that detects 9 of 9. Nothing crashed. A benchmark's characteristic failure is not a crash, it is a plausible number, so every adapter is pinned against a file its scanner certainly flags and one it certainly does not.

The same class of error bites at the build level: an editable install pointed at a different checkout than the one under test, and the first "real" result scored the wrong build of Rowan entirely. Check which build you are actually measuring before believing a number.

## Status

Early, and its premise needs revisiting in light of the prior art above. The corpus is small and pickle-focused. Worth adding: Keras Lambda layers, ONNX custom operators, GGUF chat-template injection, and the ShadowPickle attack classes. [ModelAudit](https://www.promptfoo.dev/blog/open-sourcing-modelaudit/) (Promptfoo) is a fifth scanner with no adapter here yet.

## Licence

MIT, covering quickset's own code and case specifications.

It does not cover the models fetched by `quickset.realmodels`, which carry
their own licences (BSD-3-Clause, MIT, or unstated) and are downloaded to a
gitignored cache rather than redistributed here. Nor does it cover the scanners
under test, which are invoked as separate processes and never linked. That
matters for fickling in particular, which is LGPL-3.0.
