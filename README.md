# picklebench

A neutral benchmark for ML model-file scanners. Detection and false positives, scored separately, on a corpus that generates itself.

Model-file scanners (picklescan, ModelScan, fickling, Rowan, and the scanning that hosting platforms run server-side) all claim to catch malicious pickles. There is no shared corpus to check that against, so every claim is self-reported against a private test set. This is an attempt at a public one.

## What it does

```bash
pip install -e .
pip install picklescan          # or modelscan, fickling, ...
python -m picklebench.run
```

```
case                           truth   picklescan   open-rowan
---------------------------------------------------------------
direct-os-system               MAL     o            o
cve-2025-71350-collect-env     MAL     o            o
cve-2025-1716-pip-main         MAL     o            o
cve-2025-46417-linecache-read  MAL     MISS         o
cve-2025-46417-ssl-exfil       MAL     o            o
attrgetter-chain               MAL     o            o
getattr-chain                  MAL     o            o
legacy-layout-second-pickle    MAL     o            o
bin-extension-dispatch         MAL     o            o
benign-state-dict              ben     .            .
benign-stdlib-types            ben     FP           .
benign-custom-class            ben     .            .
benign-paths-and-urls          ben     .            .
```

Scanners are invoked through their command-line interfaces as subprocesses, never imported. A scanner that is not installed is skipped, not failed.

## Design decisions

**No malicious files are committed.** Cases are specifications; bytes are generated into a temp directory at run time. A repository full of working pickle RCE payloads is a weapons cache, hazardous to contributors and likely to be flagged by the host.

**Payloads are inert by construction.** Each one resolves a genuinely dangerous callable, because that is what exercises the detection path, but the argument does nothing. Commands echo a marker string. Hosts and URLs use `.invalid`, the TLD RFC 2606 reserves as permanently non-resolvable, so even the DNS-exfiltration case cannot reach a network. A scanner reads the opcode stream and cannot tell the difference. A victim who actually loads one prints a marker.

**Detection and false positives are never combined into one score.** A scanner that flags every file has perfect detection; one that flags nothing has a perfect false-positive rate. Only the pair means anything, and single-number rankings are how benchmarks start lying.

**Case origins are declared.** `published-cve` and `published-technique` cases cite a source. Cases invented here are marked `picklebench` and should be treated as the weakest evidence in the set: a benchmark whose author also writes the test cases can accidentally encode one scanner's detection logic as ground truth.

**Two distinct failure modes are scored separately.** Most cases test whether a scanner recognises a dangerous callable. Two (`legacy-layout-second-pickle`, `bin-extension-dispatch`) test whether it reads the file at all. A parser-coverage gap defeats every rule at once and deserves to be visible, not averaged away.

## Conflict of interest

This was built at Hedgerow, which makes Rowan, which is one of the entrants. That is a real conflict and pretending otherwise would be worse than disclosing it.

What is done about it: Rowan is invoked through the same subprocess adapter as everything else, with no import-level access and no special casing. Both parser-coverage cases were found by this corpus catching Rowan missing them, and Rowan's failures are in the results above and in git history rather than fixed quietly before first publication. The corpus is intended to be contributor-driven, and a case that Rowan fails is the most valuable contribution anyone can make.

If you do not trust the numbers, the harness is thirty lines and you can run it yourself. That is the point of it being open.

## Adding a case

Add a `Case` to `MALICIOUS` or `BENIGN` in `picklebench/cases.py`. Payload arguments must stay inert; `tests/test_corpus.py` enforces that and will fail on a live command or a resolvable host.

Useful cases are ones where scanners disagree. A case every scanner catches measures nothing except that the harness works.

## Adding a scanner

Add an `Adapter` to `picklebench/adapters.py` implementing `scan(path) -> ScanOutcome`.

Then run `tests/test_adapters.py`, which is the most important file here. During development the Rowan adapter read a JSON field named `file_path` when the actual field was `file`. Every lookup returned nothing, and the harness confidently printed `0/9 (0%)` for a scanner that detects 9 of 9. Nothing crashed. A benchmark's characteristic failure is not a crash, it is a plausible number, so every adapter is pinned against a file its scanner certainly flags and one it certainly does not.

The same class of error bites at the build level: an editable install pointed at a different checkout than the one under test, and the first "real" result scored the wrong build of Rowan entirely. Check which build you are actually measuring before believing a number.

## Status

Early. The corpus is small and pickle-focused. Worth adding: Keras Lambda layers, ONNX custom operators, GGUF chat-template injection, and gadget classes from the ShadowPickle work (arXiv:2607.17503) that reports 63% evasion across ten scanners.

## Licence

Not yet chosen.
