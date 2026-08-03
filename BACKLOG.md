# Backlog

Status as of 2026-08-03: the harness works and produces a real head-to-head,
but only two of four adapters have ever been run, and the corpus is small and
disproportionately authored by one person against one scanner. Both of those
are credibility problems before they are engineering problems.

## Blocking publication

* **No licence.** `pyproject.toml` has no `license` field and there is no
  LICENSE file. Needs deciding before anything is pushed anywhere public. Note
  the corpus generates payloads rather than shipping them, so the usual
  "malware sample repository" licensing questions do not apply, but the choice
  still interacts with Hedgerow's closed-source direction for Rowan.
* **No remote.** Four commits, local only.
* **No CI.** `tests/test_adapters.py` is the file that catches the failure mode
  this project is most prone to (an adapter that silently reads nothing and
  reports a confident zero), and it only runs when someone remembers.

## Corpus credibility

* **Authorship bias is the main weakness.** Of 13 cases, 6 were written here and
  4 of those exist because Rowan failed them. A benchmark whose author also
  writes the test cases and ships one of the entrants will encode that
  scanner's detection logic as ground truth unless actively resisted.
  `cases.py` marks origins for exactly this reason, and the README discloses
  the conflict, but the real fix is external contributions. A case that Rowan
  fails is the most valuable contribution anyone can make.
* **The benign half is 4 synthetic cases.** Detection numbers get all the
  attention, but the false-positive column is where a bad scanner is actually
  exposed, and four hand-written pickles is thin. Should pull real benign
  models: the Rowan repo already hash-pins four `pytorch_model.bin` files in
  `benchmark/ground_truth/clean_models/manifest.json` and that manifest could
  be shared or duplicated here. Wants sklearn/joblib and a model with a genuine
  third-party custom class, neither of which is currently represented anywhere.
* **`picklescan`'s one false positive is a single case.** `benign-stdlib-types`
  trips its `uuid: *` wildcard. That is a real precision difference, but one
  data point should not carry the claim on its own.

## Coverage

* **Two adapters have never been run.** `modelscan` (Apache-2.0) and `fickling`
  (LGPL-3.0, keep as a subprocess, do not link) are implemented and untested
  against a live install. Until they run, their columns are unpopulated and
  `test_adapters.py` skips them, which means an adapter bug in either would sit
  undetected. Highest-value item here.
* **Pickle-only.** Nothing covers Keras Lambda layers, ONNX custom operators, or
  GGUF chat-template injection, all of which are model-file code execution and
  all of which Rowan already scans. ColdwaterQ's DEFCON 30 deck points at a
  specific ONNX PoC: https://github.com/alkaet/LobotoMl/tree/main/ONNX_runtime_hacks
* **ShadowPickle (arXiv:2607.17503) is unrepresented.** Reports 63% evasion
  across ten scanners via the Pickle VM's external module import mechanism. If
  that number is reproducible it is the most important thing missing from this
  corpus, and if it is not reproducible that is worth publishing too.
* **No case scores severity, only flagged/not-flagged.** Deliberate for now,
  since severity vocabularies do not map across tools and forcing them into one
  scale is where benchmarks start lying. But it means a scanner reporting
  everything at INFO scores identically to one reporting CRITICAL, which is the
  exact failure this whole line of work started from.

## Harness

* **`ScanOutcome.errored` is collected and never surfaced.** The runner counts
  errors per scanner but the report does not print them, so a scanner erroring
  on every case looks the same as one flagging nothing.
* **Per-case timeouts.** `TIMEOUT_SECONDS = 120` is per subprocess with no
  overall bound. The `dup-amplification-billion-laughs` case is deliberately
  tuned to degrade visibly rather than hang, but a future resource-exhaustion
  case could stall a whole run.
* **Adapters run one file per subprocess.** Fine at 13 cases; will not scale to
  a corpus of hundreds, and Rowan in particular pays full process startup each
  time.

## Notes for whoever picks this up

The two failure modes that actually bit during development, both of which
produced confident wrong numbers rather than errors:

1. An adapter read a JSON field that did not exist (`file_path` vs `file`) and
   the harness printed `0/9 (0%)` for a scanner detecting 9 of 9.
2. An editable install pointed at a different checkout than the one under test,
   so the first "real" run scored the wrong build entirely.

Neither crashed. Check which build you are measuring, and run
`tests/test_adapters.py` before believing any number.
