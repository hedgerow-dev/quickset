# Backlog

Status as of 2026-08-03: all four adapters now run against live installs and
the head-to-head is real. The remaining weakness is the corpus: small, and
disproportionately authored by one person against one scanner. That is a
credibility problem before it is an engineering problem, so it leads.

### Done (2026-08-03)

Running `modelscan` and `fickling` for the first time immediately found two
adapter bugs, both of the "confident wrong number" kind this project exists to
avoid, and both caught by `tests/test_adapters.py` before any figure was
published:

* The `modelscan` adapter reported **every benign file as malicious**. Its JSON
  fallback matched the substring `"critical"`, which appears as `"CRITICAL": 0`
  in every clean report. The underlying cause was that `json.loads` failed at
  all: modelscan prints a human preamble before the report *and* its console
  renderer hard-wraps JSON at the terminal width, mid string-literal, producing
  genuinely invalid JSON. Now read via `-o <file>`, and the text fallback is
  deleted rather than repaired. An unparseable report is an adapter failure,
  not a detection result, and must never be scored as either.
* The `fickling` adapter scored **0 on everything**. `--check-safety` prints
  nothing at all on either verdict and signals only through its exit code; the
  adapter was matching output text that never exists. Now reads
  `--json-output`, which also exposes the four-level severity.

Also landed: `errors` is surfaced in the summary (previously counted and never
printed, so a scanner erroring on every case looked identical to one flagging
nothing), and `--verbose` prints each scanner's own verdict string per case.

**Real benign models** (`picklebench/realmodels.py`, 8 entries, SHA-256 pinned,
fetched not committed). Chosen for format diversity: zip torch, legacy non-zip
torch, raw-pickle joblib, zlib joblib, and two sklearn models carrying genuine
user-defined classes. They paid for themselves immediately:

* Rowan was analysing real sklearn models **by substring match alone**. joblib
  interleaves raw numpy bytes into the pickle stream, so the walk dies partway
  through the first pickle (byte 911 of 183761 in `sklearn-iris`) and Rowan
  discarded the five globals it had already resolved. Fixed upstream; 0 globals
  resolved before, 4-5 after.
* fickling rates three ordinary sklearn models as `LIKELY_OVERTLY_MALICIOUS`,
  and cannot open zip-format torch or zlib joblib at all ("No pickle found").
  No hand-written benign pickle would have surfaced either.

**Timeouts no longer crash the run.** The first time a scanner actually timed
out (fickling, on the DUP amplification case), `subprocess.TimeoutExpired`
propagated out of the runner and killed the whole benchmark. Timeouts are now
scored as errors, never as detections: a scanner that hangs has not detected
anything, and crediting it would reward the failure.

Note Python 3.13+ cannot run this benchmark: `modelscan` caps at `<3.13`.

## Premise and prior art

* **The project was built on an unchecked claim.** The README asserted that no
  shared corpus existed. It does: PickleBench (ShadowPickle, arXiv:2607.17503),
  PickleBall (arXiv:2508.15987), SafePickle (727 labelled HuggingFace files),
  MalHug (91 malicious models), PickleCloak (57), and picklescan's own public
  46-file labelled `tests/data`. The README now leads with this. The open
  question it raises is whether this project should exist separately at all,
  or whether its distinctive parts (inert generated payloads, a real benign
  half, parser-coverage as its own axis) are better contributed upstream.
* **The name is taken.** "PickleBench" is the ShadowPickle paper's benchmark,
  same domain, published first. Rename needed before this goes anywhere public.
* **Published results disagree with these.** ShadowPickle reports fickling at
  100% and picklescan/ModelScan at 0% against its attacks; this corpus ranks
  them close to the reverse. Worth understanding *why* before either number is
  quoted: it is probably corpus composition, but "probably" is not good enough
  to publish on.
* **ModelAudit (Promptfoo) has no adapter.** A fifth scanner, missed entirely
  because the entrant list was assembled from memory rather than from a search.
* **picklescan's `tests/data` is externally authored and directly usable**,
  which is the cheapest available fix for this project's authorship bias. It
  ships real (non-inert) payloads, so importing it would mean either relaxing
  the no-malicious-files rule or fetching to a gitignored cache the way
  `realmodels.py` already does. That is a deliberate decision, not a detail.

## Blocking publication

* **No licence.** `pyproject.toml` has no `license` field and there is no
  LICENSE file. Needs deciding before anything is pushed anywhere public. Note
  the corpus generates payloads rather than shipping them, so the usual
  "malware sample repository" licensing questions do not apply, but the choice
  still interacts with Hedgerow's closed-source direction for Rowan.
* **No remote.** Local only.
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
* **The benign half still has only 8 real models.** Better than the 4 synthetic
  pickles it started with, and it immediately earned its keep (see Done), but 8
  is not a corpus. All are small; none is a large real-world checkpoint, and
  there is no TensorFlow, ONNX or GGUF entry at all. Adding real models is the
  single cheapest way to make the false-positive column mean something.
* **`picklescan`'s one false positive is a single case.** `benign-stdlib-types`
  trips its `uuid: *` wildcard. That is a real precision difference, but one
  data point should not carry the claim on its own.

## Coverage

* **Severity is still not scored, only flagged/not-flagged.** Now the most
  important open item, because the four-way run made the cost visible.
  fickling's 58% false-positive rate is not really comparable to picklescan's
  8%: it grades on four levels, treats anything above `LIKELY_SAFE` as unsafe,
  and is built to be read by a human rather than to gate a pipeline. Reducing
  that to one bit flatters gate-shaped tools and penalises analysis-shaped
  ones. `--verbose` is the current escape hatch (raw verdicts, unnormalized)
  but the summary table still implies a comparison it cannot support. Any fix
  must avoid inventing a cross-tool severity scale, which is the thing that
  would make this benchmark start lying.
* **Pickle-only.** Nothing covers Keras Lambda layers, ONNX custom operators, or
  GGUF chat-template injection, all of which are model-file code execution and
  all of which Rowan already scans. ColdwaterQ's DEFCON 30 deck points at a
  specific ONNX PoC: https://github.com/alkaet/LobotoMl/tree/main/ONNX_runtime_hacks
* **ShadowPickle (arXiv:2607.17503) is unrepresented.** Reports 63% evasion
  across ten scanners via the Pickle VM's external module import mechanism. If
  that number is reproducible it is the most important thing missing from this
  corpus, and if it is not reproducible that is worth publishing too.

## Harness

* **No overall run timeout.** `TIMEOUT_SECONDS = 120` is per subprocess with no
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
3. Two adapters were written against CLIs that had never been run: one matched
   output text a tool never prints (scored it 0 on everything), the other
   matched a substring present in every clean report (scored every benign file
   as malicious).

None of them crashed. Check which build you are measuring, and run
`tests/test_adapters.py` before believing any number.
