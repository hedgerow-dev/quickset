# Backlog

## Done (2026-08-06): two adapters were crediting themselves for files never read

Both are the same accounting error, in the harness rather than in any scanner,
and both produced a plausible number rather than a failure.

* **picklescan.** It declines to read a file in two ways and only one of them
  says so: a malformed pickle prints `could not parse as pickle`, while a
  format it has no reader for prints nothing at all and reports
  `Scanned files: 0`, which is byte-for-byte a clean scan. The adapter caught
  the first and read the second as a true negative. Measured: 14 benign files
  (9 keras zip, 3 tflite, 2 skops) were counted as cleared. Published coverage
  was 91% and is 85%; the false-positive denominator was 198 and is 184.
  Regression test added to `test_adapters.py`, which needs no fetched corpus:
  a zip named `.keras` reproduces it.
* **hayward, and this one is the conflict of interest
  showing up in code.** The adapter had no way to observe non-coverage at all.
  It treated any written report as a verdict, so a file the scanner declined
  to read counted as covered, and since the coverage rules carry a severity,
  as a *flag*. It was the only one of the five adapters with no non-coverage
  signal, and it belonged to the entrant this project's author ships, in the
  column it scored 100% in.

  The fix does not match rule ids. hayward publishes `coverage_gaps` in its
  own JSON report and its docs say a scorer should count those in a column of
  their own, so the adapter takes the report's word for it. The hand-kept id
  list in `scripts/malhug_scan.py` was already two entries stale
  (`MFV-7Z-001`, `MFV-GGUF-004`), and worse, that script filtered INFO
  findings out before checking ids, so it could never have matched either of
  them. Both scripts now read `coverage_gaps` too.

  Pinned by `test_adapters.py` against an eight-byte 7z header, which trips
  `MFV-7Z-001` with no corpus to fetch. **A perfect coverage column is not
  evidence the check works. It is what the bug looked like.**

Also landed:

* **Scanner versions are recorded.** `--json` pinned the corpus manifest and
  nothing about the four tools that produced the numbers. It now records each
  scanner's version, the interpreter and the platform, and the summary line
  prints them.
* **External corpora are pinned to commits.** They were fetched from
  `refs/heads/main`, so every number published against picklescan's test data
  and PickleCloak was measured on a snapshot nobody could name or get back.
  The benign manifest pins SHA-256 for this exact reason. Enforced by a test.
* **`test_malicious_case_actually_contains_a_gadget` was checking nothing.**
  It asserted `b"\x93" in blob or b"c" in blob`; a lone `b"c"` occurs in
  almost any binary, so it passed unconditionally for the skops archives and
  every non-pickle case. Rewritten per family, and it immediately caught a
  live case: `safetensors-name-crlf` built its header through `json.dumps`,
  which escapes the CRLF to the four characters `\r\n`, so the case carried
  none of what it claimed.
* **An ONNX case pointed at 169.254.169.254**, the cloud instance metadata
  endpoint. The inertness rule (`.invalid` hosts, RFC 2606) is the constraint
  that makes this corpus safe to run in CI, and the inertness test missed it
  because it only walked pickle opcodes and `genops` throws on byte 0 of a
  protobuf. Payload now uses `.invalid`, and the test has a format-agnostic
  raw-bytes pass that rejects any resolvable host or literal IPv4.
* **`joblib-payload-after-raw-array` is no longer a known miss:** modelaudit
  flags it at its critical tier. Kept in the corpus; the other three miss it.

## Done (2026-08-06): scanner naming and packaging

Hayward 1.0.0, MIT, on PyPI. Three consequences beyond the rename:

* **CI can install it.** The previous entrant was closed source and could not
  be installed on a public runner, so its adapter was the one the CI job could
  not exercise. That is not a coincidence with the bug above; it is the
  mechanism. `pip install hayward` is now in the workflow and every number in
  the README can be reproduced by someone who does not work at Hedgerow.
* **The adapter got smaller.** It targets the file instead of the parent
  directory, so there is no sibling-file asymmetry and no filename matching,
  which is where the historic `file_path` vs `file` bug lived. JSON comes off
  stdout, so the tempfile dance is gone, as are the `--no-sca --no-taint
  --no-cross-file` flags: hayward has no source-code passes to switch off.
* **The table is re-measured and hayward's row is restored:** 25/26 detection,
  0/219 false positives, 245/245 coverage, 7/219 at the INFO tier.

**It misses `joblib-payload-after-raw-array`, and modelaudit catches it.** That
is the only case where the scanner this project is built alongside loses
outright to a competitor, and it is the most useful row in the table. Keep it.

### Still open

* **Ask the same question of modelscan and fickling.** Two of five adapters
  were found crediting their scanner for unread files, which is not a number
  that suggests the answer is two.
* **Re-run the external-corpus block.** It is stale three ways: unpinned
  branch heads, pre-fix coverage accounting, and the old tool name.
* **Re-run `scripts/hub_sweep.py` and `scripts/malhug_scan.py`.** Both were
  invoking an executable that no longer exists and are updated but unrun. The
  docs in `docs/` still carry numbers from earlier builds.
* **`model-cache/` holds 92 directories, 0.78 GB, from a previous manifest.**
  Not scored (`cached_models()` filters by manifest) and not deleted here,
  since re-fetching costs bandwidth. Left for a decision.

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

**Real benign models** (`quickset/realmodels.py`, 8 entries, SHA-256 pinned,
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
* **Done: renamed to `quickset`** (2026-08-03). The original name collided with
  the ShadowPickle paper's PickleBench, same domain, published first. The new
  name fits the Hedgerow project family (Rowan, Thicket, Briar, Blackthorn) and
  is the traditional term for living cuttings set to grow a hedge, which is how
  this corpus works. Note there are unrelated commercial products called
  QuickSet, including a physical-security company, so search results will be
  noisy even though the PyPI name was free.
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

* **Done: external corpora are now fetched and scored by the harness**
  (`quickset/external.py`), not by hand. picklescan's 46-file set and
  PickleCloak's 154 exploit pickles run on every `quickset.run`. This was
  the highest-leverage item outstanding: every bypass fixed in Rowan during
  this project's development came from an external corpus or from adversary
  literature, and none from reviewing Rowan's own rules, yet nothing re-ran
  those corpora. Now something does.

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

* **Done: both severity thresholds are now scored** (2026-08-04). Every
  adapter reports the strict tier (what the tool's author calls actionable)
  and the unknown tier (picklescan's suspicious, modelaudit's warning,
  fickling's SUSPICIOUS, hayward's INFO), printed as a separate
  "+unknown" row. This immediately corrected a published number: modelaudit's
  benign FP rate is 13/219 at critical, not 94 (its warning tier). No
  cross-tool severity scale was invented; the tiers are each tool's own.
* **Done: hub-scale sweep** (2026-08-04). 1,185 unvetted public files, 495
  repos, 17 flagged: 9 FPs in two classes (both fixed), 8 true detections on
  four bypass-PoC repos the sweep surfaced itself. Method, per-file review
  and verbatim results: `docs/hub-sweep-2026-08-04.md` (+ `.json`). Repeat
  on every release candidate.
* **Done: range-request sampling** (2026-08-08). `quickset/rangefetch.py` reads
  only the bytes a scanner will look at, so a sweep is no longer bounded by
  download volume. It writes a *sparse* copy of the remote file, same name and
  same length with holes where nothing was fetched, rather than a fragment, so
  the scanner's own zip parsing, magic sniffing, extension dispatch and size
  limits all run unchanged over real bytes at real offsets and cannot drift out
  of agreement with a fetcher that re-derived them. Proved by
  `scripts/range_compare.py`, which scans every sampled file both ways and
  diffs the findings verbatim: 260 files, 178 repositories, all fourteen
  manifest formats, **0 divergences, 0 errors, 0 recorded as not sampled**. On
  a separate mix of 48 large files (400 MB to 165 GB, no comparison half and
  so no size cap) the fetcher reads 805 MB of 1,242 GB. One gap is stated rather
  than closed: a whole-buffer pass over an unfetched region reads zeros, which
  for hayward means an executable buried in raw tensor data between two fetched
  ranges does not reach MFV-EXEC-001.
* **Both growing prefixes overshoot.** Neither the GGUF metadata section nor a
  legacy checkpoint's pickle region declares its length anywhere, so the prefix
  grows blind from 1 MB in steps of four and can fetch several times what it
  needs. Negligible on a multi-gigabyte file, 8-13% on the 20-45 MB ones in the
  corpus. A projected hint (GGUF's token-array element count; the pickle walk's
  own stopping offset) would fix the GGUF side; the legacy side would mostly be
  fixed by starting smaller.
* **Range reading costs requests, not bytes.** The scanner reads the first four
  bytes of every zip member, so the fetcher does too, and a checkpoint with
  three hundred tensor storages takes a few hundred range requests carrying a
  few hundred kilobytes. Measured peak on the comparison run: 120 requests for
  one file, and 304 on a multi-gigabyte shard. That, rather than bandwidth, is
  what will decide how fast a full Hub sweep can politely go.
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
