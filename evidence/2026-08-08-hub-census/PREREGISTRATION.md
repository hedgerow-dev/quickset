# Pre-registration: comparative false-positive study

**Committed before the comparison is run.** Everything below is fixed in
advance so that no threshold, mapping or exclusion can be chosen after seeing
which way the result falls. If a rule here turns out to be wrong, the
amendment gets its own commit saying what changed and why, and the original
stays in history.

Written 2026-08-08. Hayward is our own tool. This document exists because a
vendor's number about its own product is a marketing claim unless the method
survives a hostile reader.

---

## 1. The question

On a benign population of real Hub models, for each scanner:

- how often does it report something **actionable** (the tier that would fail
  a build), and
- how often does it return **no verdict at all** (unsupported format, crash,
  timeout, size cap)?

This is **not** a detection study. Detection is measured separately in this
repo against picklescan's corpus, MalHug and PickleCloak. The two must not be
combined into a single score.

## 2. Sample, fixed in advance

`data/pilot_sample_1000.jsonl`: 1,000 repos, `random.seed(20260808)`, drawn
from ungated repos with 100 or more downloads that carry at least one
pickle-bearing file. 5,347 scannable files.

The sample is **not** re-drawn after seeing results. If files fail to fetch,
they are reported as fetch failures against a fixed denominator, not silently
replaced.

## 3. Scanners and versions, pinned

    hayward==1.0.1        (ours; will be re-pinned to the release that fixes
                           MFV-PICKLE-006, and the run redone, not patched)
    picklescan==1.0.5
    modelscan==0.8.8
    fickling==0.1.12
    modelaudit==0.2.52

**Default configuration for every scanner, including ours.** No tuning, no
custom rule sets, no threshold adjustment. The version is recorded on every
result row.

## 4. Scoring

This adopts `quickset.adapters.ScanOutcome`, which already encodes the rule
and predates this study:

| Bucket | Field | Meaning |
|---|---|---|
| Actionable | `flagged` | The tier the tool's own authors call actionable |
| Actionable + unknown | `flagged_lenient` | Additionally counts the tool's unknown tier: picklescan `suspicious`, modelaudit `warning`, fickling `SUSPICIOUS`, hayward INFO |
| No verdict | `errored` | The tool did not read the file |

**Both thresholds are reported, always, for every scanner.** Scoring one tool
at its strict tier while counting another's unknown tier is the specific
unfairness this exists to prevent. Where a tool has no distinguishable unknown
tier, both numbers are the same and that is stated.

**No verdict is never scored as clean and never as a miss.** It is its own
column. This is the whole reason coverage is in the study.

## 5. Fairness rules

- **Unsupported format is "no verdict", not "missed".** modelaudit registers
  more formats than hayward. Hayward must not be credited for a file another
  tool declined to parse.
- **fickling is reported with its own disclaimer attached.** Its authors state
  it is not built to gate a build. Scoring it against a purpose it disclaims
  would be a strawman.
- **picklescan's deny-list data is upstream of hayward's** and is credited in
  hayward's NOTICE. Any result where hayward beats picklescan on files that
  data covers must say so.
- **A crash is a no-verdict, not a pass.** Timeouts likewise, at a fixed limit
  applied identically to all five.

## 6. Adjudication

These are unvetted real models, so an actionable finding is a review
candidate, not automatically a false positive.

Every actionable finding from every scanner is reviewed by hand, to the same
standard, and recorded with its reasoning and root cause. Not a label, a
diagnosis. The verdicts and the evidence are published together.

At 1,000 repos this took about an hour for hayward's fourteen findings. It is
affordable here and would not be at twenty times the sample, which is a reason
this study is not larger.

## 7. Method validity gate

The range fetcher writes a **sparse local copy** with holes wherever the
scanner is not expected to read. It is proven for hayward: 260 models, 178
repos, 14 formats, scanned both range-fetched and whole, zero divergences.

**That proof does not transfer.** Before the comparison runs, each of the
other four scanners must independently reach **zero divergence across at least
200 models spanning all formats**. A scanner that does not is either given a
widened fetch plan, or downloaded in full for the formats where it diverges,
or excluded with the reason published.

Running a comparison on a fetch strategy tuned to our own tool's read pattern
would be the most damaging thing this study could do, and it would be
invisible in the results.

## 8. Known defects that must be fixed before the run

- **MFV-PICKLE-006** flags any binary argument over roughly 4 KB. Twelve of
  hayward's fourteen pilot findings were this one bug.
- **Non-ASCII filenames fail to fetch.** This correlates with Chinese,
  Japanese, Korean and Cyrillic publishers, so running before it is fixed
  would measure a quietly Anglophone subset.

## 9. Publication commitment

The result is published whatever it shows, including if hayward performs worst
on any axis. Format breadth against modelaudit is the most likely such axis.

Hayward's own false positives are named as prominently as anyone else's.

If this study is abandoned after the results are known, this file stays in the
repository and the reason is recorded.
