# Comparative scanner study: plan

## The claim

**On real models people actually download, how often does each scanner cry
wolf, and how often does it quietly not look at all?**

Both halves matter. Detection rates are already measured by others. What is
missing from the literature is a false-positive rate on a real benign
population **with coverage reported as its own column**, so that a scanner
returning no verdict cannot be mistaken for a scanner returning a clean one.

Scanners: hayward, picklescan 1.0.5, modelscan 0.8.8, fickling 0.1.12,
modelaudit 0.2.52. All five have adapters in quickset already.

**Not** a detection benchmark. quickset already scores detection against
picklescan's corpus, MalHug and PickleCloak. Keep the two separate: mixing
them is how you get a number that means nothing.

**Sample:** the 1,000 repos already enumerated in
`data/pilot_sample_1000.jsonl`, seed 20260808, drawn from the ungated 100+
download tier. 5,347 scannable files, 5.29 TB, of which the range fetcher
reads about 1.1%.

---

## The problem that outranks everything else

**We are the vendor.** Any number we publish about our own tool against four
competitors is a marketing claim unless the method survives someone hostile
reading it. Three mitigations, in descending order of importance:

1. **Pre-register.** Write the scoring rules, tier mappings and thresholds
   into this repo, and commit them, **before** running the comparison. A
   threshold chosen after seeing results is not a threshold, it is a choice.
2. **Publish the harness and the manifest**, so a reader can re-run any row.
3. **Publish the result even if we lose.** If pre-registration only holds when
   the answer flatters us, it was decoration. Say so up front so there is no
   later temptation.

---

## Stage 0: pre-register the scoring rules

Nothing runs until these are committed.

**Tier mapping.** Each scanner has its own severity vocabulary, and
`docs/accuracy.md` already identifies this as the single largest lever on any
false-positive rate. Map each scanner's output into three buckets and report
**all three separately**, never collapsed:

| Bucket | Meaning |
|---|---|
| Actionable | The scanner says this file is dangerous |
| Unknown | The scanner saw something it could not classify (hayward INFO / `MFV-PICKLE-004`, picklescan `suspicious`, modelaudit `warning`) |
| No verdict | The scanner did not read the file: unsupported format, crash, timeout, size cap |

The headline number is the **actionable** rate on a benign population, since
that is what fails a build. The unknown rate is reported next to it, always.

**What counts as a false positive.** These are real Hub models, not a vetted
benign corpus, so a finding is a *review candidate*, not automatically an
error. Any actionable finding gets manually adjudicated and the verdict
recorded with its reasoning. The pilot's fourteen took about an hour, so this
is affordable at this sample size and would not be at twenty times it.

**Fairness constraints, stated before results exist:**

- **A scanner that does not support a format is "no verdict", never "missed".**
  modelaudit registers more formats than hayward; hayward must not benefit
  from a file modelaudit declined to parse.
- **fickling says plainly it is not built to gate a build.** Report it, and
  report that caveat next to it. Do not strawman a tool by scoring it against
  a purpose it disclaims.
- **Pin every version** and record it on every row, the same way the census
  already records the hayward version.
- **Default configuration for every scanner**, including ours. No tuning.

---

## Stage 1: per-scanner range validation (the gate)

The zero-divergence proof covers **hayward only**. The sparse copy has holes
everywhere hayward does not read. Another scanner may read a hole, get zeros,
and return a verdict that is an artifact of our optimisation. That would
silently disadvantage the competition, which is the single most damaging thing
this study could do to its own credibility.

Extend `scripts/range_compare.py` across all five adapters: same file, scanned
range-fetched and downloaded whole, verdicts diffed.

**Gate: zero divergence per scanner across at least 200 models spanning all
formats.** Per scanner, not in aggregate.

Any scanner that fails gets, in order of preference: a widened fetch plan
covering the union of what all five read; or full download for the formats
where it diverges; or exclusion from the study with the reason published.

Full download for everything is not available. The sample is 5.29 TB.

---

## Stage 2: the run

Fetch once, scan five times. Fetching dominates, so the marginal cost of each
extra scanner is close to zero.

Reuse `hub_census.py` with the file-level queue, per-file resume, per-repo
semaphore and per-repo caps already in place. One row per (file, scanner).

**Verify:** kill it mid-run and restart; it must resume without rescanning and
without dropping files. Already true for the single-scanner version.

Estimated 3 to 4 hours at the pilot's observed rate, dominated by fetching.

---

## Stage 3: adjudicate

Every actionable finding, from every scanner, reviewed by hand and recorded
with its reasoning, using the same standard for all five. The pilot's own two
false-positive classes are the model for this: root cause identified, not just
labelled wrong.

**Verify:** a second person, or a fresh session with no memory of the first
pass, reaches the same verdicts from the recorded evidence.

---

## Stage 4: publish

- Actionable, unknown and no-verdict rates per scanner, side by side.
- The manifest: repo, sha, file, scanner, version, verdict.
- The adjudication table with reasoning.
- The harness.
- Our own false positives named as prominently as anyone else's. The pilot
  found fourteen, all ours, twelve from a single regex bug. That belongs in
  the writeup whatever the comparison shows.

---

## Risks

**We look like we rigged it.** Pre-registration is the only real defence.
Everything else is decoration.

**A scanner is misconfigured by us and looks worse than it is.** Mitigation:
default config only, versions pinned, and the harness published so the authors
can object with specifics.

**The sparse copy biases a competitor.** Stage 1 exists entirely for this and
gates the whole study.

**Non-ASCII filenames fail to fetch**, which correlates with Chinese, Japanese,
Korean and Cyrillic publishers. Currently being fixed. The study must not run
until it is, or the population is quietly Anglophone.

**Hayward loses on some axis.** Likely on format breadth against modelaudit.
Publish it. A study that only runs when the vendor wins is worth nothing, and
the pilot has already shown we will publish our own bugs.
