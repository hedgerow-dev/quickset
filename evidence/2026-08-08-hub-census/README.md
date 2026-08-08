# Hub census, 2026-08-08

Evidence archive. Everything here was produced on 2026-08-08 and is kept so a
blog post or paper can be written against real artifacts rather than
recollection.

**Scanner under test: hayward 1.0.1** (PyPI). Every result row records the
version that produced it, so a later release cannot silently reinterpret these
numbers.

---

## What was done

**Stage 1, full enumeration of the Hub.** Metadata only, no file contents.
Paged `huggingface.co/api/models` with `full=true`, authenticated, 1000 per
page, identifying user agent, 0.15s between pages, backoff on 429.

| | |
|---|---|
| Model repos on the Hub | 2,975,172 |
| With a file hayward can read | 2,406,067 (80.9%) |
| **Able to carry a pickle** | **1,199,071 (40.3% of all repos)** |
| Gated, needing auth | 14,944 |

Pickle-bearing file counts: 3,224,465 `.pt`, 2,245,375 `.bin`, 1,324,869
`.pth`, 536,209 `.pkl`, 408,858 `.zip`, 329,622 `.npy`, 175,084 `.npz`,
132,873 `.ckpt`, 25,930 `.joblib`, 4,953 `.pickle`.

Downloads are extremely skewed, which is the finding that shaped the design:

| Downloads | Repos | Share |
|---|---|---|
| 0 | 462,692 | 38.6% |
| 1 to 9 | 623,208 | 52.0% |
| 10 to 99 | 92,774 | 7.7% |
| 100 to 999 | 14,277 | 1.2% |
| 1,000 to 9,999 | 3,571 | 0.3% |
| 10,000+ | 2,549 | 0.2% |

**90.6% of pickle-bearing repos have fewer than ten downloads.** A uniform
random sample would therefore measure the Hub's litter rather than anything
people load, which is why the plan moved from sampling to a census of the
100+ tier (20,397 repos, of which 20,079 ungated).

**Stage 3, pilot.** 1,000 repos drawn from the ungated 100+ tier with
`random.seed(20260808)`, read by HTTP range rather than downloaded whole.

---

## Files

| Path | What it is |
|---|---|
| `data/hub_enumeration_2026-08-08.jsonl.gz` | Every repo with a readable file: id, sha, downloads, likes, gated, file lists. 1.6 GB raw, 201 MB compressed. **Not in git**, too large; regenerate with `analysis/enumerate_hub.py`, which is resumable and takes about 40 minutes. |
| `data/pilot_sample_1000.jsonl` | The 1,000 repos drawn for the pilot, seed 20260808. |
| `data/pilot_results.jsonl` | One row per file: repo, sha, status, fetch strategy, bytes read, file size, findings, hayward version. |
| `analysis/enumerate_hub.py` | Stage 1 as run. Resumable. |
| `analysis/shell_regex_false_positive.py` | Reproduces the MFV-PICKLE-006 flaw from first principles, no network. |
| `analysis/shell_regex_false_positive.out` | Its output as captured. |
| `analysis/measure_truncation.py` | The earlier run showing MFV-SKIP-003 fires on zero of 681 real files. |

The range fetcher itself lives in `quickset/rangefetch.py` on branch
`feat/range-fetch`, with its correctness harness in
`scripts/range_compare.py`. That harness scanned 260 models across 178 repos
and 14 formats **both ways**, range-fetched and downloaded whole, with
**zero divergences**. That result is the licence for every number here: it is
what says a 1% read produces the same verdict as a 100% read.

---

## Findings that need a vendor's attention, ours

### MFV-PICKLE-006 detects binary, not shell commands

`hayward/scanner.py:1308` matches arguments against:

    re.compile(r"\$\(|`|\s[;&|]|[;&|]\s")

Applied to binary decoded as latin1, this saturates. Measured over 200 trials
per size on random bytes:

| Blob size | Match rate |
|---|---|
| 64 B | 30% |
| 256 B | 66% |
| 1 KB | 99.5% |
| 4 KB and above | 100% |

The adjacent URL predicate matched 0% at every size, which is the control: the
flaw is this pattern, not the idea of reading arguments as text.

Found on `stanfordnlp/stanza-sl`, which carries gzip-compressed model data
through `_codecs.encode(<blob>, 'latin1')`. That is an ordinary way for a
pickle to hold bytes. Five of the six HIGH findings in the pilot were this one
repo.

The same run showed the pattern **misses `sh -c 'id'`**, so it over-fires on
binary and under-fires on a plain shell invocation.

### MFV-CONFUSE-001 on SpeechBrain tokenizers

`speechbrain/asr-transformer-transformerlm-librispeech/tokenizer.ckpt` begins
`0a 0e 0a 05 <unk>`, a SentencePiece protobuf. hayward sniffs protobuf as
`tf_savedmodel` and reports HIGH, "possible extension-spoofing to evade
format-specific scanning". The extension genuinely disagrees with the content,
but `.ckpt` for a SpeechBrain artifact is that project's convention rather
than evasion, and HIGH fails a build at the default threshold.

---

## Honest limits

- Stage 1 counts **repos and filenames**, not sizes. Sizes come per-repo at
  fetch time.
- The pilot covers the **100+ download tier only**. Nothing here describes the
  90.6% of pickle-bearing repos with fewer than ten downloads.
- Findings are **aggregated, not adjudicated**. A rule firing is a review
  candidate. The two above were reviewed by hand; the INFO tier was not.
- `MFV-PICKLE-004`, the unknown-callable bucket, dominates by volume and is
  reported separately for the reason `docs/accuracy.md` already gives: whether
  the unknown tier counts is the single largest lever on any scanner's
  false-positive rate.
