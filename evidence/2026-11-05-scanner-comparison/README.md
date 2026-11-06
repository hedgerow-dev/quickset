# Scanner comparison, 5 November 2026

Raw output of one `quickset` run, kept so every number in the README and in the
write-up on hedgerow.dev can be checked file by file.

## Files

- `results-2026-11-05.json`: per-file verdicts for every scanner (`per_case`),
  the summary scores, scanner versions and the threshold policy (`meta`).
- `run-2026-11-05.log`: the full console report, including the externally
  authored corpora (picklescan tests, PickleCloak exploits and chains).
- `fetch-models.log`: the benign-model download. 210 of 213 verified; two
  files now return HTTP 401 and one no longer matches its pinned SHA-256.
- `available-models.txt`: the 210 benign-manifest entries that were scored.
- `hayward-high-rescore-2026-11-06.txt` and `rescore_hayward_high.py`:
  Hayward re-scored at its default build gate (HIGH and above). The main run
  counts Hayward findings from LOW up; at HIGH and above it blocks 22/26
  generated cases, 35/35 picklescan tests, 46/57 PickleCloak exploits and
  56/97 PickleCloak chains, and 0/222 benign files.
- `setup.sh`: builds one virtual environment per scanner at the versions below.

Home-directory paths were shortened to `~`. Nothing else was edited.

## Environment

- Harness: quickset commit `a51d9f8`, benign manifest SHA-256 prefix `b4fe2992e8a85a77`.
- Machine: one Azure Standard_D2as_v5 VM, Ubuntu 24.04, Linux x86_64, Python 3.12.3.
- Transitive dependencies were not locked; `setup.sh` pins only the scanners.
- Scanners, each installed from PyPI into its own virtual environment with no
  optional extras: picklescan 1.0.5, modelscan 0.8.8, modelaudit 0.2.54,
  fickling 0.1.13, hayward 1.16.1. The harness records picklescan's version as
  `unknown` because picklescan has no `--version` flag and was not installed in
  the harness's own environment.

## Commands

```bash
git checkout a51d9f8
sh evidence/2026-11-05-scanner-comparison/setup.sh
python -m quickset.realmodels
python -m quickset.external
python -m quickset.run --jobs 2 --json results-2026-11-05.json --verbose
```

## Conflict of interest

quickset and Hayward are both built by Hedgerow, and the 26 generated
malicious cases were written alongside Hayward. These are self-measured
numbers until someone else reproduces them.
