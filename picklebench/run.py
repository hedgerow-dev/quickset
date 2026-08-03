"""Runner: build the corpus, run every installed scanner, print the matrix.

Usage:
    python -m picklebench.run
    python -m picklebench.run --keep-corpus ./corpus
    python -m picklebench.run --json results.json
"""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from . import cases as case_module
from .adapters import Adapter, all_adapters


@dataclass
class Score:
    scanner: str
    detected: int
    total_malicious: int
    false_positives: int
    total_benign: int
    errors: int

    @property
    def recall(self) -> float:
        return self.detected / self.total_malicious if self.total_malicious else 0.0

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.total_benign if self.total_benign else 0.0


def run(corpus_dir: Path) -> tuple[list[Score], dict]:
    written = case_module.write_corpus(corpus_dir)
    adapters = [a for a in all_adapters() if a.available()]

    if not adapters:
        raise SystemExit(
            "No scanners found on PATH. Install at least one of: "
            "picklescan, modelscan, fickling, open-rowan."
        )

    per_case: dict[str, dict[str, dict]] = {}
    scores: list[Score] = []

    for adapter in adapters:
        detected = fp = errors = 0
        n_mal = n_ben = 0
        for path_str, case in written.items():
            outcome = adapter.scan(Path(path_str))
            per_case.setdefault(case.id, {})[adapter.name] = {
                "flagged": outcome.flagged,
                "detail": outcome.detail,
                "errored": outcome.errored,
            }
            if outcome.errored:
                errors += 1
            if case.malicious:
                n_mal += 1
                detected += bool(outcome.flagged)
            else:
                n_ben += 1
                fp += bool(outcome.flagged)
        scores.append(Score(adapter.name, detected, n_mal, fp, n_ben, errors))

    return scores, per_case


def _print_report(scores: list[Score], per_case: dict, adapters: list[Adapter]) -> None:
    names = [s.scanner for s in scores]
    width = max([len(c.id) for c in case_module.ALL_CASES] + [12])

    print()
    print("PER-CASE RESULTS  (o = flagged, . = not flagged)")
    print()
    header = "case".ljust(width) + "  truth   " + "  ".join(n[:11].ljust(11) for n in names)
    print(header)
    print("-" * len(header))

    for case in case_module.ALL_CASES:
        truth = "MAL " if case.malicious else "ben "
        row = case.id.ljust(width) + "  " + truth + "    "
        cells = []
        for name in names:
            got = per_case.get(case.id, {}).get(name, {})
            mark = "o" if got.get("flagged") else "."
            # A miss on a malicious case and a hit on a benign one are the
            # two failures worth making visible at a glance.
            if case.malicious and not got.get("flagged"):
                mark = "MISS"
            elif not case.malicious and got.get("flagged"):
                mark = "FP"
            cells.append(mark.ljust(11))
        print(row + "  ".join(cells))

    print()
    print("SUMMARY")
    print()
    print("scanner".ljust(14), "detection".ljust(16), "false positives")
    print("-" * 52)
    for score in scores:
        det = f"{score.detected}/{score.total_malicious} ({score.recall:.0%})"
        fps = f"{score.false_positives}/{score.total_benign} ({score.fp_rate:.0%})"
        print(score.scanner.ljust(14), det.ljust(16), fps)

    print()
    print("Detection and false positives are reported separately and never")
    print("combined into a single score. A scanner that flags every file has")
    print("perfect detection, and one that flags nothing has a perfect false")
    print("positive rate; only the pair means anything.")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-corpus",
        type=Path,
        help="Write the generated corpus here and leave it in place.",
    )
    parser.add_argument("--json", type=Path, help="Write full results as JSON.")
    args = parser.parse_args()

    if args.keep_corpus:
        scores, per_case = run(args.keep_corpus)
        corpus_note = str(args.keep_corpus)
    else:
        with tempfile.TemporaryDirectory(prefix="picklebench-") as tmp:
            scores, per_case = run(Path(tmp))
        corpus_note = "(temporary, discarded)"

    adapters = [a for a in all_adapters() if a.available()]
    _print_report(scores, per_case, adapters)
    print(f"corpus: {corpus_note}")
    print("scanners run:", ", ".join(f"{a.name} [{a.license}]" for a in adapters))

    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "scores": [asdict(s) | {"recall": s.recall, "fp_rate": s.fp_rate} for s in scores],
                    "per_case": per_case,
                    "cases": [
                        {
                            "id": c.id,
                            "malicious": c.malicious,
                            "technique": c.technique,
                            "origin": c.origin,
                            "reference": c.reference,
                            "tags": list(c.tags),
                        }
                        for c in case_module.ALL_CASES
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"wrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
