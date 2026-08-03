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
from . import external as external_module
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


def run_external(adapters: list[Adapter]) -> list[tuple[object, dict[str, tuple[int, int, int, int]]]]:
    """Score each fetched external corpus. Returns (corpus, {scanner: counts}).

    Counts are (detected, malicious, false_positives, benign). Files the
    corpus author does not label are skipped, never guessed at.
    """
    results = []
    for corpus in external_module.CORPORA:
        if not external_module.is_fetched(corpus):
            continue
        files = sorted(external_module.corpus_dir(corpus).iterdir())
        tally: dict[str, tuple[int, int, int, int]] = {}
        for adapter in adapters:
            det = mal = fp = ben = 0
            for f in files:
                label = external_module.label_of(corpus, f.name)
                if label is None:
                    continue
                # Each sample gets its own directory: several scanners read
                # sibling files for context, which would leak between cases.
                with tempfile.TemporaryDirectory() as tmp:
                    target = Path(tmp) / f.name
                    target.write_bytes(f.read_bytes())
                    outcome = adapter.scan(target)
                if label:
                    mal += 1
                    det += bool(outcome.flagged)
                else:
                    ben += 1
                    fp += bool(outcome.flagged)
            tally[adapter.name] = (det, mal, fp, ben)
        results.append((corpus, tally))
    return results


def _print_external(results, names: list[str]) -> None:
    if not results:
        print()
        print("No external corpora fetched. Run `python -m picklebench.external`")
        print("to add them. They are the half of this benchmark not written here,")
        print("and every one of them has found a bug this project's own cases missed.")
        print()
        return

    print()
    print("EXTERNALLY-AUTHORED CORPORA")
    for corpus, tally in results:
        print()
        print(f"  {corpus.name}  [{corpus.license}]")
        print(f"  {corpus.origin}")
        for line in _wrap(corpus.note, 74):
            print(f"    {line}")
        print()
        for name in names:
            det, mal, fp, ben = tally.get(name, (0, 0, 0, 0))
            d = f"{det}/{mal} ({det / mal:.0%})" if mal else "-"
            f_ = f"{fp}/{ben} ({fp / ben:.0%})" if ben else "no benign half"
            print(f"      {name:12} detection {d:14} false positives {f_}")
    print()


def _wrap(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def _print_verdicts(per_case: dict, names: list[str]) -> None:
    """Each scanner's own verdict string per case.

    Severity vocabularies do not map onto each other, so the matrix reduces
    everything to flagged/not-flagged. That reduction is where a benchmark
    starts hiding things, and this is the escape hatch: the raw verdict, in
    each tool's own words, with nothing normalized.
    """
    print()
    print("VERDICTS (each scanner's own words, unnormalized)")
    for case in case_module.all_cases():
        print()
        print(f"  {case.id}  [{'malicious' if case.malicious else 'benign'}]")
        for name in names:
            got = per_case.get(case.id, {}).get(name, {})
            mark = "flag" if got.get("flagged") else "  . "
            note = got.get("detail") or ""
            if got.get("errored"):
                note = f"ERROR: {note}"
            print(f"      {mark}  {name:12} {note[:80]}")


def _print_report(scores: list[Score], per_case: dict, adapters: list[Adapter]) -> None:
    names = [s.scanner for s in scores]
    width = max([len(c.id) for c in case_module.all_cases()] + [12])

    print()
    print("PER-CASE RESULTS  (o = flagged, . = not flagged)")
    print()
    header = "case".ljust(width) + "  truth   " + "  ".join(n[:11].ljust(11) for n in names)
    print(header)
    print("-" * len(header))

    for case in case_module.all_cases():
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
    print("scanner".ljust(14), "detection".ljust(16), "false positives".ljust(18), "errors")
    print("-" * 62)
    for score in scores:
        det = f"{score.detected}/{score.total_malicious} ({score.recall:.0%})"
        fps = f"{score.false_positives}/{score.total_benign} ({score.fp_rate:.0%})"
        # Errors were previously counted and never printed, so a scanner
        # erroring on every case looked identical to one flagging nothing.
        err = str(score.errors) if score.errors else "-"
        print(score.scanner.ljust(14), det.ljust(16), fps.ljust(18), err)

    print()
    print("Detection and false positives are reported separately and never")
    print("combined into a single score. A scanner that flags every file has")
    print("perfect detection, and one that flags nothing has a perfect false")
    print("positive rate; only the pair means anything.")
    print()
    print("Scanners are scored at their own shipped defaults, which are not")
    print("the same threshold. fickling in particular grades on four levels")
    print("and treats anything above LIKELY_SAFE as unsafe -- it is built to")
    print("be read by a human, not to gate a pipeline, so its false-positive")
    print("column is measuring a different design goal. Run with --verbose")
    print("to see each scanner's own verdict string per case.")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep-corpus",
        type=Path,
        help="Write the generated corpus here and leave it in place.",
    )
    parser.add_argument("--json", type=Path, help="Write full results as JSON.")
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print each scanner's own verdict string per case, unnormalized.",
    )
    parser.add_argument(
        "--no-external", action="store_true",
        help="Skip externally-authored corpora even when they are fetched.",
    )
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
    if args.verbose:
        _print_verdicts(per_case, [s.scanner for s in scores])
    if not args.no_external:
        _print_external(run_external(adapters), [s.scanner for s in scores])
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
                        for c in case_module.all_cases()
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
