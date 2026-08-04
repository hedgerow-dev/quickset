"""Runner: build the corpus, run every installed scanner, print the matrix.

Usage:
    python -m quickset.run
    python -m quickset.run --keep-corpus ./corpus
    python -m quickset.run --json results.json
"""

from __future__ import annotations

import argparse
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
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
    # Same counts at the lenient threshold (the tool's unknown bucket
    # included). Equal to the strict counts when the tool has no unknown tier.
    detected_lenient: int = 0
    false_positives_lenient: int = 0

    @property
    def covered(self) -> int:
        """Files the scanner returned any verdict on at all. Errored files
        (parse failures, crashes, zero-file scans) are not covered: a tool
        that never read the file has no verdict to its name, and counting
        those as clean is how a broken scanner wins a benchmark."""
        return self.total_malicious + self.total_benign - self.errors

    @property
    def coverage(self) -> float:
        total = self.total_malicious + self.total_benign
        return self.covered / total if total else 0.0

    @property
    def recall(self) -> float:
        return self.detected / self.total_malicious if self.total_malicious else 0.0

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.total_benign if self.total_benign else 0.0


def run(corpus_dir: Path, jobs: int = 1) -> tuple[list[Score], dict]:
    written = case_module.write_corpus(corpus_dir)
    adapters = [a for a in all_adapters() if a.available()]

    if not adapters:
        raise SystemExit(
            "No scanners found on PATH. Install at least one of: "
            "picklescan, modelscan, fickling, open-rowan."
        )

    per_case: dict[str, dict[str, dict]] = {}
    scores: list[Score] = []
    items = list(written.items())

    for adapter in adapters:
        # Every scanner runs as its own subprocess and each case lives in its
        # own directory, so nothing is shared between scans and they can go in
        # parallel. This matters once the benign corpus is a few hundred real
        # models: the slowest scanner takes several seconds per file, and
        # serially that is most of an hour.
        if jobs > 1:
            with ThreadPoolExecutor(max_workers=jobs) as pool:
                outcomes = list(pool.map(lambda kv: adapter.scan(Path(kv[0])), items))
        else:
            outcomes = [adapter.scan(Path(p)) for p, _ in items]

        detected = fp = errors = 0
        detected_l = fp_l = 0
        n_mal = n_ben = 0
        for (_path, case), outcome in zip(items, outcomes):
            lenient = outcome.flagged if outcome.flagged_lenient is None else outcome.flagged_lenient
            per_case.setdefault(case.id, {})[adapter.name] = {
                "flagged": outcome.flagged,
                "flagged_lenient": lenient,
                "detail": outcome.detail,
                "errored": outcome.errored,
            }
            if outcome.errored:
                errors += 1
                # Errored files are excluded from both numerators and
                # denominators; the coverage column carries that cost.
                # Counting them as clean would credit a tool for files it
                # never read, and counting them as misses would double-charge
                # what coverage already says.
                continue
            if case.malicious:
                n_mal += 1
                detected += bool(outcome.flagged)
                detected_l += bool(lenient)
            else:
                n_ben += 1
                fp += bool(outcome.flagged)
                fp_l += bool(lenient)
        scores.append(Score(adapter.name, detected, n_mal, fp, n_ben, errors,
                            detected_l, fp_l))

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
        tally: dict[str, tuple[int, int, int, int, int, int, int]] = {}
        for adapter in adapters:
            det = mal = fp = ben = det_l = fp_l = errors = 0
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
                if outcome.errored:
                    errors += 1
                    continue
                lenient = (
                    outcome.flagged if outcome.flagged_lenient is None
                    else outcome.flagged_lenient
                )
                if label:
                    mal += 1
                    det += bool(outcome.flagged)
                    det_l += bool(lenient)
                else:
                    ben += 1
                    fp += bool(outcome.flagged)
                    fp_l += bool(lenient)
            tally[adapter.name] = (det, mal, fp, ben, det_l, fp_l, errors)
        results.append((corpus, tally))
    return results


def _print_external(results, names: list[str]) -> None:
    if not results:
        print()
        print("No external corpora fetched. Run `python -m quickset.external`")
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
            det, mal, fp, ben, det_l, fp_l, errors = tally.get(name, (0, 0, 0, 0, 0, 0, 0))
            total = mal + ben + errors
            d = f"{det}/{mal} ({det / mal:.0%})" if mal else "-"
            f_ = f"{fp}/{ben} ({fp / ben:.0%})" if ben else "no benign half"
            cov = f"({total - errors}/{total} covered)" if total else ""
            print(f"      {name:20} detection {d:14} false positives {f_} {cov}")
            if (det_l, fp_l) != (det, fp):
                d_l = f"{det_l}/{mal} ({det_l / mal:.0%})" if mal else "-"
                f_l = f"{fp_l}/{ben} ({fp_l / ben:.0%})" if ben else "no benign half"
                print(f"      {(name + ' +unknown'):20} detection {d_l:14} false positives {f_l}")
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
        if "real-model" in case.tags and not any(
            v.get("flagged") for v in per_case.get(case.id, {}).values()
        ):
            continue
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
    all_cases = case_module.all_cases()

    # The real-model half of the benign corpus is several hundred files. Every
    # one of them printed is a wall of dots nobody reads, and the rows that
    # matter -- the false positives -- get lost in it. So a real model is
    # listed only when some scanner flagged it; the rest are counted.
    def is_noise(case) -> bool:
        if "real-model" not in case.tags:
            return False
        return not any(v.get("flagged") for v in per_case.get(case.id, {}).values())

    shown = [c for c in all_cases if not is_noise(c)]
    hidden = len(all_cases) - len(shown)
    width = max([len(c.id) for c in shown] + [12])

    print()
    print("PER-CASE RESULTS  (o = flagged, . = not flagged)")
    if hidden:
        print(f"{hidden} real models no scanner flagged are omitted; "
              "every flagged one is listed.")
    print()
    header = "case".ljust(width) + "  truth   " + "  ".join(n[:11].ljust(11) for n in names)
    print(header)
    print("-" * len(header))

    for case in shown:
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
    print("scanner".ljust(22), "detection".ljust(16), "false positives".ljust(18),
          "coverage".ljust(16), "errors")
    print("-" * 76)
    for score in scores:
        det = f"{score.detected}/{score.total_malicious} ({score.recall:.0%})"
        fps = f"{score.false_positives}/{score.total_benign} ({score.fp_rate:.0%})"
        total = score.total_malicious + score.total_benign
        cov = f"{score.covered}/{total} ({score.coverage:.0%})"
        # Errors were previously counted and never printed, so a scanner
        # erroring on every case looked identical to one flagging nothing.
        err = str(score.errors) if score.errors else "-"
        print(score.scanner.ljust(22), det.ljust(16), fps.ljust(18), cov.ljust(16), err)
        if (score.detected_lenient, score.false_positives_lenient) != (
            score.detected, score.false_positives,
        ):
            det_l = (f"{score.detected_lenient}/{score.total_malicious} "
                     f"({score.detected_lenient / score.total_malicious:.0%})"
                     if score.total_malicious else "-")
            fp_l = (f"{score.false_positives_lenient}/{score.total_benign} "
                    f"({score.false_positives_lenient / score.total_benign:.0%})"
                    if score.total_benign else "-")
            print((score.scanner + " +unknown").ljust(22), det_l.ljust(16), fp_l.ljust(18))

    print()
    print("Detection and false positives are reported separately and never")
    print("combined into a single score. A scanner that flags every file has")
    print("perfect detection, and one that flags nothing has a perfect false")
    print("positive rate; only the pair means anything.")
    print()
    print("Each scanner's main row is its strict threshold: only the tier its")
    print("author calls actionable. The '+unknown' row adds that tool's unknown")
    print("bucket (picklescan's suspicious, modelaudit's warning, fickling's")
    print("SUSPICIOUS, open-rowan's INFO), the analogue of not-flagged for a")
    print("human triager. Report both thresholds or neither: scoring one tool")
    print("at its top tier while counting another's unknown tier is the")
    print("specific unfairness this table exists to avoid. Run with --verbose")
    print("to see each scanner's own verdict string per case.")
    print()
    print("Coverage is the share of files the scanner returned any verdict")
    print("on. Errored files (parse failures, crashes, zero-file scans) are")
    print("excluded from both numerators and denominators alike: a tool that")
    print("never read the file has no verdict to its name.")
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
    parser.add_argument(
        "--jobs", type=int, default=1,
        help="Scan this many files in parallel per scanner. Worth raising once "
             "the real-model corpus is fetched.",
    )
    args = parser.parse_args()

    if args.keep_corpus:
        scores, per_case = run(args.keep_corpus, jobs=args.jobs)
        corpus_note = str(args.keep_corpus)
    else:
        with tempfile.TemporaryDirectory(prefix="quickset-") as tmp:
            scores, per_case = run(Path(tmp), jobs=args.jobs)
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
