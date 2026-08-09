"""Scan a list of Hub repos by HTTP range and record every verdict.

Differs from hub_sweep.py in two ways that matter, and the two should merge
once this has earned its keep:

- The repo list comes from a full enumeration of the Hub rather than from
  whatever happened to be cached, so the denominator is a real population.
- Files are read with `quickset.rangefetch` rather than downloaded whole,
  which is what makes a census affordable at all.

Every row records the hayward version that produced it. A benchmark that does
not say which build it measured is not a measurement.

**The unit of work is a file, not a repository.** The first version queued
repos, one worker each, and `facebook/mms-1b-all` promptly arrived with 1,199
adapter checkpoints: one worker sat on it for five and a half hours while the
other fifteen idled, and because rows were buffered per repo, nothing was
written and progress was indistinguishable from a hang. A flat file queue has
no head-of-line blocking, gives a stable files-per-minute figure to estimate
from, and resumes at the granularity of one file.

Politeness comes from a per-repo semaphore rather than from the queue shape,
so no single repository sees more than a couple of requests in flight however
the work happens to be scheduled.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
import tempfile
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.metadata import version as pkg_version
from pathlib import Path

from huggingface_hub import get_token

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hayward import ModelFileScanner  # noqa: E402
from quickset.rangefetch import materialize, quote_path  # noqa: E402

RESOLVE = "https://huggingface.co/{repo}/resolve/{sha}/{path}"
PER_REPO_INFLIGHT = 2


def scan(path: Path) -> tuple[list[dict], str | None]:
    """Scan in-process. The CLI costs an interpreter start per file, which at
    census scale is hours of pure process spawning."""
    try:
        findings = ModelFileScanner().scan_file(path)
    except Exception as exc:
        return [], f"{type(exc).__name__}: {exc}"[:200]
    return [
        {"rule_id": f.rule_id, "severity": f.severity.value} for f in findings
    ], None


class RepoLimiter:
    """At most `n` requests in flight against any one repository."""

    def __init__(self, n: int):
        self._lock = threading.Lock()
        self._sems: dict[str, threading.Semaphore] = defaultdict(
            lambda: threading.Semaphore(n)
        )

    def get(self, repo: str) -> threading.Semaphore:
        with self._lock:
            return self._sems[repo]


def do_file(item: dict, token: str | None, hayward_version: str,
            limiter: RepoLimiter, emit) -> None:
    repo, name = item["repo"], item["file"]
    row = {
        "repo": repo, "sha": item["sha"], "file": name,
        "downloads": item["downloads"], "hayward": hayward_version,
    }
    url = RESOLVE.format(repo=repo, sha=item["sha"] or "main",
                         path=quote_path(name))
    workdir = Path(tempfile.mkdtemp(prefix="census-"))
    dest = workdir / Path(name).name

    try:
        # The fetch holds the repo's slot. Scanning is local, so it is done
        # outside the semaphore and never blocks another file's network work.
        with limiter.get(repo):
            try:
                plan = materialize(url, dest, token=token)
            except Exception as exc:
                row.update(status="fetch-error",
                           error=f"{type(exc).__name__}: {exc}"[:200])
                emit(row)
                return

            if not plan.sampled:
                row.update(status="not-sampled",
                           reason=getattr(plan, "reason", "unspecified"),
                           file_size=plan.file_size)
                emit(row)
                return

        findings, err = scan(dest)
        row.update(
            status="scanned" if not err else "scan-error", error=err,
            strategy=plan.strategy, bytes_read=plan.bytes_read,
            file_size=plan.file_size,
            findings=[
                {"rule": f["rule_id"], "severity": f["severity"]}
                for f in findings
            ],
        )
        emit(row)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def build_queue(repos: list[dict], done: set, max_files: int, emit) -> list[dict]:
    """Flatten repos into file-level work items, recording what the per-repo
    cap excludes rather than dropping it."""
    items = []
    for repo in repos:
        for index, name in enumerate(repo["pickle_bearing"]):
            if (repo["id"], name) in done:
                continue
            base = {"repo": repo["id"], "sha": repo["sha"],
                    "downloads": repo["downloads"], "file": name}
            if index >= max_files:
                emit({**base, "status": "not-sampled",
                      "reason": "per-repo file cap"})
                continue
            items.append(base)
    # Interleave, so consecutive items rarely share a repository. The
    # semaphore already bounds per-repo concurrency; this keeps the queue from
    # marching through one publisher's whole catalogue back to back.
    random.shuffle(items)
    return items


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repos", type=Path, help="JSONL from the Hub enumeration")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0, help="repos, not files")
    parser.add_argument("--jobs", type=int, default=16)
    parser.add_argument("--max-files-per-repo", type=int, default=250)
    parser.add_argument("--seed", type=int, default=20260808)
    args = parser.parse_args()

    random.seed(args.seed)
    hayward_version = pkg_version("hayward")
    token = get_token()
    print(f"hayward {hayward_version} | authenticated: {bool(token)}", flush=True)

    done = set()
    if args.out.exists():
        with args.out.open() as f:
            for line in f:
                try:
                    row = json.loads(line)
                    done.add((row["repo"], row.get("file")))
                except Exception:
                    continue
        print(f"resuming, {len(done):,} files already recorded", flush=True)

    repos = [json.loads(line) for line in args.repos.read_text().splitlines() if line]
    if args.limit:
        repos = repos[: args.limit]

    lock = threading.Lock()
    counts = {"scanned": 0, "not-sampled": 0, "other": 0}
    totals = {"read": 0, "size": 0}
    queue_size = capped = 0
    started = time.monotonic()

    with args.out.open("a") as out:
        def emit(row):
            with lock:
                status = row.get("status")
                if status == "scanned":
                    counts["scanned"] += 1
                    totals["read"] += row["bytes_read"]
                    totals["size"] += row["file_size"]
                elif status == "not-sampled":
                    counts["not-sampled"] += 1
                else:
                    counts["other"] += 1
                out.write(json.dumps(row) + "\n")
                out.flush()
                n = sum(counts.values())
                # Rows emitted while the queue is still being built are cap
                # records, not work. Reporting a rate for them divides by a
                # near-zero elapsed and prints nonsense.
                if n % 250 == 0 and queue_size:
                    elapsed = time.monotonic() - started
                    pct = (100 * totals["read"] / totals["size"]
                           if totals["size"] else 0)
                    print(
                        f'{n - capped:,}/{queue_size:,} files'
                        f' | {counts["scanned"]:,} scanned'
                        f' | {counts["not-sampled"]} not sampled'
                        f' | {counts["other"]} errors | {pct:.3f}% of bytes'
                        f' | {(n - capped) / max(1e-9, elapsed / 60):.0f} files/min'
                        f' | {elapsed / 60:.1f} min',
                        flush=True,
                    )

        items = build_queue(repos, done, args.max_files_per_repo, emit)
        capped = sum(counts.values())
        queue_size = len(items)
        started = time.monotonic()  # the clock starts at real work
        print(f"{len(items):,} files queued across {len(repos):,} repos"
              f" ({capped:,} over the per-repo cap, recorded as not sampled)",
              flush=True)

        limiter = RepoLimiter(PER_REPO_INFLIGHT)
        with ThreadPoolExecutor(args.jobs) as pool:
            futures = {
                pool.submit(do_file, item, token, hayward_version, limiter, emit): item
                for item in items
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    item = futures[future]
                    emit({"repo": item["repo"], "file": item["file"],
                          "status": "worker-error",
                          "error": f"{type(exc).__name__}: {exc}"[:200],
                          "hayward": hayward_version})

    elapsed = time.monotonic() - started
    print(f"\nDONE in {elapsed / 60:.1f} min")
    print(f"  scanned      {counts['scanned']:,}")
    print(f"  not sampled  {counts['not-sampled']:,}")
    print(f"  errors       {counts['other']:,}")
    if totals["size"]:
        print(f"  bytes read   {totals['read']:,} of {totals['size']:,} "
              f"({100 * totals['read'] / totals['size']:.3f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
