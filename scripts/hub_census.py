"""Stage 3+: scan a list of Hub repos by HTTP range and record every verdict.

Differs from hub_sweep.py in two ways that matter, and the two scripts should
be merged once this has earned its keep:

- The repo list comes from a full enumeration of the Hub rather than from
  whatever happened to be cached, so the denominator is a real population.
- Files are read with `quickset.rangefetch` rather than downloaded whole,
  which is what makes a census affordable at all.

Every row records the hayward version that produced it. A benchmark that does
not say which build it measured is not a measurement.

Resumable per file, not per repo: every (repo, file) already in the output is
skipped on restart, so an interrupt costs one file rather than one repository.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.metadata import version as pkg_version
from pathlib import Path

from huggingface_hub import get_token

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hayward import ModelFileScanner  # noqa: E402
from quickset.rangefetch import materialize  # noqa: E402

RESOLVE = "https://huggingface.co/{repo}/resolve/{sha}/{path}"


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


def do_repo(repo: dict, token: str | None, hayward_version: str, emit,
            done: set, max_files: int, budget: float) -> None:
    """Fetch and scan one repo's files, emitting each row as it is produced.

    Buffering a whole repo and returning it at the end looked fine until
    `facebook/mms-1b-all` turned up with 1,199 adapter checkpoints: nothing
    was written for over an hour, progress was indistinguishable from a hang,
    and an interrupt would have discarded all of it. Rows stream, and resume
    is keyed per file rather than per repo.

    `max_files` and `budget` bound a single repository so one outlier cannot
    hold a worker indefinitely. Whatever they cut is recorded as not sampled,
    never silently dropped.
    """
    deadline = time.monotonic() + budget
    workdir = Path(tempfile.mkdtemp(prefix="census-"))
    try:
        for index, name in enumerate(repo["pickle_bearing"]):
            if (repo["id"], name) in done:
                continue

            if index >= max_files or time.monotonic() > deadline:
                reason = ("per-repo file cap" if index >= max_files
                          else "per-repo time budget")
                emit({"repo": repo["id"], "sha": repo["sha"], "file": name,
                      "downloads": repo["downloads"], "hayward": hayward_version,
                      "status": "not-sampled", "reason": reason})
                continue

            url = RESOLVE.format(
                repo=repo["id"], sha=repo["sha"] or "main", path=name
            )
            dest = workdir / Path(name).name
            row = {
                "repo": repo["id"], "sha": repo["sha"], "file": name,
                "downloads": repo["downloads"], "hayward": hayward_version,
            }
            try:
                plan = materialize(url, dest, token=token)
            except Exception as exc:
                row.update(status="fetch-error",
                           error=f"{type(exc).__name__}: {exc}"[:200])
                emit(row)
                continue

            if not plan.sampled:
                row.update(status="not-sampled",
                           reason=getattr(plan, "reason", "unspecified"),
                           file_size=plan.file_size)
                emit(row)
                continue

            findings, err = scan(dest)
            dest.unlink(missing_ok=True)
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repos", type=Path, help="JSONL from the Hub enumeration")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--jobs", type=int, default=8,
                        help="repos in flight at once; politeness ceiling")
    parser.add_argument("--max-files-per-repo", type=int, default=250,
                        help="beyond this, files are recorded as not sampled")
    parser.add_argument("--repo-budget", type=float, default=1800,
                        help="seconds one repo may take before the rest is "
                             "recorded as not sampled")
    args = parser.parse_args()

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
    done_repos = {repo for repo, _ in done}

    repos = [json.loads(line) for line in args.repos.read_text().splitlines() if line]
    if args.limit:
        repos = repos[: args.limit]

    pending = [
        r for r in repos
        if any((r["id"], name) not in done for name in r["pickle_bearing"])
    ]
    del done_repos
    started = time.monotonic()
    bytes_read = total_size = 0
    scanned = unsampled = errored = 0
    finished = 0

    # Concurrency across repos, not within one. Each repo's files are read
    # sequentially, so a single worker never bursts against one repository.
    lock = threading.Lock()
    counts = {"scanned": 0, "not-sampled": 0, "other": 0}
    totals = {"read": 0, "size": 0}

    with args.out.open("a") as out, ThreadPoolExecutor(args.jobs) as pool:
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
                if n % 250 == 0:
                    elapsed = time.monotonic() - started
                    pct = (100 * totals["read"] / totals["size"]
                           if totals["size"] else 0)
                    print(
                        f'{n:,} files | {counts["scanned"]:,} scanned '
                        f'| {counts["not-sampled"]} not sampled '
                        f'| {counts["other"]} errors | {pct:.3f}% of bytes '
                        f'| {elapsed/60:.1f} min',
                        flush=True,
                    )

        futures = {
            pool.submit(do_repo, repo, token, hayward_version, emit, done,
                        args.max_files_per_repo, args.repo_budget): repo
            for repo in pending
        }
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                repo = futures[future]
                emit({"repo": repo["id"], "status": "repo-error",
                      "error": f"{type(exc).__name__}: {exc}"[:200],
                      "hayward": hayward_version})

    scanned = counts["scanned"]
    unsampled = counts["not-sampled"]
    errored = counts["other"]
    bytes_read, total_size = totals["read"], totals["size"]

    elapsed = time.monotonic() - started
    print(f"\nDONE in {elapsed/60:.1f} min")
    print(f"  scanned      {scanned:,}")
    print(f"  not sampled  {unsampled:,}")
    print(f"  errors       {errored:,}")
    if total_size:
        print(f"  bytes read   {bytes_read:,} of {total_size:,} "
              f"({100*bytes_read/total_size:.3f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
