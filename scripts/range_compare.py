"""Prove the range fetcher reads enough by scanning every file both ways.

`quickset.rangefetch` reads a fraction of a percent of a remote checkpoint.
The interesting question is not how little it reads, it is whether the verdict
survives reading that little. A fetcher that is right 99% of the time is worse
than useless here: the sweep's whole output is a false-positive rate, so its
errors do not average out, they land directly in the number.

So every sampled file is scanned twice, once against the sparse range-fetched
copy and once against the whole file downloaded from the same URL in the same
run, and the two finding lists are compared verbatim: rule id, severity and
message text, which carries the zip member name and the resolved callables.
Any difference is a divergence and is recorded per file. Zero is the only
acceptable result, and the count is reported whatever it is.

Sampling is seeded from `quickset/benign-models.json`, which is committed and
records each entry's format as determined from its magic bytes. That is what
guarantees the comparison spans torch zip, torch legacy, safetensors, GGUF,
joblib, ONNX, Keras, TFLite, skops, msgpack and numpy rather than 250 copies
of the one format that happens to be most common. The sample is then topped up
from the cached repo trees `scripts/hub_sweep.py` already uses.

Usage:  python scripts/range_compare.py [--sample N] [--max-size BYTES] [--jobs N]
Output: range-compare-results.json (gitignored) plus a printed summary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from quickset.rangefetch import (  # noqa: E402
    DEFAULT_FULL_LIMIT, RangeFetchError, materialize,
)

HTTP_CACHE = ROOT / "scripts" / ".cache"
MANIFEST = ROOT / "quickset" / "benign-models.json"
RESULTS = ROOT / "range-compare-results.json"
API = "https://huggingface.co"
SCANNER = "hayward"
MAX_SCAN_SECONDS = 300

MODEL_EXTS = (
    ".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib",
    ".safetensors", ".onnx", ".h5", ".hdf5", ".keras", ".gguf",
    ".npy", ".npz", ".msgpack", ".tflite", ".skops",
)

_TOKEN_PATHS = (
    Path.home() / ".cache" / "hayward-sweep" / "hf_token",
    Path.home() / ".cache" / "huggingface" / "token",
)


def _hf_token() -> str | None:
    """Optional, as everywhere else in this repo: a published result has to be
    reproducible by someone who has no credential. What it buys is fewer
    dropped connections, measured at Hub scale by `scripts/hub_sweep.py`."""
    import os

    env = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    if env:
        return env.strip()
    for candidate in _TOKEN_PATHS:
        try:
            text = candidate.read_text().strip()
        except OSError:
            continue
        if text:
            return text
    return None


TOKEN = _hf_token()


def _scrub(text: str) -> str:
    """Results are written to disk and shared; the token never reaches them."""
    return text.replace(TOKEN, "<redacted>") if TOKEN and TOKEN in text else text


def _request(url: str) -> urllib.request.Request:
    headers = {"User-Agent": "quickset-rangecompare/1.0"}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    return urllib.request.Request(url, headers=headers)


# ── sampling ────────────────────────────────────────────────────────────


def _url(repo: str, path: str) -> str:
    return f"{API}/{repo}/resolve/main/{path}"


def seed_candidates() -> list[dict]:
    """The committed manifest, which knows each entry's real format."""
    if not MANIFEST.exists():
        return []
    out = []
    for entry in json.loads(MANIFEST.read_text(encoding="utf-8")):
        out.append({
            "repo": entry["repo"], "path": entry["path"],
            "size": entry.get("size", 0), "fmt": entry.get("fmt", "?"),
            "sha256": entry.get("sha256", ""), "source": "manifest",
        })
    return out


def tree_candidates() -> list[dict]:
    """Every model-ish file in the cached repo trees, as hub_sweep selects."""
    out: list[dict] = []
    for tree_file in sorted(HTTP_CACHE.glob("tree-*.json")):
        repo = tree_file.stem.removeprefix("tree-").replace("--", "/")
        try:
            tree = json.loads(tree_file.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        for entry in tree:
            if entry.get("type") != "file":
                continue
            path = entry.get("path", "")
            if not path.lower().endswith(MODEL_EXTS):
                continue
            if (entry.get("securityFileStatus") or {}).get("status") not in ("safe", "caution"):
                continue
            size = int(entry.get("size") or 0)
            if not size:
                continue
            out.append({
                "repo": repo, "path": path, "size": size,
                "fmt": Path(path).suffix.lower(), "sha256": "",
                "source": "tree",
            })
    return out


def choose(sample: int, max_size: int) -> list[dict]:
    """Manifest first (it guarantees format spread), then trees round-robin by
    extension so one extension cannot fill the remainder."""
    chosen = [c for c in seed_candidates() if c["size"] <= max_size]
    seen = {(c["repo"], c["path"]) for c in chosen}
    if len(chosen) >= sample:
        return chosen[:sample]

    by_ext: dict[str, list[dict]] = defaultdict(list)
    for c in tree_candidates():
        if c["size"] > max_size or (c["repo"], c["path"]) in seen:
            continue
        by_ext[c["fmt"]].append(c)
    for files in by_ext.values():
        files.sort(key=lambda c: c["size"], reverse=True)  # prefer real models

    exts = sorted(by_ext)
    while len(chosen) < sample and exts:
        remaining = []
        for ext in exts:
            if by_ext[ext]:
                chosen.append(by_ext[ext].pop(0))
                if len(chosen) >= sample:
                    break
            if by_ext[ext]:
                remaining.append(ext)
        exts = remaining
    return chosen


# ── the two reads ───────────────────────────────────────────────────────


def download(url: str, dest: Path) -> None:
    """The control: the whole file, from the same URL, in the same run.

    Reusing an older cached copy would be faster and would also mean a
    divergence could come from the file having changed upstream rather than
    from the fetcher, which is precisely the ambiguity this harness exists to
    remove.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    delay = 2.0
    last = ""
    for attempt in range(4):
        try:
            with urllib.request.urlopen(_request(url), timeout=600) as response:
                with open(dest, "wb") as out:
                    shutil.copyfileobj(response, out, 1 << 20)
            return
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 404):
                raise RuntimeError(_scrub(f"HTTP {exc.code}: {exc.reason}")) from None
            last = _scrub(f"HTTP {exc.code}: {exc.reason}")
        except Exception as exc:
            last = _scrub(str(exc))
        time.sleep(delay)
        delay *= 2
    raise RuntimeError(f"download failed: {last}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan(path: Path) -> dict:
    proc = subprocess.run(
        [SCANNER, "scan", str(path), "-f", "json"],
        capture_output=True, text=True, timeout=MAX_SCAN_SECONDS, check=False,
    )
    report = json.loads(proc.stdout)
    findings = [
        [f.get("rule_id"), str(f.get("severity")), str(f.get("message", ""))]
        for f in report.get("findings", [])
    ]
    findings.sort()
    return {
        "findings": findings,
        "coverage_gaps": len(report.get("coverage_gaps") or []),
    }


def compare(item: dict, args) -> dict:
    """One file, both ways. Anything unexpected is recorded against the file
    rather than raised: a single bad archive must not end a run of hundreds,
    and an error that is counted is visible in the summary while an exception
    that killed the pool is just a shorter sample."""
    try:
        return _compare(item, args)
    except Exception as exc:  # noqa: BLE001 - see docstring
        return {
            "repo": item["repo"], "path": item["path"], "size": item["size"],
            "fmt": item["fmt"], "source": item["source"],
            "error": _scrub(f"{type(exc).__name__}: {exc}"),
        }


def _compare(item: dict, args) -> dict:
    url = _url(item["repo"], item["path"])
    record = {
        "repo": item["repo"], "path": item["path"], "size": item["size"],
        "fmt": item["fmt"], "source": item["source"],
    }
    work = Path(tempfile.mkdtemp(prefix="rangecmp-"))
    name = Path(item["path"]).name
    try:
        try:
            plan = materialize(url, work / "range" / name, token=TOKEN,
                               full_limit=args.full_limit)
        except RangeFetchError as exc:
            record["error"] = f"range: {_scrub(str(exc))}"
            return record
        record.update({
            "strategy": plan.strategy, "bytes_read": plan.bytes_read,
            "requests": plan.requests, "file_size": plan.file_size,
            "sampled": plan.sampled, "reason": plan.reason,
        })
        if not plan.sampled:
            # Recorded, never dropped. A file missing from the denominator is
            # the one failure mode that quietly corrupts the rate this whole
            # exercise measures.
            return record

        full = work / "full" / name
        try:
            download(url, full)
        except RuntimeError as exc:
            record["error"] = f"full: {exc}"
            return record
        if full.stat().st_size != plan.file_size:
            record["error"] = "size changed upstream between the two reads"
            return record
        if item["sha256"]:
            # Manifest entries carry the hash verified when they were added.
            # A mismatch is upstream drift, not a fetcher fault, and it is
            # worth knowing which of the two a surprise is.
            record["pinned_hash_ok"] = _sha256(full) == item["sha256"]

        try:
            ranged = scan(work / "range" / name)
            whole = scan(full)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, ValueError) as exc:
            record["error"] = f"scan: {type(exc).__name__}: {exc}"
            return record

        record["findings"] = len(whole["findings"])
        record["diverged"] = ranged != whole
        if record["diverged"]:
            record["range_only"] = [f for f in ranged["findings"]
                                    if f not in whole["findings"]]
            record["full_only"] = [f for f in whole["findings"]
                                   if f not in ranged["findings"]]
            record["gaps"] = [ranged["coverage_gaps"], whole["coverage_gaps"]]
        return record
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ── entry point ─────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=250)
    parser.add_argument("--max-size", type=int, default=300_000_000,
                        help="cap on a candidate: the control half downloads it whole")
    parser.add_argument("--full-limit", type=int, default=DEFAULT_FULL_LIMIT,
                        help="above this, a format with no range strategy is "
                             "recorded as not sampled instead of downloaded")
    parser.add_argument("--jobs", type=int, default=4,
                        help="kept modest deliberately; the Hub is a shared service")
    parser.add_argument("--out", type=Path, default=RESULTS)
    args = parser.parse_args()

    chosen = choose(args.sample, args.max_size)
    print(f"{len(chosen)} candidates, "
          f"{len({c['repo'] for c in chosen})} repos, "
          f"{sum(c['size'] for c in chosen) / 1e9:.2f} GB to download whole")

    free = shutil.disk_usage(ROOT).free
    if free < 8 * 1024 ** 3:
        print(f"REFUSING: {free / 1e9:.1f} GB free, want at least 8")
        return 1

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for i, record in enumerate(pool.map(lambda c: compare(c, args), chosen), 1):
            results.append(record)
            if i % 25 == 0:
                diverged = sum(1 for r in results if r.get("diverged"))
                print(f"  {i}/{len(chosen)}  diverged so far: {diverged}", flush=True)
                args.out.write_text(json.dumps(results, indent=1), encoding="utf-8")
    args.out.write_text(json.dumps(results, indent=1), encoding="utf-8")

    summarize(results)
    print(f"\nfull results: {args.out}")
    return 1 if any(r.get("diverged") for r in results) else 0


def summarize(results: list[dict]) -> None:
    compared = [r for r in results if "diverged" in r]
    errored = [r for r in results if r.get("error")]
    unsampled = [r for r in results if r.get("sampled") is False]
    diverged = [r for r in compared if r["diverged"]]

    print()
    print(f"compared    {len(compared)}")
    print(f"DIVERGED    {len(diverged)}")
    print(f"not sampled {len(unsampled)}")
    print(f"errored     {len(errored)}")

    by_strategy: Counter[str] = Counter(r.get("strategy", "?") for r in compared)
    print("\nby strategy:")
    for strategy, n in by_strategy.most_common():
        rows = [r for r in compared if r.get("strategy") == strategy]
        read = sum(r["bytes_read"] for r in rows)
        total = sum(r["file_size"] for r in rows)
        share = 100 * read / total if total else 0.0
        bad = sum(1 for r in rows if r["diverged"])
        print(f"  {strategy:16} {n:4}  {read / 1e6:9.1f} MB of {total / 1e9:6.2f} GB "
              f"({share:6.2f}%)  diverged {bad}")

    read = sum(r["bytes_read"] for r in compared)
    total = sum(r["file_size"] for r in compared)
    if total:
        print(f"\noverall: {read / 1e6:.1f} MB read of {total / 1e9:.2f} GB "
              f"({100 * read / total:.3f}%)")

    drifted = [r for r in results if r.get("pinned_hash_ok") is False]
    if drifted:
        # Not a fetcher fault, and worth saying out loud anyway: the file
        # differs from the hash the manifest pinned, so it is no longer the
        # file any earlier number was measured against.
        print("\nchanged upstream since the manifest pinned them:")
        for r in drifted:
            print(f"  {r['repo']}/{r['path']}")

    if unsampled:
        print("\nrecorded as NOT SAMPLED (never silently dropped):")
        for r in unsampled:
            print(f"  {r['repo']}/{r['path']}  {r['size'] / 1e6:.0f} MB  {r.get('reason', '')}")

    if errored:
        print("\nerrored:")
        for r in errored[:20]:
            print(f"  {r['repo']}/{r['path']}: {r['error']}")

    if diverged:
        print("\nDIVERGENCES:")
        for r in diverged:
            print(f"  {r['repo']}/{r['path']}  [{r.get('strategy')}]")
            for f in r.get("range_only", []):
                print(f"    range only: {f[0]} {f[1]} {f[2][:120]}")
            for f in r.get("full_only", []):
                print(f"    full only:  {f[0]} {f[1]} {f[2][:120]}")


if __name__ == "__main__":
    raise SystemExit(main())
