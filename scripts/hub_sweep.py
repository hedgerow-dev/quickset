"""Hub-scale false-positive sweep: scan unvetted public model files.

The benign corpus (benign-models.json) is curated: diverse, hash-pinned,
small. That is what makes its FP number defensible, and also what blinds it:
219 hand-picked files cannot show FP classes that only appear at scale. This
script samples model files from the repo trees already cached by
build_benign_manifest.py (plus any later cache), downloads them, scans every
one with open-rowan, and aggregates findings by rule.

Differences from the corpus, deliberately:

- No diversity vetting and no cherry-picking: every model-ish file with a
  safe/caution HuggingFace scan rollup and size under the cap is eligible.
- Not added to the corpus and not hash-pinned into anything: this is a
  measurement run, not ground truth. SHA-256 is still verified on download
  (a changed file is a different file than the one the rollup covered).
- Findings are aggregated, not asserted to be false positives. A rule that
  fires at scale is a review candidate; some will be genuinely malicious or
  broken files, because this sample did not get the corpus's manual vetting.

Usage: python scripts/hub_sweep.py [--max-files N] [--max-size BYTES] [--jobs N]
Output: sweep-results.json in the repo root (gitignored) plus a printed
per-rule summary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTTP_CACHE = ROOT / "scripts" / ".cache"
SWEEP_CACHE = ROOT / "sweep-cache"
RESULTS = ROOT / "sweep-results.json"
API = "https://huggingface.co"

MODEL_EXTS = (
    ".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib",
    ".safetensors", ".onnx", ".h5", ".hdf5", ".keras", ".gguf",
    ".npy", ".npz", ".msgpack", ".tflite", ".skops",
)
MAX_SCAN_SECONDS = 120


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_candidates() -> list[dict]:
    """Every model-ish file in the cached repo trees, minus corpus entries."""
    corpus_hashes: set[str] = set()
    manifest = ROOT / "quickset" / "benign-models.json"
    if manifest.exists():
        for entry in json.loads(manifest.read_text()):
            corpus_hashes.add(entry["sha256"])

    candidates: list[dict] = []
    for tree_file in sorted(HTTP_CACHE.glob("tree-*.json")):
        repo = tree_file.stem.removeprefix("tree-").replace("--", "/")
        try:
            tree = json.loads(tree_file.read_text())
        except json.JSONDecodeError:
            continue
        for entry in tree:
            if entry.get("type") != "file":
                continue
            path = entry.get("path", "")
            if not path.lower().endswith(MODEL_EXTS):
                continue
            status = (entry.get("securityFileStatus") or {}).get("status")
            if status not in ("safe", "caution"):
                continue
            sha = (entry.get("lfs") or {}).get("oid", "")
            if sha and sha in corpus_hashes:
                continue
            size = int(entry.get("size") or 0)
            if not size:
                continue
            candidates.append({
                "repo": repo, "path": path, "size": size,
                "sha256": sha, "rollup": status,
            })
    return candidates


def spread(candidates: list[dict], max_files: int, max_size: int) -> list[dict]:
    """Round-robin across repos so one prolific repo cannot fill the sample.
    Size-filtered first: the sweep measures parser behavior, not download
    patience, and a 4GB shard exercises the same code as a 4MB checkpoint."""
    candidates = [c for c in candidates if c["size"] <= max_size]
    by_repo: dict[str, list[dict]] = {}
    for c in candidates:
        by_repo.setdefault(c["repo"], []).append(c)
    for files in by_repo.values():
        files.sort(key=lambda c: c["size"], reverse=True)  # prefer real models
    chosen: list[dict] = []
    repos = sorted(by_repo)
    while len(chosen) < max_files and repos:
        remaining = []
        for repo in repos:
            if by_repo[repo]:
                chosen.append(by_repo[repo].pop(0))
                if len(chosen) >= max_files:
                    break
            if by_repo[repo]:
                remaining.append(repo)
        repos = remaining
    return chosen


def fetch(item: dict, max_size: int) -> tuple[dict, Path | None, str]:
    if item["size"] > max_size:
        return item, None, "too large"
    dest = SWEEP_CACHE / hashlib.sha256(
        f"{item['repo']}/{item['path']}".encode()).hexdigest()[:16] / Path(item["path"]).name
    if dest.exists() and (not item["sha256"] or sha256_of(dest) == item["sha256"]):
        return item, dest, ""
    dest.parent.mkdir(parents=True, exist_ok=True)
    url = f"{API}/{item['repo']}/resolve/main/{item['path']}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "quickset-sweep/1.0"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = resp.read()
    except Exception as exc:
        return item, None, f"download: {exc}"
    if item["sha256"] and hashlib.sha256(data).hexdigest() != item["sha256"]:
        return item, None, "hash mismatch"
    dest.write_bytes(data)
    return item, dest, ""


def scan(args: tuple[dict, Path]) -> dict:
    item, path = args
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        try:
            proc = subprocess.run(
                ["open-rowan", "scan", str(path.parent), "--format", "json",
                 "-o", str(out), "--no-sca", "--no-taint", "--no-cross-file"],
                capture_output=True, text=True, timeout=MAX_SCAN_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {**item, "error": "timeout"}
        if not out.exists():
            return {**item, "error": f"no report (rc={proc.returncode})"}
        try:
            report = json.loads(out.read_text())
        except (json.JSONDecodeError, OSError):
            return {**item, "error": "unparseable report"}
    findings = [
        f for f in report.get("findings", [])
        if str(f.get("file") or f.get("file_path") or "").endswith(path.name)
        and str(f.get("severity", "")).lower() != "info"
    ]
    return {
        **item,
        "findings": [
            {"rule_id": f.get("rule_id"), "severity": f.get("severity"),
             "message": str(f.get("message", ""))[:200]}
            for f in findings
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-files", type=int, default=1500)
    parser.add_argument("--max-size", type=int, default=20_000_000)
    parser.add_argument("--jobs", type=int, default=12)
    args = parser.parse_args()

    candidates = load_candidates()
    print(f"{len(candidates)} eligible files in cached trees")
    chosen = spread(candidates, args.max_files, args.max_size)
    print(f"sampling {len(chosen)} across {len({c['repo'] for c in chosen})} repos")

    free = shutil.disk_usage(ROOT).free
    wanted = sum(c["size"] for c in chosen)
    print(f"~{wanted / 1e9:.2f} GB to download, {free / 1e9:.1f} GB free")
    if free - wanted < 2 * 1024 ** 3:
        print("REFUSING: would leave less than 2 GB free")
        return 1

    fetched: list[tuple[dict, Path]] = []
    failures = 0
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for i, (item, path, error) in enumerate(
            pool.map(lambda c: fetch(c, args.max_size), chosen), 1
        ):
            if error:
                failures += 1
            elif path is not None:
                fetched.append((item, path))
            if i % 200 == 0:
                print(f"  fetched {i}/{len(chosen)} ({failures} failed)")
    print(f"{len(fetched)} files on disk, {failures} download failures")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for i, result in enumerate(pool.map(scan, fetched), 1):
            results.append(result)
            if i % 200 == 0:
                print(f"  scanned {i}/{len(fetched)}")

    RESULTS.write_text(json.dumps(results, indent=1), encoding="utf-8")

    from collections import Counter
    by_rule: Counter[str] = Counter()
    flagged_files = errors = 0
    for r in results:
        if r.get("error"):
            errors += 1
            continue
        findings = r.get("findings") or []
        if findings:
            flagged_files += 1
        for f in findings:
            by_rule[f"{f['rule_id']} ({f['severity']})"] += 1

    print()
    print(f"scanned {len(results) - errors}, errored {errors}")
    print(f"files with >=1 finding above INFO: {flagged_files}")
    print("\nby rule:")
    for rule, n in by_rule.most_common():
        print(f"  {rule:32} {n}")
    print(f"\nfull results: {RESULTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
