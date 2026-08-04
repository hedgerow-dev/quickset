"""MalHug re-measurement: fetch, scan, and score the MalHug corpus.

MalHug (github.com/security-pride/MalHug) is 91 real in-the-wild malicious
HuggingFace models with per-model labels: the malicious behavior class and
the library/API used (the sink). Two claims depend on it:

- detection: how many of the 91 Rowan (and the other entrants) flag;
- reason-correctness: when Rowan flags, does the finding name the same sink
  the corpus author recorded? The 79/80 claim from the first session was
  never re-verified and the corpus was not cached, so it is provisional.

Evidence discipline (P3-4): the artifact written by --json pins the corpus
CSV sha256, the tool commit (open-rowan via PYTHONPATH), the threshold
policy, and the raw per-file outcome. Nothing here may be asserted from a
session transcript.

Usage:
  python scripts/malhug_scan.py [--csv URL] [--jobs N] [--json out.json]
  --scan-only        skip downloads, rescan the cache
  --purge            delete the cache

Downloads go to external-cache/malhug/ (gitignored), one subdir per repo,
only the file(s) named in the corpus row.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "external-cache" / "malhug"
CSV_URL = "https://raw.githubusercontent.com/security-pride/MalHug/main/malhug_result_info.csv"
API = "https://huggingface.co"
TIMEOUT = 120


def fetch_csv() -> tuple[Path, str]:
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / "malhug_result_info.csv"
    if not dest.exists():
        req = urllib.request.Request(CSV_URL, headers={"User-Agent": "quickset-malhug/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            dest.write_bytes(resp.read())
    sha = hashlib.sha256(dest.read_bytes()).hexdigest()
    return dest, sha


def malicious_models(csv_path: Path) -> list[dict]:
    rows = list(csv.DictReader(open(csv_path, encoding="latin-1")))
    return [
        r for r in rows
        if r["type"] == "model" and r["malicious_behaviors"] not in ("", "[]")
    ]


def _files_of(row: dict) -> list[str]:
    """The corpus 'files' field is a ':'- and ','-separated list of paths.

    Most entries name the outer model file (pytorch_model.bin); some also
    name the payload path inside it (archive/data.pkl), which is not a
    repo-root file and 404s harmlessly during fetch. A comma variant
    separates additional real files (vae/diffusion_pytorch_model.bin).
    Fetching every unique path and ignoring 404s is robust to both."""
    raw = row.get("files") or ""
    seen: list[str] = []
    for part in raw.replace(",", ":").split(":"):
        part = part.strip()
        if part and "." in part and part not in seen:
            seen.append(part)
    return seen


def fetch_one(row: dict) -> tuple[str, Path | None, str]:
    repo = row["model_id/dataset_id"]
    dest = CACHE / repo.replace("/", "--")
    if (dest / ".done").exists():
        return repo, dest, ""
    dest.mkdir(parents=True, exist_ok=True)
    got = 0
    headers = {"User-Agent": "quickset-malhug/1.0"}
    tok = Path.home() / ".cache/huggingface/token"
    if tok.exists():
        # Sent only to huggingface.co: private/gated repos and rate limits.
        headers["Authorization"] = f"Bearer {tok.read_text().strip()}"
    for f in _files_of(row):
        url = f"{API}/{repo}/resolve/main/{f}"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=300) as resp:
                blob = resp.read()
        except Exception as exc:
            continue
        # Preserve the original basename: Rowan's extension dispatch is
        # name-sensitive (keras_metadata.pb and saved_model.pb are scanned
        # only under those exact names), so a slash-renamed copy would
        # silently unscannable.
        (dest / Path(f).name).write_bytes(blob)
        got += 1
    if got == 0:
        return repo, None, "no files downloaded"
    (dest / ".done").write_text("ok")
    return repo, dest, ""


def scan_dir(repo_dir: Path, row: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        try:
            proc = subprocess.run(
                ["open-rowan", "scan", str(repo_dir), "--format", "json", "-o", str(out),
                 "--no-sca", "--no-taint", "--no-cross-file"],
                capture_output=True, text=True, timeout=TIMEOUT, check=False,
            )
        except subprocess.TimeoutExpired:
            return {"repo": row["model_id/dataset_id"], "error": "timeout"}
        if not out.exists():
            return {"repo": row["model_id/dataset_id"], "error": f"no report rc={proc.returncode}"}
        try:
            report = json.loads(out.read_text())
        except (json.JSONDecodeError, OSError):
            return {"repo": row["model_id/dataset_id"], "error": "unparseable report"}
    findings = [
        f for f in report.get("findings", [])
        if str(f.get("severity", "")).lower() != "info"
    ]
    return {
        "repo": row["model_id/dataset_id"],
        "behavior": row["malicious_behaviors"],
        "sink": row["libraries_and_apis"],
        "findings": [
            {"rule_id": f.get("rule_id"), "severity": f.get("severity"),
             "message": str(f.get("message", ""))[:300]}
            for f in findings
        ],
    }


def _sink_matches(message: str, sink: str) -> bool:
    """Does the finding's message name the same sink the corpus recorded?

    The corpus sink may be a comma list (exec,runpy._run_code), a class
    (Keras.Lambda), or a callable (os.system / posix.system / nt.system /
    webbrowser.open / eval). Rowan names the resolved global or the layer
    class. Match on the terminal name where possible, with a module-family
    fallback (os == posix == nt). Any one listed sink matching counts."""
    sink = (sink or "").strip()
    if not sink:
        return False
    for part in sink.split(","):
        part = part.strip()
        if not part:
            continue
        base = part.split(".")[-1]
        if base in message:
            return True
        if part in message or part.replace("os.", "posix.") in message:
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--json", type=Path, help="write evidence artifact")
    parser.add_argument("--purge", action="store_true")
    args = parser.parse_args()

    if args.purge:
        shutil.rmtree(CACHE, ignore_errors=True)
        print(f"purged {CACHE}")
        return 0

    csv_path, csv_sha = fetch_csv()
    models = malicious_models(csv_path)
    print(f"{len(models)} malicious-labeled models, csv sha256 {csv_sha[:12]}")

    fetched: list[tuple[str, Path | None, str]] = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for i, result in enumerate(pool.map(fetch_one, models), 1):
            fetched.append(result)
            if i % 20 == 0:
                print(f"  fetched {i}/{len(models)}")

    scan_rows = [r for r, (repo, d, err) in zip(models, fetched) if d is not None]
    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for i, res in enumerate(pool.map(lambda r: scan_dir(
                CACHE / r["model_id/dataset_id"].replace("/", "--"), r), scan_rows), 1):
            results.append(res)
            if i % 20 == 0:
                print(f"  scanned {i}/{len(scan_rows)}")

    detected = [r for r in results if r.get("findings")]
    sink_ok = [r for r in detected if _sink_matches(r["findings"][0]["message"], r.get("sink"))]
    errors = [r for r in results if r.get("error")]

    print()
    print(f"scanned {len(results)}, detected {len(detected)}, errors {len(errors)}")
    print(f"reason-correct (top finding names corpus sink): {len(sink_ok)}/{len(detected)}")
    print("\nmissed:")
    for r in results:
        if not r.get("findings"):
            print(f"  {r['repo']} ({r.get('sink')})")
    print("\nmisattributed (detected but wrong sink):")
    for r in detected:
        if r not in sink_ok:
            print(f"  {r['repo']}: corpus {r.get('sink')!r}, got {r['findings'][0]['message'][:100]}")

    if args.json:
        args.json.write_text(json.dumps({
            "meta": {
                "corpus": "MalHug",
                "corpus_csv_sha256": csv_sha,
                "scanner": "open-rowan (PYTHONPATH defines commit)",
                "threshold_policy": "findings above INFO; errored excluded from both counts",
                "models_labeled": len(models),
            },
            "results": results,
        }, indent=1), encoding="utf-8")
        print(f"\nartifact: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
