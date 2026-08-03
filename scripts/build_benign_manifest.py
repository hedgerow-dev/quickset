"""Build quickset/benign-models.json, the manifest for the real benign corpus.

The manifest is committed; the model files it points at are not (the cache is
gitignored). This script is the only writer of the manifest, so that every
entry passed through the same provenance checks:

1. Candidates come from the HuggingFace hub API: repo search plus each repo's
   file tree with `security=true`, so HuggingFace's own malware scanning is
   read for every file before it is considered.
2. A file is eligible only when its `securityFileStatus` rollup is `safe` or
   `caution`, no sub-scanner (Protect AI, AV, VirusTotal, JFrog) calls it
   unsafe, and no import in the pickle scan is labelled dangerous.
3. Every file is downloaded, its format is read from its own magic bytes (not
   from its extension), and its SHA-256 is computed locally and checked
   against the LFS oid when the file is LFS-backed.

Composition is enforced, not hoped for: per-bucket targets, a per-publisher
cap, a per-repo cap, a total size budget, and SHA-256 dedup across the whole
corpus. The tests in tests/test_realmodels.py pin the properties a reader
cares about (diversity, pinning, no unsafe entries); this script's job is to
satisfy them from real data.

Re-running is cheap: tree and metadata responses are cached under
scripts/.cache/, and files already in model-cache with the right hash are not
re-downloaded.

Usage: python scripts/build_benign_manifest.py [--max-repos N] [--write]
Without --write the script prints what it would do and writes nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "model-cache"
MANIFEST_PATH = ROOT / "quickset" / "benign-models.json"
HTTP_CACHE = ROOT / "scripts" / ".cache"

API = "https://huggingface.co"
TOKEN_PATH = Path.home() / ".cache" / "huggingface" / "token"

MAX_PER_PUBLISHER = 25
MAX_PER_REPO = 3
SIZE_BUDGET = int(2.2e9)

# Statuses any of HuggingFace's sub-scanners can report that disqualify a
# file. Everything else (safe, unscanned, queued, not-applicable) is neutral;
# the rollup filter is what requires a positive verdict.
UNSAFE_STATUSES = {"unsafe", "dangerous", "infected", "danger"}


def http_get(url: str, *, token: bool = False, retries: int = 4) -> bytes:
    """GET with backoff. The token is sent only to huggingface.co API calls,
    never to resolve/CDN URLs: downloads are public and a leaked Authorization
    header on a redirect is a self-inflicted wound."""
    headers = {"User-Agent": "quickset-corpus/1.0"}
    if token and TOKEN_PATH.exists():
        headers["Authorization"] = f"Bearer {TOKEN_PATH.read_text().strip()}"
    delay = 1.0
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 410):
                raise
            if attempt == retries - 1:
                raise
            time.sleep(delay)
            delay *= 2
        except urllib.error.URLError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)
            delay *= 2
    raise AssertionError("unreachable")


def api_json(path: str, params: dict[str, str], *, cache_key: str) -> object:
    """One API call, cached on disk so a re-run after a partial download does
    not re-crawl the hub."""
    HTTP_CACHE.mkdir(exist_ok=True)
    cache_file = HTTP_CACHE / f"{cache_key}.json"
    if cache_file.exists():
        return json.loads(cache_file.read_text(encoding="utf-8"))
    query = urllib.parse.urlencode(params)
    data = http_get(f"{API}{path}?{query}", token=True)
    parsed = json.loads(data)
    cache_file.write_text(json.dumps(parsed), encoding="utf-8")
    time.sleep(0.2)
    return parsed


# --------------------------------------------------------------------------
# Format classification, from the file's own bytes.
# --------------------------------------------------------------------------

TORCH_EXTS = (".bin", ".pt", ".pth", ".ckpt")
SKLEARN_EXTS = (".joblib", ".pkl", ".pickle")


def classify(path: Path) -> str | None:
    """The file's format from its magic bytes. Returns None for anything
    unrecognised, which excludes it from the corpus: an entry whose format we
    cannot state is an entry we cannot reason about."""
    name = path.name.lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    with open(path, "rb") as fh:
        head = fh.read(4096)

    if head[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
        except zipfile.BadZipFile:
            return None
        if any(n == "data.pkl" or n.endswith("/data.pkl") for n in names):
            return "torch zip"
        if name.endswith(".npz"):
            return "numpy npz"
        if name.endswith(".keras"):
            return "keras zip"
        if name.endswith(".skops") and "schema.json" in names:
            return "skops"
        return None

    if head[:2] == b"\x1f\x8b":
        if name.endswith(".joblib"):
            return "joblib gzip"
        return None
    if head[:1] == b"\x78":
        if name.endswith(".joblib"):
            return "joblib zlib"
        return None
    if head[:1] == b"\x80":
        if name.endswith(".joblib"):
            return "joblib raw pickle"
        if name.endswith((".pkl", ".pickle")):
            return "pickle"
        if name.endswith(TORCH_EXTS):
            return "torch legacy (non-zip)"
        return None
    if head[:8] == b"\x89HDF\r\n\x1a\n":
        return "keras h5" if name.endswith((".h5", ".hdf5")) else None
    if head[:4] == b"GGUF":
        return "gguf"
    if head[:6] == b"\x93NUMPY":
        return "numpy npy"
    if head[4:8] == b"TFL3":
        return "tflite"
    if name.endswith(".safetensors") and head[8:9] == b"{":
        return "safetensors"
    if name.endswith(".onnx"):
        return "onnx"
    if name.endswith(".msgpack"):
        return "flax msgpack"
    return None


# --------------------------------------------------------------------------
# Buckets: what the corpus is made of.
# --------------------------------------------------------------------------


def _ext_matcher(*exts: str):
    return lambda p: p.lower().endswith(exts)


BUCKETS: list[dict] = [
    {"fmt": "torch zip", "target": 45, "max_size": 30_000_000,
     "match": _ext_matcher(*TORCH_EXTS)},
    {"fmt": "torch legacy (non-zip)", "target": 20, "max_size": 30_000_000,
     "match": _ext_matcher(*TORCH_EXTS)},
    {"fmt": "safetensors", "target": 45, "max_size": 60_000_000,
     "match": _ext_matcher(".safetensors")},
    {"fmt": "joblib raw pickle", "target": 20, "max_size": 25_000_000,
     "match": _ext_matcher(*SKLEARN_EXTS)},
    {"fmt": "joblib zlib", "target": 12, "max_size": 25_000_000,
     "match": _ext_matcher(".joblib")},
    {"fmt": "joblib gzip", "target": 6, "max_size": 25_000_000,
     "match": _ext_matcher(".joblib")},
    {"fmt": "pickle", "target": 10, "max_size": 25_000_000,
     "match": _ext_matcher(".pkl", ".pickle")},
    {"fmt": "onnx", "target": 25, "max_size": 50_000_000,
     "match": _ext_matcher(".onnx")},
    {"fmt": "keras h5", "target": 15, "max_size": 30_000_000,
     "match": _ext_matcher(".h5", ".hdf5")},
    {"fmt": "keras zip", "target": 10, "max_size": 30_000_000,
     "match": _ext_matcher(".keras")},
    {"fmt": "gguf", "target": 10, "max_size": 60_000_000,
     "match": _ext_matcher(".gguf")},
    {"fmt": "numpy npy", "target": 8, "max_size": 20_000_000,
     "match": _ext_matcher(".npy")},
    {"fmt": "numpy npz", "target": 8, "max_size": 20_000_000,
     "match": _ext_matcher(".npz")},
    {"fmt": "tflite", "target": 10, "max_size": 20_000_000,
     "match": _ext_matcher(".tflite", ".lite")},
    {"fmt": "flax msgpack", "target": 10, "max_size": 30_000_000,
     "match": _ext_matcher(".msgpack")},
    {"fmt": "skops", "target": 10, "max_size": 25_000_000,
     "match": _ext_matcher(".skops")},
]

# Repo searches, most specific first. The tree of every repo found is scanned
# for every unfilled bucket, so these exist to surface repos, not to target
# one format each. `author+search` pairs pin down known small-model families;
# library sweeps catch the long tail.
QUERIES: list[dict[str, str]] = [
    # Tiny transformers: pytorch_model.bin (zip-era), .safetensors, .msgpack.
    {"author": "hf-internal-testing", "search": "tiny-random", "limit": "100"},
    {"author": "sshleifer", "search": "tiny", "limit": "100"},
    {"author": "prajjwal1", "limit": "100"},
    {"search": "tiny-random", "sort": "downloads", "direction": "-1", "limit": "100"},
    # Old checkpoints: the legacy non-zip torch layout lives here.
    {"author": "distilbert", "limit": "100"},
    {"author": "google", "search": "bert_uncased_L-", "limit": "100"},
    {"author": "microsoft", "search": "xtremedistil", "limit": "100"},
    # HF staff namespaces from 2019-2021: small checkpoints, often the legacy
    # non-zip torch layout.
    {"author": "patrickvonplaten", "limit": "100"},
    {"author": "lysandre", "limit": "100"},
    {"author": "thomwolf", "limit": "100"},
    {"author": "julien-c", "limit": "100"},
    {"author": "n1t0", "limit": "100"},
    {"author": "sgugger", "limit": "100"},
    {"author": "valhalla", "limit": "100"},
    {"author": "mrm8488", "limit": "100"},
    {"author": "NielsRogge", "limit": "100"},
    # safetensors beyond the tiny families.
    {"filter": "safetensors", "sort": "downloads", "direction": "-1", "limit": "100"},
    {"author": "sentence-transformers", "sort": "downloads", "direction": "-1", "limit": "100"},
    {"author": "timm", "sort": "downloads", "direction": "-1", "limit": "50"},
    # sklearn / joblib / raw pickles.
    {"filter": "sklearn", "sort": "downloads", "direction": "-1", "limit": "100"},
    {"filter": "joblib", "sort": "downloads", "direction": "-1", "limit": "100"},
    {"search": "sklearn", "sort": "downloads", "direction": "-1", "limit": "100"},
    # ONNX.
    {"filter": "onnx", "sort": "downloads", "direction": "-1", "limit": "100"},
    {"author": "onnx-community", "limit": "100"},
    {"author": "onnx", "limit": "100"},
    {"author": "Xenova", "sort": "downloads", "direction": "-1", "limit": "100"},
    # Keras.
    {"filter": "keras", "sort": "downloads", "direction": "-1", "limit": "100"},
    {"author": "keras-team", "limit": "100"},
    {"author": "tensorflow", "limit": "100"},
    {"author": "Kaggle", "limit": "100"},
    # GGUF: mostly huge, so look for test-scale files explicitly.
    {"author": "hf-internal-testing", "search": "gguf", "limit": "100"},
    {"filter": "gguf", "sort": "likes", "direction": "-1", "limit": "100"},
    {"search": "tiny gguf", "sort": "downloads", "direction": "-1", "limit": "100"},
    # numpy arrays.
    {"search": "npz", "sort": "downloads", "direction": "-1", "limit": "100"},
    {"search": "npy", "sort": "downloads", "direction": "-1", "limit": "100"},
    # TFLite.
    {"filter": "tf-lite", "sort": "downloads", "direction": "-1", "limit": "100"},
    {"search": "tflite", "sort": "downloads", "direction": "-1", "limit": "100"},
    # Flax.
    {"filter": "flax", "sort": "downloads", "direction": "-1", "limit": "100"},
    # skops.
    {"filter": "skops", "sort": "downloads", "direction": "-1", "limit": "100"},
]

# Repos known good from the previous 8-entry manifest; checked first.
SEED_REPOS = [
    "hholb/sklearn-iris",
    "electricweegie/mlewp-sklearn-wine",
    "BenjaminB/plain-sklearn",
    "nateraw/custom-sklearn-pipe-objects",
    "hf-internal-testing/tiny-random-bert",
    "hf-internal-testing/tiny-random-t5",
    "sshleifer/tiny-gpt2",
]


# --------------------------------------------------------------------------
# Selection.
# --------------------------------------------------------------------------


def security_rollup(entry: dict) -> str | None:
    """The rollup verdict if the file is eligible, else None."""
    status = entry.get("securityFileStatus")
    if not status:
        return None
    rollup = status.get("status")
    if rollup not in ("safe", "caution"):
        return None
    for key in ("protectAiScan", "avScan", "virusTotalScan", "jFrogScan"):
        sub = status.get(key) or {}
        if str(sub.get("status", "")).lower() in UNSAFE_STATUSES:
            return None
    pickle_scan = status.get("pickleImportScan") or {}
    if str(pickle_scan.get("status", "")).lower() in UNSAFE_STATUSES:
        return None
    for imp in pickle_scan.get("pickleImports") or []:
        if str(imp.get("safety", "")).lower() in UNSAFE_STATUSES:
            return None
    return rollup


def candidate_repos(max_repos: int) -> list[str]:
    """Ordered, deduped repo list: seeds first, then query results."""
    repos: list[str] = list(SEED_REPOS)
    seen = set(repos)
    for query in QUERIES:
        params = {**query, "full": "true"}
        digest = hashlib.sha256(
            json.dumps(params, sort_keys=True).encode()).hexdigest()[:12]
        try:
            results = api_json("/api/models", params, cache_key=f"search-{digest}")
        except Exception as exc:
            print(f"  query {query} failed: {exc}")
            continue
        for r in results:  # type: ignore[union-attr]
            rid = r.get("id") or r.get("modelId")
            if rid and rid not in seen:
                seen.add(rid)
                repos.append(rid)
    return repos[:max_repos]


def tree_for(repo: str) -> list[dict]:
    data = api_json(
        f"/api/models/{repo}/tree/main",
        {"expand": "true", "security": "true", "recursive": "true"},
        cache_key=f"tree-{repo.replace('/', '--')}",
    )
    return data if isinstance(data, list) else []


def repo_meta(repo: str) -> dict:
    data = api_json(f"/api/models/{repo}", {"full": "true"},
                    cache_key=f"meta-{repo.replace('/', '--')}")
    return data if isinstance(data, dict) else {}


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", text).strip("-")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select(max_repos: int) -> list[dict]:
    """Walk repos in order, picking files into unfilled buckets. Returns
    manifest-shaped dicts for files already verified in the cache plus
    download work items merged; actual classification happens on download."""
    counts = {b["fmt"]: 0 for b in BUCKETS}
    publisher_counts: dict[str, int] = {}
    chosen: list[dict] = []
    seen_hashes: set[str] = set()
    total_size = 0

    repos = candidate_repos(max_repos)
    print(f"{len(repos)} candidate repos")

    for repo in repos:
        per_repo = 0
        try:
            tree = tree_for(repo)
        except Exception:
            continue  # deleted, gated, or moved repo: not a corpus entry
        for entry in tree:
            if per_repo >= MAX_PER_REPO:
                break
            if entry.get("type") != "file":
                continue
            path = entry.get("path", "")
            size = int(entry.get("size") or 0)
            if not size:
                continue
            rollup = security_rollup(entry)
            if rollup is None:
                continue
            lfs_sha = (entry.get("lfs") or {}).get("oid", "")
            if lfs_sha and lfs_sha in seen_hashes:
                continue
            # Which buckets would take this file (by extension and size)?
            fits = [b for b in BUCKETS
                    if counts[b["fmt"]] < b["target"]
                    and b["match"](path) and size <= b["max_size"]]
            if not fits:
                continue
            publisher = repo.split("/")[0]
            if publisher_counts.get(publisher, 0) >= MAX_PER_PUBLISHER:
                break
            if total_size + size > SIZE_BUDGET:
                continue
            entry_id = slug(f"{repo.replace('/', '--')}--{path.replace('/', '--')}")
            chosen.append({
                "id": entry_id,
                "repo": repo,
                "path": path,
                "sha256": lfs_sha,  # empty for small non-LFS files; filled on download
                "filename": path.rsplit("/", 1)[-1],
                "size": size,
                "hf_scan": rollup,
                "last_commit": (entry.get("lastCommit") or {}).get("date", ""),
                "_buckets": [b["fmt"] for b in fits],
                "_lfs": bool(lfs_sha),
            })
            # Reserve optimistically; a failed download rolls this back.
            counts[fits[0]["fmt"]] += 1
            publisher_counts[publisher] = publisher_counts.get(publisher, 0) + 1
            total_size += size
            per_repo += 1
        if all(counts[b["fmt"]] >= b["target"] for b in BUCKETS):
            print("all buckets filled")
            break
    return chosen


def fetch_and_classify(item: dict) -> tuple[dict | None, str]:
    """Download one file, classify from magic bytes, verify the hash. Returns
    (manifest_entry, "") or (None, reason)."""
    dest = CACHE_DIR / item["id"] / item["filename"]
    expected = item["sha256"]
    already = dest.exists() and (not expected or sha256_of(dest) == expected)
    if not already:
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        url = f"{API}/{item['repo']}/resolve/main/{item['path']}"
        try:
            data = http_get(url, token=False)
        except Exception as exc:
            return None, f"download failed: {exc}"
        tmp.write_bytes(data)
        actual = hashlib.sha256(data).hexdigest()
        if expected and actual != expected:
            tmp.unlink(missing_ok=True)
            return None, f"LFS oid {expected[:12]}... != downloaded sha256 {actual[:12]}..."
        tmp.rename(dest)
    fmt = classify(dest)
    known = {b["fmt"] for b in BUCKETS}
    if fmt is None or fmt not in known:
        dest.unlink(missing_ok=True)
        return None, f"magic says {fmt!r}, not a corpus format"
    entry = {
        "id": item["id"],
        "repo": item["repo"],
        "path": item["path"],
        "sha256": sha256_of(dest),
        "filename": item["filename"],
        "fmt": fmt,
        "size": dest.stat().st_size,
        "hf_scan": item["hf_scan"],
        "last_commit": item["last_commit"],
    }
    return entry, ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-repos", type=int, default=600)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--write", action="store_true",
                        help="Write the manifest. Without this, dry-run only.")
    args = parser.parse_args()

    chosen = select(args.max_repos)
    print(f"{len(chosen)} files selected, downloading and classifying...")

    accepted: list[dict] = []
    rejected: list[tuple[str, str]] = []
    seen_hashes: set[str] = set()
    fmt_counts: dict[str, int] = {}
    targets = {b["fmt"]: b["target"] for b in BUCKETS}
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = zip(chosen, pool.map(fetch_and_classify, chosen))
        for item, (entry, reason) in results:
            if entry is None:
                rejected.append((item["id"], reason))
            elif entry["sha256"] in seen_hashes:
                rejected.append((item["id"], "byte-identical to another entry"))
            elif fmt_counts.get(entry["fmt"], 0) >= targets[entry["fmt"]]:
                rejected.append((item["id"], f"bucket {entry['fmt']} already full"))
            else:
                fmt_counts[entry["fmt"]] = fmt_counts.get(entry["fmt"], 0) + 1
                seen_hashes.add(entry["sha256"])
                accepted.append(entry)

    # Enrich with repo metadata (downloads, library, licence), cached.
    for entry in accepted:
        meta = repo_meta(entry["repo"])
        entry["downloads"] = int(meta.get("downloads") or 0)
        entry["library"] = meta.get("library_name") or ""
        card = meta.get("cardData") or {}
        entry["license"] = str(card.get("license") or "")
        entry["note"] = ""

    accepted.sort(key=lambda e: e["id"])
    key_order = ["id", "repo", "path", "sha256", "filename", "fmt", "size",
                 "hf_scan", "library", "downloads", "last_commit", "note",
                 "license"]
    ordered = [{k: e.get(k, "") for k in key_order} for e in accepted]

    from collections import Counter
    by_fmt = Counter(e["fmt"] for e in ordered)
    by_pub = Counter(e["repo"].split("/")[0] for e in ordered)
    years = sorted({(e["last_commit"] or "?")[:4] for e in ordered})
    total = sum(e["size"] for e in ordered)
    print()
    print(f"{len(ordered)} entries, {total / 1e9:.2f} GB, "
          f"{len(by_pub)} publishers, years {years}")
    for fmt, n in by_fmt.most_common():
        target = next(b["target"] for b in BUCKETS if b["fmt"] == fmt)
        print(f"  {fmt:26} {n:3} / {target}")
    if rejected:
        print(f"\n{len(rejected)} rejected:")
        for rid, reason in rejected[:20]:
            print(f"  {rid}: {reason}")
        if len(rejected) > 20:
            print(f"  ... and {len(rejected) - 20} more")

    if len(ordered) < 200:
        print(f"\nREFUSING to write: {len(ordered)} entries is under the 200 "
              "the corpus tests require. Widen --max-repos or the queries.")
        return 1
    if not args.write:
        print("\ndry run: pass --write to write quickset/benign-models.json")
        return 0
    tmp = MANIFEST_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ordered, indent=1) + "\n", encoding="utf-8")
    tmp.rename(MANIFEST_PATH)
    print(f"\nwrote {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
