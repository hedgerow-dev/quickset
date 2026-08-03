"""Real benign models, fetched rather than generated.

The malicious corpus is generated at run time from specifications, because
shipping working payloads would be irresponsible. The benign corpus has the
opposite problem: it needs to be *real*. Hand-written benign pickles only
exercise the shapes their author thought of, which are exactly the shapes the
author's scanner already handles. Every "zero false positives" claim is worth
about as much as the benign corpus is representative, and a dozen files is not
representative of anything.

So these are downloaded from HuggingFace and verified by SHA-256. Nothing is
committed: the cache directory is gitignored, and a case whose file has not
been fetched is skipped rather than failed, exactly like an uninstalled
scanner.

The manifest lives in `benign-models.json` beside this module. It is data, not
code, because there are several hundred entries and a Python literal that long
is unreadable. Each entry records the repo, the path inside it, the SHA-256
that was verified when the entry was added, the byte size, the format as
determined from the file's own magic bytes, and the state of HuggingFace's own
malware scanning at the time it was selected.

Selection favours *format* diversity over model quality, because the formats
are what the scanners actually parse: zip and legacy torch checkpoints, raw
and zlib-compressed joblib, safetensors, Keras H5 and .keras, ONNX, GGUF,
numpy .npy/.npz, Flax msgpack and TFLite.

Three rules decide whether a file counts as benign, and none of them is "it
looked fine":

1. Every file's `securityFileStatus` was read from the HuggingFace API and no
   sub-scanner (Palo Alto Protect AI, the AV scan, VirusTotal, JFrog) reported
   it unsafe, and no import in HuggingFace's own pickle scan is labelled
   `dangerous`.
2. A `caution` rollup is *allowed* and is recorded per entry. HuggingFace
   labels ordinary constructors like `sklearn.pipeline.Pipeline` and
   `joblib.numpy_pickle.NumpyArrayWrapper` "suspicious", so excluding caution
   files would delete the entire joblib category and leave a corpus of files
   nobody flags, which is the opposite of what a false-positive corpus is for.
3. Publishers are either recognized organizations (HuggingFace's own testing
   orgs, model vendors, framework projects) or repos with a meaningful
   download count, so the corpus is made of files people actually load.

A changed upstream hash fails loudly rather than silently scoring a different
file, because it invalidates every number previously measured against it.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parent.parent / "model-cache"
MANIFEST_PATH = Path(__file__).resolve().parent / "benign-models.json"

# Refuse to start a fetch that would leave the disk nearly full. The corpus is
# ~1.5 GB and a partially-filled disk is a worse failure than a missing corpus.
HEADROOM_BYTES = 2 * 1024 ** 3


@dataclass(frozen=True)
class RealModel:
    """One hash-pinned benign model file."""

    id: str
    repo: str
    path: str
    sha256: str
    filename: str
    fmt: str
    size: int = 0
    # HuggingFace's own scan rollup at selection time: "safe" or "caution".
    hf_scan: str = ""
    library: str = ""
    downloads: int = 0
    last_commit: str = ""
    note: str = ""
    license: str = ""

    @property
    def url(self) -> str:
        return f"https://huggingface.co/{self.repo}/resolve/main/{self.path}"


def _load_manifest() -> tuple[RealModel, ...]:
    raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return tuple(RealModel(**entry) for entry in raw)


MANIFEST: tuple[RealModel, ...] = _load_manifest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cached_path(model: RealModel) -> Path:
    return CACHE_DIR / model.id / model.filename


def is_cached(model: RealModel) -> bool:
    """True when the file is present and its bytes are the pinned ones.

    Size is checked first because it is a stat call and rules out most
    mismatches without reading a gigabyte off disk.
    """
    path = cached_path(model)
    if not path.exists():
        return False
    if model.size and path.stat().st_size != model.size:
        return False
    return _sha256(path) == model.sha256


def cached_models() -> list[RealModel]:
    return [m for m in MANIFEST if is_cached(m)]


def _fetch_one(model: RealModel) -> tuple[RealModel, str]:
    """Download and verify one entry. Returns (model, error) with an empty
    error on success. Already-verified files are left alone, which is what
    makes an interrupted fetch resumable."""
    dest = cached_path(model)
    if is_cached(model):
        return model, ""
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Download to a .part file so an interrupted run never leaves a truncated
    # file that looks fetched.
    tmp = dest.with_suffix(dest.suffix + ".part")
    try:
        request = urllib.request.Request(
            model.url, headers={"User-Agent": "quickset-corpus/1.0"}
        )
        with urllib.request.urlopen(request, timeout=300) as response:  # noqa: S310 - pinned HTTPS
            with open(tmp, "wb") as out:
                shutil.copyfileobj(response, out, 1 << 20)
    except Exception as exc:  # network, 404 after a repo moves, ...
        tmp.unlink(missing_ok=True)
        return model, f"download failed: {exc}"

    actual = _sha256(tmp)
    if actual != model.sha256:
        # A changed hash means the upstream file changed. That invalidates
        # every number previously measured against it, so it fails loudly
        # rather than silently scoring a different file.
        tmp.unlink(missing_ok=True)
        return model, f"HASH MISMATCH: expected {model.sha256}, got {actual}"
    tmp.rename(dest)
    return model, ""


def fetch_all(jobs: int = 8) -> int:
    """Download every manifest entry, verifying its hash. Returns exit code.

    Re-running after a partial or failed fetch only downloads what is missing:
    anything already present with the right hash is left untouched.
    """
    todo = [m for m in MANIFEST if not is_cached(m)]
    have = len(MANIFEST) - len(todo)
    wanted = sum(m.size for m in todo)
    print(f"{len(MANIFEST)} entries, {have} already cached and verified")
    if not todo:
        print("nothing to do")
        return 0

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(CACHE_DIR).free
    print(f"need ~{wanted / 1e9:.2f} GB, {free / 1e9:.1f} GB free")
    if free - wanted < HEADROOM_BYTES:
        print("REFUSING: this would leave less than 2 GB free. Free some space first.")
        return 1

    failures: list[tuple[RealModel, str]] = []
    done = 0
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for model, error in pool.map(_fetch_one, todo):
            done += 1
            if error:
                failures.append((model, error))
                print(f"  [{done}/{len(todo)}] FAILED {model.id}: {error}")
            elif done % 25 == 0 or done == len(todo):
                print(f"  [{done}/{len(todo)}] ok")

    cached = cached_models()
    total = sum(m.size for m in cached)
    print()
    print(f"{len(cached)}/{len(MANIFEST)} verified, {total / 1e9:.2f} GB on disk")
    if failures:
        print(f"{len(failures)} failed. Re-run to retry only those.")
        return 1
    return 0


def purge() -> None:
    if CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
        print(f"removed {CACHE_DIR}")


def summarize() -> None:
    """Print the corpus breakdown: what a reader needs to judge whether a
    false-positive rate measured against it means anything."""
    from collections import Counter

    cached = {m.id for m in cached_models()}
    by_fmt = Counter(m.fmt for m in MANIFEST)
    by_lib = Counter(m.library or "(none)" for m in MANIFEST)
    by_year = Counter((m.last_commit or "?")[:4] for m in MANIFEST)
    total = sum(m.size for m in MANIFEST)

    print(f"{len(MANIFEST)} entries, {total / 1e9:.2f} GB, {len(cached)} fetched")
    print(f"{len({m.repo for m in MANIFEST})} repos, "
          f"{len({m.repo.split('/')[0] for m in MANIFEST})} publishers")
    print(f"HuggingFace scan rollup: {dict(Counter(m.hf_scan for m in MANIFEST))}")
    for title, counter in (("format", by_fmt), ("library", by_lib), ("year", by_year)):
        print(f"\nby {title}:")
        for key, n in counter.most_common():
            print(f"  {key:28} {n}")


if __name__ == "__main__":
    import sys

    if "--purge" in sys.argv:
        purge()
        raise SystemExit(0)
    if "--summary" in sys.argv:
        summarize()
        raise SystemExit(0)
    raise SystemExit(fetch_all())
