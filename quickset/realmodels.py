"""Real benign models, fetched rather than generated.

The malicious corpus is generated at run time from specifications, because
shipping working payloads would be irresponsible. The benign corpus has the
opposite problem: it needs to be *real*. Hand-written benign pickles only
exercise the shapes their author thought of, which are exactly the shapes the
author's scanner already handles. Every "zero false positives" claim is worth
about as much as the benign corpus is representative, and four synthetic
pickles is not representative of anything.

So these are downloaded from HuggingFace and verified by SHA-256. Nothing is
committed: the cache directory is gitignored, and a case whose file has not
been fetched is skipped rather than failed, exactly like an uninstalled
scanner.

Selection favours *format* diversity over model quality, because the formats
are what the scanners actually parse:

  - zip-format torch checkpoints (the modern `torch.save` default)
  - a legacy non-zip torch checkpoint (several concatenated pickles)
  - raw-pickle joblib files
  - zlib-compressed joblib files
  - sklearn models carrying genuine third-party custom classes

That last one matters most. A user-defined class is on nobody's allow list and
is the single most common cause of false positives in this space, and a
corpus without one cannot detect an over-eager scanner.
"""

from __future__ import annotations

import hashlib
import urllib.request
from dataclasses import dataclass
from pathlib import Path

CACHE_DIR = Path(__file__).resolve().parent.parent / "model-cache"


@dataclass(frozen=True)
class RealModel:
    """One hash-pinned benign model."""

    id: str
    repo: str
    url: str
    sha256: str
    filename: str
    fmt: str
    note: str = ""
    license: str = ""


MANIFEST: tuple[RealModel, ...] = (
    RealModel(
        id="real-torch-bert-zip",
        repo="hf-internal-testing/tiny-random-bert",
        url="https://huggingface.co/hf-internal-testing/tiny-random-bert/resolve/main/pytorch_model.bin",
        sha256="9922e8996d0c7e24c7f4e7a5d9c5b7303549f4ee94de0f1138b103014b51be13",
        filename="pytorch_model.bin",
        fmt="torch zip",
        note="Also exercises .bin extension dispatch: this is the filename "
             "convention the malicious bin-extension-dispatch case uses.",
    ),
    RealModel(
        id="real-torch-t5-zip",
        repo="hf-internal-testing/tiny-random-t5",
        url="https://huggingface.co/hf-internal-testing/tiny-random-t5/resolve/main/pytorch_model.bin",
        sha256="ee24a75c56a0f32c871229a719e24cdb57e56a879dd3cff15bbd478b70073bdc",
        filename="pytorch_model.bin",
        fmt="torch zip",
    ),
    RealModel(
        id="real-torch-gpt2-legacy",
        repo="sshleifer/tiny-gpt2",
        url="https://huggingface.co/sshleifer/tiny-gpt2/resolve/main/pytorch_model.bin",
        sha256="b706b24034032bdfe765ded5ab6403d201d295a995b790cb24c74becca5c04e6",
        filename="pytorch_model.bin",
        fmt="torch legacy (non-zip)",
        note="The benign counterpart to legacy-layout-second-pickle: several "
             "concatenated pickles followed by raw tensor storage. A scanner "
             "that mishandles that layout can fail in either direction.",
    ),
    RealModel(
        id="real-sklearn-iris",
        repo="hholb/sklearn-iris",
        url="https://huggingface.co/hholb/sklearn-iris/resolve/main/model.joblib",
        sha256="f7513aa7aa8d793ef8535d15ed998e1d6b5d79ff4af3d67df7f604214a9afaa7",
        filename="model.joblib",
        fmt="joblib raw pickle",
        note="joblib interleaves raw numpy array bytes into the pickle "
             "stream, so the opcode walk stops partway (byte 911 of 183761 "
             "here). A scanner that discards everything resolved before that "
             "point analyses real sklearn models by substring alone.",
    ),
    RealModel(
        id="real-sklearn-wine-rfc",
        repo="electricweegie/mlewp-sklearn-wine",
        url="https://huggingface.co/electricweegie/mlewp-sklearn-wine/resolve/main/rfc.joblib",
        sha256="caf7d2d2bdbd2f8e2d65cbff2cc6ec94a4624a450175fefa89647cf72733cd83",
        filename="rfc.joblib",
        fmt="joblib raw pickle",
        license="MIT",
    ),
    RealModel(
        id="real-sklearn-plain",
        repo="BenjaminB/plain-sklearn",
        url="https://huggingface.co/BenjaminB/plain-sklearn/resolve/main/sklearn_model.joblib",
        sha256="b8be99a5b79e48487ca91a80eb60ec7fa08c9b7f23974c36f9e9b5aeca005efa",
        filename="sklearn_model.joblib",
        fmt="joblib raw pickle",
        license="BSD-3-Clause",
    ),
    RealModel(
        id="real-sklearn-custom-class",
        repo="nateraw/custom-sklearn-pipe-objects",
        url="https://huggingface.co/nateraw/custom-sklearn-pipe-objects/resolve/main/sklearn_model.joblib",
        sha256="b88fc3e3f2a60b39ab9e579564648c44a4e643d65e9a8dc93fe9815414f045d8",
        filename="sklearn_model.joblib",
        fmt="joblib zlib",
        note="Carries a genuine user-defined class (__main__.CustomClassifier) "
             "and is zlib-compressed. The most valuable benign entry here: an "
             "unrecognized custom class is on nobody's allow list and is the "
             "single most common false-positive trigger in this space.",
    ),
    RealModel(
        id="real-sklearn-custom-transformer",
        repo="nateraw/custom-sklearn-pipe-objects",
        url="https://huggingface.co/nateraw/custom-sklearn-pipe-objects/resolve/main/sklearn_transformer.joblib",
        sha256="178dec1149bf2ee473bd1413e59b51a033ac90ae79df4e1d77e4e09e35245c14",
        filename="sklearn_transformer.joblib",
        fmt="joblib zlib",
        note="49 bytes, and its only global is a user-defined class.",
    ),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cached_path(model: RealModel) -> Path:
    return CACHE_DIR / model.id / model.filename


def is_cached(model: RealModel) -> bool:
    path = cached_path(model)
    return path.exists() and _sha256(path) == model.sha256


def cached_models() -> list[RealModel]:
    return [m for m in MANIFEST if is_cached(m)]


def fetch_all() -> int:
    """Download every manifest entry, verifying its hash. Returns exit code."""
    ok = True
    for model in MANIFEST:
        dest = cached_path(model)
        if is_cached(model):
            print(f"  cached & verified: {model.id}")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        print(f"  fetching {model.id} ({model.repo}) ...")
        try:
            urllib.request.urlretrieve(model.url, dest)  # noqa: S310 - pinned HTTPS
        except Exception as exc:  # network, 404 after a repo moves, ...
            print(f"    FAILED: {exc}")
            ok = False
            continue
        actual = _sha256(dest)
        if actual != model.sha256:
            # A changed hash means the upstream file changed. That invalidates
            # every number previously measured against it, so it fails loudly
            # rather than silently scoring a different file.
            print(f"    HASH MISMATCH: expected {model.sha256}, got {actual}")
            dest.unlink(missing_ok=True)
            ok = False
        else:
            print(f"    OK ({dest.stat().st_size} bytes, {model.fmt})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(fetch_all())
