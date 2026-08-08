"""Tests for the range fetcher.

The failure this file exists to catch is a *quiet* one. A range read that
stops too early does not crash and does not produce a wrong answer that looks
wrong; it produces a clean verdict on bytes nobody looked at, and that verdict
lands in a false-positive rate as a true negative. So the properties pinned
here are the ones whose violation is invisible downstream:

- the prefix arithmetic knows the difference between "this stream ended" and
  "this stream ran out", because only the first is safe to trust;
- the whole pipeline, run against a local server that speaks HTTP ranges,
  gives byte-for-byte the same scanner findings as reading the whole file.

Everything runs offline. `scripts/range_compare.py` is the same comparison
against live Hub repositories, which is the evidence that matters, but a
regression here is caught in a second instead of in an hour of downloads.
"""

from __future__ import annotations

import json
import pickle
import random
import re
import struct
import subprocess
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from quickset import rangefetch
from quickset.rangefetch import (
    NEED_MORE, NOT_A_PICKLE_PREFIX, gguf_structured_end, materialize,
    pickle_region_end,
)

RANGE_RE = re.compile(r"bytes=(\d+)-(\d+)")


# ── prefix arithmetic ───────────────────────────────────────────────────


def _legacy_torch_bytes(trailer: bytes = b"\x11" * 4096) -> bytes:
    """torch.save's legacy layout: five pickles, then raw storage.

    Five, not four. The magic number, the protocol version, `sys_info`, the
    object, and the sorted storage-key list all go in before a byte of tensor
    data. A fetcher that stops after four cuts the fifth in half.
    """
    parts = [
        pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2),
        pickle.dumps(1001, protocol=2),
        pickle.dumps({"protocol_version": 1001, "little_endian": True}, protocol=2),
        pickle.dumps({"weight": [1.0, 2.0]}, protocol=2),
        pickle.dumps(["0", "1"], protocol=2),
    ]
    return b"".join(parts) + trailer


def test_region_end_lands_after_the_last_complete_pickle():
    data = _legacy_torch_bytes()
    end = pickle_region_end(data, at_eof=True)
    assert end == len(data) - 4096
    # And the prefix it names really is whole: five streams, five STOPs, no
    # bytes left over. Counted by reading opcodes rather than by unpickling,
    # because nothing in this project loads a pickle to find out what is in it.
    assert _count_stops(data[:end]) == 5


def _count_stops(data: bytes) -> int:
    import io
    import pickletools

    stream = io.BytesIO(data)
    seen = 0
    while stream.tell() < len(data):
        for op, _arg, _offset in pickletools.genops(stream):
            if op.name == "STOP":
                seen += 1
                break
    return seen


def test_a_prefix_cut_inside_the_fifth_pickle_asks_for_more():
    data = _legacy_torch_bytes()
    end = pickle_region_end(data, at_eof=True)
    for cut in range(end - len(pickle.dumps(["0", "1"], protocol=2)) + 1, end):
        assert pickle_region_end(data[:cut], at_eof=False) == NEED_MORE, cut


def test_a_prefix_cut_on_a_boundary_still_asks_for_more():
    """Four complete pickles and nothing after them is not evidence the file
    has only four. This is the exact shape the prototype's fixed count got
    wrong, and hayward 1.0.1 answers it with MFV-SKIP-003."""
    parts = [pickle.dumps(i, protocol=2) for i in range(4)]
    assert pickle_region_end(b"".join(parts), at_eof=False) == NEED_MORE


def test_raw_data_spliced_into_the_stream_is_not_a_prefix():
    """joblib writes arrays into the middle of its pickle. There is no prefix
    that ends on a stream boundary, so the strategy has to decline."""
    spliced = pickle.dumps({"a": 1}, protocol=2)[:-1] + b"\xff" * 64
    assert pickle_region_end(spliced, at_eof=True) == NOT_A_PICKLE_PREFIX


def _gguf_bytes(tensor_data: bytes = b"\x00" * 1024) -> bytes:
    def string(value: bytes) -> bytes:
        return struct.pack("<Q", len(value)) + value

    kv = (
        string(b"general.architecture") + struct.pack("<I", 8) + string(b"llama")
        + string(b"tokenizer.tokens") + struct.pack("<I", 9)
        + struct.pack("<IQ", 8, 2) + string(b"hello") + string(b"world")
        + string(b"general.count") + struct.pack("<I", 4) + struct.pack("<I", 7)
    )
    info = string(b"tok_embd.weight") + struct.pack("<I", 2) \
        + struct.pack("<QQ", 4, 8) + struct.pack("<I", 0) + struct.pack("<Q", 0)
    return b"GGUF" + struct.pack("<IQQ", 3, 1, 3) + kv + info + tensor_data


def test_gguf_structured_end_stops_at_the_tensor_data():
    data = _gguf_bytes()
    assert gguf_structured_end(data) == len(data) - 1024


def test_gguf_truncated_in_its_metadata_asks_for_more():
    data = _gguf_bytes()
    end = gguf_structured_end(data)
    assert gguf_structured_end(data[:end - 8]) == NEED_MORE


# ── dispatch ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("head, suffix, expected", [
    (b"PK\x03\x04rest", ".bin", "torch-zip"),
    (b"PK\x03\x04rest", ".pt", "torch-zip"),
    # A .keras or .npz is a zip too, and a different format with a different
    # reader. Half-understanding it is worse than downloading it.
    (b"PK\x03\x04rest", ".keras", "full"),
    (b"PK\x03\x04rest", ".npz", "full"),
    (b"\x80\x02X\x04", ".bin", "torch-legacy"),
    (b"GGUF\x03\x00\x00\x00", ".gguf", "gguf"),
    (b"\x40\x00\x00\x00\x00\x00\x00\x00{", ".safetensors", "safetensors"),
    (b"\x08\x00\x12", ".onnx", "full"),
])
def test_strategy_dispatch(head, suffix, expected):
    assert rangefetch._choose(head, suffix) == expected


# ── end to end against a range-speaking server ──────────────────────────


class _RangeHandler(BaseHTTPRequestHandler):
    directory: Path

    def log_message(self, *args):  # keep pytest output readable
        pass

    def _target(self) -> Path:
        # Basename only. This is a localhost test fixture, but a handler that
        # joins a request path straight onto a directory is a traversal bug
        # wherever it is written.
        return self.directory / Path(self.path.lstrip("/")).name

    def do_HEAD(self):
        target = self._target()
        if not target.exists():
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(target.stat().st_size))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()

    def do_GET(self):
        target = self._target()
        if not target.exists():
            self.send_error(404)
            return
        match = RANGE_RE.match(self.headers.get("Range", ""))
        if match is None:
            self.send_error(400, "this harness only serves ranges")
            return
        start, end = int(match.group(1)), int(match.group(2))
        with open(target, "rb") as handle:
            handle.seek(start)
            body = handle.read(end - start + 1)
        self.send_response(206)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Range",
                         f"bytes {start}-{start + len(body) - 1}/{target.stat().st_size}")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def served(tmp_path):
    root = tmp_path / "served"
    root.mkdir()
    handler = type("Handler", (_RangeHandler,), {"directory": root})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield root, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _noisy_tensor_bytes(size: int = 3_000_000, first: int = 40_000) -> bytes:
    """Pseudo-random storage with a PROTO marker every 40 KB, roughly the
    density real float data produces. Seeded, so a failure is reproducible.
    `first` is where the markers start: storage that opens with one is the
    separate case below, and is not what a checkpoint usually looks like."""
    rng = random.Random(7)
    raw = bytearray(rng.randbytes(size))
    for n, i in enumerate(range(first, size - 2, 40_000)):
        raw[i:i + 2] = b"\x80" + bytes([2 + n % 4])
    return bytes(raw)


def _torch_zip(path: Path, payload: bytes, filler_members: int = 6) -> None:
    """A checkpoint shaped like torch's: one pickle member, the rest stored
    tensor blobs. One blob deliberately opens with a pickle marker, because
    real float data does that constantly and the scanner reads any member
    that looks like one."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("archive/data.pkl", payload)
        zf.writestr("archive/version", "3\n")
        for i in range(filler_members):
            blob = (b"\x80\x02" if i == 2 else b"\x33\x44") + bytes(200_000)
            zf.writestr(f"archive/data/{i}", blob)


def _scan(path: Path) -> list:
    proc = subprocess.run(["hayward", "scan", str(path), "-f", "json"],
                          capture_output=True, text=True, check=False)
    report = json.loads(proc.stdout)
    return sorted([f["rule_id"], str(f["severity"]), f["message"]]
                  for f in report.get("findings", []))


def _both_ways(served, name: str, builder) -> tuple[list, list, object]:
    root, base = served
    builder(root / name)
    dest = root.parent / "ranged" / name
    plan = materialize(f"{base}/{name}", dest)
    return _scan(dest), _scan(root / name), plan


@pytest.mark.parametrize("name, builder, strategy", [
    (
        "pytorch_model.bin",
        lambda p: _torch_zip(p, pickle.dumps({"weight": [1.0, 2.0]}, protocol=2)),
        "torch-zip",
    ),
    (
        "malicious.pt",
        # Resolves a genuinely denied callable so the comparison has something
        # to agree about beyond "both clean". Inert: it echoes a marker.
        lambda p: _torch_zip(p, pickle.dumps(
            _Reduce("os", "system", "echo quickset-range-marker"), protocol=2)),
        "torch-zip",
    ),
    (
        "legacy.pth",
        lambda p: p.write_bytes(_legacy_torch_bytes(b"\x11" * 3_000_000)),
        "torch-legacy",
    ),
    (
        # The sharpest case for the sparse design. The scanner resyncs on
        # PROTO markers after a stream stops parsing, and float tensor data
        # contains them constantly, so it walks a dozen stretches of garbage
        # on the real file and none at all on a hole full of zeros. If those
        # garbage walks resolved anything, or shifted the memo profile, the
        # two reads would part company here.
        "legacy_noisy.pth",
        lambda p: p.write_bytes(_legacy_torch_bytes(_noisy_tensor_bytes())),
        "torch-legacy",
    ),
    (
        "model.safetensors",
        lambda p: p.write_bytes(_safetensors_bytes()),
        "safetensors",
    ),
    (
        "model.gguf",
        lambda p: p.write_bytes(_gguf_bytes(b"\x00" * 2_000_000)),
        "gguf",
    ),
])
def test_range_read_and_whole_file_agree(served, name, builder, strategy):
    ranged, whole, plan = _both_ways(served, name, builder)
    assert plan.strategy == strategy
    assert ranged == whole, "the range read reached a different verdict"
    assert plan.bytes_read < plan.file_size, "nothing was saved"


def test_a_format_with_no_strategy_is_recorded_rather_than_dropped(served, tmp_path):
    root, base = served
    (root / "graph.onnx").write_bytes(b"\x08\x01\x12" + bytes(2_000_000))
    plan = materialize(f"{base}/graph.onnx", tmp_path / "graph.onnx",
                       full_limit=1_000_000)
    assert plan.sampled is False
    assert plan.reason
    assert not (tmp_path / "graph.onnx").exists()


def test_storage_that_opens_like_a_pickle_falls_back_to_the_whole_file(served, tmp_path):
    """When the bytes after the last complete stream open with a PROTO marker,
    nothing distinguishes "the next pickle" from "the first tensor", so there
    is no prefix the fetcher can defend. It downloads the file instead of
    guessing, which is the only answer that cannot silently under-read."""
    root, base = served
    (root / "ambiguous.pth").write_bytes(
        _legacy_torch_bytes(_noisy_tensor_bytes(first=0)))
    plan = materialize(f"{base}/ambiguous.pth", tmp_path / "ambiguous.pth")
    assert plan.strategy == "full-fallback"
    assert plan.bytes_read == plan.file_size
    assert _scan(tmp_path / "ambiguous.pth") == _scan(root / "ambiguous.pth")


def test_a_small_file_is_just_downloaded(served, tmp_path):
    """Three round trips cost more than a file this size does."""
    root, base = served
    (root / "tiny.onnx").write_bytes(b"\x08\x01\x12" + bytes(1024))
    plan = materialize(f"{base}/tiny.onnx", tmp_path / "tiny.onnx")
    assert plan.strategy == "full-small"
    assert plan.bytes_read == plan.file_size


def test_the_sparse_copy_keeps_the_real_length(served, tmp_path):
    root, base = served
    _torch_zip(root / "model.pt", pickle.dumps({"a": 1}, protocol=2))
    real = (root / "model.pt").stat().st_size
    plan = materialize(f"{base}/model.pt", tmp_path / "model.pt")
    assert (tmp_path / "model.pt").stat().st_size == real == plan.file_size


class _Reduce:
    """Pickles into a REDUCE of `module.name(argument)` without importing it.

    The argument is inert by construction, the same rule `quickset/cases.py`
    holds itself to: a scanner reads the opcode stream and cannot tell the
    difference, and anyone who actually loads this prints a marker.
    """

    def __init__(self, module: str, name: str, argument: str):
        self.module, self.name, self.argument = module, name, argument

    def __reduce__(self):
        import importlib

        return (getattr(importlib.import_module(self.module), self.name),
                (self.argument,))


def _safetensors_bytes() -> bytes:
    header = json.dumps({
        "weight": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
        "__metadata__": {"format": "pt"},
    }).encode()
    return struct.pack("<Q", len(header)) + header + bytes(1_000_000)


def test_module_constants_track_the_scanner():
    """These mirror hayward's own limits, and the fetcher only reads the same
    bytes as the scanner while they agree. A hayward release that changes one
    turns this fetcher into a silently short read."""
    from hayward.scanner import GGUF_METADATA_SCAN_BYTES, ModelFileScanner

    assert rangefetch.MAX_ZIP_MEMBER_BYTES == ModelFileScanner.MAX_ZIP_MEMBER_BYTES
    assert rangefetch.GGUF_METADATA_SCAN_BYTES == GGUF_METADATA_SCAN_BYTES
    assert rangefetch.MAX_SCAN_BYTES == ModelFileScanner.MAX_SCAN_BYTES


def test_a_gguf_past_the_scan_cap_is_not_read(served, tmp_path):
    """Above its cap the scanner opens nothing, so neither should the fetcher.

    Most real GGUF quantisations are on that side of the cap, and pulling four
    megabytes of metadata for a scan that reads none of it is pure waste. The
    fixture is a sparse file, so half a gigabyte costs no disk here either.
    """
    root, base = served
    big = root / "big.gguf"
    with open(big, "wb") as handle:
        handle.write(_gguf_bytes(b""))
        handle.truncate(rangefetch.MAX_SCAN_BYTES + 1_000_000)

    plan = materialize(f"{base}/big.gguf", tmp_path / "big.gguf")
    assert plan.strategy == "oversized-unread"
    assert plan.bytes_read == 4096
    ranged, whole = _scan(tmp_path / "big.gguf"), _scan(big)
    assert ranged == whole
    assert [f[0] for f in whole] == ["MFV-SKIP-001"]
