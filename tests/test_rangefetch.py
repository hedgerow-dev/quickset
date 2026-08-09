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

import io
import json
import pickle
import random
import re
import struct
import subprocess
import threading
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from quickset import rangefetch
from quickset.rangefetch import (
    NEED_MORE, NOT_A_PICKLE_PREFIX, gguf_structured_end, materialize,
    pickle_region_end, quote_path,
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
    assert rangefetch.choose_strategy(head, suffix) == expected


# ── end to end against a range-speaking server ──────────────────────────


class _RangeHandler(BaseHTTPRequestHandler):
    directory: Path

    def log_message(self, *args):  # keep pytest output readable
        pass

    def _target(self) -> Path:
        # Decoded first: a client that percent-encodes is doing the right
        # thing, and a server that compares the raw request path against a
        # filename cannot find any name that needed encoding.
        #
        # Basename only. This is a localhost test fixture, but a handler that
        # joins a request path straight onto a directory is a traversal bug
        # wherever it is written.
        decoded = urllib.parse.unquote(self.path.lstrip("/"))
        return self.directory / Path(decoded).name

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


class _Unseekable(io.RawIOBase):
    """A sink with no `tell`, so `zipfile` streams instead of patching.

    `writestr` to an ordinary file seeks back and fills the local header in,
    leaving no data descriptor and no flag bit 3. torch.save's writer streams,
    so every member of a real checkpoint carries one. The fixtures above
    therefore never exercised the layout that every file on the Hub actually
    has.
    """

    def __init__(self, handle):
        self._handle = handle

    def writable(self) -> bool:
        return True

    def write(self, data):
        return self._handle.write(data)


def _streamed_torch_zip(path: Path, payload: bytes) -> None:
    with open(path, "wb") as raw:
        with zipfile.ZipFile(_Unseekable(raw), "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("archive/data.pkl", payload)
            zf.writestr("archive/version", "3\n")
            # Zero length, so the old plan skipped its header entirely: too
            # small to be a member any scanner would parse, and a member the
            # central directory still names.
            zf.writestr("archive/byteorder", b"")
            for i in range(4):
                zf.writestr(f"archive/data/{i}", b"\x33\x44" + bytes(200_000))


def test_every_member_header_and_descriptor_is_fetched(served, tmp_path):
    """The sparse copy has to carry the whole zip skeleton, not just the parts
    hayward parses.

    modelaudit validates every central-directory entry against the local entry
    it points at, including the trailing data descriptor, and one hole makes
    it declare the directory inconsistent and abandon the archive: measured on
    the Hub, it turned every range-fetched torch checkpoint from "3 warnings"
    into "1 info", which in the comparative study is a competitor scoring
    differently because of our optimisation. Headers and descriptors are a few
    hundred bytes and sit where the fetcher already reads, so the fix costs
    bytes rather than requests.
    """
    root, base = served
    name = "streamed.pt"
    _streamed_torch_zip(root / name, pickle.dumps({"weight": [1.0, 2.0]}, protocol=2))
    dest = tmp_path / name
    plan = materialize(f"{base}/{name}", dest)
    assert plan.strategy == "torch-zip"
    assert plan.bytes_read < plan.file_size, "nothing was saved"

    whole = (root / name).read_bytes()
    sparse = dest.read_bytes()
    with zipfile.ZipFile(root / name) as zf:
        infos = zf.infolist()
    assert any(info.file_size == 0 for info in infos), "fixture lost its empty member"
    assert all(info.flag_bits & 0x08 for info in infos), "fixture is not streamed"
    for info in infos:
        start = info.header_offset
        name_len, extra_len = struct.unpack("<HH", whole[start + 26:start + 30])
        header_end = start + 30 + name_len + extra_len
        assert sparse[start:header_end] == whole[start:header_end], \
            f"hole in the local header of {info.filename}"
        data_end = header_end + info.compress_size
        trailer_end = data_end + rangefetch.ZIP_DATA_DESCRIPTOR_BYTES
        assert sparse[data_end:trailer_end] == whole[data_end:trailer_end], \
            f"hole in the data descriptor of {info.filename}"


def test_a_safetensors_read_reaches_past_the_header(served, tmp_path):
    """Hayward reads the header and stops. modelaudit will not route the file
    to its safetensors scanner until it has structurally probed the bytes
    after the header for a pickle hiding behind the extension, and on a hole
    full of zeros that probe never resolves: measured on the Hub, a clean
    44 MB checkpoint became "no scanner matched", which is a no-verdict in the
    study's own results caused by nothing but the fetch."""
    root, base = served
    # Non-zero tensor data, or the hole and the payload are the same bytes and
    # the assertion below holds however little was fetched.
    (root / "model.safetensors").write_bytes(
        _safetensors_bytes(_noisy_tensor_bytes(size=1_000_000)))
    dest = tmp_path / "model.safetensors"
    plan = materialize(f"{base}/model.safetensors", dest)

    whole = (root / "model.safetensors").read_bytes()
    header_size, = struct.unpack("<Q", whole[:8])
    end = 8 + header_size + rangefetch.SAFETENSORS_PROBE_BYTES
    assert end < len(whole), "fixture is too small to prove anything"
    assert dest.read_bytes()[:end] == whole[:end]
    assert plan.bytes_read < plan.file_size, "nothing was saved"


def test_quote_path_encodes_the_name_but_not_the_separators():
    assert quote_path("icd_eval/o_data/A榜 (1).zip") == (
        "icd_eval/o_data/A%E6%A6%9C%20%281%29.zip")


def test_a_name_with_a_space_and_non_ascii_survives_the_round_trip(served, tmp_path):
    """Handed the name raw, urllib refuses before a byte leaves the machine and
    the file is recorded as a fetch error rather than as a verdict. Encoded, it
    reads the same as any other checkpoint.

    Both trigger characters are in one name on purpose. The space is what
    actually fired on the Hub census, but a space encodes to `%20` under any
    scheme, so a fix that only handled ASCII would pass a space-only test and
    still drop every CJK and Cyrillic filename.
    """
    root, base = served
    name = "A榜 (1).pt"
    _torch_zip(root / name, pickle.dumps({"weight": [1.0, 2.0]}, protocol=2))

    with pytest.raises(rangefetch.RangeFetchError, match="control characters"):
        materialize(f"{base}/{name}", tmp_path / "raw.pt")

    dest = tmp_path / name
    plan = materialize(f"{base}/{quote_path(name)}", dest)
    assert plan.strategy == "torch-zip"
    assert _scan(dest) == _scan(root / name)


def test_a_zero_length_file_is_scanned_rather_than_failed(served, tmp_path):
    """An empty file is not a fetch failure. Nothing went wrong: every byte it
    has was read, and the scanner reads them and finds nothing. Counting it as
    an error moves a real file out of the denominator of the very rate the
    census exists to measure."""
    root, base = served
    (root / "empty.pkl").write_bytes(b"")
    dest = tmp_path / "empty.pkl"
    plan = materialize(f"{base}/empty.pkl", dest)
    assert plan.sampled is True
    assert plan.file_size == 0 and plan.bytes_read == 0
    assert dest.stat().st_size == 0
    assert _scan(dest) == []


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


def _safetensors_bytes(tensor_data: bytes = bytes(1_000_000)) -> bytes:
    header = json.dumps({
        "weight": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
        "__metadata__": {"format": "pt"},
    }).encode()
    return struct.pack("<Q", len(header)) + header + tensor_data


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
