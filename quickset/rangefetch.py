"""Fetch only the bytes a model-file scanner will actually look at.

A Hub-scale false-positive measurement is bounded by download volume, not by
scan time: a torch checkpoint is a zip whose tensor storage is almost all of
it, and the pickle that decides what executes on load is one small member.
HTTP range requests read that member and leave the weights on the server.
Measured on `sentence-transformers/all-MiniLM-L6-v2`: 2.9 MB of 90 MB, 3.2%.
(An earlier prototype managed 84 KB on the same file by reading `data.pkl` and
nothing else, and a hayward-only plan managed 223 KB. Each step up bought
agreement with a reader that looks at more of the container: the member sniff
needs four bytes of every member, the storage blobs that open like a pickle
have to be read as pickles, and modelaudit classifies every member from a
window of its own. Every one of those is bytes some scanner reads, so every
one is bytes the fetcher has to read to reach the same verdict. The cheaper
versions were cheaper because they were answering a narrower question.)

What this module produces is **not** a fragment handed to the scanner. It is a
*sparse local copy* of the remote file: same name, same total length, the
fetched ranges written at their true offsets, everything else left as a hole
that reads back as zeros. The scanner is then pointed at that path and runs
its ordinary code over it.

That choice is the whole design, and it is worth the paragraph:

- Nothing about the container is reimplemented here. `zipfile` finds the
  central directory where it really is, local header offsets resolve, lied
  general-purpose flag bits still make the strict reader refuse and still fall
  through to the raw-bytes path, nested archives still open. A fetcher that
  extracted `archive/data.pkl` and scanned it alone would instead have to
  re-derive every one of those behaviours, and would diverge the first time
  the scanner changed one.
- Size-dependent behaviour is preserved for free. A 600 MB checkpoint hits the
  scanner's own oversized-file rule in both paths, because the sparse file is
  600 MB.
- What the file *is* stays decided by its own bytes. Extension dispatch, magic
  sniffing and extension-confusion checks all see what the server served.

The cost is the part that has to be stated plainly: **a whole-buffer pass over
a region we did not fetch reads zeros.** Hayward has one, the embedded-
executable scan (MFV-EXEC-001), and it runs over every byte of files under its
in-memory cap. Range-reading cannot reproduce a scan of bytes it did not read.
Ranges we do fetch (headers, pickle members, metadata) are covered normally.
`scripts/range_compare.py` exists to measure whether that gap ever shows up on
real repositories rather than to argue that it cannot.

**The plan is the union of what five scanners read, not what hayward reads.**
That distinction was expensive to learn. A plan cut to hayward's own read
pattern agreed with hayward on 260 files and disagreed with modelaudit on
every torch zip in the same sample, because modelaudit validates parts of the
container hayward never looks at. In a study comparing the two, a hole is not
a neutral optimisation: it is a competitor being scored on bytes we chose not
to fetch. Where a comment below says a window exists for another scanner, that
is why it is there and why it does not come out.

Formats and what gets read:

    torch zip (PK)      end-of-central-directory, the central directory, then
                        per member: the local header, its trailing data
                        descriptor and the first four bytes, then in full only
                        the members a scanner will parse
    torch legacy (\\x80) a prefix grown until every pickle stream in it has
                        reached STOP and the bytes after the last one are
                        plainly not another pickle
    safetensors         the 8-byte length prefix, the JSON header, and the
                        probe window past it that modelaudit's format router
                        reads before it will route the file at all
    gguf                the header, the KV metadata and the tensor-info table
    flat, oversized     nothing past the first 4 KB: past the scanner's
                        in-memory cap a non-container format is not read at
                        all, only reported as non-coverage
    everything else     downloaded whole, or recorded as NOT SAMPLED

A format that cannot be range-read is downloaded or recorded. It is never
quietly dropped: the denominator of a false-positive rate is the point of the
exercise, and a silently missing file is a lie in it.
"""

from __future__ import annotations

import io
import pickletools
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

USER_AGENT = "quickset-rangefetch/1.0"

# Ceiling on a whole-file download for a format with no range strategy.
# Above it the file is recorded as not sampled rather than pulled.
DEFAULT_FULL_LIMIT = 400_000_000

# Below this, three round trips cost more than the file does.
SMALL_FILE_BYTES = 262_144

# Two ranges closer together than this are fetched as one. A wasted kilobyte
# is cheaper than a second request, and the Hub notices requests.
COALESCE_GAP = 8192

# Widest gap the budgeted second pass will bridge. Above it the skipped span
# is real tensor data and paying for it to save one request is a bad trade.
MAX_COALESCE_GAP = 256 * 1024

# Speculative slack for a local file header's extra field. PyTorch's writer
# pads it to 64-byte-align tensor data; the value is verified after the fetch
# and a short read is corrected, so this is a round-trip optimisation and not
# an assumption.
LOCAL_HEADER_SLACK = 128

# A streamed zip member repeats its CRC and sizes in a descriptor after the
# data: 16 bytes, 24 with zip64 sizes, either optionally preceded by a 4-byte
# signature. 24 covers every combination, and the window lands immediately
# before the next member's local header, so the coalescer folds the two into
# one request and the descriptors cost bytes rather than round trips.
#
# Hayward does not read these. modelaudit does, for every member the central
# directory names, and a hole where one should be aborts its entire zip
# analysis (`_ZipLocalEntryMismatch`), which is not a verdict about the model.
ZIP_DATA_DESCRIPTOR_BYTES = 24

# How much of every zip member is fetched regardless of what its first bytes
# look like.
#
# Hayward sniffs four bytes and reads no further unless they open a pickle.
# modelaudit classifies every member instead: 16 bytes, then up to 64 KB when
# those bytes could begin a pickle (`_PICKLE_DISCOVERY_LONG_PROBE_BYTES` in
# modelaudit 0.2.52). 64 KB is the longest probe it runs over a member it has
# not otherwise selected, and the size is what makes both halves work:
#
# - a member of 64 KB or less is fetched whole, so when a probe runs off the
#   end of it and zipfile verifies the CRC, the CRC is right;
# - a larger member is never read to its end by such a probe, so no CRC is
#   verified and the bytes read are real ones.
#
# Without it, a probe that reached the end of a short member on a hole
# produced "CRC validation failed for archive member ...", a warning about our
# fetch presented as a warning about the model. On a checkpoint already
# carrying a warning that changed nothing; on a clean one it would have
# flipped the lenient threshold.
#
# This is *not* a proof that 64 KB is every byte modelaudit can want from a
# member. Its deeper reads are larger (a megabyte of TorchScript source, ten
# for storage trust metadata) and are selected by member name or by a
# pickle-looking prefix, which is the rule that fetches whole members below.
# What backs the combination is the measurement in `scripts/range_compare.py`,
# not this comment.
ZIP_MEMBER_PROBE_BYTES = 65_536

# How far past a safetensors header the fetcher reads.
#
# Hayward needs none of it. modelaudit's format router does: before it will
# route a `.safetensors` file to its safetensors scanner it structurally
# probes the bytes after the header to rule out a pickle hiding behind the
# extension, and this is the size of that first probe window
# (`PROTO0_1_MAX_PROBE_BYTES` in modelaudit 0.2.52). Reading zeros there
# leaves the probe undecided, the router answers
# "pickle_routing_inconclusive", and no scanner runs at all: measured, a
# 44 MB checkpoint that scans clean whole became a no-verdict range-fetched.
# A no-verdict is a column in the study's own results, so a fetch artifact
# that produces one would land directly in a published number.
#
# The residual risk is stated rather than hidden: when that first probe is
# still undecided after 64 KB of real bytes, modelaudit widens it to 16 MB and
# the rest of what it reads is hole again. The window is not raised to 16 MB
# because that is two thousand times the bytes for a case the comparison run
# does not produce, and the failure mode if it ever does is loud -- the file
# becomes a no-verdict, not a wrong verdict.
SAFETENSORS_PROBE_BYTES = 65_536

# Mirrors hayward's own limits. Both decide what the scanner reads, so the
# fetcher has to agree with them to fetch the same bytes.
MAX_ZIP_MEMBER_BYTES = 200_000_000
GGUF_METADATA_SCAN_BYTES = 10_000_000
MAX_SCAN_BYTES = 500_000_000

EOCD_SIG = b"PK\x05\x06"
ZIP64_LOCATOR_SIG = b"PK\x06\x07"
ZIP64_EOCD_SIG = b"PK\x06\x06"
LOCAL_SIG = b"PK\x03\x04"
GGUF_MAGIC = b"GGUF"

# A protocol 2+ pickle opens with PROTO and its version byte. Same marker set
# hayward resyncs on, for the same reason: specific enough not to match tensor
# data constantly.
PICKLE_MARKERS = tuple(b"\x80" + bytes([p]) for p in range(2, 6))

# First bytes hayward treats as "worth running the pickle analysis over".
PICKLE_OPENERS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05",
                  b"c", b"(", b"]", b"}")

# Extensions whose zip container holds a pickle. Everything else that happens
# to be a zip (.keras, .npz, .skops) is a different format with a different
# reader, and gets downloaded whole rather than half-understood.
PICKLE_ZIP_EXTS = frozenset({
    ".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".th", ".mar", ".zip", "",
})


class RangeFetchError(Exception):
    """The remote file could not be read the way this module intended."""


def quote_path(path: str) -> str:
    """Percent-encode a repository file path for use in a URL.

    Per segment with `safe=""`, so the `/` separators survive and everything
    else does not. urllib does no encoding of its own: handed a raw name it
    raises "URL can't contain control characters" and the file is recorded as
    a fetch error, which is how a Hub census lost every file whose name held a
    space or a CJK character.

    Callers build the URL, so callers encode it. Doing it inside `materialize`
    would mean re-encoding a string that may already be encoded, and a name
    containing a literal `%` makes those two cases indistinguishable.
    """
    return "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))


@dataclass
class RangePlan:
    """What one file cost and how it was read."""

    strategy: str
    file_size: int = 0
    bytes_read: int = 0
    requests: int = 0
    sampled: bool = True
    reason: str = ""
    members: list[str] = field(default_factory=list)

    @property
    def fraction(self) -> float:
        return self.bytes_read / self.file_size if self.file_size else 0.0


# ── transport ───────────────────────────────────────────────────────────


class _DropAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Never carry the credential across a host boundary.

    `resolve/main/...` answers with a redirect, and where it points is decided
    by the repository, not by us. urllib replays the original headers on the
    new request, so a repository that redirected somewhere else would be handed
    the Bearer token. Strip it whenever the host changes; the Hub's own CDN
    URLs are pre-signed and do not want it anyway.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and new.host != req.host:
            new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(_DropAuthOnRedirect)


def _scrub(text: str, token: str | None) -> str:
    """Keep the credential out of every string that leaves this module.

    urllib puts request headers in a Request's repr, so an exception carrying
    the request carries the token. Results are written to disk and shared.
    """
    return text.replace(token, "<redacted>") if token and token in text else text


def probe(url: str, *, token: str | None = None, length: int = 4,
          timeout: int = 60) -> tuple[bytes, int]:
    """The file's first bytes and its total length, in **one** request.

    `RangeReader` would answer the same question with a HEAD and then a GET.
    That is the right shape when the whole file is about to be read, and the
    wrong shape when thousands of remote files are being classified to decide
    which ones are worth reading at all: the second request doubles what a
    selection pass costs the Hub for nothing. A 206 carries the total length
    in its `Content-Range`, so one ranged GET answers both halves.

    Raises `RangeFetchError` rather than returning a sentinel. A file that
    cannot be classified must be skipped by the caller, never guessed at.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept-Encoding": "identity",
        "Range": f"bytes=0-{max(0, length - 1)}",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            if response.status != 206:
                raise RangeFetchError(f"probe returned {response.status}, not 206")
            head = response.read(length)
            content_range = response.headers.get("Content-Range", "")
    except urllib.error.HTTPError as exc:
        raise RangeFetchError(_scrub(f"HTTP {exc.code}: {exc.reason}", token)) from None
    except RangeFetchError:
        raise
    except Exception as exc:
        raise RangeFetchError(_scrub(str(exc), token)) from None
    total = content_range.rsplit("/", 1)[-1]
    if not total.isdigit():
        raise RangeFetchError("no total length in Content-Range")
    return head, int(total)


class RangeReader:
    """A remote file read in pieces, counting every byte pulled.

    The Hub answers `resolve/main/...` with a redirect to a pre-signed CDN
    URL. That redirect is followed once, up front, and every range request
    then goes straight to the CDN: it is one fewer Hub request per range, and
    the signed URL needs no `Authorization` header, so the credential is sent
    exactly once per file.
    """

    def __init__(self, url: str, token: str | None = None, timeout: int = 120):
        self.origin_url = url
        self.token = token
        self.timeout = timeout
        self.bytes_read = 0
        self.requests = 0
        self.size = 0
        self.url = url
        self._resolve()

    def _open(self, request: urllib.request.Request):
        """One request with backoff. 429 and 5xx are the server asking for
        room, not verdicts about the file, so they are retried; 401/403/404
        are answers and are raised immediately."""
        delay = 2.0
        for attempt in range(5):
            try:
                self.requests += 1
                return _OPENER.open(request, timeout=self.timeout)
            except urllib.error.HTTPError as exc:
                if exc.code in (401, 403, 404, 416):
                    raise RangeFetchError(
                        _scrub(f"HTTP {exc.code}: {exc.reason}", self.token)) from None
                if attempt == 4:
                    raise RangeFetchError(
                        _scrub(f"HTTP {exc.code}: {exc.reason}", self.token)) from None
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                wait = float(retry_after) if (retry_after or "").isdigit() else delay
                time.sleep(min(wait, 60.0))
                delay *= 2
            except Exception as exc:
                if attempt == 4:
                    raise RangeFetchError(_scrub(str(exc), self.token)) from None
                time.sleep(delay)
                delay *= 2
        raise RangeFetchError("unreachable")

    def _resolve(self) -> None:
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.origin_url, headers=headers, method="HEAD")
        with self._open(request) as response:
            self.url = response.geturl()
            length = response.headers.get("Content-Length")
            if response.headers.get("Accept-Ranges", "").lower() == "none":
                raise RangeFetchError("server refuses range requests")
        if not length:
            raise RangeFetchError("no Content-Length; cannot plan a range read")
        self.size = int(length)

    def read(self, start: int, length: int) -> bytes:
        if length <= 0:
            return b""
        end = min(start + length, self.size) - 1
        if end < start:
            return b""
        headers = {
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "identity",
            "Range": f"bytes={start}-{end}",
        }
        # The resolved CDN URL is pre-signed. Only send the credential when
        # the redirect kept us on the origin.
        if self.token and self.url == self.origin_url:
            headers["Authorization"] = f"Bearer {self.token}"
        with self._open(urllib.request.Request(self.url, headers=headers)) as response:
            if response.status != 206:
                raise RangeFetchError(
                    f"range request returned {response.status}, not 206")
            data = response.read()
        self.bytes_read += len(data)
        return data


class SparseCopy:
    """The local stand-in: right name, right length, holes where we did not
    look. Ranges are batched so adjacent ones become one request."""

    def __init__(self, reader: RangeReader, dest: Path):
        self.reader = reader
        self.dest = dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(dest, "wb+")
        self.handle.truncate(reader.size)
        self._have: list[list[int]] = []

    def close(self) -> None:
        self.handle.close()

    def __enter__(self) -> SparseCopy:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def covered(self, start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in self._have)

    def _missing(self, start: int, end: int) -> list[tuple[int, int]]:
        """The parts of [start, end) not already on disk. Growing a prefix
        re-asks for a span it mostly holds, so without this the bytes-read
        figure counts the same kilobytes several times over and the request
        actually re-pulls them."""
        gaps: list[tuple[int, int]] = []
        cursor = start
        for held_start, held_end in self._have:
            if held_end <= cursor:
                continue
            if held_start >= end:
                break
            if held_start > cursor:
                gaps.append((cursor, min(held_start, end)))
            cursor = max(cursor, held_end)
            if cursor >= end:
                return gaps
        if cursor < end:
            gaps.append((cursor, end))
        return gaps

    def fetch(self, ranges: list[tuple[int, int]]) -> None:
        """Fetch [start, end) spans, coalescing and skipping what we hold."""
        wanted: list[tuple[int, int]] = []
        for start, end in ranges:
            start = max(0, start)
            end = min(end, self.reader.size)
            if end > start:
                wanted.extend(self._missing(start, end))
        if not wanted:
            return
        wanted.sort()
        merged: list[list[int]] = []
        for start, end in wanted:
            if merged and start - merged[-1][1] <= COALESCE_GAP:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        merged = self._spend_gap_budget(merged)
        for start, end in merged:
            data = self.reader.read(start, end - start)
            self.handle.seek(start)
            self.handle.write(data)
            self._have.append([start, start + len(data)])
        self.handle.flush()
        self._have.sort()
        held: list[list[int]] = []
        for span in self._have:
            if held and span[0] <= held[-1][1]:
                held[-1][1] = max(held[-1][1], span[1])
            else:
                held.append(span)
        self._have = held

    def _spend_gap_budget(self, merged: list[list[int]]) -> list[list[int]]:
        """Trade a little bandwidth for far fewer requests.

        A checkpoint with three hundred tensor storages needs the first four
        bytes of each, and those windows sit megabytes apart, so a strict
        coalescer issues one request per member. The Hub notices. Closing the
        narrowest gaps first, against a budget set as a fraction of the file,
        collapses most of them while keeping the extra bytes bounded and
        visible in the byte count rather than hidden.
        """
        budget = max(1 << 20, self.reader.size // 50)
        gaps = sorted((merged[i + 1][0] - merged[i][1], i)
                      for i in range(len(merged) - 1))
        dissolve: set[int] = set()
        for gap, index in gaps:
            if gap > budget or gap > MAX_COALESCE_GAP:
                break
            budget -= gap
            dissolve.add(index)
        out: list[list[int]] = []
        for i, span in enumerate(merged):
            if out and i - 1 in dissolve:
                out[-1][1] = max(out[-1][1], span[1])
            else:
                out.append(span)
        return out

    def at(self, start: int, length: int) -> bytes:
        self.handle.seek(start)
        return self.handle.read(length)


# ── pickle prefix arithmetic ────────────────────────────────────────────

NEED_MORE = -1
NOT_A_PICKLE_PREFIX = -2


def _stream_end(data: bytes, pos: int) -> int | None:
    """Offset just past the STOP of the pickle starting at `pos`, or None."""
    stream = io.BytesIO(data)
    stream.seek(pos)
    try:
        for op, _arg, offset in pickletools.genops(stream):
            if op.name == "STOP" and offset is not None:
                return offset + 1
    except Exception:
        return None
    return None


def pickle_region_end(data: bytes, at_eof: bool) -> int:
    """Where the concatenated pickle streams in `data` stop.

    Returns a byte offset, or `NEED_MORE` when the prefix ends inside a stream
    that has not reached STOP, or `NOT_A_PICKLE_PREFIX` when the walk dies on
    bytes it could read (joblib splices raw arrays into its stream and lands
    here, which is why that format is downloaded whole instead).

    This is the condition the whole legacy strategy turns on, and it is not
    "read four pickles". `torch.save`'s legacy path writes *five*: the magic
    number, the protocol version, `sys_info`, the object, and then the sorted
    list of storage keys, before a single byte of tensor data. A prefix cut
    after the fourth ends mid-stream, and hayward 1.0.1 says so out loud with
    MFV-SKIP-003. Counting streams at all is the mistake; the question is
    whether the bytes that follow the last complete one are still a pickle.
    """
    total = len(data)
    pos = 0
    while pos < total:
        if total - pos < 2 and not at_eof:
            # One byte left is not enough to tell a PROTO opcode from the
            # first byte of tensor storage, and guessing the wrong way cuts
            # the next stream in half.
            return NEED_MORE
        if data[pos:pos + 2] not in PICKLE_MARKERS:
            # Raw storage. Everything before here is whole.
            return pos
        end = _stream_end(data, pos)
        if end is None:
            stream = io.BytesIO(data)
            stream.seek(pos)
            try:
                for _ in pickletools.genops(stream):
                    pass
            except Exception:
                pass
            if stream.tell() >= total:
                return NEED_MORE
            return NOT_A_PICKLE_PREFIX
        pos = end
    # Ended exactly on a boundary. Another stream may follow.
    return total if at_eof else NEED_MORE


# ── gguf prefix arithmetic ──────────────────────────────────────────────

_GGUF_FIXED_SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1,
                     10: 8, 11: 8, 12: 8}
_GGUF_STRING = 8
_GGUF_ARRAY = 9


def gguf_structured_end(data: bytes) -> int:
    """End of the GGUF header, KV metadata and tensor-info table.

    Everything hayward reads from a GGUF lives before this offset; past it is
    tensor data, which it only measures against the file length. Returns
    `NEED_MORE` when the prefix runs out mid-structure and
    `NOT_A_PICKLE_PREFIX` (reused as "give up") when a field is nonsense,
    since a malformed header is exactly the case worth downloading whole and
    letting the scanner report.
    """
    if len(data) < 24 or data[:4] != GGUF_MAGIC:
        return NOT_A_PICKLE_PREFIX
    _version, tensor_count, kv_count = struct.unpack_from("<IQQ", data, 4)
    total = len(data)
    offset = 24
    # Bounded by what the bytes in hand could pay for: a KV entry costs at
    # least 12 bytes and a tensor info at least 24, so an attacker-declared
    # count of 2**63 cannot spin these loops. Hitting a bound means the
    # section is not verifiable from this prefix, which is a request for more
    # bytes rather than a verdict.
    if kv_count > total // 12 + 1 or tensor_count > total // 24 + 1:
        return NEED_MORE

    def u64(at: int) -> int | None:
        if at + 8 > total:
            return None
        return struct.unpack_from("<Q", data, at)[0]

    def u32(at: int) -> int | None:
        if at + 4 > total:
            return None
        return struct.unpack_from("<I", data, at)[0]

    for _ in range(kv_count):
        key_len = u64(offset)
        if key_len is None:
            return NEED_MORE
        offset += 8 + key_len
        value_type = u32(offset)
        if value_type is None:
            return NEED_MORE
        offset += 4
        if value_type == _GGUF_STRING:
            vlen = u64(offset)
            if vlen is None:
                return NEED_MORE
            offset += 8 + vlen
        elif value_type == _GGUF_ARRAY:
            elem_type = u32(offset)
            count = u64(offset + 4)
            if elem_type is None or count is None:
                return NEED_MORE
            offset += 12
            if elem_type == _GGUF_STRING:
                if count > total // 8 + 1:
                    return NEED_MORE
                for _ in range(count):
                    slen = u64(offset)
                    if slen is None:
                        return NEED_MORE
                    offset += 8 + slen
            else:
                size = _GGUF_FIXED_SIZES.get(elem_type)
                if size is None:
                    return NOT_A_PICKLE_PREFIX
                offset += count * size
        else:
            size = _GGUF_FIXED_SIZES.get(value_type)
            if size is None:
                return NOT_A_PICKLE_PREFIX
            offset += size
        if offset > total:
            return NEED_MORE

    for _ in range(tensor_count):
        name_len = u64(offset)
        if name_len is None:
            return NEED_MORE
        offset += 8 + name_len
        n_dims = u32(offset)
        if n_dims is None:
            return NEED_MORE
        if n_dims > 8:
            return NOT_A_PICKLE_PREFIX
        offset += 4 + 8 * n_dims + 4 + 8
        if offset > total:
            return NEED_MORE
    return offset


# ── zip planning ────────────────────────────────────────────────────────


def _central_directory_offset(tail: bytes, tail_start: int) -> int:
    """Where the central directory begins, zip64 included."""
    eocd = tail.rfind(EOCD_SIG)
    if eocd == -1:
        raise RangeFetchError("no end-of-central-directory record")
    if eocd + 22 > len(tail):
        raise RangeFetchError("end-of-central-directory record is truncated")
    cd_offset, = struct.unpack("<I", tail[eocd + 16:eocd + 20])
    if cd_offset != 0xFFFFFFFF:
        return cd_offset
    # zip64: the locator sits immediately before the EOCD and points at the
    # zip64 EOCD record, whose offsets are 64-bit. Real checkpoints reach this
    # once a repo ships shards past 4 GB, and raising instead would drop the
    # largest models out of the sample without saying so.
    locator = tail.rfind(ZIP64_LOCATOR_SIG, 0, eocd)
    if locator == -1 or locator + 20 > len(tail):
        raise RangeFetchError("zip64 end-of-central-directory locator missing")
    z64_offset, = struct.unpack("<Q", tail[locator + 8:locator + 16])
    rel = z64_offset - tail_start
    if rel < 0 or rel + 56 > len(tail):
        raise RangeFetchError("zip64 record lies outside the fetched tail")
    if tail[rel:rel + 4] != ZIP64_EOCD_SIG:
        raise RangeFetchError("zip64 record signature mismatch")
    return struct.unpack("<Q", tail[rel + 48:rel + 56])[0]


def _plan_zip(copy: SparseCopy, plan: RangePlan) -> None:
    size = copy.reader.size
    tail_len = min(size, 65_557 + 20)
    tail_start = size - tail_len
    copy.fetch([(tail_start, size)])
    tail = copy.at(tail_start, tail_len)
    cd_offset = _central_directory_offset(tail, tail_start)
    if cd_offset < tail_start:
        copy.fetch([(cd_offset, tail_start)])

    with zipfile.ZipFile(copy.dest) as zf:
        infos = list(zf.infolist())

    # Which members the scanner will look at. A member named like a pickle is
    # read whatever its first bytes say; anything else is decided on its first
    # four, so those have to be fetched for every member the scanner would
    # sniff. Members outside the size bounds are read by neither the pickle
    # sniff nor the nested-zip descent, so neither reads them here.
    #
    # The *header* of every member is fetched regardless of that filter.
    # modelaudit walks the central directory and checks each entry against the
    # local header it points at, so a single skipped header (measured: a
    # zero-length member, and any member over the size bound) makes it declare
    # the directory inconsistent and abandon the archive. Headers are a couple
    # of hundred bytes and sit where the fetcher is already reading.
    candidates: list[tuple[zipfile.ZipInfo, bool]] = []
    heads: list[tuple[int, int]] = []
    for info in infos:
        named = (info.filename.endswith((".pkl", ".pickle"))
                 or info.filename.rsplit("/", 1)[-1] == "data.pkl")
        name_len = len(info.filename.encode("utf-8"))
        heads.append((info.header_offset,
                      info.header_offset + 30 + name_len + LOCAL_HEADER_SLACK + 4))
        if named or 2 <= info.file_size <= MAX_ZIP_MEMBER_BYTES:
            candidates.append((info, named))
    copy.fetch(heads)

    # The local header's name/extra lengths are authoritative and may differ
    # from the central directory's (which is itself a parser-differential
    # trick), so the speculative window above is checked rather than trusted.
    # Keyed by header offset, not by name: a zip may carry two members with
    # the same name, and that duplication is itself a parser-differential
    # trick rather than an accident.
    starts: dict[int, int] = {}
    wanted: list[tuple[int, int]] = []
    corrections: list[tuple[int, int]] = []
    for info in infos:
        local = copy.at(info.header_offset, 30)
        if len(local) < 30 or local[:4] != LOCAL_SIG:
            continue
        name_len, extra_len = struct.unpack("<HH", local[26:30])
        data_start = info.header_offset + 30 + name_len + extra_len
        starts[info.header_offset] = data_start
        if not copy.covered(info.header_offset, data_start + 4):
            corrections.append((info.header_offset, data_start + 4))
        # Bit 3: sizes live in a descriptor after the data rather than in the
        # header. torch.save sets it on every member it writes.
        if struct.unpack("<H", local[6:8])[0] & 0x08:
            data_end = data_start + info.compress_size
            wanted.append((data_end, data_end + ZIP_DATA_DESCRIPTOR_BYTES))
        # The probe window every member gets, whatever its first bytes say.
        wanted.append((data_start,
                       data_start + min(info.compress_size, ZIP_MEMBER_PROBE_BYTES)))
    if corrections:
        copy.fetch(corrections)

    # Full members: everything named like a pickle, everything whose first
    # bytes open one, everything that is itself a zip, and every deflated
    # member (a partly-fetched deflate stream cannot be sniffed locally
    # without risking a different answer than the scanner's).
    for info, named in candidates:
        data_start = starts.get(info.header_offset)
        if data_start is None:
            continue
        # One megabyte past the scanner's own decompression cap, so a member
        # that overruns it overruns it here too and both paths report the
        # zip-bomb rule rather than one of them reporting a clean member.
        take = min(info.compress_size, MAX_ZIP_MEMBER_BYTES + 1_000_000)
        head = copy.at(data_start, 4)
        if (named
                or info.compress_type != zipfile.ZIP_STORED
                or head.startswith(PICKLE_OPENERS)
                or head == LOCAL_SIG):
            wanted.append((data_start, data_start + take))
            plan.members.append(info.filename)
    copy.fetch(wanted)


# ── entry point ─────────────────────────────────────────────────────────


def _grow(copy: SparseCopy, probe, start: int = 1 << 20,
          ceiling: int | None = None) -> int:
    """Fetch a prefix, ask `probe` whether it is complete, repeat."""
    top = min(ceiling or copy.reader.size, copy.reader.size)
    window = min(start, top)
    while True:
        copy.fetch([(0, window)])
        verdict = probe(copy.at(0, window), window >= copy.reader.size)
        if verdict >= 0 or verdict == NOT_A_PICKLE_PREFIX:
            return verdict
        if window >= top:
            return NEED_MORE
        window = min(window * 4, top)


def _download_full(copy: SparseCopy) -> None:
    copy.fetch([(0, copy.reader.size)])


def _fall_back(copy: SparseCopy, plan: RangePlan, full_limit: int, reason: str) -> None:
    """A range strategy that cannot finish becomes a whole download, or an
    explicit non-sample. Never a partial read presented as a whole one."""
    plan.strategy = "full-fallback"
    plan.reason = reason
    if copy.reader.size > full_limit:
        plan.sampled = False
    else:
        _download_full(copy)


def materialize(
    url: str,
    dest: Path,
    *,
    token: str | None = None,
    full_limit: int = DEFAULT_FULL_LIMIT,
    timeout: int = 120,
) -> RangePlan:
    """Write a scannable local copy of `url` to `dest`, reading as little as
    the format allows. `dest`'s name decides the scanner's dispatch, so pass
    the remote filename.

    A returned plan with `sampled is False` means nothing usable was written
    and the file must be recorded as not measured. It is never an empty pass.
    """
    reader = RangeReader(url, token=token, timeout=timeout)
    suffix = dest.suffix.lower()

    with SparseCopy(reader, dest) as copy:
        plan = RangePlan(strategy="", file_size=reader.size)

        if reader.size <= SMALL_FILE_BYTES:
            # A zero-length file lands here and is deliberately not an error.
            # Nothing failed: it is a file whose contents were read in full,
            # and the scanner reports it clean. Raising instead put eight
            # files from two ordinary repositories in the error column of a
            # census whose whole subject was how often the scanner is wrong.
            _download_full(copy)
            plan.strategy = "full-small"
        else:
            copy.fetch([(0, 4096)])
            head = copy.at(0, 4096)
            plan.strategy = choose_strategy(head, suffix)

            if plan.strategy in ("torch-legacy", "gguf") and reader.size > MAX_SCAN_BYTES:
                # Above its in-memory cap the scanner reads nothing but the
                # file's length: a flat format is neither a zip nor HDF5, so
                # neither of the two lazy container paths applies and it
                # reports non-coverage without opening anything. The sparse
                # copy already carries the length, so there is nothing left to
                # fetch and both reads reach the same verdict on 4 KB. Most
                # real GGUF quantisations are on this side of the cap.
                plan.strategy = "oversized-unread"
                plan.reason = "larger than the scanner's in-memory cap; it reads no content"
            elif plan.strategy == "torch-zip":
                try:
                    _plan_zip(copy, plan)
                except (RangeFetchError, zipfile.BadZipFile, struct.error,
                        ValueError) as exc:
                    # A container this fetcher cannot navigate is still a file
                    # the scanner has an opinion about, and one it is likely to
                    # report on. Dropping it would remove exactly the damaged
                    # archives worth measuring.
                    _fall_back(copy, plan, full_limit, f"zip: {exc}")
            elif plan.strategy == "torch-legacy":
                end = _grow(copy, pickle_region_end)
                if end < 0:
                    _fall_back(copy, plan, full_limit,
                               "pickle region did not terminate cleanly"
                               if end == NEED_MORE else
                               "raw data spliced into the pickle stream")
            elif plan.strategy == "safetensors":
                header_size, = struct.unpack("<Q", head[:8])
                # A header the scanner rejects on arithmetic alone (over its
                # own limit, or running past the end of the file) needs no
                # bytes past the length the sparse copy already carries.
                if header_size <= 100_000_000 and 8 + header_size <= reader.size:
                    copy.fetch([(0, 8 + header_size + SAFETENSORS_PROBE_BYTES)])
            elif plan.strategy == "gguf":
                # Ceiling well past any real metadata section: nothing in the
                # container declares its length, so the prefix has to grow
                # blind, and a corrupt header must not turn that into a full
                # download of a file the scanner will only read 10 MB of.
                end = _grow(copy, lambda d, _eof: gguf_structured_end(d),
                            ceiling=64 << 20)
                if end < 0 or end > GGUF_METADATA_SCAN_BYTES:
                    copy.fetch([(0, min(GGUF_METADATA_SCAN_BYTES, reader.size))])
            elif plan.strategy == "full":
                if reader.size > full_limit:
                    plan.sampled = False
                    plan.reason = (
                        f"no range strategy for this format and {reader.size} bytes "
                        f"exceeds the {full_limit}-byte download limit")
                else:
                    _download_full(copy)
            else:
                raise RangeFetchError(f"unplanned strategy {plan.strategy!r}")

        plan.bytes_read = reader.bytes_read
        plan.requests = reader.requests

    if not plan.sampled:
        dest.unlink(missing_ok=True)
    return plan


def choose_strategy(head: bytes, suffix: str) -> str:
    """Pick a strategy from the file's own first bytes and its name."""
    if head[:4] == LOCAL_SIG and suffix in PICKLE_ZIP_EXTS:
        return "torch-zip"
    if head[:4] == GGUF_MAGIC:
        return "gguf"
    if suffix == ".safetensors" and len(head) >= 8:
        return "safetensors"
    if head[:2] in PICKLE_MARKERS:
        return "torch-legacy"
    return "full"
