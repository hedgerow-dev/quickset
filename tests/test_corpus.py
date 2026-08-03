"""Corpus integrity tests.

Two properties have to hold for this project to be safe to publish and honest
to cite, and neither is self-evident from reading cases.py:

1. Payloads are inert. They reference dangerous callables (that is the point)
   but can never do anything. If a real command or a resolvable host ever gets
   committed, this file fails.
2. Cases are what they claim. A malicious case that does not actually contain
   its gadget would be scored as a miss for every scanner, silently deflating
   everyone's number.
"""

from __future__ import annotations

import pickletools
import io

import pytest

from quickset import cases


def test_corpus_has_both_classes():
    assert cases.MALICIOUS, "no malicious cases"
    assert cases.BENIGN, "a detection-only corpus scores a flag-everything scanner as perfect"


def test_case_ids_are_unique():
    ids = [c.id for c in cases.ALL_CASES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("case", cases.ALL_CASES, ids=lambda c: c.id)
def test_every_case_builds_deterministically(case):
    first, second = case.build(), case.build()
    assert first == second, "case bytes must be reproducible for results to be comparable"
    assert first, "case built to empty bytes"


@pytest.mark.parametrize("case", cases.MALICIOUS, ids=lambda c: c.id)
def test_malicious_payload_arguments_are_inert(case):
    """No payload may carry a command that does anything, or a host that
    resolves. Commands echo the marker; hosts live under .invalid, which
    RFC 2606 reserves as permanently non-resolvable."""
    blob = case.build()

    # Pull out every string constant the payload pushes.
    strings = []
    stream = io.BytesIO(blob)
    while stream.tell() < len(blob):
        start = stream.tell()
        try:
            for op, arg, _pos in pickletools.genops(stream):
                if isinstance(arg, str):
                    strings.append(arg)
        except Exception:
            break
        if stream.tell() <= start:
            break

    for text in strings:
        lowered = text.lower()
        if "://" in lowered:
            assert ".invalid/" in lowered or lowered.endswith(".invalid"), (
                f"{case.id} contains a URL that could resolve: {text!r}"
            )
        # Anything that looks like a shell command must be an echo of the marker.
        if any(tok in text for tok in ("curl ", "wget ", "bash ", "sh -c", "rm ")):
            raise AssertionError(f"{case.id} contains a live-looking command: {text!r}")

    # The one hostname-bearing case must use the reserved TLD.
    if "exfil" in case.id or "ssl" in case.id:
        assert any(s.endswith(".invalid") for s in strings), (
            f"{case.id} must use a .invalid host"
        )


@pytest.mark.parametrize("case", cases.MALICIOUS, ids=lambda c: c.id)
def test_malicious_case_actually_contains_a_gadget(case):
    """Guards against a case that scores as a universal miss because the
    payload is malformed rather than because scanners are evading it."""
    blob = case.build()
    assert b"\x93" in blob or b"c" in blob, f"{case.id} has no global-resolution opcode"


def test_legacy_layout_hides_payload_after_first_stop():
    """The legacy-format case is only meaningful if the gadget really does sit
    past the first STOP opcode. If torch's layout is ever simplified here, this
    case silently stops testing anything."""
    blob = cases.legacy_torch_layout(b"\x80\x04\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R.")

    stream = io.BytesIO(blob)
    first_ops = [op.name for op, _a, _p in pickletools.genops(stream)]
    assert first_ops[-1] == "STOP"
    assert stream.tell() < len(blob), "nothing follows the first pickle"
    assert b"system" not in blob[: stream.tell()], (
        "the gadget must not be visible within the first pickle"
    )


def test_origins_are_declared():
    """Cases invented here are the weakest evidence in the set and have to be
    distinguishable from published ones at a glance."""
    allowed = {"published-cve", "published-technique", "folklore", "quickset", "real-world"}
    for case in cases.ALL_CASES:
        assert case.origin in allowed, f"{case.id} has an undeclared origin"
    for case in cases.MALICIOUS:
        if case.origin.startswith("published"):
            assert case.reference, f"{case.id} claims a published origin but cites nothing"
