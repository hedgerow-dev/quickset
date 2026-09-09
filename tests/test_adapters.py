"""Adapter tests: does each adapter correctly read its scanner's output?

This is the highest-value test file in the project, and the reason is worth
stating plainly. During development the Hayward adapter looked for a JSON
field named `file_path`; the actual field is `file`. Every lookup returned
nothing, every case scored as not-flagged, and the harness printed a clean,
confident, entirely wrong `0/9 (0%)` for a scanner that detects 9 of 9. Nothing
crashed and nothing warned.

A benchmark's characteristic failure is not a crash, it is a plausible number.
An adapter that silently reads nothing is indistinguishable from a scanner that
detects nothing, so each adapter is pinned here against a file its scanner
certainly flags and one it certainly does not. Skipped when the scanner is not
installed, because nobody has all of them.
"""

from __future__ import annotations

import io
import pickle
import zipfile
from pathlib import Path

import pytest

from quickset import cases
from quickset.adapters import all_adapters


@pytest.fixture()
def obvious_malware(tmp_path: Path) -> Path:
    """os.system with a marker argument. Every scanner in this project's scope
    detects this; one that doesn't is misconfigured, not merely weaker."""
    p = tmp_path / "obvious" / "direct_os_system.pkl"
    p.parent.mkdir(parents=True)
    p.write_bytes(cases.MALICIOUS[0].build())
    return p


@pytest.fixture()
def obvious_benign(tmp_path: Path) -> Path:
    p = tmp_path / "benign" / "state_dict.pkl"
    p.parent.mkdir(parents=True)
    p.write_bytes(pickle.dumps({"weight": [1.0, 2.0]}, protocol=4))
    return p


@pytest.fixture()
def unreadable_by_picklescan(tmp_path: Path) -> Path:
    """A zip named .keras: a real format, and one picklescan has no reader
    for. It reports `Scanned files: 0` and says nothing else."""
    p = tmp_path / "unreadable" / "model.keras"
    p.parent.mkdir(parents=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", "{}")
    p.write_bytes(buf.getvalue())
    return p


def test_hayward_coverage_gap_is_not_a_verdict(tmp_path: Path):
    """A file hayward could not fully read must score as no-verdict.

    hayward states this in the report rather than leaving it to be inferred:
    `coverage_gaps` lists the files it did not finish. The previous adapter
    read no such signal at all, so a file the scanner declined to read counted
    as covered, and since the coverage rules carry a severity, as a finding.
    This 7z header is the cheapest trigger: MFV-7Z-001 fires whenever no
    extractor is available, needs no fetched corpus, and is eight bytes.

    A perfect coverage column is not evidence this works. It is what the bug
    looked like.
    """
    adapter = next(a for a in all_adapters() if a.name == "hayward")
    if not adapter.available():
        pytest.skip("hayward not installed")

    p = tmp_path / "gap" / "archive.7z"
    p.parent.mkdir(parents=True)
    p.write_bytes(b"7z\xbc\xaf\x27\x1c\x00\x04")

    outcome = adapter.scan(p)
    assert outcome.errored, (
        f"hayward reported a coverage gap and the adapter scored a verdict "
        f"anyway (detail={outcome.detail!r}). A file the scanner did not "
        f"finish reading belongs in the coverage column, not in detection or "
        f"false positives."
    )
    assert not outcome.flagged
    assert outcome.flagged_lenient is not True


def test_picklescan_zero_file_scan_is_not_a_clean_verdict(unreadable_by_picklescan):
    """picklescan declines to read a file in two ways and only one says so.

    A malformed pickle prints "could not parse as pickle". A format it has no
    reader for prints nothing at all and reports `Scanned files: 0`, which is
    byte-for-byte identical to a clean scan. The adapter read the second as a
    true negative, so picklescan was credited with clearing 14 benign files it
    never opened, and its published coverage was 91% when it was 85%.

    This is the same accounting every other adapter already does: modelscan's
    total_scanned == 0, modelaudit's empty scanner_names, Rowan's MFV-SKIP-*.
    """
    adapter = next(a for a in all_adapters() if a.name == "picklescan")
    if not adapter.available():
        pytest.skip("picklescan not installed")

    outcome = adapter.scan(unreadable_by_picklescan)
    assert outcome.errored, (
        "picklescan reported no verdict on this file and the adapter recorded "
        f"a clean scan (detail={outcome.detail!r}). A file the scanner never "
        "opened is not a file it cleared, and counting it as one inflates both "
        "coverage and the false-positive denominator."
    )
    assert not outcome.flagged


@pytest.mark.parametrize("adapter", all_adapters(), ids=lambda a: a.name)
def test_adapter_flags_obvious_malware(adapter, obvious_malware):
    """Guards against the silent-misread failure: an adapter whose output
    parsing is broken reports not-flagged for everything, which reads as a
    real result rather than an error."""
    if not adapter.available():
        pytest.skip(f"{adapter.name} not installed")

    outcome = adapter.scan(obvious_malware)
    assert outcome.flagged, (
        f"{adapter.name} did not flag a direct os.system payload. Either the "
        f"scanner is misconfigured or this adapter is misreading its output "
        f"-- do not publish numbers until this passes. detail={outcome.detail!r}"
    )
    assert not outcome.errored


@pytest.mark.parametrize("adapter", all_adapters(), ids=lambda a: a.name)
def test_adapter_does_not_flag_obvious_benign(adapter, obvious_benign):
    """The mirror image: an adapter that reports everything as flagged would
    score perfect detection and be equally worthless."""
    if not adapter.available():
        pytest.skip(f"{adapter.name} not installed")

    outcome = adapter.scan(obvious_benign)
    assert not outcome.flagged, (
        f"{adapter.name} flagged a plain dict state_dict as malicious "
        f"(detail={outcome.detail!r}); check the adapter before trusting any "
        f"false-positive number it produces."
    )


def test_at_least_one_scanner_is_installed():
    """A run with no scanners on PATH prints an empty matrix rather than
    failing, which is fine interactively and misleading in CI."""
    if not any(a.available() for a in all_adapters()):
        pytest.skip("no scanners installed in this environment")
