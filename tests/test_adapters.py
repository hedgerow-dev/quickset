"""Adapter tests: does each adapter correctly read its scanner's output?

This is the highest-value test file in the project, and the reason is worth
stating plainly. During development the open-rowan adapter looked for a JSON
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

import pickle
from pathlib import Path

import pytest

from picklebench import cases
from picklebench.adapters import all_adapters


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
