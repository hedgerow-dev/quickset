"""Tests for the real benign corpus.

The false-positive half of this benchmark is the half that is easy to fake. A
corpus of three hundred near-identical tiny-random transformers checkpoints
would look impressive in a count and prove almost nothing, because every one of
them exercises the same parser through the same shapes. So the properties
tested here are mostly about *composition*: how many formats, how many
publishers, how concentrated the corpus is in its largest bucket. A regression
in any of those quietly weakens every "zero false positives" number measured
against it, and nothing else in the project would notice.

The other half is provenance. Every entry is pinned by SHA-256 and carries the
verdict HuggingFace's own malware scanning gave it. An entry HuggingFace called
unsafe must never be in here, and a file whose bytes no longer match its pin
must never be scored, because both would move a scanner's number for a reason
that has nothing to do with the scanner.

Everything except the last class runs without fetching anything.
"""

from __future__ import annotations

import re
from collections import Counter

import pytest

from quickset import cases, realmodels

SHA256 = re.compile(r"^[0-9a-f]{64}$")


def test_manifest_is_not_empty():
    assert len(realmodels.MANIFEST) >= 200, (
        "a false-positive claim is worth about as much as the corpus behind it"
    )


def test_ids_are_unique():
    ids = [m.id for m in realmodels.MANIFEST]
    assert len(ids) == len(set(ids))


def test_every_entry_is_pinned():
    for m in realmodels.MANIFEST:
        assert SHA256.match(m.sha256), f"{m.id} is not pinned to a SHA-256"
        assert m.size > 0, f"{m.id} has no recorded size"


def test_filename_is_the_basename_of_the_path():
    """The cache lays files out as <id>/<filename>, so a filename that is not
    the real basename would fetch to a path the scanners then see under the
    wrong name -- and several real-world scanner gaps are extension dispatch
    bugs, so the name is part of what is being measured."""
    for m in realmodels.MANIFEST:
        assert m.filename == m.path.rsplit("/", 1)[-1], m.id


def test_ids_cannot_escape_the_cache_directory():
    """Ids are derived from repo and path, which are upstream-controlled
    strings. A `..` in one would write outside model-cache."""
    cache = realmodels.CACHE_DIR.resolve()
    for m in realmodels.MANIFEST:
        resolved = realmodels.cached_path(m).resolve()
        assert cache in resolved.parents, m.id
        assert ".." not in m.id and "/" not in m.id


def test_nothing_huggingface_called_unsafe_is_in_the_corpus():
    """Selection read each file's securityFileStatus from the HuggingFace API.
    A `caution` rollup is allowed on purpose -- HuggingFace labels ordinary
    sklearn and joblib constructors "suspicious", and dropping those would
    leave a corpus of files nobody flags, which measures nothing. `unsafe` is
    a different claim and must never appear."""
    for m in realmodels.MANIFEST:
        assert m.hf_scan in ("safe", "caution"), f"{m.id} rollup is {m.hf_scan!r}"


class TestDiversity:
    """Count is the least interesting property of this corpus."""

    def test_spans_many_file_formats(self):
        formats = {m.fmt for m in realmodels.MANIFEST}
        assert len(formats) >= 10, sorted(formats)

    def test_the_formats_scanners_actually_disagree_about_are_present(self):
        """Pickle-bearing formats are where false positives live, and the
        legacy non-zip torch layout and compressed joblib are the two that
        parsers most often get wrong in one direction or the other."""
        formats = {m.fmt for m in realmodels.MANIFEST}
        for required in ("torch zip", "torch legacy (non-zip)",
                         "joblib raw pickle", "safetensors", "onnx"):
            assert required in formats, f"{required} missing from {sorted(formats)}"

    def test_no_single_format_dominates(self):
        counts = Counter(m.fmt for m in realmodels.MANIFEST)
        top, n = counts.most_common(1)[0]
        assert n / len(realmodels.MANIFEST) <= 0.40, (
            f"{top} is {n}/{len(realmodels.MANIFEST)} of the corpus"
        )

    def test_no_single_publisher_dominates(self):
        counts = Counter(m.repo.split("/")[0] for m in realmodels.MANIFEST)
        top, n = counts.most_common(1)[0]
        assert len(counts) >= 40, f"only {len(counts)} publishers"
        assert n / len(realmodels.MANIFEST) <= 0.15, (
            f"{top} is {n}/{len(realmodels.MANIFEST)} of the corpus"
        )

    def test_spans_several_vintages(self):
        """A file written by torch 1.4 in 2020 and one written by torch 2.6 in
        2025 are different formats wearing the same extension."""
        years = {(m.last_commit or "?")[:4] for m in realmodels.MANIFEST}
        years.discard("?")
        assert len(years) >= 5, sorted(years)

    def test_stays_within_a_manageable_size(self):
        total = sum(m.size for m in realmodels.MANIFEST)
        assert total < 3e9, f"{total / 1e9:.1f} GB is too much to ask anyone to fetch"


class TestFetchedCorpus:
    """Skipped unless `python -m quickset.realmodels` has run."""

    def test_cached_models_are_all_hash_verified(self):
        cached = realmodels.cached_models()
        if not cached:
            pytest.skip("corpus not fetched")
        for m in cached:
            path = realmodels.cached_path(m)
            assert path.exists()
            assert realmodels._sha256(path) == m.sha256, m.id

    def test_a_tampered_file_is_not_treated_as_cached(self, tmp_path, monkeypatch):
        """The pin is the only thing standing between this benchmark and
        silently scoring a file nobody vetted."""
        cached = realmodels.cached_models()
        if not cached:
            pytest.skip("corpus not fetched")
        model = cached[0]
        monkeypatch.setattr(realmodels, "CACHE_DIR", tmp_path)
        dest = realmodels.cached_path(model)
        dest.parent.mkdir(parents=True)
        dest.write_bytes(b"\x80\x04}q\x00." + b"\x00" * model.size)
        assert not realmodels.is_cached(model)

    def test_fetched_models_become_benign_cases(self):
        if not realmodels.cached_models():
            pytest.skip("corpus not fetched")
        real = cases.real_model_cases()
        assert real
        assert all(not c.malicious for c in real)
        assert all("real-model" in c.tags for c in real)
        assert len({c.id for c in real}) == len(real)

    def test_case_bytes_are_the_pinned_bytes(self):
        """`build()` reads from the cache, so a case could in principle serve
        different bytes from the ones the manifest pinned."""
        cached = realmodels.cached_models()
        if not cached:
            pytest.skip("corpus not fetched")
        by_id = {c.id: c for c in cases.real_model_cases()}
        import hashlib
        for m in cached[:20]:
            blob = by_id[m.id].build()
            assert hashlib.sha256(blob).hexdigest() == m.sha256, m.id
