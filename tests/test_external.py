"""Tests for externally-authored corpus handling.

The label logic is the part that matters and it is pure, so most of this runs
without fetching anything. The rule it enforces: a file the corpus author does
not label is excluded from scoring, never assigned a label by us. Inventing
ground truth is how a benchmark quietly becomes a measurement of its own
assumptions, and this project already carries enough author bias without
adding that.
"""

from __future__ import annotations

import re

import pytest

from quickset import external


def test_every_corpus_declares_provenance():
    """A corpus with no stated licence or origin cannot be cited, and two of
    these have no declared licence at all, which readers need to know."""
    for corpus in external.CORPORA:
        assert corpus.origin.startswith("http"), corpus.id
        assert corpus.license, corpus.id
        assert corpus.note, corpus.id


def test_corpus_ids_are_unique():
    ids = [c.id for c in external.CORPORA]
    assert len(ids) == len(set(ids))


def test_every_corpus_is_pinned_to_a_commit():
    """A branch head is not a corpus. These repositories keep moving, so a
    `refs/heads/main` archive meant every published number was measured on a
    snapshot nobody could name and nobody could fetch again. The benign
    manifest pins SHA-256 for exactly this reason and the external half had no
    business being treated differently."""
    for corpus in external.CORPORA:
        assert re.fullmatch(r"[0-9a-f]{40}", corpus.commit), corpus.id
        assert corpus.commit in corpus.url, corpus.id
        assert "refs/heads/" not in corpus.url, corpus.id


class TestLabelling:
    def _corpus(self, cid: str):
        return next(c for c in external.CORPORA if c.id == cid)

    @pytest.mark.parametrize("name, expected", [
        ("malicious0.pkl", True),
        ("malicious1_wrong_ext.zip", True),
        ("benign0_v3.pkl", False),
    ])
    def test_filename_convention_is_honoured(self, name, expected):
        assert external.label_of(self._corpus("picklescan-tests"), name) is expected

    @pytest.mark.parametrize("name", [
        "broken_model.pkl",        # partial parse errors, label not stated
        "bad_pytorch.pt",          # a PNG with a .pt extension
        "not_a_pickle.bin",        # not a pickle at all
        "benign_password_protected.zip",
    ])
    def test_unlabelled_files_are_excluded_not_guessed(self, name):
        """These are neither malicious nor a clean model. Scoring them either
        way would move every scanner's number for no reason connected to
        detection quality."""
        assert external.label_of(self._corpus("picklescan-tests"), name) is None

    def test_author_asserted_malicious_wins_over_filename(self):
        """picklescan's own test suite asserts pytorch_magic_bypass.pt yields
        __builtin__.eval and posix.system (both Dangerous). The corpus
        author's label wins over the filename convention."""
        assert external.label_of(
            self._corpus("picklescan-tests"), "pytorch_magic_bypass.pt") is True

    def test_all_malicious_corpus_labels_everything_malicious(self):
        corpus = self._corpus("picklecloak-exploits")
        assert corpus.all_malicious
        assert external.label_of(corpus, "exp_17.pkl") is True

    def test_unknown_name_in_a_labelled_corpus_is_excluded(self):
        """A file the convention does not cover must not default to either
        class. If picklescan adds a differently-named fixture, it drops out of
        scoring until someone looks at it."""
        assert external.label_of(self._corpus("picklescan-tests"), "something_new.pkl") is None


class TestNoBenignHalfIsDeclared:
    """PickleCloak has no benign files, so a scanner that flags everything
    scores 100% on it. That is a property of the corpus, not of the scanner,
    and the report has to say so rather than printing a bare percentage."""

    def test_all_malicious_corpora_say_so_in_their_note(self):
        for corpus in external.CORPORA:
            if corpus.all_malicious:
                assert "NO BENIGN HALF" in corpus.note.upper(), corpus.id


class TestFetchedCorpora:
    """Skipped unless `python -m quickset.external` has run."""

    @pytest.mark.parametrize("corpus", external.CORPORA, ids=lambda c: c.id)
    def test_fetched_corpus_has_scoreable_files(self, corpus):
        if not external.is_fetched(corpus):
            pytest.skip(f"{corpus.id} not fetched")

        files = list(external.corpus_dir(corpus).iterdir())
        assert files, corpus.id
        labelled = [f for f in files if external.label_of(corpus, f.name) is not None]
        assert labelled, f"{corpus.id} fetched but nothing in it is scoreable"

    @pytest.mark.parametrize("corpus", external.CORPORA, ids=lambda c: c.id)
    def test_extraction_flattens_and_strips_paths(self, corpus):
        """Archive members are written by basename only, so a path-traversal
        entry in a downloaded archive cannot escape the cache directory."""
        if not external.is_fetched(corpus):
            pytest.skip(f"{corpus.id} not fetched")

        cache = external.corpus_dir(corpus).resolve()
        for f in external.corpus_dir(corpus).iterdir():
            assert f.resolve().parent == cache, f
            assert "/" not in f.name and ".." not in f.name
