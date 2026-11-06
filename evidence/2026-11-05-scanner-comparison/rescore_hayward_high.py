"""Re-score Hayward on quickset's external corpora at its default gate (HIGH and above).

Mirrors quickset.run.run_external: same files, same labels, same adapter;
only the threshold differs. Prints per-corpus counts at LOW+ and HIGH+.
"""
import tempfile
from pathlib import Path

from quickset import external
from quickset.adapters import all_adapters

hw = [a for a in all_adapters() if a.name == "hayward"][0]
assert hw.available(), "hayward not on PATH"
print("hayward", hw.version())
for corpus in external.CORPORA:
    if not external.is_fetched(corpus):
        print(corpus.id, "not fetched")
        continue
    mal = low = high = ben = fp_low = fp_high = err = 0
    for f in sorted(external.corpus_dir(corpus).iterdir()):
        label = external.label_of(corpus, f.name)
        if label is None:
            continue
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / f.name
            target.write_bytes(f.read_bytes())
            out = hw.scan(target)
        if out.errored:
            err += 1
            continue
        sev = out.detail.split("/")[-1].strip().lower() if out.flagged else ""
        is_high = sev in ("high", "critical")
        if label:
            mal += 1; low += bool(out.flagged); high += is_high
        else:
            ben += 1; fp_low += bool(out.flagged); fp_high += is_high
    print(f"{corpus.id}: malicious {mal}, LOW+ {low}, HIGH+ {high}; benign {ben}, FP LOW+ {fp_low}, FP HIGH+ {fp_high}; no verdict {err}")
