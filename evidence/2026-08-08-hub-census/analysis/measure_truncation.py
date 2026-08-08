"""Count how often the truncation check fires on real files.

The question the docs note is hedging: is the ~2% misfire on synthetic random
bytes reachable on models people actually publish, or is it theoretical?
"""

import sys
import time
from collections import Counter
from pathlib import Path

from hayward import ModelFileScanner

roots = [Path(p) for p in sys.argv[1:]]
scanner = ModelFileScanner()

truncated = []
counts = Counter()
scanned = 0
started = time.monotonic()

for root in roots:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            findings = scanner.scan_file(path)
        except Exception as exc:
            counts["scan raised"] += 1
            print(f"  RAISED {path.name}: {type(exc).__name__} {exc}")
            continue

        scanned += 1
        for f in findings:
            counts[f.rule_id] += 1
            if f.metadata.get("skipped_reason") == "pickle_truncated":
                truncated.append(path)

elapsed = time.monotonic() - started
print(f"\nscanned {scanned} files in {elapsed:.0f}s")
print(f"pickle_truncated findings: {len(truncated)}")
for path in truncated:
    print(f"  {path}")
print("\nall rule ids seen:")
for rule, n in counts.most_common():
    print(f"  {rule:22} {n}")
