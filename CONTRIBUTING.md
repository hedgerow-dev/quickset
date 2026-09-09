# Contributing to quickset

We welcome contributions to expand scanner coverage, add real benign models, and include new exploit techniques.

## Core Rules

1. **Zero Malware on Disk**: All malicious cases must be generated at runtime through `quickset/cases.py`. Never commit working exploit payloads or live malware to the repository.
2. **Inert Payloads**: Any network call must target `.invalid` domains ([RFC 2606](https://datatracker.ietf.org/doc/html/rfc2606)). Any command execution must use harmless marker strings (e.g. `echo <MARKER>`).
3. **Subprocess Adapters**: Scanners must be invoked as subprocesses in `quickset/adapters.py`, never imported directly into the Python process.
4. **Honest Evaluation**: Test cases should reflect real-world attack vectors and model formats. Cases that highlight scanner weaknesses or disagreement between tools are the most valuable.

## Adding a Scanner

1. Create a new subclass of `Adapter` in `quickset/adapters.py`.
2. Implement `scan(path: Path) -> ScanOutcome`.
3. Add a test in `tests/test_adapters.py` verifying that the adapter detects an obvious malicious sample and clears an obvious benign sample.
4. Run the test suite:
   ```bash
   pytest tests/test_adapters.py -v
   ```

## Adding a Test Case

1. Add a `Case` entry to `MALICIOUS` or `BENIGN` in `quickset/cases.py`.
2. Ensure payloads are synthesized dynamically using inert arguments.
3. Run the corpus validation tests:
   ```bash
   pytest tests/test_corpus.py -v
   ```

## Running the Test Suite

```bash
pip install -e ".[dev]"
pip install picklescan modelscan fickling modelaudit hayward
pytest tests/ -v
```
