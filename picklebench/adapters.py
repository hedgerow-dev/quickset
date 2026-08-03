"""Scanner adapters.

Every scanner is driven through its command-line interface as a subprocess.
That is not laziness: importing a scanner would put it in this project's
dependency graph, and a benchmark that must resolve four scanners' pinned
transitive dependencies simultaneously does not install. Subprocess also means
the harness stays honest about what it is measuring -- the shipped CLI, with
its shipped defaults, the way a user would actually run it.

Adding a scanner means adding one `Adapter` here. The contract is deliberately
narrow: given a file, say whether the scanner flagged it. Severity is recorded
as free text when a scanner reports one, because severity vocabularies do not
map onto each other and pretending they do would be the first place a
benchmark starts lying.

A missing scanner is skipped, never failed. Nobody has all of these installed.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import subprocess
from dataclasses import dataclass
from pathlib import Path

TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class ScanOutcome:
    """What one scanner said about one file."""

    flagged: bool
    detail: str = ""
    errored: bool = False


@dataclass(frozen=True)
class Adapter:
    name: str
    # Homepage/licence recorded so the report can cite what it ran.
    license: str
    executable: str

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def scan(self, path: Path) -> ScanOutcome:  # pragma: no cover - overridden
        raise NotImplementedError

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )


class PicklescanAdapter(Adapter):
    def __init__(self) -> None:
        object.__setattr__(self, "name", "picklescan")
        object.__setattr__(self, "license", "MIT")
        object.__setattr__(self, "executable", "picklescan")

    def scan(self, path: Path) -> ScanOutcome:
        proc = self._run(self.executable, "-p", str(path))
        text = proc.stdout + proc.stderr
        # picklescan prints "dangerous import '<x>' FOUND" per hit and an
        # "Infected files: N" summary line.
        dangerous = "FOUND" in text
        infected = 0
        for line in text.splitlines():
            if line.strip().startswith("Infected files:"):
                with_digits = line.split(":", 1)[1].strip()
                infected = int(with_digits) if with_digits.isdigit() else 0
        return ScanOutcome(
            flagged=dangerous or infected > 0,
            detail=_first_signal(text, "FOUND"),
        )


class ModelscanAdapter(Adapter):
    def __init__(self) -> None:
        object.__setattr__(self, "name", "modelscan")
        object.__setattr__(self, "license", "Apache-2.0")
        object.__setattr__(self, "executable", "modelscan")

    def scan(self, path: Path) -> ScanOutcome:
        proc = self._run(self.executable, "-p", str(path), "-r", "json")
        raw = proc.stdout.strip()
        # modelscan prints a JSON report to stdout with -r json; fall back to
        # text matching if the format shifts rather than silently scoring zero.
        try:
            report = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            text = raw + proc.stderr
            return ScanOutcome(
                flagged="issues found" in text.lower() or "critical" in text.lower(),
                detail=_first_signal(text, "issue"),
                errored=not text,
            )
        issues = report.get("summary", {}).get("total_issues", 0)
        return ScanOutcome(flagged=bool(issues), detail=f"{issues} issue(s)")


class FicklingAdapter(Adapter):
    def __init__(self) -> None:
        object.__setattr__(self, "name", "fickling")
        # LGPL-3.0: fine to invoke as a separate process, do not link.
        object.__setattr__(self, "license", "LGPL-3.0")
        object.__setattr__(self, "executable", "fickling")

    def scan(self, path: Path) -> ScanOutcome:
        proc = self._run(self.executable, "--check-safety", str(path))
        text = (proc.stdout + proc.stderr).strip()
        lowered = text.lower()
        likely_safe = "likely safe" in lowered or "no overtly malicious" in lowered
        return ScanOutcome(flagged=not likely_safe and bool(text), detail=_first_line(text))


class OpenRowanAdapter(Adapter):
    """Included so this benchmark can be run against Rowan like any other
    entrant. It gets no special treatment and no import-level access: same
    subprocess contract, same scoring, and it is skipped when absent exactly
    like the rest.
    """

    def __init__(self) -> None:
        object.__setattr__(self, "name", "open-rowan")
        object.__setattr__(self, "license", "see project")
        object.__setattr__(self, "executable", "open-rowan")

    def scan(self, path: Path) -> ScanOutcome:
        # Rowan writes a banner and log lines to stdout alongside the report,
        # so JSON has to be captured via -o rather than scraped from stdout.
        # The --no-* flags switch off Rowan's source-code passes (SCA, taint,
        # cross-file), which have no counterpart in the other entrants; leaving
        # them on would score Rowan on work nobody else is doing and make each
        # case take an Opengrep run.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            self._run(
                self.executable, "scan", str(path.parent),
                "--format", "json", "-o", str(out),
                "--no-sca", "--no-taint", "--no-cross-file",
            )
            if not out.exists():
                return ScanOutcome(flagged=False, detail="no report written", errored=True)
            try:
                report = json.loads(out.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, ValueError, OSError):
                return ScanOutcome(flagged=False, detail="unparseable report", errored=True)

        # Rowan's JSON reporter names the location field "file". Getting this
        # wrong scored it 0/9 on a corpus it actually detects 9/9 of, which is
        # the single most likely way a benchmark like this produces a
        # confidently wrong headline number -- hence test_adapters.py, which
        # pins each adapter against a known-flagged and known-clean file.
        findings = [
            f for f in report.get("findings", [])
            if str(f.get("file") or f.get("file_path") or "").endswith(path.name)
            and str(f.get("severity", "")).lower() != "info"
        ]
        if not findings:
            return ScanOutcome(flagged=False)
        top = max(findings, key=lambda f: _SEVERITY_ORDER.index(str(f.get("severity", "info")).lower()))
        return ScanOutcome(flagged=True, detail=f"{top.get('rule_id')} / {top.get('severity')}")


_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _first_line(text: str) -> str:
    return text.splitlines()[0].strip() if text.strip() else ""


def _first_signal(text: str, needle: str) -> str:
    for line in text.splitlines():
        if needle in line:
            return line.strip()[:120]
    return ""


def all_adapters() -> list[Adapter]:
    return [
        PicklescanAdapter(),
        ModelscanAdapter(),
        FicklingAdapter(),
        OpenRowanAdapter(),
    ]
