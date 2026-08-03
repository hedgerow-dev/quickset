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
import os
import shutil
import tempfile
import subprocess
from dataclasses import dataclass
from pathlib import Path

TIMEOUT_SECONDS = 120
# Sentinel returncode for a scanner that ran out of time. Distinct from any
# real exit status so a hang is never mistaken for a verdict.
TIMED_OUT_RETURNCODE = -9999


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

    def _run(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        """Run a scanner, converting a timeout into a result instead of an
        exception.

        A resource-exhaustion case is a legitimate corpus entry -- the
        `dup-amplification-billion-laughs` case exists precisely to see which
        scanners survive one -- so a scanner hanging on it must not take the
        whole run down with it. It did exactly that the first time a scanner
        actually timed out.

        The timeout is reported through `TIMED_OUT_RETURNCODE` so callers can
        distinguish it from a clean verdict. It is scored as an error, never
        as a detection: a scanner that hangs has not detected anything, and
        crediting it would reward the failure.
        """
        child_env = None
        if env:
            child_env = {**os.environ, **env}
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
                check=False,
                env=child_env,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(
                args, TIMED_OUT_RETURNCODE, stdout="", stderr="quickset: timed out"
            )


class PicklescanAdapter(Adapter):
    def __init__(self) -> None:
        object.__setattr__(self, "name", "picklescan")
        object.__setattr__(self, "license", "MIT")
        object.__setattr__(self, "executable", "picklescan")

    def scan(self, path: Path) -> ScanOutcome:
        proc = self._run(self.executable, "-p", str(path))
        if proc.returncode == TIMED_OUT_RETURNCODE:
            return ScanOutcome(flagged=False, detail="timed out", errored=True)
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
        # Two reasons this goes through -o rather than reading stdout:
        # modelscan writes a human preamble ("No settings file detected...",
        # "Scanning <path> using <scanner>...") ahead of the report, and its
        # console renderer hard-wraps the JSON at the terminal width -- mid
        # string-literal, which produces genuinely invalid JSON. Slicing from
        # the first brace is not enough to survive that; `COLUMNS=100000`
        # happens to avoid it but relies on an env var the tool never promised
        # to honour.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.json"
            proc = self._run(self.executable, "-p", str(path), "-r", "json", "-o", str(out))
            if proc.returncode == TIMED_OUT_RETURNCODE:
                return ScanOutcome(flagged=False, detail="timed out", errored=True)
            report = None
            if out.exists():
                try:
                    report = json.loads(out.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, ValueError, OSError):
                    report = None

        if report is None:
            # Deliberately no text-matching fallback. The previous one looked
            # for "critical" in the output, which matches the string
            # `"CRITICAL": 0` present in every clean report -- it reported
            # every benign file as malicious. A scanner whose output cannot be
            # parsed is an adapter failure, not a detection result, and must
            # never be scored as either.
            return ScanOutcome(flagged=False, detail="unparseable report", errored=True)

        summary = report.get("summary", {})
        issues = summary.get("total_issues", 0)
        by_severity = summary.get("total_issues_by_severity", {})
        worst = next(
            (s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if by_severity.get(s)),
            "",
        )
        return ScanOutcome(
            flagged=bool(issues),
            detail=f"{issues} issue(s){f', worst {worst}' if worst else ''}",
        )


class FicklingAdapter(Adapter):
    def __init__(self) -> None:
        object.__setattr__(self, "name", "fickling")
        # LGPL-3.0: fine to invoke as a separate process, do not link.
        object.__setattr__(self, "license", "LGPL-3.0")
        object.__setattr__(self, "executable", "fickling")

    def scan(self, path: Path) -> ScanOutcome:
        # `--check-safety` prints nothing at all on either verdict and signals
        # only through the exit code (1 = not likely safe, 0 = likely safe).
        # The first version of this adapter matched on output text that never
        # exists, so fickling scored 0 on everything.
        #
        # `--json-output` carries the actual severity, which is worth having:
        # fickling grades on four levels and the pass/fail bit alone hides
        # that a "LIKELY_UNSAFE" verdict on an ordinary `OrderedDict.update`
        # is a different claim from "LIKELY_OVERTLY_MALICIOUS" on os.system.
        # The flag threshold still matches fickling's own CLI contract --
        # anything above LIKELY_SAFE -- because the stated rule for these
        # adapters is to score the shipped tool at its shipped defaults, not
        # at a threshold picked here to flatter anyone.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fickling.json"
            proc = self._run(
                self.executable, "--check-safety", "--json-output", str(out), str(path)
            )
            severity = ""
            if out.exists():
                try:
                    severity = str(json.loads(out.read_text(encoding="utf-8")).get("severity", ""))
                except (json.JSONDecodeError, ValueError, OSError):
                    severity = ""

        if proc.returncode == TIMED_OUT_RETURNCODE:
            return ScanOutcome(flagged=False, detail="timed out", errored=True)

        stderr = proc.stderr.strip()
        if not severity and stderr and ("Traceback" in stderr or "Error" in stderr):
            # A crash also exits non-zero, and counting that as a detection
            # would silently inflate the score.
            return ScanOutcome(flagged=False, detail=_first_line(stderr), errored=True)

        if severity:
            return ScanOutcome(flagged=severity != "LIKELY_SAFE", detail=severity)
        return ScanOutcome(flagged=proc.returncode != 0, detail=f"exit {proc.returncode}")


class ModelAuditAdapter(Adapter):
    """Promptfoo's ModelAudit.

    Three behaviours worth knowing, all observed rather than read off the docs:

    - Telemetry blocks every invocation on a network call, turning a 0.026s
      scan into ~11s wall time. `PROMPTFOO_DISABLE_TELEMETRY=1` removes it.
      This is per file, so on a benchmark it dominates everything else.
    - `--output` writes the JSON to a file but reverts *stdout* to the human
      report, so the file flag is the wrong way round from every other tool
      here. stdout is pure JSON already.
    - Top-level `"success": true` means "the scan ran", not "the file is
      clean". It is true for a malicious file and for a nonexistent path.
    """

    def __init__(self) -> None:
        object.__setattr__(self, "name", "modelaudit")
        object.__setattr__(self, "license", "MIT")
        object.__setattr__(self, "executable", "modelaudit")

    def scan(self, path: Path) -> ScanOutcome:
        proc = self._run(
            self.executable, "scan", "--format", "json", str(path),
            env={"PROMPTFOO_DISABLE_TELEMETRY": "1", "NO_ANALYTICS": "1"},
        )
        if proc.returncode == TIMED_OUT_RETURNCODE:
            return ScanOutcome(flagged=False, detail="timed out", errored=True)
        try:
            report = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError):
            return ScanOutcome(flagged=False, detail="unparseable report", errored=True)

        # An empty `scanner_names` means no scanner recognised the file. That
        # is "not scanned", not "clean", and scoring it as a true negative
        # would silently credit the tool for files it never looked at.
        if not report.get("scanner_names"):
            return ScanOutcome(flagged=False, detail="no scanner matched", errored=True)

        issues = report.get("issues", [])
        actionable = [i for i in issues if i.get("severity") in ("warning", "critical")]
        worst = next(
            (s for s in ("critical", "warning", "info", "debug")
             if any(i.get("severity") == s for i in issues)),
            "",
        )
        return ScanOutcome(
            flagged=bool(actionable),
            detail=f"{len(issues)} issue(s){f', worst {worst}' if worst else ''}",
        )


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
            proc = self._run(
                self.executable, "scan", str(path.parent),
                "--format", "json", "-o", str(out),
                "--no-sca", "--no-taint", "--no-cross-file",
            )
            if proc.returncode == TIMED_OUT_RETURNCODE:
                return ScanOutcome(flagged=False, detail="timed out", errored=True)
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
        ModelAuditAdapter(),
        FicklingAdapter(),
        OpenRowanAdapter(),
    ]
