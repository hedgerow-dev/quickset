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
    """What one scanner said about one file.

    `flagged` is the strict threshold: only the tier its author calls
    actionable. `flagged_lenient` additionally counts the tool's *unknown*
    bucket (picklescan's "suspicious", modelaudit's "warning", hayward's INFO,
    fickling's SUSPICIOUS), the tier each tool itself declines to stand
    behind. None means the tool has no distinguishable unknown tier, so both
    thresholds are the same. Scoring one tool at its top tier while counting
    another's unknown tier is the specific unfairness this field exists to
    prevent; report both thresholds or neither.
    """

    flagged: bool
    detail: str = ""
    errored: bool = False
    flagged_lenient: bool | None = None


@dataclass(frozen=True)
class Adapter:
    name: str
    # Homepage/licence recorded so the report can cite what it ran.
    license: str
    executable: str

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def version(self) -> str:
        """The scanner's own version string.

        A results file that pins the corpus but not the tools is not evidence
        of anything: "picklescan detects 12/15" is a claim about a build. Most
        of these answer `--version`; picklescan has no such flag and prints
        its usage instead, so fall back to the installed distribution metadata
        (the documented install puts the scanners in the same environment as
        quickset). Never fails a run: an unknown version is recorded as
        unknown rather than raising.
        """
        proc = self._run(self.executable, "--version")
        line = _first_line(proc.stdout + proc.stderr)
        if proc.returncode == 0 and line and not line.lower().startswith("usage:"):
            # Some print "<name>, version 1.2.3" and some "<name> 1.2.3";
            # the report already says which scanner this is.
            _, _, tail = line.rpartition("version ")
            value = (tail or line).strip()
            prefix = f"{self.executable} "
            if value.lower().startswith(prefix.lower()):
                value = value[len(prefix):].strip()
            return value
        try:
            from importlib.metadata import version as _dist_version

            return _dist_version(self.name)
        except Exception:
            return "unknown"

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
        # picklescan prints "dangerous import '<x>' FOUND" per hit and summary
        # lines for "Scanned files:", "Infected files:", "Suspicious globals:"
        # and "Dangerous globals:". "Suspicious" is picklescan's own unknown
        # bucket: the strict threshold counts dangerous only.
        #
        # picklescan declines to read a file in two ways, and only one of them
        # says so. A parse failure prints "could not parse as pickle" next to
        # "Infected files: 0". A format it has no reader for at all (measured:
        # keras zip, tflite, skops) prints nothing and reports "Scanned files:
        # 0", which is byte-for-byte a clean verdict. Both are files picklescan
        # never read, so both are errors here, same as modelscan's
        # total_scanned == 0 and modelaudit's empty scanner_names.
        dangerous = "FOUND" in text
        infected = 0
        suspicious = 0
        scanned: int | None = None
        parse_failed = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("Scanned files:"):
                with_digits = stripped.split(":", 1)[1].strip()
                scanned = int(with_digits) if with_digits.isdigit() else None
            elif stripped.startswith("Infected files:"):
                with_digits = stripped.split(":", 1)[1].strip()
                infected = int(with_digits) if with_digits.isdigit() else 0
            elif stripped.startswith("Suspicious globals:"):
                with_digits = stripped.split(":", 1)[1].strip()
                suspicious = int(with_digits) if with_digits.isdigit() else 0
            elif "could not parse as pickle" in stripped or stripped.startswith(
                "ERROR: parsing"
            ):
                parse_failed = True
        if parse_failed:
            return ScanOutcome(
                flagged=False,
                detail=_first_signal(text, "parse") or "parse failure",
                errored=True,
            )
        if scanned == 0:
            return ScanOutcome(
                flagged=False, detail="scanned 0 files", errored=True,
            )
        flagged = dangerous or infected > 0
        return ScanOutcome(
            flagged=flagged,
            detail=_first_signal(text, "FOUND"),
            flagged_lenient=flagged or suspicious > 0,
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
        # A scan that read zero files produced no verdict. modelscan's own
        # `errors` array records why (measured on the benign corpus: 130
        # files, nearly all a removed private numpy API in its joblib path).
        # Counting those as clean credits it for files it never read.
        scanned = (summary.get("scanned") or {}).get("total_scanned")
        errors = report.get("errors") or []
        if scanned == 0 or errors:
            first = str(errors[0].get("description", ""))[:100] if errors else "no files scanned"
            return ScanOutcome(flagged=False, detail=first, errored=True)

        issues = summary.get("total_issues", 0)
        by_severity = summary.get("total_issues_by_severity", {})
        worst = next(
            (s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if by_severity.get(s)),
            "",
        )
        # Tier map: modelscan documents no unknown bucket, so strict is
        # CRITICAL/HIGH and lenient is any issue (its CLI gates on all of
        # them). MEDIUM/LOW are its weakest, least-actionable tiers.
        strong = bool(by_severity.get("CRITICAL") or by_severity.get("HIGH"))
        return ScanOutcome(
            flagged=strong,
            detail=f"{issues} issue(s){f', worst {worst}' if worst else ''}",
            flagged_lenient=bool(issues),
        )


class FicklingAdapter(Adapter):
    def __init__(self) -> None:
        object.__setattr__(self, "name", "fickling")
        # LGPL-3.0: fine to invoke as a separate process, do not link.
        object.__setattr__(self, "license", "LGPL-3.0")
        object.__setattr__(self, "executable", "fickling")

    def scan(self, path: Path) -> ScanOutcome:
        # The flag threshold below strictens fickling's own CLI contract.
        # fickling grades on four levels (LIKELY_SAFE < SUSPICIOUS <
        # LIKELY_UNSAFE < LIKELY_OVERTLY_MALICIOUS) and its CLI flags anything
        # above LIKELY_SAFE -- but SUSPICIOUS is its unknown bucket, the tier
        # it declines to call unsafe. Strict is LIKELY_UNSAFE and above;
        # lenient is the shipped CLI default.
        #
        # --json-output on a multi-pickle file (torch legacy layout, 27 files
        # in the benign corpus) writes one JSON object PER EMBEDDED PICKLE,
        # concatenated, which is not valid JSON. Decode the stream and take
        # the worst verdict across the embedded pickles; only fall back to the
        # exit code when nothing decodes at all.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fickling.json"
            proc = self._run(
                self.executable, "--check-safety", "--json-output", str(out), str(path)
            )
            severity = ""
            if out.exists():
                try:
                    raw = out.read_text(encoding="utf-8")
                    decoder = json.JSONDecoder()
                    idx = 0
                    verdicts: list[str] = []
                    while idx < len(raw):
                        while idx < len(raw) and raw[idx].isspace():
                            idx += 1
                        if idx >= len(raw):
                            break
                        obj, end = decoder.raw_decode(raw, idx)
                        verdicts.append(str(obj.get("severity", "")))
                        idx = end
                    if verdicts:
                        severity = max(
                            verdicts,
                            key=lambda s: _FICKLING_SEVERITY_ORDER.get(s, -1),
                        )
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
            return ScanOutcome(
                flagged=severity in ("LIKELY_UNSAFE", "LIKELY_OVERTLY_MALICIOUS",
                                     "OVERTLY_MALICIOUS"),
                detail=severity,
                flagged_lenient=severity != "LIKELY_SAFE",
            )
        return ScanOutcome(
            flagged=proc.returncode != 0,
            detail=f"exit {proc.returncode}",
            flagged_lenient=proc.returncode != 0,
        )


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
        # "warning" is modelaudit's unknown bucket (its own docs decline to
        # call it actionable): strict is critical only, lenient is the shipped
        # default gate of warning+critical.
        critical = [i for i in issues if i.get("severity") == "critical"]
        actionable = [i for i in issues if i.get("severity") in ("warning", "critical")]
        worst = next(
            (s for s in ("critical", "warning", "info", "debug")
             if any(i.get("severity") == s for i in issues)),
            "",
        )
        return ScanOutcome(
            flagged=bool(critical),
            detail=f"{len(issues)} issue(s){f', worst {worst}' if worst else ''}",
            flagged_lenient=bool(actionable),
        )


class HaywardAdapter(Adapter):
    """Hedgerow's Hayward, the model-file scanner this project is built
    alongside. It gets no special treatment and no import-level access: same
    subprocess contract, same scoring, skipped when absent exactly like the
    rest. It is MIT and on PyPI, so unlike its predecessor a public CI runner
    can install it and re-measure every number below.
    """

    def __init__(self) -> None:
        object.__setattr__(self, "name", "hayward")
        object.__setattr__(self, "license", "MIT")
        object.__setattr__(self, "executable", "hayward")

    def scan(self, path: Path) -> ScanOutcome:
        # Targets the file rather than its parent directory. The predecessor
        # scanned the parent and then filtered findings by filename, which was
        # both an asymmetry (it alone saw sibling files) and the site of the
        # `file_path` vs `file` bug that scored it 0/9 on a corpus it detects
        # 9/9 of. One file in, one report out, nothing to match up.
        proc = self._run(self.executable, "scan", str(path), "-f", "json")
        if proc.returncode == TIMED_OUT_RETURNCODE:
            return ScanOutcome(flagged=False, detail="timed out", errored=True)
        try:
            report = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError):
            return ScanOutcome(flagged=False, detail="unparseable report", errored=True)

        # Hayward states non-coverage in the report rather than leaving it to
        # be inferred: `coverage_gaps` lists the files it could not fully read,
        # and its own docs say a scorer should count them in a column of their
        # own. Taking the report's word for it is better than matching rule ids
        # here, which is what the previous adapter did not do at all -- a file
        # it declined to read counted as covered, and since MFV-SKIP-001/2/3
        # are LOW, as a flag.
        #
        # A file with a real finding *and* a coverage gap was still read well
        # enough to find something, so the finding wins and only a gap on its
        # own is a no-verdict.
        gaps = {str(g) for g in (report.get("coverage_gaps") or [])}
        findings_all = [
            f for f in report.get("findings", [])
            if f.get("rule_id") not in _HAYWARD_COVERAGE_RULES
        ]
        if not findings_all and gaps:
            return ScanOutcome(
                flagged=False, detail="coverage gap, file not fully read", errored=True,
            )

        findings = [
            f for f in findings_all
            if str(f.get("severity", "")).lower() != "info"
        ]
        if not findings:
            return ScanOutcome(
                flagged=False,
                flagged_lenient=bool(findings_all),
            )
        top = max(findings, key=lambda f: _SEVERITY_ORDER.index(str(f.get("severity", "info")).lower()))
        return ScanOutcome(
            flagged=True,
            detail=f"{top.get('rule_id')} / {top.get('severity')}",
            flagged_lenient=True,
        )


_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Hayward's own COVERAGE_RULE_IDS, duplicated because importing the scanner
# under test is exactly what the subprocess contract exists to avoid. Only
# needed to keep a coverage finding from being scored as a detection; the
# errored decision reads the report's `coverage_gaps` and so stays correct
# even if this list falls behind.
_HAYWARD_COVERAGE_RULES = frozenset({
    "MFV-SKIP-001", "MFV-SKIP-002", "MFV-SKIP-003",
    "MFV-7Z-001", "MFV-GGUF-004",
})

_FICKLING_SEVERITY_ORDER = {
    "LIKELY_SAFE": 0,
    "SUSPICIOUS": 2,
    "LIKELY_UNSAFE": 3,
    "LIKELY_OVERTLY_MALICIOUS": 4,
    "OVERTLY_MALICIOUS": 5,
}


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
        HaywardAdapter(),
    ]
