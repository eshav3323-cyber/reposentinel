from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import tempfile

from app.core.archive_handler import SourceFile
from app.core.finding_normalizer import normalize_finding
from app.models.findings import Finding

from .engine import RepoSentinelCore


_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_INVALID_WINDOWS_CHARACTERS = re.compile(r'[<>:"|?*\x00-\x1f]')


class RepoSentinelCoreScanError(RuntimeError):
    """Raised when Core cannot safely stage or scan repository files."""


def _validated_relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise RepoSentinelCoreScanError("A source file has an empty or invalid path.")

    normalized = value.replace("\\", "/")
    windows_path = PureWindowsPath(value)
    if (
        normalized.startswith("/")
        or windows_path.is_absolute()
        or windows_path.drive
    ):
        raise RepoSentinelCoreScanError("A source file has an absolute path.")

    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise RepoSentinelCoreScanError("A source file has an unsafe relative path.")

    for part in parts:
        if (
            _INVALID_WINDOWS_CHARACTERS.search(part)
            or part.endswith((" ", "."))
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES
        ):
            raise RepoSentinelCoreScanError("A source file has an invalid path.")

    return PurePosixPath(*parts)


def _stage_source_files(files: list[SourceFile], root: Path) -> None:
    """Write validated files beneath a private staging root without following links."""

    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise RepoSentinelCoreScanError("The temporary staging root is unsafe.")

    resolved_root = root.resolve(strict=True)
    seen_paths: set[str] = set()
    validated_files = []

    for source_file in files:
        relative = _validated_relative_path(source_file.path)
        path_key = relative.as_posix().casefold()
        if path_key in seen_paths:
            raise RepoSentinelCoreScanError(
                "Source files contain duplicate normalized paths."
            )
        seen_paths.add(path_key)
        validated_files.append((source_file, relative))

    for source_file, relative in validated_files:
        destination = root.joinpath(*relative.parts)
        if not destination.resolve(strict=False).is_relative_to(resolved_root):
            raise RepoSentinelCoreScanError(
                "A source file resolved outside the temporary staging directory."
            )

        current = root
        for part in relative.parts[:-1]:
            current = current / part
            current.mkdir(exist_ok=True)
            if current.is_symlink() or not current.resolve(strict=True).is_relative_to(
                resolved_root
            ):
                raise RepoSentinelCoreScanError(
                    "A source file path contains an unsafe symbolic link."
                )

        if destination.is_symlink() or not destination.resolve(
            strict=False
        ).is_relative_to(resolved_root):
            raise RepoSentinelCoreScanError(
                "A source file path contains an unsafe symbolic link."
            )

        try:
            with destination.open("x", encoding="utf-8", errors="strict") as handle:
                handle.write(source_file.content)
        except (OSError, UnicodeError) as exc:
            raise RepoSentinelCoreScanError(
                "A source file could not be safely staged."
            ) from exc


def scan_with_reposentinel_core(files: list[SourceFile]) -> list[Finding]:
    """Run RepoSentinel Core's static analyzers on safely staged source text."""

    try:
        with tempfile.TemporaryDirectory(prefix="reposentinel-core-") as temp:
            root = Path(temp) / "source"
            _stage_source_files(files, root)
            report = RepoSentinelCore().scan_repository(root)
    except RepoSentinelCoreScanError:
        raise
    except Exception as exc:
        raise RepoSentinelCoreScanError(
            "RepoSentinel Core could not complete its static analysis."
        ) from exc

    raw_findings = report.get("findings")
    if not isinstance(raw_findings, list):
        raise RepoSentinelCoreScanError(
            "RepoSentinel Core returned an unexpected findings format."
        )

    findings = []
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise RepoSentinelCoreScanError(
                "RepoSentinel Core returned an invalid finding."
            )

        description = str(raw.get("description") or "No description provided.")
        cwe = str(raw.get("cwe") or "").strip()
        if cwe:
            description = f"{description} ({cwe})"

        findings.append(
            normalize_finding(
                {
                    "title": raw.get("title"),
                    "rule_id": raw.get("rule_id"),
                    "severity": raw.get("severity"),
                    "confidence": raw.get("confidence"),
                    "file_path": raw.get("file_path"),
                    "line_number": raw.get("line_number"),
                    "description": description,
                    "evidence": raw.get("evidence"),
                    "remediation": raw.get("recommendation"),
                },
                source_scanner="RepoSentinel Core",
                detection_type="scanner",
            )
        )

    return findings
