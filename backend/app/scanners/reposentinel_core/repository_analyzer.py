import hashlib
import os
from pathlib import Path

from .config import DEFAULT_CONFIG, ScannerConfig
from .language_detector import LanguageDetector
from .models import FileMetadata, RepositoryReport


class RepositoryAnalyzer:
    def __init__(self, config: ScannerConfig = DEFAULT_CONFIG):
        self.config = config
        self.language_detector = LanguageDetector(config)

    def analyze(self, repository_path: str | Path) -> RepositoryReport:
        requested_path = Path(repository_path)

        if requested_path.is_symlink():
            raise ValueError("Repository root cannot be a symbolic link.")

        if not requested_path.exists():
            raise ValueError("Repository path does not exist.")

        if not requested_path.is_dir():
            raise ValueError("Repository path must be a directory.")

        root = requested_path.resolve(strict=True)

        report = RepositoryReport(repository_path=str(root))
        pending_directories = [root]

        while pending_directories:
            current_directory = pending_directories.pop()

            try:
                with os.scandir(current_directory) as entries:
                    for entry in entries:

                        try:
                            if entry.is_symlink():
                                self._skip(report, "symbolic_link")
                                continue

                            if entry.is_dir(follow_symlinks=False):
                                if entry.name in self.config.ignored_directories:
                                    self._skip(report, "ignored_directory")
                                    continue

                                pending_directories.append(Path(entry.path))
                                continue

                            if not entry.is_file(follow_symlinks=False):
                                continue

                            if (
                                report.total_files_discovered
                                >= self.config.max_files
                            ):
                                report.scan_truncated = True
                                report.truncation_reason = (
                                    "maximum_file_limit_reached"
                                )
                                pending_directories.clear()
                                break

                            report.total_files_discovered += 1

                            file_path = Path(entry.path)

                            if entry.name in self.config.ignored_filenames:
                                self._skip(report, "ignored_filename")
                                continue

                            language = self.language_detector.detect(file_path)

                            if language is None:
                                self._skip(report, "unsupported_extension")
                                continue

                            resolved_file = file_path.resolve(strict=True)

                            if not resolved_file.is_relative_to(root):
                                self._skip(report, "outside_repository")
                                continue

                            file_size = entry.stat(
                                follow_symlinks=False
                            ).st_size

                            if file_size > self.config.max_file_size_bytes:
                                self._skip(report, "file_too_large")
                                continue

                            fingerprint = self._calculate_sha256(resolved_file)

                            if fingerprint is None:
                                self._skip(report, "binary_file")
                                continue

                            relative_path = resolved_file.relative_to(root)

                            metadata = FileMetadata(
                                path=relative_path.as_posix(),
                                extension=resolved_file.suffix.lower(),
                                language=language,
                                size_bytes=file_size,
                                sha256=fingerprint,
                            )

                            report.files.append(metadata)
                            report.analyzed_files += 1
                            report.total_size_bytes += file_size

                            report.language_counts[language] = (
                                report.language_counts.get(language, 0) + 1
                            )

                        except (OSError, PermissionError, ValueError):
                            self._skip(report, "file_access_error")
                            continue

            except (OSError, PermissionError):
                report.errors.append(
                    "Could not inspect directory: "
                    + str(current_directory.relative_to(root))
                )

        return report

    def _calculate_sha256(self, file_path: Path) -> str | None:
        hasher = hashlib.sha256()
        first_chunk = True

        with file_path.open("rb") as file:
            while True:
                chunk = file.read(self.config.hash_chunk_size)

                if not chunk:
                    break

                if first_chunk:
                    first_chunk = False

                    if b"\x00" in chunk:
                        return None

                hasher.update(chunk)

        return hasher.hexdigest()

    @staticmethod
    def _skip(report: RepositoryReport, reason: str) -> None:
        report.skipped_files += 1
        report.skipped_reasons[reason] = (
            report.skipped_reasons.get(reason, 0) + 1
        )