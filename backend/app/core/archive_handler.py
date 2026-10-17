
from __future__ import annotations

import io
import stat
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath


MAX_ARCHIVE_SIZE = 20 * 1024 * 1024       # 20 MB
MAX_EXTRACTED_SIZE = 100 * 1024 * 1024    # 100 MB total
MAX_FILE_COUNT = 2000
MAX_FILE_SIZE = 1 * 1024 * 1024           # 1 MB per file
MAX_COMPRESSION_RATIO = 200

# Only these text-oriented source/configuration extensions are read.
ALLOWED_EXTENSIONS = {
    ".py", ".pyi",
    ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx",
    ".java", ".go", ".rs", ".php",
    ".rb", ".sh", ".ps1",
    ".html", ".css",
    ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf",
    ".xml", ".sql",
    ".env", ".example", ".sample",
    ".md", ".txt",
}

# Avoid reading generated output, dependency trees, and version-control data.
IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "coverage",
    ".next",
}

# Some files have no extension, so allow only explicitly named files.
ALLOWED_FILENAMES = {
    "Dockerfile",
    "Makefile",
    "Procfile",
    ".gitignore",
    ".dockerignore",
    ".gitleaks.toml",
    "requirements.txt",
    "Pipfile",
    "Gemfile",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
}


class ArchiveValidationError(ValueError):
    """Raised when an uploaded ZIP violates archive safety rules."""


@dataclass
class SourceFile:
    path: str
    content: str
    line_count: int


def _validate_member_path(name: str) -> PurePosixPath:
    """Reject absolute paths, traversal, and Windows-style paths."""

    if not name or "\x00" in name:
        raise ArchiveValidationError("Archive contains an invalid file path.")

    # ZIP member paths should use forward slashes.
    if "\\" in name:
        raise ArchiveValidationError(
            "Archive contains an unsafe path separator."
        )

    path = PurePosixPath(name)

    if path.is_absolute() or name.startswith("/"):
        raise ArchiveValidationError(
            "Archive contains an absolute file path."
        )

    if any(part in {"..", "."} for part in path.parts):
        raise ArchiveValidationError(
            "Archive contains a path traversal attempt."
        )

    # Reject Windows drive prefixes such as C:/folder/file.py.
    if path.parts and path.parts[0].endswith(":"):
        raise ArchiveValidationError(
            "Archive contains a drive-qualified path."
        )

    return path


def _is_symbolic_link(info: zipfile.ZipInfo) -> bool:
    """Detect Unix symbolic links recorded in ZIP metadata."""

    unix_mode = info.external_attr >> 16
    return stat.S_ISLNK(unix_mode)


def _is_supported_text_file(path: PurePosixPath) -> bool:
    if any(part.lower() in IGNORED_DIRECTORIES for part in path.parts):
        return False

    filename = path.name

    if filename in ALLOWED_FILENAMES:
        return True

    if filename.startswith(".") and filename.count(".") == 1:
        # Allows names such as .env and .gitignore.
        return filename in {".env", ".gitignore", ".dockerignore"}

    return path.suffix.lower() in ALLOWED_EXTENSIONS


def read_repository_zip(archive_bytes: bytes) -> list[SourceFile]:
    """
    Validate a repository ZIP and read supported UTF-8 text files.

    Nothing is extracted to disk. Uploaded code is never executed,
    imported, installed, or launched.

    Raises ArchiveValidationError for invalid or unsafe archives.
    """

    if not isinstance(archive_bytes, bytes):
        raise ArchiveValidationError("Archive data must be bytes.")

    if not archive_bytes:
        raise ArchiveValidationError("The uploaded archive is empty.")

    if len(archive_bytes) > MAX_ARCHIVE_SIZE:
        raise ArchiveValidationError(
            f"Archive exceeds the {MAX_ARCHIVE_SIZE // (1024 * 1024)} MB limit."
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes), mode="r")
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise ArchiveValidationError(
            "The uploaded file is not a valid ZIP archive."
        ) from exc

    source_files: list[SourceFile] = []
    total_uncompressed = 0

    with archive:
        entries = archive.infolist()

        if len(entries) > MAX_FILE_COUNT:
            raise ArchiveValidationError(
                f"Archive exceeds the {MAX_FILE_COUNT} entry limit."
            )

        seen_paths: set[str] = set()

        for info in entries:
            path = _validate_member_path(info.filename)

            # Directory entries are metadata, not source files.
            if info.is_dir():
                continue

            normalized_path = path.as_posix()

            if normalized_path in seen_paths:
                raise ArchiveValidationError(
                    "Archive contains duplicate file paths."
                )

            seen_paths.add(normalized_path)

            if _is_symbolic_link(info):
                raise ArchiveValidationError(
                    "Archive contains a symbolic link."
                )

            if info.flag_bits & 0x1:
                raise ArchiveValidationError(
                    "Encrypted ZIP entries are not supported."
                )

            if info.file_size < 0 or info.compress_size < 0:
                raise ArchiveValidationError(
                    "Archive contains invalid file-size metadata."
                )

            total_uncompressed += info.file_size

            if total_uncompressed > MAX_EXTRACTED_SIZE:
                raise ArchiveValidationError(
                    "Archive exceeds the total uncompressed-size limit."
                )

            if info.file_size > MAX_FILE_SIZE:
                # Oversized individual files are ignored, not read.
                continue

            if info.file_size > 0:
                if info.compress_size == 0:
                    raise ArchiveValidationError(
                        "Archive contains suspicious compression metadata."
                    )

                ratio = info.file_size / info.compress_size

                if ratio > MAX_COMPRESSION_RATIO:
                    raise ArchiveValidationError(
                        "Archive contains an entry with an excessive "
                        "compression ratio."
                    )

            if not _is_supported_text_file(path):
                continue

            # Read at most the configured per-file limit plus one byte.
            try:
                with archive.open(info, mode="r") as file_handle:
                    raw = file_handle.read(MAX_FILE_SIZE + 1)
            except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
                raise ArchiveValidationError(
                    f"Could not safely read archive entry: {normalized_path}"
                ) from exc

            if len(raw) > MAX_FILE_SIZE:
                continue

            # Verify the actual data size matches ZIP metadata.
            if len(raw) != info.file_size:
                raise ArchiveValidationError(
                    f"Archive entry has inconsistent size metadata: "
                    f"{normalized_path}"
                )

            try:
                content = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                # Unsupported/binary-encoded files are ignored.
                continue

            # Ignore files containing NUL bytes, which commonly indicate
            # binary content even if the filename has a text extension.
            if "\x00" in content:
                continue

            source_files.append(
                SourceFile(
                    path=normalized_path,
                    content=content,
                    line_count=len(content.splitlines()),
                )
            )

    return source_files
