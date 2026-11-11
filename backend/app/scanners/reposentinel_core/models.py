from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FileMetadata:
    path: str
    extension: str
    language: str
    size_bytes: int
    sha256: str


@dataclass
class RepositoryReport:
    repository_path: str
    total_files_discovered: int = 0
    analyzed_files: int = 0
    skipped_files: int = 0
    total_size_bytes: int = 0

    scan_truncated: bool = False
    truncation_reason: str | None = None

    language_counts: dict[str, int] = field(default_factory=dict)
    files: list[FileMetadata] = field(default_factory=list)
    skipped_reasons: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)