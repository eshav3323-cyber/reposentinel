from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScannerConfig:
    """
    Central configuration for RepoSentinel Core.

    These limits help prevent unnecessarily expensive repository scans.
    """

    supported_extensions: dict[str, str] = field(
        default_factory=lambda: {
            ".py": "Python",
            ".js": "JavaScript",
            ".jsx": "JavaScript",
            ".ts": "TypeScript",
            ".tsx": "TypeScript",
        }
    )

    ignored_directories: frozenset[str] = frozenset({
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "node_modules",
        "dist",
        "build",
        ".next",
        ".idea",
        ".vscode",
        "coverage",
    })

    max_file_size_bytes: int = 1_000_000
    max_files: int = 5_000
    hash_chunk_size: int = 64 * 1024

    ignored_filenames: frozenset[str] = frozenset({
        ".DS_Store",
        "Thumbs.db",
    })


DEFAULT_CONFIG = ScannerConfig()