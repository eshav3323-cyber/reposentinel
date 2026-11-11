from pathlib import Path

from .config import DEFAULT_CONFIG, ScannerConfig


class LanguageDetector:
    def __init__(self, config: ScannerConfig = DEFAULT_CONFIG):
        self.config = config

    def detect(self, file_path: str | Path) -> str | None:
        extension = Path(file_path).suffix.lower()

        return self.config.supported_extensions.get(extension)