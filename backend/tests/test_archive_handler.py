
import io
import zipfile

import pytest

from app.core.archive_handler import (
    ArchiveValidationError,
    read_repository_zip,
)


def make_zip(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)

    return buffer.getvalue()


def test_reads_supported_python_file():
    data = make_zip({"app.py": "password = 'example'\n"})

    files = read_repository_zip(data)

    assert len(files) == 1
    assert files[0].path == "app.py"
    assert files[0].line_count == 1


def test_ignores_unsupported_binary_extension():
    data = make_zip({"image.png": "not an actual image"})

    assert read_repository_zip(data) == []


def test_rejects_path_traversal():
    data = make_zip({"../outside.py": "print('unsafe')"})

    with pytest.raises(ArchiveValidationError, match="traversal"):
        read_repository_zip(data)


def test_rejects_absolute_path():
    data = make_zip({"/outside.py": "print('unsafe')"})

    with pytest.raises(ArchiveValidationError, match="absolute"):
        read_repository_zip(data)


def test_rejects_invalid_zip():
    with pytest.raises(ArchiveValidationError, match="valid ZIP"):
        read_repository_zip(b"this is not a zip archive")


def test_rejects_empty_upload():
    with pytest.raises(ArchiveValidationError, match="empty"):
        read_repository_zip(b"")


def test_ignores_dependency_directories():
    data = make_zip({
        "node_modules/package/index.js": "const x = 1;",
        "app.js": "const y = 2;",
    })

    files = read_repository_zip(data)

    assert [item.path for item in files] == ["app.js"]
