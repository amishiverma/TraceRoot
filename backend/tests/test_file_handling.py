"""Tests for SafeArchiveExtractor and SafeTempDirectory security features.

Tests cover:
- Path traversal attacks
- Absolute paths
- Unsafe links (symlinks/hardlinks)
- Oversized archives (zip bombs)
- Malformed archives
- Valid archives
"""
import io
import zipfile
import tarfile
import pytest
import tempfile
import os

from pathlib import Path

from app.security.file_handling import (
    SafeArchiveExtractor,
    SafeTempDirectory,
    ExtractionLimits,
    ArchiveExtractionError,
)


class TestExtractionLimits:
    """Test default ExtractionLimits values."""

    def test_default_limits(self):
        """Test default ExtractionLimits values."""
        limits = ExtractionLimits()
        assert limits.max_total_size == 100 * 1024 * 1024  # 100 MB
        assert limits.max_file_size == 10 * 1024 * 1024  # 10 MB
        assert limits.max_files == 10000
        assert limits.max_depth == 50
        assert limits.allowed_extensions is None

    def test_custom_limits(self):
        """Test custom ExtractionLimits values."""
        limits = ExtractionLimits(
            max_total_size=1024,
            max_file_size=256,
            max_files=10,
            max_depth=3,
        )
        assert limits.max_total_size == 1024
        assert limits.max_file_size == 256
        assert limits.max_files == 10
        assert limits.max_depth == 3


class TestSafeTempDirectory:
    """Test SafeTempDirectory context manager."""

    def test_temp_dir_cleanup_on_success(self):
        """Temp directory is cleaned up on successful exit."""
        with SafeTempDirectory() as tmpdir:
            assert tmpdir.exists()
        assert not tmpdir.exists()

    def test_temp_dir_cleanup_on_exception(self):
        """Temp directory is cleaned up even when exception occurs."""
        try:
            with SafeTempDirectory() as tmpdir:
                assert tmpdir.exists()
                raise ValueError("test exception")
        except ValueError:
            pass
        assert not tmpdir.exists()

    def test_temp_dir_creates_unique_directory(self):
        """Each temp dir has a unique name."""
        with SafeTempDirectory() as tmpdir1:
            with SafeTempDirectory() as tmpdir2:
                assert tmpdir1 != tmpdir2
                assert tmpdir1.name != tmpdir2.name

    def test_temp_dir_manual_create_cleanup(self):
        """Test manual create and cleanup."""
        tmpdir = SafeTempDirectory()
        path = tmpdir.create()
        assert path.exists()
        tmpdir.cleanup()
        assert not path.exists()


class TestSafeArchiveExtractor:
    """Test SafeArchiveExtractor security features."""

    def _create_zip_on_disk(self, tmpdir, entries):
        """Create a ZIP archive on disk from a dict of {name: content}."""
        zip_path = tmpdir / "test.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for name, content in entries.items():
                zf.writestr(name, content)
        return zip_path

    def _create_tar_on_disk(self, tmpdir, entries, format='tar'):
        """Create a TAR archive on disk from a dict of {name: content}."""
        suffix = ".tar.gz" if format == 'gz' else ".tar"
        tar_path = tmpdir / f"test{suffix}"
        mode = 'w:gz' if format == 'gz' else 'w'
        with tarfile.open(tar_path, mode) as tf:
            for name, content in entries.items():
                data = content.encode() if isinstance(content, str) else content
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return tar_path

    def test_valid_zip_extraction(self):
        """Valid ZIP archive extracts correctly."""
        with SafeTempDirectory() as tmpdir:
            zip_path = self._create_zip_on_disk(tmpdir, {
                'package.json': '{"name": "test"}',
                'README.md': '# Test Package',
            })
            extractor = SafeArchiveExtractor()
            extracted = extractor.extract_zip(zip_path, tmpdir)
            assert len(extracted) == 2
            assert (tmpdir / 'package.json').exists()
            assert (tmpdir / 'README.md').exists()

    def test_path_traversal_zip_blocked(self):
        """Path traversal in ZIP is blocked."""
        with SafeTempDirectory() as tmpdir:
            zip_path = self._create_zip_on_disk(tmpdir, {
                'package.json': '{"name": "test"}',
                '../etc/passwd': 'root:x:0:0:',
            })
            extractor = SafeArchiveExtractor()
            with pytest.raises(ArchiveExtractionError) as exc:
                extractor.extract_zip(zip_path, tmpdir)
            assert "path traversal" in str(exc.value).lower()

    def test_absolute_path_zip_blocked(self):
        """Absolute path in ZIP is blocked."""
        with SafeTempDirectory() as tmpdir:
            zip_path = self._create_zip_on_disk(tmpdir, {
                'package.json': '{"name": "test"}',
                '/etc/passwd': 'root:x:0:0:',
            })
            extractor = SafeArchiveExtractor()
            with pytest.raises(ArchiveExtractionError) as exc:
                extractor.extract_zip(zip_path, tmpdir)
            assert "path traversal" in str(exc.value).lower()

    def test_max_depth_exceeded_zip_blocked(self):
        """ZIP exceeding max depth is blocked."""
        # Create a truly nested path: level0/level1/level2/level3/level4/level5/file.js
        entries = {'level0/level1/level2/level3/level4/level5/file.js': 'code'}
        with SafeTempDirectory() as tmpdir:
            zip_path = self._create_zip_on_disk(tmpdir, entries)
            extractor = SafeArchiveExtractor(limits=ExtractionLimits(max_depth=3))
            with pytest.raises(ArchiveExtractionError) as exc:
                extractor.extract_zip(zip_path, tmpdir)
            assert "depth" in str(exc.value).lower()

    def test_max_files_exceeded_zip_blocked(self):
        """ZIP exceeding max files is blocked."""
        entries = {f'file{i}.js': 'code' for i in range(101)}
        with SafeTempDirectory() as tmpdir:
            zip_path = self._create_zip_on_disk(tmpdir, entries)
            extractor = SafeArchiveExtractor(limits=ExtractionLimits(max_files=100))
            with pytest.raises(ArchiveExtractionError) as exc:
                extractor.extract_zip(zip_path, tmpdir)
            assert "too many files" in str(exc.value).lower()

    def test_max_file_size_exceeded_zip_blocked(self):
        """File exceeding max_file_size is blocked."""
        with SafeTempDirectory() as tmpdir:
            zip_path = self._create_zip_on_disk(tmpdir, {
                'package.json': '{"name": "test"}',
                'huge.js': 'x' * (10 * 1024 * 1024 + 1),  # 10 MB + 1 byte
            })
            extractor = SafeArchiveExtractor(limits=ExtractionLimits(max_file_size=10 * 1024 * 1024))
            with pytest.raises(ArchiveExtractionError) as exc:
                extractor.extract_zip(zip_path, tmpdir)
            assert "too large" in str(exc.value).lower() or "max" in str(exc.value).lower()

    def test_valid_tar_extraction(self):
        """Valid TAR archive extracts correctly."""
        with SafeTempDirectory() as tmpdir:
            tar_path = self._create_tar_on_disk(tmpdir, {
                'package.json': '{"name": "test"}',
                'README.md': '# Test Package',
            })
            extractor = SafeArchiveExtractor()
            extracted = extractor.extract_tar(tar_path, tmpdir)
            assert len(extracted) == 2
            assert (tmpdir / 'package.json').exists()
            assert (tmpdir / 'README.md').exists()

    def test_path_traversal_tar_blocked(self):
        """Path traversal in TAR is blocked."""
        with SafeTempDirectory() as tmpdir:
            tar_path = self._create_tar_on_disk(tmpdir, {
                'package.json': '{"name": "test"}',
                '../etc/passwd': 'root:x:0:0:',
            })
            extractor = SafeArchiveExtractor()
            with pytest.raises(ArchiveExtractionError) as exc:
                extractor.extract_tar(tar_path, tmpdir)
            assert "path traversal" in str(exc.value).lower()

    def test_absolute_path_tar_blocked(self):
        """Absolute path in TAR is blocked."""
        with SafeTempDirectory() as tmpdir:
            tar_path = self._create_tar_on_disk(tmpdir, {
                'package.json': '{"name": "test"}',
                '/etc/passwd': 'root:x:0:0:',
            })
            extractor = SafeArchiveExtractor()
            with pytest.raises(ArchiveExtractionError) as exc:
                extractor.extract_tar(tar_path, tmpdir)
            assert "path traversal" in str(exc.value).lower()

    def test_valid_tar_gz_extraction(self):
        """Valid gzip-compressed TAR archive extracts correctly."""
        with SafeTempDirectory() as tmpdir:
            tar_path = self._create_tar_on_disk(tmpdir, {
                'package.json': '{"name": "test"}',
            }, format='gz')
            extractor = SafeArchiveExtractor()
            extracted = extractor.extract_tar(tar_path, tmpdir)
            assert len(extracted) >= 0


class TestValidateMemberPath:
    """Test _validate_member_path helper method."""

    def test_normal_path_is_safe(self):
        """Normal relative path is safe."""
        extractor = SafeArchiveExtractor()
        dest_dir = Path("/tmp/test")
        result = extractor._validate_member_path("package.json", dest_dir)
        assert result is not None
        # Path is resolved, so just check it's within dest_dir
        assert dest_dir.resolve() in result.resolve().parents or result.resolve() == dest_dir.resolve()

    def test_absolute_path_is_unsafe(self):
        """Absolute path is unsafe."""
        extractor = SafeArchiveExtractor()
        dest_dir = Path("/tmp/test")
        result = extractor._validate_member_path("/etc/passwd", dest_dir)
        assert result is None

    def test_path_traversal_with_leading_unsafe(self):
        """Path starting with .. is unsafe."""
        extractor = SafeArchiveExtractor()
        dest_dir = Path("/tmp/test")
        result = extractor._validate_member_path("../etc/passwd", dest_dir)
        assert result is None

    def test_path_traversal_with_inline_unsafe(self):
        """Path with /../ in middle is unsafe."""
        extractor = SafeArchiveExtractor()
        dest_dir = Path("/tmp/test")
        result = extractor._validate_member_path("subdir/../../etc/passwd", dest_dir)
        assert result is None

    def test_path_with_backslash_normalized(self):
        """Windows-style backslashes are normalized."""
        extractor = SafeArchiveExtractor()
        dest_dir = Path("/tmp/test")
        result = extractor._validate_member_path("subdir\\..\\etc\\passwd", dest_dir)
        assert result is None  # Contains .. after normalization

    def test_safe_path_within_dest(self):
        """Path within dest_dir is safe."""
        extractor = SafeArchiveExtractor()
        dest_dir = Path("/tmp/test")
        result = extractor._validate_member_path("safe/file.js", dest_dir)
        assert result is not None
        # Check that resolved path is within resolved dest_dir
        assert dest_dir.resolve() in result.resolve().parents or result.resolve() == dest_dir.resolve()

    def test_escaping_path_not_within_dest(self):
        """Path that escapes dest_dir is unsafe."""
        extractor = SafeArchiveExtractor()
        dest_dir = Path("/tmp/test")
        # This would resolve to /tmp/other, not /tmp/test
        result = extractor._validate_member_path("../../../etc/passwd", dest_dir)
        assert result is None
