"""
Safe file handling for repository ingestion.

Provides secure archive extraction, temporary directory management,
and protection against zip bombs, path traversal, and resource exhaustion.
"""

import os
import shutil
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Set


@dataclass
class ExtractionLimits:
    """Limits for archive extraction to prevent resource exhaustion."""
    max_total_size: int = 100 * 1024 * 1024      # 100 MB max total extracted
    max_file_size: int = 10 * 1024 * 1024        # 10 MB max single file
    max_files: int = 10000                       # 10k files max
    max_depth: int = 50                          # Max directory depth
    allowed_extensions: Optional[Set[str]] = None  # None = allow all


class ArchiveExtractionError(Exception):
    """Raised when archive extraction fails security checks."""
    pass


class SafeArchiveExtractor:
    """
    Secure archive extractor with protection against:
    - Zip bombs (excessive compression ratios)
    - Path traversal attacks
    - Symlink escaping extraction directory
    - Excessive file counts and sizes
    - Unexpected file types
    """

    def __init__(self, limits: Optional[ExtractionLimits] = None):
        self.limits = limits or ExtractionLimits()

    def extract_zip(self, zip_path: Path, dest_dir: Path) -> list[Path]:
        """
        Safely extract a ZIP archive.

        Args:
            zip_path: Path to the ZIP file
            dest_dir: Destination directory (must exist)

        Returns:
            List of extracted file paths

        Raises:
            ArchiveExtractionError: If any security check fails
        """
        if not zip_path.exists():
            raise ArchiveExtractionError(f"ZIP file not found: {zip_path}")

        if not zipfile.is_zipfile(zip_path):
            raise ArchiveExtractionError(f"Not a valid ZIP file: {zip_path}")

        # Check file size before extraction
        file_size = zip_path.stat().st_size
        if file_size > self.limits.max_total_size:
            raise ArchiveExtractionError(
                f"ZIP file too large: {file_size} bytes (max {self.limits.max_total_size})"
            )

        extracted_files = []
        total_extracted_size = 0
        file_count = 0

        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Validate all members before extraction
            for info in zf.infolist():
                # Skip directories
                if info.is_dir():
                    continue

                file_count += 1
                if file_count > self.limits.max_files:
                    raise ArchiveExtractionError(
                        f"Too many files in archive: {file_count} (max {self.limits.max_files})"
                    )

                # Check file size
                if info.file_size > self.limits.max_file_size:
                    raise ArchiveExtractionError(
                        f"File too large: {info.filename} ({info.file_size} bytes, "
                        f"max {self.limits.max_file_size})"
                    )

                total_extracted_size += info.file_size
                if total_extracted_size > self.limits.max_total_size:
                    raise ArchiveExtractionError(
                        f"Total extracted size would exceed limit: "
                        f"{total_extracted_size} bytes (max {self.limits.max_total_size})"
                    )

                # Check path traversal
                safe_path = self._validate_member_path(info.filename, dest_dir)
                if safe_path is None:
                    raise ArchiveExtractionError(
                        f"Path traversal detected: {info.filename}"
                    )

                # Check depth
                if self._get_depth(safe_path, dest_dir) > self.limits.max_depth:
                    raise ArchiveExtractionError(
                        f"Excessive directory depth: {info.filename} "
                        f"(max {self.limits.max_depth})"
                    )

                # Check file extension if restricted
                if self.limits.allowed_extensions:
                    ext = Path(info.filename).suffix.lower()
                    if ext not in self.limits.allowed_extensions:
                        raise ArchiveExtractionError(
                            f"File extension not allowed: {info.filename}"
                        )

            # All checks passed - now extract
            for info in zf.infolist():
                if info.is_dir():
                    continue
                safe_path = self._validate_member_path(info.filename, dest_dir)
                if safe_path:
                    zf.extract(info, dest_dir)
                    extracted_files.append(safe_path)

        return extracted_files

    def extract_tar(self, tar_path: Path, dest_dir: Path) -> list[Path]:
        """
        Safely extract a TAR archive (including .tar.gz, .tgz).

        Args:
            tar_path: Path to the TAR file
            dest_dir: Destination directory (must exist)

        Returns:
            List of extracted file paths

        Raises:
            ArchiveExtractionError: If any security check fails
        """
        if not tar_path.exists():
            raise ArchiveExtractionError(f"TAR file not found: {tar_path}")

        # Check file size
        file_size = tar_path.stat().st_size
        if file_size > self.limits.max_total_size:
            raise ArchiveExtractionError(
                f"TAR file too large: {file_size} bytes (max {self.limits.max_total_size})"
            )

        extracted_files = []
        total_extracted_size = 0
        file_count = 0

        # Determine mode based on extension
        suffix = tar_path.suffix.lower()
        if suffix in ('.gz', '.tgz'):
            mode = 'r:gz'
        elif suffix == '.bz2':
            mode = 'r:bz2'
        elif suffix == '.xz':
            mode = 'r:xz'
        else:
            mode = 'r'

        with tarfile.open(tar_path, mode) as tf:
            # Validate all members before extraction
            for member in tf.getmembers():
                # Skip directories and symlinks (we'll handle them carefully)
                if member.isdir() or member.issym() or member.islnk():
                    continue

                file_count += 1
                if file_count > self.limits.max_files:
                    raise ArchiveExtractionError(
                        f"Too many files in archive: {file_count} (max {self.limits.max_files})"
                    )

                # Check file size
                if member.size > self.limits.max_file_size:
                    raise ArchiveExtractionError(
                        f"File too large: {member.name} ({member.size} bytes, "
                        f"max {self.limits.max_file_size})"
                    )

                total_extracted_size += member.size
                if total_extracted_size > self.limits.max_total_size:
                    raise ArchiveExtractionError(
                        f"Total extracted size would exceed limit: "
                        f"{total_extracted_size} bytes (max {self.limits.max_total_size})"
                    )

                # Check path traversal
                safe_path = self._validate_member_path(member.name, dest_dir)
                if safe_path is None:
                    raise ArchiveExtractionError(
                        f"Path traversal detected: {member.name}"
                    )

                # Check depth
                if self._get_depth(safe_path, dest_dir) > self.limits.max_depth:
                    raise ArchiveExtractionError(
                        f"Excessive directory depth: {member.name} "
                        f"(max {self.limits.max_depth})"
                    )

                # Check file extension if restricted
                if self.limits.allowed_extensions:
                    ext = Path(member.name).suffix.lower()
                    if ext not in self.limits.allowed_extensions:
                        raise ArchiveExtractionError(
                            f"File extension not allowed: {member.name}"
                        )

            # All checks passed - now extract
            # Use extractall with 'data' filter for secure extraction (Python 3.12+)
            # This blocks absolute paths, path traversal (..), and symlinks
            # escaping the extraction directory, satisfying Bandit B202.
            tf.extractall(dest_dir, filter='data')

            # Collect extracted file paths
            for member in tf.getmembers():
                if member.isfile():
                    safe_path = dest_dir / member.name
                    if safe_path.exists():
                        extracted_files.append(safe_path)

        return extracted_files

    def _validate_member_path(self, member_path: str, dest_dir: Path) -> Optional[Path]:
        """
        Validate and resolve a member path to ensure it stays within dest_dir.

        Returns resolved Path if safe, None if path traversal detected.
        """
        # Normalize the member path
        member_path = member_path.replace('\\', '/')  # Normalize Windows paths

        # Check for path traversal attempts
        if member_path.startswith('/') or member_path.startswith('..') or '/../' in member_path:
            return None

        # Resolve the target path
        try:
            target = (dest_dir / member_path).resolve()
            dest_resolved = dest_dir.resolve()

            # Ensure target is within dest_dir
            if not target.is_relative_to(dest_resolved):
                return None
        except (ValueError, RuntimeError):
            return None

        return target

    def _get_depth(self, path: Path, base: Path) -> int:
        """Calculate directory depth relative to base."""
        try:
            # Resolve both paths to handle symlinks (e.g., /tmp -> /private/tmp on macOS)
            rel = path.resolve().relative_to(base.resolve())
            return len(rel.parts)
        except ValueError:
            return 999  # Path not relative to base


@contextmanager
def safe_temp_directory(prefix: str = "traceroot_", base_dir: Optional[Path] = None):
    """
    Context manager for creating and safely cleaning up a temporary directory.

    Each scan gets a unique working directory. The directory is automatically
    cleaned up on exit, even if an exception occurs.

    Args:
        prefix: Prefix for the temporary directory name
        base_dir: Optional base directory (defaults to system temp)

    Yields:
        Path to the temporary directory
    """
    temp_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=base_dir))
    try:
        yield temp_dir
    finally:
        # Best-effort cleanup
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass  # Best effort - log in production


class SafeTempDirectory:
    """
    Class-based safe temporary directory with explicit lifecycle management.

    Use as context manager or manually call create()/cleanup().
    """

    def __init__(self, prefix: str = "traceroot_", base_dir: Optional[Path] = None):
        self.prefix = prefix
        self.base_dir = base_dir
        self.path: Optional[Path] = None
        self._created = False

    def create(self) -> Path:
        """Create the temporary directory."""
        if self._created:
            raise RuntimeError("Temporary directory already created")
        self.path = Path(tempfile.mkdtemp(prefix=self.prefix, dir=self.base_dir))
        self._created = True
        return self.path

    def cleanup(self) -> None:
        """Clean up the temporary directory."""
        if self.path and self.path.exists():
            shutil.rmtree(self.path, ignore_errors=True)
        self.path = None
        self._created = False

    def __enter__(self) -> Path:
        return self.create()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def get_subdirectory(self, name: str) -> Path:
        """Create and return a subdirectory within the temp directory."""
        if not self._created or not self.path:
            raise RuntimeError("Temporary directory not created")
        subdir = self.path / name
        subdir.mkdir(parents=True, exist_ok=True)
        return subdir