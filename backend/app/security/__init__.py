"""
Security utilities for TraceRoot.

Provides URL validation, SSRF prevention, safe file handling,
and other security hardening utilities.
"""

from app.security.url_validation import (
    validate_github_repository_url,
    GitHubRepositoryURL,
    ValidationError,
    is_private_ip,
    is_loopback_ip,
    is_link_local_ip,
    is_cloud_metadata_ip,
    resolve_hostname_safely,
)
from app.security.file_handling import (
    SafeArchiveExtractor,
    SafeTempDirectory,
    ExtractionLimits,
    ArchiveExtractionError,
)
from app.security.request_limits import (
    RequestLimits,
    configure_request_limits,
)

__all__ = [
    # URL validation
    "validate_github_repository_url",
    "GitHubRepositoryURL",
    "ValidationError",
    "is_private_ip",
    "is_loopback_ip",
    "is_link_local_ip",
    "is_cloud_metadata_ip",
    "resolve_hostname_safely",
    # File handling
    "SafeArchiveExtractor",
    "SafeTempDirectory",
    "ExtractionLimits",
    "ArchiveExtractionError",
    # Request limits
    "RequestLimits",
    "configure_request_limits",
]