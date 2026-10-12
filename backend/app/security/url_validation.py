"""
GitHub repository URL validation with SSRF prevention.

This module provides comprehensive validation for GitHub repository URLs
to prevent SSRF attacks, open redirects, and other URL-based attacks.
"""

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse


class ValidationError(Exception):
    """Raised when URL validation fails."""
    pass


# GitHub hostname allowlist - only these hosts are permitted
ALLOWED_HOSTNAMES = frozenset({
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
})

# Regex for validating GitHub owner and repository names
# GitHub usernames: alphanumeric, hyphens, underscores, 1-39 chars
# Repository names: alphanumeric, hyphens, underscores, dots, 1-100 chars
GITHUB_OWNER_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$")
GITHUB_REPO_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{1,100}$")

# Maximum URL length
MAX_URL_LENGTH = 2048

# Blocked IP ranges for SSRF prevention
BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private RFC1918
    ipaddress.ip_network("172.16.0.0/12"),     # Private RFC1918
    ipaddress.ip_network("192.168.0.0/16"),    # Private RFC1918
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    # Cloud metadata endpoints
    ipaddress.ip_network("169.254.169.254/32"), # AWS/GCP/Azure metadata
]


@dataclass
class GitHubRepositoryURL:
    """Parsed and validated GitHub repository URL."""
    original_url: str
    normalized_url: str
    hostname: str
    owner: str
    repo: str
    is_api_url: bool
    is_raw_url: bool


def validate_github_repository_url(url: str) -> GitHubRepositoryURL:
    """
    Validate and parse a GitHub repository URL.

    Performs comprehensive validation including:
    - Scheme must be https (http rejected for security)
    - Hostname must be in allowlist
    - No credentials in URL
    - No unexpected ports
    - Owner and repo names match GitHub patterns
    - No path traversal
    - SSRF prevention via DNS resolution check

    Args:
        url: The URL string to validate

    Returns:
        GitHubRepositoryURL with parsed components

    Raises:
        ValidationError: If URL fails any validation check
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")

    if len(url) > MAX_URL_LENGTH:
        raise ValidationError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters")

    # Parse URL
    try:
        parsed = urlparse(url.strip())
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {e}")

    # Validate scheme - only HTTPS allowed
    if parsed.scheme.lower() != "https":
        raise ValidationError("Only HTTPS URLs are allowed")

    # Reject credentials in URL
    if parsed.username or parsed.password:
        raise ValidationError("URLs with embedded credentials are not allowed")

    # Validate hostname
    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("URL must have a hostname")

    hostname_lower = hostname.lower()

    # Check against allowlist
    if hostname_lower not in ALLOWED_HOSTNAMES:
        raise ValidationError(
            f"Hostname '{hostname}' not allowed. "
            f"Allowed: {', '.join(sorted(ALLOWED_HOSTNAMES))}"
        )

    # Validate port - reject non-standard ports
    if parsed.port is not None:
        # Only allow standard HTTPS port 443
        if parsed.port != 443:
            raise ValidationError(f"Port {parsed.port} not allowed. Only port 443 (HTTPS) is permitted")

    # Validate path
    path = parsed.path.strip("/")
    if not path:
        raise ValidationError("URL must have a path (owner/repo)")

    # Split path into components
    path_parts = path.split("/")
    if len(path_parts) < 2:
        raise ValidationError("URL must be in format: https://github.com/owner/repo")

    # Allow extra path components (like /tree/branch/path) but validate first two
    owner = path_parts[0]
    repo = path_parts[1]

    # Remove .git suffix from repo if present
    if repo.endswith(".git"):
        repo = repo[:-4]

    # Validate owner and repo names
    if not GITHUB_OWNER_PATTERN.match(owner):
        raise ValidationError(
            f"Invalid owner name '{owner}'. "
            "Must be 1-39 alphanumeric characters, hyphens, or underscores."
        )

    if not GITHUB_REPO_PATTERN.match(repo):
        raise ValidationError(
            f"Invalid repository name '{repo}'. "
            "Must be 1-100 alphanumeric characters, hyphens, underscores, or dots."
        )

    # Check for path traversal attempts
    if ".." in owner or ".." in repo:
        raise ValidationError("Path traversal detected in owner or repo name")

    # SSRF Prevention: Resolve hostname and check IP
    _validate_hostname_dns(hostname_lower)

    # Build normalized URL
    normalized_path = f"{owner}/{repo}"
    if len(path_parts) > 2:
        normalized_path += "/" + "/".join(path_parts[2:])
    normalized_url = f"https://{hostname_lower}/{normalized_path}"

    return GitHubRepositoryURL(
        original_url=url.strip(),
        normalized_url=normalized_url,
        hostname=hostname_lower,
        owner=owner,
        repo=repo,
        is_api_url=hostname_lower == "api.github.com",
        is_raw_url=hostname_lower == "raw.githubusercontent.com",
    )


def _validate_hostname_dns(hostname: str) -> None:
    """
    Perform DNS resolution and check resolved IPs against blocked ranges.

    This prevents SSRF by ensuring the hostname doesn't resolve to
    private, loopback, link-local, or cloud metadata IPs.
    """
    try:
        # Get all resolved IPs (both IPv4 and IPv6)
        addr_infos = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValidationError(f"Failed to resolve hostname '{hostname}': {e}")

    for addr_info in addr_infos:
        ip_str = addr_info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        # Check against blocked networks
        for network in BLOCKED_NETWORKS:
            if ip in network:
                raise ValidationError(
                    f"Hostname '{hostname}' resolves to blocked IP address '{ip_str}'. "
                    "Access to private, loopback, link-local, and cloud metadata IPs is prohibited."
                )


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def is_loopback_ip(ip_str: str) -> bool:
    """Check if an IP address is a loopback address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback
    except ValueError:
        return False


def is_link_local_ip(ip_str: str) -> bool:
    """Check if an IP address is a link-local address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_link_local
    except ValueError:
        return False


def is_cloud_metadata_ip(ip_str: str) -> bool:
    """Check if an IP address is a cloud metadata endpoint."""
    metadata_ips = {
        "169.254.169.254",  # AWS, GCP, Azure
        "169.254.170.2",    # AWS ECS metadata
        "metadata.google.internal",  # GCP metadata DNS
    }
    return ip_str in metadata_ips


def resolve_hostname_safely(hostname: str) -> list[str]:
    """
    Safely resolve a hostname to IP addresses.

    Returns list of resolved IP addresses after blocking checks.
    Raises ValidationError if resolution fails or IPs are blocked.
    """
    _validate_hostname_dns(hostname)
    addr_infos = socket.getaddrinfo(hostname, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return list(set(addr[4][0] for addr in addr_infos))