"""
Request limits and rate limiting configuration.

Provides configuration for request size limits, rate limiting,
and other API protection measures.
"""

from dataclasses import dataclass
from typing import Optional
from fastapi import FastAPI, Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import time
from collections import defaultdict


@dataclass
class RequestLimits:
    """Configuration for request and scan limits."""
    # Request body limits
    max_request_size: int = 10 * 1024 * 1024      # 10 MB max request body
    max_json_depth: int = 50                       # Max JSON nesting depth
    max_json_keys: int = 1000                      # Max keys in JSON object

    # Scan limits
    max_scan_duration: int = 300                   # 5 minutes max per scan
    max_dependencies: int = 5000                   # Max dependencies to process
    max_archive_size: int = 100 * 1024 * 1024      # 100 MB max archive
    max_archive_files: int = 10000                 # Max files in archive

    # Rate limiting
    requests_per_minute: int = 60                  # Requests per minute per IP
    scans_per_hour: int = 100                      # Scans per hour per IP

    # External API timeouts
    github_api_timeout: float = 30.0               # GitHub API timeout (seconds)
    osv_api_timeout: float = 15.0                  # OSV API timeout (seconds)
    npm_api_timeout: float = 15.0                  # NPM Registry timeout (seconds)

    # CORS
    allowed_origins: list[str] = None              # If None, uses ["*"]


class RateLimiter(BaseHTTPMiddleware):
    """Simple in-memory rate limiter for API endpoints."""

    def __init__(self, app: FastAPI, limits: RequestLimits):
        super().__init__(app)
        self.limits = limits
        self._request_counts: defaultdict[str, list[float]] = defaultdict(list)
        self._scan_counts: defaultdict[str, list[float]] = defaultdict(list)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _clean_old_entries(self, counts: dict[str, list[float]], window_seconds: int) -> None:
        """Remove entries older than the window."""
        now = time.time()
        for ip in list(counts.keys()):
            counts[ip] = [t for t in counts[ip] if now - t < window_seconds]
            if not counts[ip]:
                del counts[ip]

    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = self._get_client_ip(request)
        now = time.time()

        # Rate limit for all requests (per minute)
        self._clean_old_entries(self._request_counts, 60)
        if len(self._request_counts[client_ip]) >= self.limits.requests_per_minute:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded: {self.limits.requests_per_minute} requests per minute"
            )
        self._request_counts[client_ip].append(now)

        # Stricter rate limit for scan endpoint (per hour)
        if request.url.path == "/api/scan" and request.method == "POST":
            self._clean_old_entries(self._scan_counts, 3600)
            if len(self._scan_counts[client_ip]) >= self.limits.scans_per_hour:
                raise HTTPException(
                    status_code=429,
                    detail=f"Scan rate limit exceeded: {self.limits.scans_per_hour} scans per hour"
                )
            self._scan_counts[client_ip].append(now)

        # Add request size limit check
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > RequestLimits.max_request_size:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Request body too large: {size} bytes (max {RequestLimits.max_request_size})"
                    )
            except ValueError:
                pass

        return await call_next(request)


def configure_request_limits(app: FastAPI, limits: RequestLimits = None) -> RequestLimits:
    """
    Configure request limits and rate limiting for the FastAPI app.

    Args:
        app: FastAPI application
        limits: RequestLimits configuration (uses defaults if None)

    Returns:
        The configured RequestLimits instance
    """
    limits = limits or RequestLimits()

    # Add rate limiter middleware
    app.add_middleware(RateLimiter, limits=limits)

    # Configure CORS with restricted origins if specified
    if limits.allowed_origins is not None:
        # Find and update existing CORS middleware
        for middleware in app.user_middleware:
            if middleware.cls.__name__ == "CORSMiddleware":
                middleware.kwargs["allow_origins"] = limits.allowed_origins
                break

    return limits


def validate_scan_input(
    github_url: str,
    max_dependencies: int = None,
    max_duration: int = None,
) -> None:
    """
    Validate scan input parameters.

    Args:
        github_url: GitHub repository URL (validated separately)
        max_dependencies: Maximum allowed dependencies
        max_duration: Maximum scan duration in seconds

    Raises:
        ValueError: If validation fails
    """
    if not github_url or not isinstance(github_url, str):
        raise ValueError("GitHub URL is required")

    if max_dependencies is not None and max_dependencies <= 0:
        raise ValueError("max_dependencies must be positive")

    if max_duration is not None and max_duration <= 0:
        raise ValueError("max_duration must be positive")


# Default limits instance for easy import
DEFAULT_LIMITS = RequestLimits()