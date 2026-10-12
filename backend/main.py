"""
FastAPI backend for DevSecOps tool - Phase 2
Scans GitHub repositories for package.json dependencies and enriches with threat intelligence.
"""
from dotenv import load_dotenv
load_dotenv()  # This loads the variables from .env into your system environment
import os
import re
import asyncio
import logging
from typing import Any, Optional
import httpx
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, field_validator
from blockchain import anchor_manifest
from fastapi.encoders import jsonable_encoder
from app.graph.builder import build_dependency_graph
from app.risk.assessment import assess_all_risks
from app.security import (
    validate_github_repository_url,
    ValidationError,
    RequestLimits,
    configure_request_limits,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Environment Configuration & Validation ---
def get_cors_allowed_origins() -> list[str]:
    """
    Parse CORS_ALLOWED_ORIGINS from environment.
    Format: comma-separated list of origins.
    Defaults to localhost for development only.
    """
    cors_env = os.getenv("CORS_ALLOWED_ORIGINS", "")
    if cors_env:
        origins = [o.strip() for o in cors_env.split(",") if o.strip()]
        # Validate each origin is a proper URL
        for origin in origins:
            if not (origin.startswith("http://") or origin.startswith("https://")):
                raise ValueError(f"Invalid CORS origin (must start with http:// or https://): {origin}")
        return origins
    
    # Development default - only localhost
    logger.warning("CORS_ALLOWED_ORIGINS not set, defaulting to localhost for development")
    return [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]


def validate_required_env() -> None:
    """Validate required environment variables at startup."""
    # Check for required production config
    cors_origins = get_cors_allowed_origins()
    if "*" in cors_origins:
        raise ValueError("Wildcard CORS origin (*) is not allowed in production")
    
    # Log configuration (without secrets)
    logger.info(f"CORS allowed origins: {cors_origins}")
    logger.info(f"GEMINI_API_KEY configured: {bool(os.getenv('GEMINI_API_KEY'))}")
    logger.info(f"BLOCKCHAIN_RPC_URL configured: {bool(os.getenv('BLOCKCHAIN_RPC_URL'))}")
    logger.info(f"BLOCKCHAIN_PRIVATE_KEY configured: {bool(os.getenv('BLOCKCHAIN_PRIVATE_KEY'))}")


# Validate environment at module load
validate_required_env()

CORS_ALLOWED_ORIGINS = get_cors_allowed_origins()


class ScanRequest(BaseModel):
    """Request model for scanning a GitHub repository."""
    github_url: str

    @field_validator("github_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        """Validate that the URL is a GitHub repository URL using security module."""
        try:
            validated = validate_github_repository_url(v)
            return validated.normalized_url
        except ValidationError as e:
            raise ValueError(str(e))


class PackageInfo(BaseModel):
    package: str
    version: str
    parent: str = "root"


class NPMMaintainer(BaseModel):
    """Model for NPM package maintainer."""
    name: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None


class NPMMetadata(BaseModel):
    """Model for NPM registry metadata."""
    maintainers: list[NPMMaintainer] = []
    times: dict[str, str] = {}
    # Resolved versions from package-lock.json if available
    resolved: dict[str, str] = {}


class OSVVulnerability(BaseModel):
    """Model for a single OSV vulnerability."""
    id: str
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: list[dict] = []
    affected: list[dict] = []
    references: list[dict] = []
    published: Optional[str] = None
    modified: Optional[str] = None


class ManifestEntry(BaseModel):
    package: str
    version: str  # requested version from package.json (may be range)
    requested_version: str = ""  # explicitly track requested version
    resolved_version: str = ""   # resolved version from lockfile if available
    parent: str = "root"
    vulnerabilities: Any
    npm_metadata: Any

app = FastAPI(
    title="DevSecOps Scanner API",
    description="Scan GitHub repositories for package.json dependencies and enrich with threat intelligence",
    version="2.0.0"
)

# Configure CORS with explicit allowed origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure request limits and rate limiting
limits = RequestLimits(
    allowed_origins=CORS_ALLOWED_ORIGINS
)
configure_request_limits(app, limits)


def convert_to_raw_package_url(github_url: str, branch: str = "main") -> str:
    """
    Convert a GitHub repository URL to a raw package.json URL.

    Args:
        github_url: Standard GitHub repo URL (e.g., https://github.com/facebook/react)
        branch: Branch name (default: main)

    Returns:
        Raw GitHub content URL for package.json
    """
    # Remove trailing slash and extract owner/repo
    url = github_url.rstrip("/")
    # Pattern: https://github.com/owner/repo
    match = re.match(r"https?://github\.com/([\w\-]+)/([\w\-\.]+)", url)
    if not match:
        raise ValueError("Invalid GitHub URL format")

    owner, repo = match.groups()
    # Remove .git suffix if present
    repo = repo.replace(".git", "")

    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/package.json"


def fetch_package_json(github_url: str) -> dict:
    """
    Fetch package.json from GitHub, trying 'main' branch first, then 'master'.

    Args:
        github_url: GitHub repository URL (must be validated)

    Returns:
        Parsed package.json as dictionary

    Raises:
        HTTPException: If package.json not found or other errors
    """
    import requests
    branches = ["main", "master"]
    last_error = None

    for branch in branches:
        raw_url = convert_to_raw_package_url(github_url, branch)
        try:
            response = requests.get(raw_url, timeout=10)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                last_error = f"package.json not found on branch '{branch}'"
                continue
            else:
                last_error = f"GitHub returned status {response.status_code} for branch '{branch}'"
                continue

        except requests.exceptions.Timeout:
            last_error = f"Request timeout for branch '{branch}'"
            continue
        except requests.exceptions.RequestException as e:
            last_error = f"Request failed for branch '{branch}': {str(e)}"
            continue
        except ValueError as e:
            # JSON decode error
            last_error = f"Invalid JSON response for branch '{branch}': {str(e)}"
            continue

    # If we get here, both branches failed
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"package.json not found at the root of the repository. Tried branches: main, master. Last error: {last_error}"
    )


def extract_dependencies(package_json: dict) -> list[PackageInfo]:
    """
    Extract and merge dependencies and devDependencies from package.json.
    
    Args:
        package_json: Parsed package.json dictionary
    
    Returns:
        List of PackageInfo objects
    """
    dependencies = package_json.get("dependencies", {}) or {}
    dev_dependencies = package_json.get("devDependencies", {}) or {}
    
    # Merge both dictionaries (devDependencies will overwrite if same key, but that's fine)
    all_deps = {**dependencies, **dev_dependencies}
    
    # Convert to list of PackageInfo
    result = [
        PackageInfo(package=name, version=version)
        for name, version in all_deps.items()
    ]
    
    return result


async def fetch_osv_vulnerabilities(client: httpx.AsyncClient, package_name: str, version: str) -> list[OSVVulnerability]:
    """
    Fetch vulnerabilities for a package from OSV API.
    
    Args:
        client: Async HTTP client
        package_name: Name of the npm package
        version: Version of the package
    
    Returns:
        List of OSVVulnerability objects (empty if none found or error)
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "npm"
        },
        "version": version
    }
    
    try:
        response = await client.post(url, json=payload, timeout=limits.osv_api_timeout)
        
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])
            
            result = []
            for vuln in vulns:
                # Extract severity info
                severity = vuln.get("severity", [])
                
                result.append(OSVVulnerability(
                    id=vuln.get("id", ""),
                    summary=vuln.get("summary"),
                    details=vuln.get("details"),
                    severity=severity,
                    affected=vuln.get("affected", []),
                    references=vuln.get("references", []),
                    published=vuln.get("published"),
                    modified=vuln.get("modified")
                ))
            
            return result
        else:
            # OSV API returned non-200, return empty list
            return []
            
    except Exception:
        # Any error (timeout, network, etc.) - return empty list
        return []


async def fetch_npm_metadata(client: httpx.AsyncClient, package_name: str) -> NPMMetadata:
    """
    Fetch package metadata from NPM Registry API.
    
    Args:
        client: Async HTTP client
        package_name: Name of the npm package
    
    Returns:
        NPMMetadata object with maintainers and times (empty if 404 or error)
    """
    url = f"https://registry.npmjs.org/{package_name}"
    
    try:
        response = await client.get(url, timeout=limits.npm_api_timeout)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract maintainers
            maintainers_raw = data.get("maintainers", [])
            maintainers = [
                NPMMaintainer(
                    name=m.get("name"),
                    email=m.get("email"),
                    username=m.get("username")
                )
                for m in maintainers_raw
            ]
            
            # Extract times object (publish dates)
            times = data.get("time", {})
            
            return NPMMetadata(
                maintainers=maintainers,
                times=times
            )
        elif response.status_code == 404:
            # Package not found - return empty metadata gracefully
            return NPMMetadata()
        else:
            # Other error - return empty metadata
            return NPMMetadata()
            
    except Exception:
        # Any error (timeout, network, etc.) - return empty metadata
        return NPMMetadata()


async def enrich_package(client: httpx.AsyncClient, pkg: PackageInfo) -> ManifestEntry:
    """
    Enrich a single package with OSV vulnerabilities and NPM metadata.
    Makes both API calls concurrently for performance.
    
    Args:
        client: Async HTTP client
        pkg: PackageInfo object
    
    Returns:
        ManifestEntry with enriched data
    """
    # Run both API calls concurrently
    osv_task = fetch_osv_vulnerabilities(client, pkg.package, pkg.version)
    npm_task = fetch_npm_metadata(client, pkg.package)
    
    vulnerabilities, npm_metadata = await asyncio.gather(osv_task, npm_task)
    
    # Determine requested vs resolved version
    requested_version = pkg.version
    resolved_version = ""
    
    # Check if version is a range (e.g., ^2.0.0, ~1.0.0, >=1.0.0)
    # If it's a range and we have npm metadata with resolved versions, try to resolve
    from app.graph.builder import _is_version_range
    if _is_version_range(requested_version):
        # Try to get resolved version from npm metadata (package-lock.json data if available)
        resolved_dict = getattr(npm_metadata, 'resolved', {}) or {}
        if pkg.package in resolved_dict:
            resolved_version = resolved_dict[pkg.package]
        # If not in resolved dict, we can't resolve without package-lock.json
        # The requested_version will be used as-is (range)
    else:
        # Already a resolved version
        resolved_version = requested_version
    
    return ManifestEntry(
        package=pkg.package,
        version=requested_version,  # original version from package.json
        requested_version=requested_version,
        resolved_version=resolved_version,
        parent=pkg.parent,
        vulnerabilities=vulnerabilities,
        npm_metadata=npm_metadata
    )


@app.post("/api/scan")
async def scan_repository(request: ScanRequest):
    """
    Scan a GitHub repository for package.json dependencies and enrich with threat intelligence.
    
    Args:
        request: ScanRequest containing github_url
    
    Returns:
        List of ManifestEntry objects (The Manifest) - limited to first 5 packages
    
    Raises:
        HTTPException: If package.json not found or invalid
    """
    try:
        # Fetch package.json (tries main then master)
        package_json = fetch_package_json(request.github_url)
        
        # Extract and merge dependencies
        dependencies = extract_dependencies(package_json)
        
        # Limit to first 5 packages to avoid rate limits during testing
        dependencies = dependencies[:5]
        
        # Enrich all packages concurrently using httpx.AsyncClient
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                limits.github_api_timeout,
                connect=limits.osv_api_timeout
            ),
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)
        ) as client:
            # Create enrichment tasks for all packages
            enrichment_tasks = [
                enrich_package(client, pkg)
                for pkg in dependencies
            ]
            
            # Execute all enrichments concurrently
            manifest = await asyncio.gather(*enrichment_tasks)
        
       # 1. Convert the custom Pydantic objects into standard dictionaries safely
        safe_manifest = jsonable_encoder(manifest)

        # ---> ADD THIS BLOCK TO TEST PARAM'S GRAPH <---
       # ---> RUN PARAM'S GRAPH AND AI RISK SCORER <---
        try:
            # 1. Build Param's Graph
            graph = build_dependency_graph(safe_manifest)
            
            # 2. RUN PARAM'S AI RISK SCORER!
            safe_manifest = assess_all_risks(graph, safe_manifest)

            # 3. GENERATE GEMINI AI THREAT EXPLANATIONS
            try:
                from app.ai.explanation import generate_threat_explanation
                for pkg in safe_manifest:
                    pkg["ai_threat_explanation"] = generate_threat_explanation(
                        pkg.get("package", "unknown"),
                        pkg.get("final_risk_score", 0),
                        pkg.get("risk_flags", [])
                    )
            except Exception as ai_err:
                print(f"⚠️ AI Threat Explanation Warning: {ai_err}")
                for pkg in safe_manifest:
                    if "ai_threat_explanation" not in pkg:
                        pkg["ai_threat_explanation"] = "Package behavior appears normal. No immediate threats detected."
            
            # --- THE GHOST DETECTOR (ADD THESE 2 LINES) ---
            first_pkg = safe_manifest[0]
            print(f"👻 GHOST DETECTOR: First package is {first_pkg['package']} with Score: {first_pkg.get('final_risk_score', 'MISSING!')}")
            # ----------------------------------------------
            
            print(f"🚀 SUCCESS! AI Risk Scores & Threat Explanations calculated.")
        except Exception as e:
            print(f"❌ AI/GRAPH ERROR: {e}")
        # ---------------------------------------------
        # 2. Get the blockchain hash using the safe data
        tx_hash = anchor_manifest(safe_manifest)
        
        # 3. Return BOTH the hash and the manifest
        return {
            "transaction_hash": tx_hash,
            "dependencies": safe_manifest
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {"status": "healthy", "service": "devsecops-scanner", "version": "2.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)