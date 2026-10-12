"""
FastAPI backend for DevSecOps tool - Phase 1
Scans GitHub repositories for package.json dependencies.
"""

import re
import requests
from typing import Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, field_validator


class ScanRequest(BaseModel):
    """Request model for scanning a GitHub repository."""
    github_url: str

    @field_validator("github_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        """Validate that the URL is a GitHub repository URL."""
        github_pattern = r"^https?://github\.com/[\w\-]+/[\w\-\.]+/?$"
        if not re.match(github_pattern, v.rstrip("/")):
            raise ValueError("Invalid GitHub repository URL format. Expected: https://github.com/owner/repo")
        return v.rstrip("/")


class PackageInfo(BaseModel):
    """Model for a single package dependency."""
    package: str
    version: str


app = FastAPI(
    title="DevSecOps Scanner API",
    description="Scan GitHub repositories for package.json dependencies",
    version="1.0.0"
)

# Configure CORS for local hackathon - allow all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
        github_url: GitHub repository URL
    
    Returns:
        Parsed package.json as dictionary
    
    Raises:
        HTTPException: If package.json not found or other errors
    """
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


@app.post("/api/scan", response_model=list[PackageInfo])
async def scan_repository(request: ScanRequest) -> list[PackageInfo]:
    """
    Scan a GitHub repository for package.json dependencies.
    
    Args:
        request: ScanRequest containing github_url
    
    Returns:
        List of packages with their versions
    
    Raises:
        HTTPException: If package.json not found or invalid
    """
    try:
        # Fetch package.json (tries main then master)
        package_json = fetch_package_json(request.github_url)
        
        # Extract and merge dependencies
        dependencies = extract_dependencies(package_json)
        
        return dependencies
        
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
    return {"status": "healthy", "service": "devsecops-scanner"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
