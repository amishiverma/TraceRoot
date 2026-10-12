"""
AI Explanation Module for DevSecOps Scanner.

Generates human-readable threat explanations using Google Gemini AI API.
Converts raw risk scores and flags into professional security analysis.
"""

import os
import logging
from typing import Any, List

from google import genai
from google.genai import types

logger = logging.getLogger(__name__)

# Model configuration
MODEL_NAME = "gemini-1.5-flash"  # Use "gemini-1.5-pro" for higher quality
FALLBACK_MESSAGE = "High risk detected based on heuristics, but AI-generated detailed analysis is currently unavailable."
NORMAL_MESSAGE = "Package behavior appears normal. No immediate threats detected."

# Request timeout in seconds
REQUEST_TIMEOUT = 30.0


def _get_client() -> genai.Client | None:
    """
    Create and return a Gemini client if API key is configured.
    Returns None if GEMINI_API_KEY is not set.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return None
    return genai.Client(api_key=api_key)


def _build_prompt(pkg_name: str, risk_score: int, flags: List[str]) -> str:
    """Builds the professional prompt for the Gemini API."""
    return (
        f"You are a DevSecOps expert. A package named {pkg_name} has a high "
        f"security risk score of {risk_score}/100. The detected flags are: {', '.join(flags)}. "
        f"Write a professional, strict, and concise 2-sentence explanation of why "
        f"this package is dangerous and what the risk is to the application. "
        f"Do not use emojis. Do not use introductory phrases. Just give the two sentences."
    )


def generate_threat_explanation(pkg_name: str, risk_score: int, flags: List[str]) -> str:
    """
    The main function called by main.py to get a human-readable threat analysis.
    """
    # 1. If risk is low, return the normal message immediately (saves API tokens)
    if risk_score < 70:
        return NORMAL_MESSAGE

    # 2. If risk is high, call Gemini AI
    try:
        client = _get_client()
        if client is None:
            logger.warning("GEMINI_API_KEY not configured, returning fallback message")
            return FALLBACK_MESSAGE

        # Create the prompt
        prompt = _build_prompt(pkg_name, risk_score, flags)

        # Generate the response with timeout and safety settings
        config = types.GenerateContentConfig(
            temperature=0.3,
            max_output_tokens=200,
            http_options=types.HttpOptions(timeout=REQUEST_TIMEOUT),
        )

        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt,
            config=config,
        )

        # Validate structured output
        if response is None or not hasattr(response, "text") or not response.text:
            logger.warning("Empty response from Gemini API")
            return FALLBACK_MESSAGE

        return response.text.strip()

    except Exception as e:
        logger.error(f"Gemini API Error: {type(e).__name__}: {e}")
        return FALLBACK_MESSAGE


def generate_batch_explanations(
    packages: list[dict[str, Any]],
    max_calls: int = 10
) -> dict[str, str]:
    """
    Generate explanations for multiple high-risk packages efficiently.

    Args:
        packages: List of package dicts with keys: package, final_risk_score, risk_flags
        max_calls: Maximum API calls to make (rate limiting protection)

    Returns:
        Dict mapping package_name -> explanation
    """
    explanations = {}
    calls_made = 0

    for pkg in packages:
        if calls_made >= max_calls:
            break

        risk_score = pkg.get("final_risk_score", 0)
        if risk_score >= 70:
            pkg_name = pkg.get("package", "unknown")
            flags = pkg.get("risk_flags", [])
            explanations[pkg_name] = generate_threat_explanation(pkg_name, risk_score, flags)
            calls_made += 1

    return explanations


# =============================================================================
# MAIN: Quick Self-Test
# =============================================================================

if __name__ == "__main__":
    # Test cases
    test_cases = [
        {
            "pkg_name": "express",
            "risk_score": 85,
            "flags": ["Known CVEs found", "High Impact: Graph centrality score 100/100"]
        },
        {
            "pkg_name": "lodash",
            "risk_score": 45,
            "flags": []
        },
        {
            "pkg_name": "qs",
            "risk_score": 72,
            "flags": ["Package dormant for > 1 year", "Low maintainer count"]
        }
    ]

    print("=== AI Explanation Tests ===\n")

    for tc in test_cases:
        print(f"Package: {tc['pkg_name']}")
        print(f"Score: {tc['risk_score']}")
        print(f"Flags: {tc['flags']}")
        print("-" * 50)

        explanation = generate_threat_explanation(
            tc["pkg_name"],
            tc["risk_score"],
            tc["flags"]
        )
        print(f"Explanation: {explanation}")
        print()