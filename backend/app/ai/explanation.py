"""
AI Explanation Module for DevSecOps Scanner.

Generates human-readable threat explanations using Google Gemini AI API.
Converts raw risk scores and flags into professional security analysis.
"""

import os
import google.generativeai as genai
from typing import List

# Configure Gemini API using the .env key loaded by main.py
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Model configuration
MODEL_NAME = "gemini-1.5-flash" # Use "gemini-1.5-pro" for higher quality
FALLBACK_MESSAGE = "High risk detected based on heuristics, but AI-generated detailed analysis is currently unavailable."
NORMAL_MESSAGE = "Package behavior appears normal. No immediate threats detected."

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
        if not GEMINI_API_KEY:
            return FALLBACK_MESSAGE

        # Initialize the model
        model = genai.GenerativeModel(MODEL_NAME)
        
        # Create the prompt
        prompt = _build_prompt(pkg_name, risk_score, flags)
        
        # Generate the response
        response = model.generate_content(prompt)
        
        return response.text.strip()

    except Exception as e:
        print(f"❌ Gemini API Error: {e}")
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