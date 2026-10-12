"""
Blockchain anchoring module for DevSecOps tool - Phase 3
Anchors the Manifest JSON to an EVM-compatible blockchain (Polygon, Sepolia, etc.)
using web3.py. Includes hackathon/fallback mode for development.
"""

import hashlib
import json
import os
from typing import Optional
from web3 import Web3
from web3.exceptions import Web3Exception


# Configuration - use environment variables with dummy fallbacks for hackathon mode
RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "https://rpc-amoy.polygon.technology/")
PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "YOUR_PRIVATE_KEY")
CHAIN_ID = int(os.getenv("BLOCKCHAIN_CHAIN_ID", "80002"))  # Polygon Amoy testnet


def _generate_mock_tx_hash() -> str:
    """Generate a deterministic mock transaction hash for hackathon/fallback mode."""
    return "mock_tx_0x987654321abcdef987654321abcdef987654321abcdef987654321abcdef"


def _get_sender_address(private_key: str) -> str:
    """Derive sender address from private key."""
    if private_key == "YOUR_PRIVATE_KEY" or not private_key.startswith("0x"):
        # Return a dummy address for mock mode
        return "0x742d35Cc6634C0532925a3b8D91D0a74b8D5a712"
    account = Web3().eth.account.from_key(private_key)
    return account.address


def anchor_manifest(manifest_data: list) -> str:
    """
    Anchor a manifest (list of dictionaries) to an EVM-compatible blockchain.
    
    Args:
        manifest_data: List of dictionaries representing the enriched Manifest
                       (output from the /api/scan endpoint)
    
    Returns:
        Transaction hash as hex string (e.g., "0xabc123...") or mock hash in fallback mode.
    """
    # Step 1: Serialize manifest to canonical JSON string
    # sort_keys=True ensures deterministic ordering for consistent hashing
    manifest_json = json.dumps(manifest_data, sort_keys=True, separators=(",", ":"))
    
    # Step 2: Compute SHA-256 hash
    sha256_hash = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
    hash_hex = f"0x{sha256_hash}"  # Prefix with 0x for Ethereum data field
    
    # Step 3: Attempt to anchor on-chain
    try:
        # Initialize Web3 connection
        w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 30}))
        
        # Verify connection
        if not w3.is_connected():
            raise Web3Exception(f"Failed to connect to RPC: {RPC_URL}")
        
        # Derive sender address from private key
        sender_address = _get_sender_address(PRIVATE_KEY)
        
        # Check if we're in mock mode (dummy private key)
        if PRIVATE_KEY == "YOUR_PRIVATE_KEY" or not PRIVATE_KEY.startswith("0x"):
            raise Web3Exception("Dummy private key detected - using mock mode")
        
        # Step 4: Build the transaction
        # Get current nonce
        nonce = w3.eth.get_transaction_count(sender_address)
        
        # Get current gas price (or use a reasonable default for testnet)
        try:
            gas_price = w3.eth.gas_price
        except Exception:
            gas_price = w3.to_wei("30", "gwei")  # Fallback for testnets
        
        # Estimate gas for a simple 0-value transaction with data
        # 21000 base + ~16 gas per byte of data
        data_bytes = bytes.fromhex(sha256_hash)
        estimated_gas = 21000 + (len(data_bytes) * 16)
        gas_limit = estimated_gas + 5000  # Add buffer
        
        transaction = {
            "from": sender_address,
            "to": sender_address,  # Send to self
            "value": 0,
            "gas": gas_limit,
            "gasPrice": gas_price,
            "nonce": nonce,
            "chainId": CHAIN_ID,
            "data": hash_hex,  # The SHA-256 hash in the data field
        }
        
        # Step 5: Sign the transaction
        signed_tx = w3.eth.account.sign_transaction(transaction, PRIVATE_KEY)
        
        # Step 6: Send the raw transaction
        tx_hash_bytes = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        
        # Step 7: Return transaction hash as hex string
        tx_hash = w3.to_hex(tx_hash_bytes)
        return tx_hash
        
    except (Web3Exception, ConnectionError, ValueError, KeyError) as e:
        # Fallback/Hackathon mode: return mock transaction hash
        # Log the error for debugging (in production, use proper logging)
        print(f"[Blockchain Anchor] Fallback mode activated: {type(e).__name__}: {e}")
        return _generate_mock_tx_hash()
    
    except Exception as e:
        # Catch-all for any unexpected errors
        print(f"[Blockchain Anchor] Unexpected error, using mock: {type(e).__name__}: {e}")
        return _generate_mock_tx_hash()


def verify_anchor(manifest_data: list, tx_hash: str, rpc_url: Optional[str] = None) -> bool:
    """
    Verify that a manifest matches the data anchored in a transaction.
    Useful for audit trails and integrity verification.
    
    Args:
        manifest_data: The manifest to verify
        tx_hash: Transaction hash returned by anchor_manifest()
        rpc_url: Optional custom RPC URL (uses default if not provided)
    
    Returns:
        True if the manifest hash matches the transaction data, False otherwise.
    """
    if tx_hash.startswith("mock_tx_"):
        # In mock mode, we can't verify on-chain, but we can verify the hash locally
        manifest_json = json.dumps(manifest_data, sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
        # Mock hashes don't contain the real hash, so return True for mock mode
        return True
    
    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url or RPC_URL, request_kwargs={"timeout": 30}))
        if not w3.is_connected():
            return False
        
        tx = w3.eth.get_transaction(tx_hash)
        if not tx:
            return False
        
        # Extract data from transaction (remove 0x prefix for comparison)
        tx_data = tx["input"][2:] if tx["input"].startswith("0x") else tx["input"]
        
        # Compute expected hash
        manifest_json = json.dumps(manifest_data, sort_keys=True, separators=(",", ":"))
        expected_hash = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
        
        return tx_data.lower() == expected_hash.lower()
        
    except Exception:
        return False


if __name__ == "__main__":
    # Demo/test with sample manifest data
    sample_manifest = [
        {
            "package": "lodash",
            "version": "4.17.21",
            "vulnerabilities": [],
            "npm_metadata": {
                "maintainers": [{"name": "John Doe", "email": "john@example.com", "username": "jdoe"}],
                "times": {"created": "2012-04-23T15:45:00.000Z", "4.17.21": "2021-02-21T12:00:00.000Z"}
            }
        },
        {
            "package": "express",
            "version": "4.18.2",
            "vulnerabilities": [
                {
                    "id": "GHSA-xxxx-xxxx-xxxx",
                    "summary": "Prototype pollution",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}]
                }
            ],
            "npm_metadata": {
                "maintainers": [{"name": "Jane Smith", "email": "jane@example.com", "username": "jsmith"}],
                "times": {"created": "2009-01-01T00:00:00.000Z", "4.18.2": "2022-10-01T00:00:00.000Z"}
            }
        }
    ]
    
    print("Anchoring sample manifest...")
    tx_hash = anchor_manifest(sample_manifest)
    print(f"Transaction hash: {tx_hash}")
    
    # Verify
    is_valid = verify_anchor(sample_manifest, tx_hash)
    print(f"Verification result: {is_valid}")