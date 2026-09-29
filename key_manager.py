"""
key_manager.py
Handles generation and derivation of cryptographic keys used by CryptoShield.

- A random master key is generated once and stored locally (for demo purposes).
  In a real production system this would live in a KMS/HSM, not a plain file.
- From the master key, we derive two separate keys using HKDF (built on HMAC-SHA256):
    1. An encryption key for ChaCha20-Poly1305
    2. An authentication key for the extra HMAC-SHA256 integrity layer
  Deriving separate keys for separate purposes is a cryptography best practice
  (never reuse the same key for two different algorithms/purposes).
"""

import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MASTER_KEY_FILE = "master.key"
KEY_LEN = 32  # 256-bit keys for both ChaCha20-Poly1305 and HMAC-SHA256


def generate_master_key(path: str = MASTER_KEY_FILE) -> bytes:
    """Generate a new random 256-bit master key and save it to disk."""
    key = os.urandom(KEY_LEN)
    with open(path, "wb") as f:
        f.write(key)
    return key


def load_or_create_master_key(path: str = MASTER_KEY_FILE) -> bytes:
    """Load the master key if it exists, otherwise create a new one."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    return generate_master_key(path)


def derive_key(master_key: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    """
    Derive a sub-key from the master key using HKDF (HMAC-SHA256 based).
    'info' is a context string that makes sure keys derived for different
    purposes (e.g. b'encryption' vs b'authentication') are cryptographically
    independent, even though they come from the same master key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)


def get_encryption_key(master_key: bytes) -> bytes:
    return derive_key(master_key, b"cryptoshield-encryption-key")


def get_auth_key(master_key: bytes) -> bytes:
    return derive_key(master_key, b"cryptoshield-auth-key")


if __name__ == "__main__":
    mk = load_or_create_master_key()
    print("Master key (hex):", mk.hex())
    print("Encryption key (hex):", get_encryption_key(mk).hex())
    print("Auth key (hex):", get_auth_key(mk).hex())
