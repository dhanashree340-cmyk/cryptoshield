"""
integrity_module.py
Provides SHA-256 based hashing utilities used to fingerprint data
before encryption and after decryption, so we can prove that the
plaintext was never altered.
"""

import hashlib


def sha256_hash(data: bytes) -> str:
    """Return the SHA-256 hash of the given bytes as a hex string."""
    return hashlib.sha256(data).hexdigest()


def sha256_hash_file(file_path: str) -> str:
    """Compute the SHA-256 hash of a file's contents (streamed, memory-safe)."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_hash(data: bytes, expected_hash: str) -> bool:
    """Check that the SHA-256 hash of data matches the expected hash."""
    return sha256_hash(data) == expected_hash


if __name__ == "__main__":
    sample = b"Hello, CryptoShield!"
    h = sha256_hash(sample)
    print("Data:", sample)
    print("SHA-256:", h)
    print("Verify (should be True):", verify_hash(sample, h))
    print("Verify tampered (should be False):", verify_hash(b"Hello, CryptoShield?", h))
