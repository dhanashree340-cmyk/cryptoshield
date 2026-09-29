"""
auth_module.py
Provides an extra authentication layer using HMAC-SHA256, on top of the
Poly1305 tag already provided by ChaCha20-Poly1305.

Why add this if Poly1305 already authenticates the data?
- Defense in depth: two independent authentication mechanisms mean a flaw
  in one algorithm's implementation doesn't automatically break the system.
- HMAC-SHA256 here authenticates the *envelope* (ciphertext + nonce +
  metadata like filename/timestamp) as a single bundle, which is useful
  when you store/transmit these pieces together and want one tag that
  covers everything, not just the raw ciphertext.
"""

import hmac
import hashlib


def compute_hmac(key: bytes, message: bytes) -> str:
    """Compute an HMAC-SHA256 tag over 'message' using 'key'. Returns hex string."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, message: bytes, tag: str) -> bool:
    """
    Verify an HMAC-SHA256 tag using a constant-time comparison
    (hmac.compare_digest) to avoid timing attacks.
    """
    expected = compute_hmac(key, message)
    return hmac.compare_digest(expected, tag)


def build_envelope(nonce: bytes, ciphertext: bytes, metadata: bytes = b"") -> bytes:
    """Combine nonce + ciphertext + metadata into one byte string for HMAC coverage."""
    return nonce + ciphertext + metadata


if __name__ == "__main__":
    key = b"0" * 32
    nonce = b"n" * 12
    ciphertext = b"fake-ciphertext-bytes"
    envelope = build_envelope(nonce, ciphertext, b"file:sample.txt")

    tag = compute_hmac(key, envelope)
    print("HMAC tag:", tag)
    print("Verify (should be True):", verify_hmac(key, envelope, tag))

    tampered_envelope = envelope + b"x"
    print("Verify tampered (should be False):", verify_hmac(key, tampered_envelope, tag))
