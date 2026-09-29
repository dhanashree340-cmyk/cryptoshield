"""
encrypt_module.py
Handles authenticated encryption and decryption using ChaCha20-Poly1305.

ChaCha20-Poly1305 is an AEAD (Authenticated Encryption with Associated Data)
cipher: it gives you confidentiality (ChaCha20 stream cipher) AND integrity/
authenticity (Poly1305 MAC) in a single operation. If even one bit of the
ciphertext or nonce is changed, decryption will fail with an exception
instead of silently returning corrupted data.

IMPORTANT: A nonce (12 bytes for this construction) must NEVER be reused
with the same key. We generate a fresh random nonce for every encryption.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NONCE_LEN = 12  # 96 bits, required by ChaCha20-Poly1305


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes = None) -> dict:
    """
    Encrypt plaintext with ChaCha20-Poly1305.
    Returns a dict with the nonce and ciphertext (which includes the
    16-byte Poly1305 authentication tag appended by the library).
    """
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
    return {"nonce": nonce, "ciphertext": ciphertext}


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypt and verify ciphertext with ChaCha20-Poly1305.
    Raises cryptography.exceptions.InvalidTag if the data was tampered with
    or the wrong key/nonce/associated_data was used.
    """
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, associated_data)


if __name__ == "__main__":
    key = os.urandom(32)
    message = b"This is a secret message for CryptoShield."

    result = encrypt(message, key)
    print("Nonce (hex):", result["nonce"].hex())
    print("Ciphertext (hex):", result["ciphertext"].hex())

    recovered = decrypt(result["ciphertext"], key, result["nonce"])
    print("Decrypted:", recovered)
    assert recovered == message

    # Simulate tampering: flip a byte in the ciphertext
    tampered = bytearray(result["ciphertext"])
    tampered[0] ^= 0xFF
    try:
        decrypt(bytes(tampered), key, result["nonce"])
    except Exception as e:
        print("Tamper detected as expected:", type(e).__name__)
