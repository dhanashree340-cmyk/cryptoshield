"""
app.py
CryptoShield Web Dashboard

A Flask web UI over the SAME crypto modules used by the CLI (main.py):
  key_manager.py      -> master key + HKDF-derived encryption/auth keys
  integrity_module.py -> SHA-256 hashing
  encrypt_module.py   -> ChaCha20-Poly1305 authenticated encryption
  auth_module.py       -> HMAC-SHA256 envelope authentication

Run with:  python app.py
Then open: http://127.0.0.1:5000 in your browser.
"""

import os
import datetime
from flask import Flask, render_template, request, jsonify

from key_manager import load_or_create_master_key, get_encryption_key, get_auth_key
from integrity_module import sha256_hash
from encrypt_module import encrypt, decrypt
from auth_module import compute_hmac, verify_hmac, build_envelope

app = Flask(__name__)

LOG_FILE = os.path.join("logs", "audit_log.txt")
FILENAME_TAG = b"web-message"  # stand-in "filename" covered by the HMAC envelope

# One master key per server run, derived sub-keys held in memory
MASTER_KEY = load_or_create_master_key()
ENC_KEY = get_encryption_key(MASTER_KEY)
AUTH_KEY = get_auth_key(MASTER_KEY)

# In-memory "bundle" for the current demo session (single-user demo, not for production)
current_bundle = None


def log(message: str):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def read_log(limit=25):
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE) as f:
        lines = f.readlines()
    return [l.strip() for l in lines[-limit:]][::-1]


@app.route("/")
def index():
    return render_template(
        "index.html",
        master_key=MASTER_KEY.hex(),
        enc_key=ENC_KEY.hex(),
        auth_key=AUTH_KEY.hex(),
    )


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    global current_bundle
    text = request.json.get("text", "")
    if not text:
        return jsonify({"error": "Empty input"}), 400

    plaintext = text.encode()
    plaintext_hash = sha256_hash(plaintext)

    result = encrypt(plaintext, ENC_KEY)
    nonce, ciphertext = result["nonce"], result["ciphertext"]

    envelope = build_envelope(nonce, ciphertext, FILENAME_TAG)
    hmac_tag = compute_hmac(AUTH_KEY, envelope)

    current_bundle = {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "hmac_tag": hmac_tag,
        "sha256_hash": plaintext_hash,
    }

    log(f"ENCRYPTED {len(plaintext)} bytes with ChaCha20-Poly1305, sealed with HMAC-SHA256")

    return jsonify({
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "hmac_tag": hmac_tag,
        "sha256_hash": plaintext_hash,
    })


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    if current_bundle is None:
        return jsonify({"error": "No bundle to decrypt. Encrypt something first."}), 400

    nonce = current_bundle["nonce"]
    ciphertext = current_bundle["ciphertext"]
    stored_tag = current_bundle["hmac_tag"]
    stored_hash = current_bundle["sha256_hash"]

    steps = []

    # Step 1: HMAC-SHA256 envelope check
    envelope = build_envelope(nonce, ciphertext, FILENAME_TAG)
    hmac_ok = verify_hmac(AUTH_KEY, envelope, stored_tag)
    steps.append({"label": "HMAC-SHA256 envelope check", "ok": hmac_ok})
    if not hmac_ok:
        log("REJECTED: HMAC-SHA256 verification failed (envelope tampered)")
        return jsonify({"steps": steps, "success": False})

    # Step 2: ChaCha20-Poly1305 decrypt + built-in tag check
    try:
        plaintext = decrypt(ciphertext, ENC_KEY, nonce)
        steps.append({"label": "ChaCha20-Poly1305 tag check", "ok": True})
    except Exception:
        steps.append({"label": "ChaCha20-Poly1305 tag check", "ok": False})
        log("REJECTED: ChaCha20-Poly1305 decryption failed (InvalidTag)")
        return jsonify({"steps": steps, "success": False})

    # Step 3: final SHA-256 integrity check
    hash_ok = sha256_hash(plaintext) == stored_hash
    steps.append({"label": "SHA-256 final integrity check", "ok": hash_ok})

    if not hash_ok:
        log("REJECTED: SHA-256 mismatch after decryption")
        return jsonify({"steps": steps, "success": False})

    log("DECRYPTED & VERIFIED successfully — all three checks passed")
    return jsonify({"steps": steps, "success": True, "plaintext": plaintext.decode(errors="replace")})


@app.route("/api/tamper", methods=["POST"])
def api_tamper():
    global current_bundle
    if current_bundle is None:
        return jsonify({"error": "No bundle to tamper with. Encrypt something first."}), 400

    tampered = bytearray(current_bundle["ciphertext"])
    tampered[0] ^= 0xFF
    current_bundle["ciphertext"] = bytes(tampered)

    log("TAMPERED: flipped first byte of stored ciphertext")
    return jsonify({"ciphertext": current_bundle["ciphertext"].hex()})


@app.route("/api/log")
def api_log():
    return jsonify({"lines": read_log()})


if __name__ == "__main__":
    app.run(debug=True)
