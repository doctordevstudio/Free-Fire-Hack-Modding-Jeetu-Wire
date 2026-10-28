import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask, request, jsonify

app = Flask(__name__)

# ------------------------------------------------------------------
# CONFIG — set these on Render as environment variables
# ------------------------------------------------------------------
PRODUCT_CODE = os.environ.get("PRODUCT_CODE", "D11AA8C43D8AFAE9")

# ONE valid license key, hardcoded. Everything else returns error.
VALID_KEY = os.environ.get("VALID_KEY", "JW-CLONE-0001-TEST")

# Seconds the key is valid for from first successful login (30 days).
LICENSE_SECONDS = int(os.environ.get("LICENSE_SECONDS", str(30 * 24 * 3600)))

# Path to the RSA *private* key (PEM). You generate it once (see Part 2).
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "private_key.pem")

# Simple device binding: first device that logs in is remembered.
# In-memory only — Render free tier restarts and wipes this. For a real
# deployment use a small persistent store, e.g. a JSON file under /tmp
# (still wipes on restart) or a free Redis/KV.
_BINDINGS = {}  # {license_key: {"device_id":..., "exp_epoch":...}}


# ------------------------------------------------------------------
# Load private key at boot
# ------------------------------------------------------------------
def _load_private_key():
    path = PRIVATE_KEY_PATH
    if not os.path.exists(path):
        # Fallback: allow key in env as base64 PEM (useful for Render)
        b64 = os.environ.get("PRIVATE_KEY_PEM_B64")
        if b64:
            pem = base64.b64decode(b64)
            return serialization.load_pem_private_key(pem, password=None)
        raise RuntimeError(
            f"Private key not found at {path} and PRIVATE_KEY_PEM_B64 unset"
        )
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


_PRIV = _load_private_key()


# ------------------------------------------------------------------
# The exact canonical string the client signs/verifies
# ------------------------------------------------------------------
def _canonical(nonce: str, expires_at: str, remaining_seconds: int) -> bytes:
    return (
        f"ok=true&nonce={nonce}"
        f"&expires_at={expires_at}"
        f"&remaining_seconds={remaining_seconds}"
    ).encode("utf-8")


def _sign(canonical: bytes) -> str:
    sig = _PRIV.sign(
        canonical,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("ascii")


def _now() -> int:
    return int(time.time())


# ------------------------------------------------------------------
# Login endpoint
# ------------------------------------------------------------------
@app.route("/", methods=["POST", "GET"])
def keydock_connect():
    # The app sends form-encoded POST. GET is included for easy debugging
    # via browser; the real client only ever POSTs.
    data = request.form if request.method == "POST" else request.args

    user_key    = (data.get("user_key")    or "").strip()
    device_id   = (data.get("device_id")   or "").strip()
    nonce       = (data.get("nonce")       or "").strip()
    app_ver     = (data.get("app_ver")     or "").strip()
    product     = (data.get("product_code") or "").strip()

    # -- Validate required fields ----------------------------------
    if not user_key or not nonce:
        return jsonify({"ok": False, "error": "Missing parameters"}), 200

    if product != PRODUCT_CODE:
        return jsonify({"ok": False, "error": "Wrong product"}), 200

    # -- Validate license key --------------------------------------
    if user_key != VALID_KEY:
        return jsonify({"ok": False, "error": "Invalid key"}), 200

    # -- Device binding --------------------------------------------
    now = _now()
    binding = _BINDINGS.get(user_key)

    if binding is None:
        # First login → bind to this device, start countdown
        binding = {
            "device_id": device_id,
            "exp_epoch": now + LICENSE_SECONDS,
        }
        _BINDINGS[user_key] = binding
    elif binding["device_id"] != device_id:
        return jsonify(
            {"ok": False, "error": "Key bound to another device"}
        ), 200

    # -- Expiry ----------------------------------------------------
    remaining = binding["exp_epoch"] - now
    if remaining <= 0:
        # Expired — optionally keep or delete; app treats expired the same
        return jsonify({"ok": False, "error": "Key expired"}), 200

    # ISO timestamp (client stores it verbatim, doesn't parse it)
    expires_at = datetime.fromtimestamp(
        binding["exp_epoch"], tz=timezone.utc
    ).isoformat()

    # -- Sign + respond --------------------------------------------
    canonical = _canonical(nonce, expires_at, remaining)
    sig = _sign(canonical)

    return jsonify(
        {
            "ok": True,
            "nonce": nonce,             # echo required by client
            "expires_at": expires_at,
            "remaining_seconds": remaining,
            "sig": sig,
        }
    ), 200


# ------------------------------------------------------------------
# Health check (Render pings this)
# ------------------------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "product": PRODUCT_CODE}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
