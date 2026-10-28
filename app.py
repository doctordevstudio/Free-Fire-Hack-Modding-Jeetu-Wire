import os
import time
from datetime import datetime, timezone

from flask import Flask, request, jsonify

app = Flask(__name__)

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------
PRODUCT_CODE = os.environ.get("PRODUCT_CODE", "D11AA8C43D8AFAE9")

# One license key, hardcoded, and the single device it's bound to.
VALID_KEY    = os.environ.get("VALID_KEY", "Jhonny Sins")
# If you want to allow *any* device, leave this empty.
VALID_DEVICE = os.environ.get("VALID_DEVICE", "")   # e.g. "abcdef0123456789"

# How long the key is valid for from the first successful login.
LICENSE_SECONDS = int(os.environ.get("LICENSE_SECONDS", str(30 * 24 * 3600)))

# Server-side expiry cache (in-memory; resets on redeploy/cold start).
_EXPIRY = {}   # {user_key: exp_epoch}


def _now() -> int:
    return int(time.time())


@app.route("/keydock_connect.php", methods=["POST", "GET"])
@app.route("/",                    methods=["POST", "GET"])
def keydock_connect():
    data = request.form if request.method == "POST" else request.args

    user_key  = (data.get("user_key")  or "").strip()
    device_id = (data.get("device_id") or "").strip()
    product   = (data.get("product_code") or "").strip()

    print(f"REQ user_key={user_key!r} device_id={device_id!r} product={product!r}",
          flush=True)

    if not user_key or not device_id:
        return jsonify({"ok": False, "error": "Missing parameters"}), 200

    if product and product != PRODUCT_CODE:
        return jsonify({"ok": False, "error": "Wrong product"}), 200

    if user_key != VALID_KEY:
        return jsonify({"ok": False, "error": "Invalid key"}), 200

    if VALID_DEVICE and device_id != VALID_DEVICE:
        return jsonify({"ok": False, "error": "Key bound to another device"}), 200

    # Start countdown on first login, then stick to it.
    now = _now()
    exp = _EXPIRY.get(user_key)
    if exp is None:
        exp = now + LICENSE_SECONDS
        _EXPIRY[user_key] = exp

    remaining = exp - now
    if remaining <= 0:
        return jsonify({"ok": False, "error": "Key expired"}), 200

    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()

    # No sig, no nonce — just the data the client needs to store.
    return jsonify({
        "ok": True,
        "expires_at": expires_at,
        "remaining_seconds": remaining,
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
