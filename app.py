import os
import io
import json
import base64
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
ALLOWED_EXT = set()  # allow any file type

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB limit
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-please-change")

# Utility functions
def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    """Derive a 32-byte key from password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(plaintext: bytes, password: str):
    """Encrypt bytes with AES-GCM using a key derived from password."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    iv = os.urandom(12)  # 96-bit IV recommended for GCM
    ciphertext = aesgcm.encrypt(iv, plaintext, associated_data=None)  # tag is appended
    # Return components base64-encoded for JSON-friendly storage
    return {
        "salt_b64": base64.b64encode(salt).decode("utf-8"),
        "iv_b64": base64.b64encode(iv).decode("utf-8"),
        "cipher_b64": base64.b64encode(ciphertext).decode("utf-8")
    }

def decrypt_bytes(cipher_b64: str, password: str, salt_b64: str, iv_b64: str):
    salt = base64.b64decode(salt_b64)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(cipher_b64)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, associated_data=None)
    return plaintext

# Routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    """
    Form fields:
      - file (file upload)
      - password (string)
      - replace_notice (optional checkbox)  # not used here but present for UI compatibility
    Returns: zip/download of .enc and .meta.json via links on page
    """
    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    if not uploaded or not password:
        flash("Please provide a file and password.", "error")
        return redirect(url_for("index"))

    filename = secure_filename(uploaded.filename) or "uploaded_file"
    original_bytes = uploaded.read()
    # encrypt
    enc = encrypt_bytes(original_bytes, password)
    # save encrypted file
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    enc_name = f"{filename}.enc"
    meta_name = f"{enc_name}.meta.json"
    enc_path = UPLOAD_DIR / f"{ts}__{enc_name}"
    meta_path = UPLOAD_DIR / f"{ts}__{meta_name}"

    # write ciphertext as raw bytes (decoded from base64)
    with open(enc_path, "wb") as f:
        f.write(base64.b64decode(enc["cipher_b64"]))

    meta = {
        "original_name": filename,
        "timestamp": ts,
        "salt_b64": enc["salt_b64"],
        "iv_b64": enc["iv_b64"],
        "cipher_filename": enc_path.name,
        "note": "AES-GCM; PBKDF2-HMAC-SHA256; iterations=200000"
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    flash("File encrypted successfully. Download links below.", "success")
    return render_template("index.html",
                           encrypted=True,
                           enc_file=enc_path.name,
                           meta_file=meta_path.name)

@app.route("/download/<fname>")
def download_file(fname):
    # Only allow files inside uploads directory
    fpath = UPLOAD_DIR / fname
    if not fpath.exists():
        flash("File not found.", "error")
        return redirect(url_for("index"))
    return send_file(str(fpath), as_attachment=True, download_name=fname)

@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    """
    Form fields:
      - enc_file (file upload)  -- the .enc binary
      - meta_file (file upload) -- the JSON metadata
      - password (string)
    """
    enc_file = request.files.get("enc_file")
    meta_file = request.files.get("meta_file")
    password = request.form.get("password_decrypt", "")

    if not enc_file or not meta_file or not password:
        flash("Please provide encrypted file, metadata, and password.", "error")
        return redirect(url_for("index"))

    try:
        meta = json.load(meta_file)
        # read ciphertext bytes
        cipher_bytes = enc_file.read()
        cipher_b64 = base64.b64encode(cipher_bytes).decode("utf-8")
        # decrypt
        plaintext = decrypt_bytes(cipher_b64, password, meta["salt_b64"], meta["iv_b64"])
    except Exception as e:
        app.logger.exception("Decryption failed")
        flash("Decryption failed. Wrong password or corrupted files.", "error")
        return redirect(url_for("index"))

    # save decrypted file for download
    original_name = meta.get("original_name", "decrypted_file")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"decrypted_{ts}__{original_name}"
    out_path = UPLOAD_DIR / out_name
    with open(out_path, "wb") as f:
        f.write(plaintext)

    flash("Decryption successful. Download the restored file below.", "success")
    return render_template("index.html",
                           decrypted=True,
                           decrypted_file=out_path.name)

# Simple listing route (optional) to show available uploads - helpful during dev
@app.route("/files")
def files():
    items = sorted([p.name for p in UPLOAD_DIR.iterdir()], reverse=True)
    return render_template("files.html", files=items)

if __name__ == "__main__":
    # run in debug on localhost
    app.run(host="127.0.0.1", port=5000, debug=True)
