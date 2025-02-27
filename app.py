from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import json
import secrets
import string
import datetime  # For audit logging
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Required for session management

# Configuration
SALT_FILE = "salt.bin"
VALIDATION_FILE = "validation.bin"
PASSWORDS_FILE = "passwords.bin"
ITERATIONS = 100000

class PasswordManager:
    def __init__(self):
        self.key = None
        self.backend = default_backend()

    def derive_key(self, pin, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(pin.encode())

    def encrypt_data(self, data):
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_data(self, encrypted_data):
        try:
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        except Exception as e:
            print(f"Decryption error: {e}")
            return b'[]'

    def save_passwords(self, data):
        encrypted = self.encrypt_data(json.dumps(data).encode())
        with open(PASSWORDS_FILE, "wb") as f:
            f.write(encrypted)

    def load_passwords(self):
        try:
            if not os.path.exists(PASSWORDS_FILE):
                return []
            
            with open(PASSWORDS_FILE, "rb") as f:
                encrypted_data = f.read()
            
            decrypted = self.decrypt_data(encrypted_data)
            return json.loads(decrypted.decode())
        except Exception as e:
            print(f"Loading error: {e}")
            return []

pm = PasswordManager()

# Helper Functions
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    while True:
        pwd = ''.join(secrets.choice(chars) for _ in range(length))
        if (any(c.islower() for c in pwd) and 
            any(c.isupper() for c in pwd) and 
            any(c.isdigit() for c in pwd) and 
            any(c in "!@#$%^&*()" for c in pwd)):
            return pwd

# Audit Logging
def log_audit(action):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("audit.log", "a") as log_file:
        log_file.write(f"{timestamp} - {action}\n")

# Routes
@app.route("/")
def index():
    if "authenticated" not in session:
        return redirect(url_for("login"))
    
    passwords = pm.load_passwords()
    return render_template("index.html", passwords=passwords)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pin = request.form.get("pin")
        if not pin or len(pin) != 4 or not pin.isdigit():
            flash("Invalid PIN. Must be 4 digits.", "error")
            return redirect(url_for("login"))
        
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        
        pm.key = pm.derive_key(pin, salt)[:32]
        try:
            with open(VALIDATION_FILE, "rb") as f:
                if pm.decrypt_data(f.read()) == b"valid":
                    session["authenticated"] = True
                    return redirect(url_for("index"))
        except Exception:
            pass
        
        flash("Invalid PIN. Please try again.", "error")
    return render_template("login.html")

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if os.path.exists(SALT_FILE):
        return redirect(url_for("login"))
    
    if request.method == "POST":
        pin = request.form.get("pin")
        if not pin or len(pin) != 4 or not pin.isdigit():
            flash("Invalid PIN. Must be 4 digits.", "error")
            return redirect(url_for("setup"))
        
        confirm = request.form.get("confirm_pin")
        if pin != confirm:
            flash("PINs do not match.", "error")
            return redirect(url_for("setup"))
        
        salt = os.urandom(16)
        pm.key = pm.derive_key(pin, salt)[:32]
        
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        
        with open(VALIDATION_FILE, "wb") as f:
            f.write(pm.encrypt_data(b"valid"))
        
        pm.save_passwords([])
        flash("PIN setup complete! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("setup.html")

@app.route("/add", methods=["POST"])
def add_password():
    if "authenticated" not in session:
        return redirect(url_for("login"))
    
    service = request.form.get("service")
    username = request.form.get("username")
    password = request.form.get("password")
    
    if not service or not username or not password:
        flash("All fields are required.", "error")
        return redirect(url_for("index"))
    
    data = pm.load_passwords()
    data.append({
        "service": service,
        "username": username,
        "password": password
    })
    pm.save_passwords(data)
    
    # Log the action
    log_audit(f"Added password for service: {service}")
    
    flash("Password saved successfully!", "success")
    return redirect(url_for("index"))

@app.route("/generate", methods=["POST"])
def generate():
    if "authenticated" not in session:
        return redirect(url_for("login"))
    
    length = int(request.form.get("length", 16))
    password = generate_password(length)
    
    # Log the action
    log_audit("Generated a new password")
    
    return {"password": password}

@app.route("/log-reveal", methods=["POST"])
def log_reveal():
    if "authenticated" not in session:
        return redirect(url_for("login"))
    
    data = request.get_json()
    log_audit(data.get("action", "Unknown action"))
    return "", 200

@app.route("/audit-log", methods=["GET", "POST"])
def audit_log():
    if "authenticated" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        pin = request.form.get("pin")
        if not pin or len(pin) != 4 or not pin.isdigit():
            flash("Invalid PIN. Must be 4 digits.", "error")
            return redirect(url_for("audit_log"))
        
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        
        key = pm.derive_key(pin, salt)[:32]
        try:
            with open(VALIDATION_FILE, "rb") as f:
                if pm.decrypt_data(f.read()) == b"valid":
                    session["audit_access"] = True  # Set the audit access flag
                    return redirect(url_for("audit_log"))
        except Exception:
            pass
        
        flash("Invalid PIN. Please try again.", "error")
        return redirect(url_for("audit_log"))
    
    # Check if the user has access to the audit log
    if not session.get("audit_access", False):
        return render_template("audit_log_pin.html")
    
    # If access is granted, show the audit log
    try:
        with open("audit.log", "r") as log_file:
            logs = log_file.readlines()
    except FileNotFoundError:
        logs = ["No audit log entries found."]
    
    session.pop("audit_access", None)  # Clear the audit access flag
    return render_template("audit_log.html", logs=logs)
    
@app.route("/logout")
def logout():
    session.pop("authenticated", None)
    return redirect(url_for("login"))
@app.route("/delete-password", methods=["POST"])
def delete_password():
    if "authenticated" not in session:
        return jsonify({"success": False, "message": "Not authenticated."}), 401
    
    data = request.get_json()
    service = data.get("service")
    username = data.get("username")
    pin = data.get("pin")
    
    print(f"Received delete request for service: {service}, username: {username}, PIN: {pin}")  # Debug
    
    if not service or not username or not pin or len(pin) != 4 or not pin.isdigit():
        print("Invalid request data.")  # Debug
        return jsonify({"success": False, "message": "Invalid request."}), 400
    
    # Verify PIN
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    
    key = pm.derive_key(pin, salt)[:32]
    try:
        with open(VALIDATION_FILE, "rb") as f:
            if pm.decrypt_data(f.read()) != b"valid":
                print("Invalid PIN.")  # Debug
                return jsonify({"success": False, "message": "Invalid PIN."}), 401
    except Exception as e:
        print(f"PIN verification error: {e}")  # Debug
        return jsonify({"success": False, "message": "Invalid PIN."}), 401
    
    # Delete the password
    data = pm.load_passwords()
    updated_data = [entry for entry in data if entry["service"] != service or entry["username"] != username]
    
    if len(updated_data) == len(data):
        print("Password not found.")  # Debug
        return jsonify({"success": False, "message": "Password not found."}), 404
    
    pm.save_passwords(updated_data)
    
    # Log the action
    log_audit(f"Deleted password for service: {service} (username: {username})")
    
    print("Password deleted successfully.")  # Debug
    return jsonify({"success": True, "message": "Password deleted successfully."})


if __name__ == "__main__":
    app.run(debug=True)