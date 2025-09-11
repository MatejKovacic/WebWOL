#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# DEPENDENCIES:
# pip install wakeonlan flask flask-wtf werkzeug
# 
# FEATURES:
# - Default password is "changeme". After first login, password change is required.
# - Password length validation implemented (8 characters minimum), however, there are no password complexity requirements implemented.
# - Password is stored in hashed form (PBKDF2 with SHA256 with unique per-password salt).
# - Enforced strict file permissions (chmod 600) to prevent LAN read and implemented auto healing file permissions.
# - You can set/reset the password from terminal: "python3 webwol.py --set-password".
# - Login rate limiting implemented (3 failed attempts per IP, if exceeded, IP is blocked for 5 minutes).
# - Rate limiting is in-memory only - it resets when you restart the app.
# - Implemented security headers that prevent basic attacks like MIME sniffing and clickjacking and only allows scripts, styles, and images from your server.
# - HTTP-only and SameSite attributes set on session cookie.
# - CSRF protection.
# - Validation of IP and port fields when adding/editing entries.
#
# RECOMMENDATIONS:
# - Change the host from 0.0.0.0 to specific IP address. Use a firewall to restrict access.
# - Never expose this directly to the internet. Run it on an internal network behind a reverse proxy with HTTPS.

import os
import re
import sys
import time
import html
import hmac
import getpass
from collections import defaultdict
from subprocess import run
from functools import wraps
import ipaddress
from wakeonlan import send_magic_packet

from flask import Flask, request, render_template_string, redirect, url_for, session, flash
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError

from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- Configuration ----------------
DATA_FILE = os.path.expanduser("/opt/webwol/data/servers.txt")
PASSWORD_FILE = os.path.expanduser("/opt/webwol/data/password.txt")

SECRET_KEY = os.getenv("APP_SESSION_KEY", None)
if not SECRET_KEY:
    SECRET_KEY = os.urandom(32)

SESSION_TIMEOUT = 15 * 60  # 15 minutes

DATA_FILE = os.path.expanduser("/opt/webwol/data/servers.txt")
PASSWORD_FILE = os.path.expanduser("/opt/webwol/data/password.txt")

# ---------------- Enforce strict files permissions ----------------
def enforce_file_permissions():
    """Self-heal file permissions for critical files."""
    for file_path in [PASSWORD_FILE, DATA_FILE]:
        if os.path.exists(file_path):
            try:
                os.chmod(file_path, 0o600)
            except Exception as e:
                print(f"Warning: Failed to set permissions for {file_path}: {e}")

# ---------------- App ----------------
app = Flask(__name__)
# Enable CSRF protection
csrf = CSRFProtect(app)

app.secret_key = SECRET_KEY

# --- Session cookie hardening ---
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Do NOT set SESSION_COOKIE_SECURE because we do not use HTTPS

# ---------------- Password Management ----------------
def ensure_password_file():
    """Ensure password file exists with default 'changeme' and strict permissions."""
    folder = os.path.dirname(PASSWORD_FILE)
    os.makedirs(folder, exist_ok=True)
    if not os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
            f.write(generate_password_hash("changeme"))
    os.chmod(PASSWORD_FILE, 0o600)  # Owner read/write only


def load_password():
    """Load hashed password from file."""
    ensure_password_file()
    try:
        with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None


def save_password(new_password):
    """Save new hashed password to file with strict permissions."""
    folder = os.path.dirname(PASSWORD_FILE)
    os.makedirs(folder, exist_ok=True)
    with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
        f.write(generate_password_hash(new_password))
    os.chmod(PASSWORD_FILE, 0o600)


def cli_set_password():
    """CLI command to set/reset password."""
    pw1 = getpass.getpass("New password: ")
    if len(pw1) < 8:
        print("Password must be at least 8 characters long.")
        sys.exit(1)
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        sys.exit(1)
    save_password(pw1)
    print("Password updated successfully.")


# ---------------- Rate Limiting ----------------
FAILED_ATTEMPTS = defaultdict(list)
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_SECONDS = 5 * 60


def is_locked(ip):
    now = time.time()
    attempts = [t for t in FAILED_ATTEMPTS[ip] if now - t < LOCKOUT_SECONDS]
    FAILED_ATTEMPTS[ip] = attempts
    return len(attempts) >= MAX_FAILED_ATTEMPTS


def register_failed(ip):
    FAILED_ATTEMPTS[ip].append(time.time())


# ---------------- Helpers ----------------
def validate_ip(ip_str):
    ip_str = ip_str.strip()
    if not ip_str:  # treat empty as default broadcast
        return "255.255.255.255"
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return str(ip)
    except ipaddress.AddressValueError:
        return None


def ensure_data_file():
    """Ensure servers data file exists and has strict permissions."""
    folder = os.path.dirname(DATA_FILE)
    os.makedirs(folder, exist_ok=True)
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            f.write("")
    os.chmod(DATA_FILE, 0o600)


def normalize_mac(mac):
    if mac is None:
        return None
    mac = mac.strip().upper().replace("-", ":")
    if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", mac):
        return mac
    return None


def load_entries():
    ensure_data_file()
    rows = []
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                mac = parts[0].strip().upper()
                name = parts[1].strip()
                ip = parts[2].strip() if len(parts) > 2 and parts[2].strip() else "255.255.255.255"
                port = int(parts[3].strip()) if len(parts) > 3 and parts[3].strip().isdigit() else 9
                rows.append({"mac": mac, "name": name, "ip": ip, "port": port})
    except Exception as e:
        return [], f"Failed to read data file: {e}"
    return rows, None


def save_entries(rows):
    """Save entries safely and enforce strict permissions."""
    try:
        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for r in rows:
                name = r["name"].replace("\t", " ").replace("\r", " ").replace("\n", " ")
                mac = r["mac"]
                ip = r.get("ip", "255.255.255.255")
                port = str(r.get("port", 9))
                f.write(f"{mac}\t{name}\t{ip}\t{port}\n")
        os.replace(tmp, DATA_FILE)
        os.chmod(DATA_FILE, 0o600)  # Ensure strict permissions after replace
        return None
    except Exception as e:
        return f"Failed to save data: {e}"


# ---------------- Session Management ----------------
@app.before_request
def session_management():
    session.permanent = True
    app.permanent_session_lifetime = SESSION_TIMEOUT
    if "last_active" in session and time.time() - session["last_active"] > SESSION_TIMEOUT:
        session.clear()
        flash("Session timed out", "error")
        return redirect(url_for("login"))
    session["last_active"] = time.time()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return wrapper


# ---------------- Templates ----------------
BASE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
  <title>WebWoL</title>
  <style>
    body { margin:0; font-family: Arial, sans-serif; background:#111; color:#eee; }
    nav { background:#222; padding:10px 20px; display:flex; justify-content:space-between; align-items:center; }
    nav a { color:#eee; text-decoration:none; margin-left:15px; font-weight:bold; }
    nav #title { font-size:1.5em; font-weight:bold; }
    .container { max-width:900px; margin:auto; padding:20px; }
    .flash-container { min-height: 50px; margin-bottom: 15px; position:relative; }
    .flash-container .card { font-size:0.85em; padding:8px 12px; margin-bottom:6px; border-radius:8px; position:relative; }
    .card.wol { background:#113311; color:#8f8; }
    .card.error { background:#551111; color:#f88; }
    table { width:100%; border-collapse: collapse; margin-bottom:20px; }
    th, td { padding:10px; border-bottom:1px solid #444; text-align:left; }
    td.actions { text-align:right; white-space:nowrap; }
    button { border:none; padding:6px 12px; border-radius:8px; cursor:pointer; color:white; background:#444; margin-left:5px; }
    button.wake { background:#81c784; color:#111; }
    button.delete { background:#e57373; color:#111; }
    button.edit { background:#64b5f6; color:#111; }
    input[type=text], input[type=password], input[type=number] { padding:8px; border-radius:6px; border:1px solid #444; background:#111; color:#eee; }
    .searchbox { width:100%; padding:8px; margin-bottom:12px; border-radius:6px; border:1px solid #444; background:#111; color:#eee; }
    #session-timer { margin-bottom:15px; font-size:0.8em; color:#aaa; text-align:right; }
    footer { text-align:center; padding:10px; color:#888; font-size:0.85em; white-space:pre-line; }
    footer a { color:#81c784; text-decoration:none; }
    footer a:hover { text-decoration:underline; }
    /* Modal */
    #confirm-modal { display:none; position:fixed; top:0; left:0; width:100%; height:100%; 
                     background:rgba(0,0,0,0.7); align-items:center; justify-content:center; z-index:9999; }
    #confirm-modal .box { background:#222; padding:20px; border-radius:12px; width:300px; text-align:center; }
    #confirm-modal button { margin-top:10px; }
  </style>
</head>
<body>
  <nav>
    <div id="title">
      <img src="{{ url_for('static', filename='favicon.ico') }}"
           alt="Logo"
           style="width:18px; height:18px; vertical-align:middle; margin-right:2px;">
      WebWoL
    </div>
    <div>
      <a href="{{ url_for('index') }}">Home</a>
      <a href="{{ url_for('edit') }}">Edit</a>
      <a href="{{ url_for('change_password') }}">Change Password</a>
      <a href="{{ url_for('logout') }}">Logout</a>
    </div>
  </nav>

  <div class="container">
    <div id="session-timer"></div>
    <div class="flash-container">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, msg in messages %}
            <div class="card {{ category }}">{{ msg }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
    </div>

    {{ content|safe }}
  </div>

  <footer>
    <a href="https://github.com/MatejKovacic/WebWOL/" target="_blank">WebWOL</a> - web interface to wake devices from sleep mode with Wake-on-LAN magic packets.
    Auto logout after 15 minutes. MAC format: AA:BB:CC:DD:EE:FF
    (GPL) <a href="https://telefoncek.si" target="_blank">Matej Kovačič</a>, 2025.
  </footer>

  <!-- Confirmation Modal -->
  <div id="confirm-modal">
    <div class="box">
      <p id="confirm-message">Are you sure?</p>
      <div style="margin-top:15px;">
        <button id="confirm-yes" style="background:#e57373; color:#111; margin-right:10px;">Yes</button>
        <button id="confirm-no" style="background:#64b5f6; color:#111;">No</button>
      </div>
    </div>
  </div>

  <script>
    document.addEventListener("DOMContentLoaded", function() {
      // --- Search filter ---
      const search = document.getElementById("search");
      if (search) {
        search.addEventListener("keyup", function() {
          const filter = search.value.toLowerCase();
          document.querySelectorAll("table tr").forEach((row, idx) => {
            if (idx === 0) return;
            row.style.display = row.innerText.toLowerCase().includes(filter) ? "" : "none";
          });
        });
      }

      // --- Session countdown ---
      const timerEl = document.getElementById("session-timer");
      {% if timeout %}
        let remaining = {{ timeout }};
        function updateTimer() {
            let m = Math.floor(remaining/60);
            let s = remaining % 60;
            timerEl.textContent = "Auto logout in " + m + "m " + s + "s";
            if (remaining <= 60) {
                timerEl.style.color = "red";
                timerEl.style.fontWeight = "bold";
            } else {
               timerEl.style.color = "#aaa";
               timerEl.style.fontWeight = "normal";
          }
           if (remaining > 0) {
             remaining--;
            setTimeout(updateTimer, 1000);
          } else {
            window.location.href = "{{ url_for('logout') }}";
          }
        }
        updateTimer();
      {% endif %}

      // --- Flash auto-fade ---
      const flashes = document.querySelectorAll(".flash-container .card");
      if (flashes.length > 0) {
        setTimeout(() => {
          flashes.forEach(f => {
            f.style.transition = "opacity 1s";
            f.style.opacity = "0";
            setTimeout(() => f.remove(), 1000);
          });
        }, 4000);
      }

      // --- Delete confirmation modal ---
      const modal = document.getElementById("confirm-modal");
      const msg = document.getElementById("confirm-message");
      const yes = document.getElementById("confirm-yes");
      const no = document.getElementById("confirm-no");
      let currentForm = null;

      document.querySelectorAll("button.delete").forEach(btn => {
        btn.addEventListener("click", function(e) {
          e.preventDefault();
          currentForm = btn.closest("form");
          const name = btn.getAttribute("data-name");
          const mac = btn.getAttribute("data-mac");
          msg.textContent = `Delete ${name} (${mac})?`;
          modal.style.display = "flex";
        });
      });

      yes.addEventListener("click", function() {
        if (currentForm) {
          // Remove previous delete action input if exists
          const old = currentForm.querySelector("input[name='action'][value='delete']");
          if (old) old.remove();

          // Append delete action
          let hidden = document.createElement("input");
          hidden.type = "hidden";
          hidden.name = "action";
          hidden.value = "delete";
          currentForm.appendChild(hidden);
          currentForm.submit();
        }
        modal.style.display = "none";
      });

      no.addEventListener("click", function() {
        modal.style.display = "none";
        currentForm = null;
      });
    });
  </script>
</body>
</html>"""


LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <link rel="icon" href="{{ url_for('static', filename='favicon.ico') }}">
  <title>WebWoL - Sign in</title>
  <style>
    body { background:#111; color:#eee; font-family:Arial,sans-serif; margin:0; }
    .login-wrap { display:flex; align-items:center; justify-content:center; min-height:100vh; }
    .login-card { width:320px; background:#222; padding:20px; border-radius:12px; box-shadow:0 6px 18px rgba(0,0,0,0.5); }
    .login-card form { display:flex; flex-direction:column; gap:10px; }
    h4 { text-align:center; margin:0 0 10px 0; color:#eee; }
    input, button { padding:10px; border-radius:8px; border:1px solid #444; background:#111; color:#eee; width:100%; box-sizing:border-box; }
    button { border:none; background:#444; font-weight:bold; cursor:pointer; }
    .card { background:#e57373; color:#111; padding:10px; border-radius:8px; margin-bottom:10px; font-size:0.85em; }
  </style>
</head>
<body>
  <div class="login-wrap">
    <div class="login-card">
      <h4>WebWoL - Sign in</h4>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, msg in messages %}
            <div class="card {{ category }}">{{ msg }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="password" name="password" placeholder="Password" required autofocus>
        <button type="submit">Login</button>
      </form>
    </div>
  </div>
</body>
</html>"""

# ---------------- Routes ----------------
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("CSRF token missing or invalid. Please try again.", "error")
    return redirect(request.referrer or url_for("index"))

# ---------------- Routes with CSRF ----------------
from flask_wtf.csrf import generate_csrf, CSRFError

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("CSRF token missing or invalid. Please try again.", "error")
    return redirect(request.referrer or url_for("index"))

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr

    if is_locked(ip):
        flash("Too many failed login attempts. Try again in 5 minutes.", "error")
        return render_template_string(LOGIN_HTML, csrf_token=generate_csrf())

    if request.method == "POST":
        password = request.form.get("password", "").strip()
        stored_hash = load_password()

        if stored_hash and check_password_hash(stored_hash, password):
            session.clear()
            session.permanent = True
            app.permanent_session_lifetime = SESSION_TIMEOUT
            session["logged_in"] = True
            session["last_active"] = time.time()

            if check_password_hash(stored_hash, "changeme"):
                flash("Default password must be changed.", "error")
                return redirect(url_for("change_password"))

            return redirect(url_for("index"))
        else:
            register_failed(ip)
            flash("Invalid password", "error")

    return render_template_string(LOGIN_HTML, csrf_token=generate_csrf())


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    rows, err = load_entries()
    if err:
        content = f"<div class='card error'>{html.escape(err)}</div>"
        return render_template_string(BASE_HTML, content=content, timeout=SESSION_TIMEOUT)

    csrf_token = generate_csrf()
    content = "<h4>Computers</h4>"
    content += "<input id='search' class='searchbox' placeholder='Search by name, MAC, IP or port...'>"
    content += "<table><tr><th>Name</th><th>MAC</th><th>IP</th><th>Port</th><th>Action</th></tr>"
    for r in rows:
        content += (
            f"<tr><td>{html.escape(r['name'])}</td>"
            f"<td>{html.escape(r['mac'])}</td>"
            f"<td>{html.escape(r['ip'])}</td>"
            f"<td>{r['port']}</td>"
            f"<td class='actions'>"
            f"<form method='post' action='{url_for('wake')}' style='display:inline;'>"
            f"<input type='hidden' name='csrf_token' value='{csrf_token}'>"
            f"<button class='wake' name='mac' value='{html.escape(r['mac'])}' type='submit'>Wake</button>"
            f"</form></td></tr>"
        )
    content += "</table>"
    return render_template_string(BASE_HTML, content=content, timeout=SESSION_TIMEOUT)


@app.route("/wake", methods=["POST"])
@login_required
def wake():
    mac = normalize_mac(request.form.get("mac", ""))
    rows, _ = load_entries()
    entry = next((r for r in rows if r["mac"] == mac), None)

    if mac and entry:
        try:
            send_magic_packet(mac, ip_address=entry.get("ip"), port=entry.get("port"))
            flash(f"Sent WOL to {entry['name']} ({mac})", "wol")
        except Exception as e:
            flash(f"Failed to send WOL: {e}", "error")
    else:
        flash("Invalid MAC", "error")

    return redirect(url_for("index"))


from flask_wtf.csrf import generate_csrf, validate_csrf

@app.route("/edit", methods=["GET", "POST"])
@login_required
def edit():
    rows, err = load_entries()
    if err:
        content = f"<div class='card error'>{html.escape(err)}</div>"
        return render_template_string(
            BASE_HTML,
            content=content,
            timeout=SESSION_TIMEOUT,
            csrf_token=generate_csrf()
        )

    if request.method == "POST":
        try:
            validate_csrf(request.form.get("csrf_token"))
        except Exception:
            flash("Invalid CSRF token", "error")
            return redirect(url_for("edit"))

        action = request.form.get("action")
        idx = int(request.form.get("idx", "-1"))

        # --- ADD ---
        if action == "add":
            name = request.form.get("name", "").strip()
            mac = normalize_mac(request.form.get("mac", ""))
            ip = validate_ip(request.form.get("ip", "255.255.255.255"))
            port = request.form.get("port", "9").strip()

            if not name or not mac:
                flash("Name and valid MAC required", "error")
            elif ip is None:
                flash("Invalid IP address", "error")
            else:
                try:
                    port = int(port)
                except:
                    port = 9
                rows.append({"name": name, "mac": mac, "ip": ip, "port": port})
                err = save_entries(rows)
                flash(err if err else f"Added {name} ({mac})", "error" if err else "wol")

        # --- UPDATE ---
        elif action == "update" and 0 <= idx < len(rows):
            name = request.form.get("name", "").strip()
            mac = normalize_mac(request.form.get("mac", ""))
            ip = validate_ip(request.form.get("ip", "255.255.255.255"))
            port = request.form.get("port", "9").strip()

            if not name or not mac:
                flash("Name and valid MAC required", "error")
            elif ip is None:
                flash("Invalid IP address", "error")
            else:
                try:
                    port = int(port)
                except:
                    port = 9
                rows[idx] = {"name": name, "mac": mac, "ip": ip, "port": port}
                err = save_entries(rows)
                flash(err if err else f"Updated {name} ({mac})", "error" if err else "wol")

        # --- DELETE ---
        elif action == "delete" and 0 <= idx < len(rows):
            name, mac = rows[idx]["name"], rows[idx]["mac"]
            del rows[idx]
            err = save_entries(rows)
            flash(err if err else f"Deleted {name} ({mac})", "error" if err else "wol")

        return redirect(url_for("edit"))

    # --- BUILD PAGE CONTENT ---
    content = "<h4>Edit Computers</h4>"

    # Add new entry form
    content += (
        "<form method='post' style='margin-bottom:15px;'>"
        f"<input type='hidden' name='csrf_token' value='{generate_csrf()}'>"
        "<input type='hidden' name='action' value='add'>"
        "<input type='text' name='name' placeholder='Name' required> "
        "<input type='text' name='mac' placeholder='MAC (AA:BB:CC:DD:EE:FF)' required> "
        "<input type='text' name='ip' placeholder='IP (default broadcast)'> "
        "<input type='number' name='port' placeholder='Port (default 9)' min='1' max='65535'> "
        "<button type='submit'>Add</button>"
        "</form>"
    )

    # Existing entries table (tight layout restored)
    content += "<table><tr><th>Name</th><th>MAC</th><th>IP</th><th>Port</th><th>Action</th></tr>"

    for idx, r in enumerate(rows):
        content += (
            f"<tr>"
            f"<td><input type='text' name='name' value='{html.escape(r['name'])}' form='form-{idx}' required></td>"
            f"<td><input type='text' name='mac' value='{html.escape(r['mac'])}' form='form-{idx}' required></td>"
            f"<td><input type='text' name='ip' value='{html.escape(r['ip'])}' form='form-{idx}'></td>"
            f"<td><input type='number' name='port' value='{r['port']}' min='1' max='65535' form='form-{idx}'></td>"
            f"<td class='actions'>"
            f"<form id='form-{idx}' method='post' style='display:inline;'>"
            f"<input type='hidden' name='csrf_token' value='{generate_csrf()}'>"
            f"<input type='hidden' name='idx' value='{idx}'>"
            f"<button class='edit' name='action' value='update'>Save</button> "
            f"<button type='button' class='delete' data-name='{html.escape(r['name'])}' data-mac='{html.escape(r['mac'])}'>Delete</button>"
            f"</form>"
            f"</td>"
            f"</tr>"
        )
    content += "</table>"

    return render_template_string(
        BASE_HTML,
        content=content,
        timeout=SESSION_TIMEOUT,
        csrf_token=generate_csrf()
    )


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old = request.form.get("old_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        stored_hash = load_password()

        if not check_password_hash(stored_hash, old):
            flash("Old password incorrect", "error")
        elif new != confirm:
            flash("Passwords do not match", "error")
        elif len(new) < 8:
            flash("Password must be at least 8 characters long", "error")
        else:
            save_password(new)
            flash("Password updated successfully", "wol")
            return redirect(url_for("index"))

    content = (
        "<h4 style='text-align:center;'>Change Password</h4>"
        "<form method='post' style='width:320px; margin:auto; display:flex; flex-direction:column; gap:10px;'>"
        f"<input type='hidden' name='csrf_token' value='{generate_csrf()}'>"
        "<input type='password' name='old_password' placeholder='Old Password' required>"
        "<input type='password' name='new_password' placeholder='New Password' required>"
        "<input type='password' name='confirm_password' placeholder='Confirm New Password' required>"
        "<button type='submit'>Change</button>"
        "</form>"
    )
    return render_template_string(BASE_HTML, content=content, timeout=SESSION_TIMEOUT, csrf_token=generate_csrf())


@app.after_request
def add_security_headers(resp):
    # Prevent MIME type sniffing
    resp.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    resp.headers["X-Frame-Options"] = "DENY"
    # Referrer policy
    resp.headers["Referrer-Policy"] = "no-referrer"
    # Basic Content Security Policy for LAN without HTTPS
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:"
    )
    return resp


# ---------------- Main ----------------
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--set-password":
        cli_set_password()
        sys.exit(0)

    # --- Ensure files exist and enforce strict permissions ---
    ensure_password_file()
    ensure_data_file()
    enforce_file_permissions()

    app.run(host="0.0.0.0", port=8080)

