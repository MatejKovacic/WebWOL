#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# INSTRUCTIONS:
# sudo apt install python3-flask wakeonlan
# Check "Configuration" below

import os
import re
import time
import hmac
import html
from flask import Flask, request, render_template_string, redirect, url_for, session, flash
from subprocess import run
from functools import wraps

# ---------------- Configuration ----------------
DATA_FILE = os.path.expanduser('~/.webwol/webwol.txt')
USERNAME = os.getenv('APP_USERNAME', 'admin')
PASSWORD = os.getenv('APP_PASSWORD', 'changeme')
SECRET_KEY = os.getenv('APP_SESSION_KEY', None)
if not SECRET_KEY:
    SECRET_KEY = os.urandom(32)
SESSION_TIMEOUT = 15 * 60  # 20 minutes
WOL_CMD = os.getenv('APP_WOL_CMD', 'wakeonlan')

# ---------------- App ----------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------------- Helpers ----------------
def ensure_data_file():
    folder = os.path.dirname(DATA_FILE)
    if not os.path.exists(folder):
        try:
            os.makedirs(folder, exist_ok=True)
        except Exception as e:
            return f"Cannot create folder {folder}: {e}"
    if not os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'w', encoding='utf-8') as f:
                f.write('')
        except Exception as e:
            return f"Cannot create {DATA_FILE}: {e}"
    return None

def normalize_mac(mac):
    if mac is None:
        return None
    mac = mac.strip().upper().replace('-', ':')
    if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
        return mac
    return None

def load_entries():
    err = ensure_data_file()
    if err:
        return [], err
    rows = []
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                mac = parts[0].strip().upper()
                name = parts[1].strip()
                ip = parts[2].strip() if len(parts) > 2 else '255.255.255.255'
                port = int(parts[3].strip()) if len(parts) > 3 and parts[3].strip().isdigit() else 9
                rows.append({'mac': mac, 'name': name, 'ip': ip, 'port': port})
    except Exception as e:
        return [], f"Failed to read data file: {e}"
    return rows, None

def save_entries(rows):
    try:
        tmp = DATA_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            for r in rows:
                name = r['name'].replace('\t',' ').replace('\r',' ').replace('\n',' ')
                mac = r['mac']
                ip = r.get('ip','255.255.255.255')
                port = str(r.get('port',9))
                f.write(f"{mac}\t{name}\t{ip}\t{port}\n")
        os.replace(tmp, DATA_FILE)
        return None
    except Exception as e:
        return f"Failed to save data: {e}"

# ---------------- Session Management ----------------
@app.before_request
def session_management():
    session.permanent = True
    app.permanent_session_lifetime = SESSION_TIMEOUT
    if 'last_active' in session and time.time() - session['last_active'] > SESSION_TIMEOUT:
        session.clear()
        flash("Session timed out", "error")
        return redirect(url_for('login'))
    session['last_active'] = time.time()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

# ---------------- Templates ----------------
BASE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>WebWOL</title>
<style>
body { margin:0; font-family: Arial, sans-serif; background:#111; color:#eee; }
nav { background:#222; padding:10px 20px; display:flex; justify-content:space-between; align-items:center; }
nav a { color:#eee; text-decoration:none; margin-left:15px; font-weight:bold; }
nav #title { font-size:1.5em; font-weight:bold; }
.container { max-width:900px; margin:auto; padding:20px; }
.flash-container { min-height: 50px; margin-bottom: 15px; position:relative; }
.flash-container .card { font-size:0.85em; padding:8px 12px; margin-bottom:6px; border-radius:8px; position:relative; }
.card.wol { background:#331111; color:#f88; }
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
@media(max-width:600px){
    td.actions { display:flex; gap:5px; justify-content:flex-start; margin-top:5px; }
    table, th, td { display:block; }
    th { display:none; }
    td { border:none; padding:5px 0; }
}
</style>
</head>
<body>
<nav>
  <div id="title">WebWOL</div>
  <div>
    <a href="{{ url_for('index') }}">Home</a>
    <a href="{{ url_for('edit') }}">Edit</a>
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
WebWOL - web interface to wake devices from sleep mode with Wake-on-LAN magic packets.
Auto logout after 15 minutes. MAC format: AA:BB:CC:DD:EE:FF
(GPL) Matej Kovačič, 2025
</footer>
<script>
const logoutTime = Date.now() + {{ timeout * 1000 }};
function updateTimer() {
    const remainingMs = logoutTime - Date.now();
    if (remainingMs <= 0) {
        window.location.href = "{{ url_for('logout') }}";
        return;
    }
    const remaining = Math.floor(remainingMs / 1000);
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    const timerEl = document.getElementById("session-timer");
    timerEl.textContent = "You will be logged out in " +
        minutes.toString().padStart(2,'0') + ":" +
        seconds.toString().padStart(2,'0');
    timerEl.style.color = remaining < 60 ? "red" : "#aaa";
}
setInterval(updateTimer, 1000);
updateTimer();
</script>
</body>
</html>
"""

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>WebWOL - Sign in</title>
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
    <h4>WebWOL - Sign in</h4>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}{% for category, msg in messages %}<div class="card {{ category }}">{{ msg }}</div>{% endfor %}{% endif %}
    {% endwith %}
    <form method="post">
      <input type="text" name="username" placeholder="Username" required autofocus>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Login</button>
    </form>
  </div>
</div>
</body>
</html>
"""

# ---------------- Routes ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if hmac.compare_digest(u, USERNAME) and hmac.compare_digest(p, PASSWORD):
            session['logged_in'] = True
            session['last_active'] = time.time()
            return redirect(url_for('index'))
        flash("Invalid username or password", "error")
    return render_template_string(LOGIN_HTML)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    rows, err = load_entries()
    if err:
        content = f"<div class='card error'>{html.escape(err)}</div>"
        return render_template_string(BASE_HTML, content=content, timeout=SESSION_TIMEOUT)
    content = "<h4>Computers</h4>"
    content += "<input id='search' class='searchbox' placeholder='Search by name, MAC, IP or port...'>"
    content += "<table><tr><th>Name</th><th>MAC</th><th>IP</th><th>Port</th><th>Action</th></tr>"
    for r in rows:
        content += (
            f"<tr><td>{html.escape(r['name'])}</td>"
            f"<td>{html.escape(r['mac'])}</td>"
            f"<td>{html.escape(r['ip'])}</td>"
            f"<td>{r['port']}</td>"
            f"<td class='actions'><form method='post' action='{url_for('wake')}' style='display:inline;'>"
            f"<button class='wake' name='mac' value='{html.escape(r['mac'])}' type='submit'>Wake</button></form></td></tr>"
        )
    content += "</table>"
    return render_template_string(BASE_HTML, content=content, timeout=SESSION_TIMEOUT)

@app.route('/wake', methods=['POST'])
@login_required
def wake():
    mac = normalize_mac(request.form.get('mac',''))
    rows,_ = load_entries()
    entry = next((r for r in rows if r['mac']==mac), None)
    if mac and entry:
        try:
            cmd = [WOL_CMD]
            if entry.get('ip'):
                cmd += ['-i', entry['ip']]
            if entry.get('port'):
                cmd += ['-p', str(entry['port'])]
            cmd.append(mac)
            run(cmd)
            flash(f"Sent WOL to {entry['name']} ({mac})", "wol")
        except Exception as e:
            flash(f"Failed to send WOL: {e}", "error")
    else:
        flash("Invalid MAC", "error")
    return redirect(url_for('index'))

@app.route('/edit', methods=['GET','POST'])
@login_required
def edit():
    rows, err = load_entries()
    if err:
        content = f"<div class='card error'>{html.escape(err)}</div>"
        return render_template_string(BASE_HTML, content=content, timeout=SESSION_TIMEOUT)
    if request.method == 'POST':
        action = request.form.get('action')
        if action=='add':
            name = request.form.get('name','').strip()
            mac = normalize_mac(request.form.get('mac',''))
            ip = request.form.get('ip','255.255.255.255').strip()
            port = request.form.get('port','9').strip()
            try: port = int(port)
            except: port = 9
            if name and mac:
                rows.append({'name':name,'mac':mac,'ip':ip,'port':port})
                save_err = save_entries(rows)
                flash(save_err if save_err else "Entry added", "wol" if not save_err else "error")
            else: flash("Invalid name or MAC","error")
        elif action=='update':
            try:
                idx = int(request.form.get('idx','-1'))
                name = request.form.get('name','').strip()
                mac = normalize_mac(request.form.get('mac',''))
                ip = request.form.get('ip','255.255.255.255').strip()
                port = request.form.get('port','9').strip()
                try: port = int(port)
                except: port = 9
                if 0<=idx<len(rows) and name and mac:
                    rows[idx].update({'name':name,'mac':mac,'ip':ip,'port':port})
                    save_err = save_entries(rows)
                    flash(save_err if save_err else "Entry updated","wol" if not save_err else "error")
                else: flash("Invalid entry","error")
            except: flash("Error updating entry","error")
        elif action=='delete':
            try:
                idx = int(request.form.get('idx','-1'))
                if 0<=idx<len(rows):
                    del rows[idx]
                    save_err = save_entries(rows)
                    flash(save_err if save_err else "Entry deleted","wol" if not save_err else "error")
                else: flash("Invalid entry","error")
            except: flash("Error deleting entry","error")
        return redirect(url_for('edit'))

    content = "<h4>Edit Entries</h4><h5>Add Entry</h5>"
    content += ("<form method='post' style='margin-bottom:20px;'>"
                "<input type='hidden' name='action' value='add'>"
                "<input type='text' name='name' placeholder='Name' required> "
                "<input type='text' name='mac' placeholder='MAC AA:BB:CC:DD:EE:FF' required pattern='^([0-9A-Fa-f]{2}[:\\-]){5}([0-9A-Fa-f]{2})$'> "
                "<input type='text' name='ip' placeholder='Broadcast IP (default 255.255.255.255)'> "
                "<input type='number' name='port' placeholder='Port (default 9)' min='1' max='65535'> "
                "<button type='submit'>Add</button></form>")
    content += "<table><tr><th>Name</th><th>MAC</th><th>IP</th><th>Port</th><th>Actions</th></tr>"
    for idx,r in enumerate(rows):
        content += (f"<tr><form method='post'>"
                    f"<td><input type='text' name='name' value='{html.escape(r['name'])}' required></td>"
                    f"<td><input type='text' name='mac' value='{html.escape(r['mac'])}' required></td>"
                    f"<td><input type='text' name='ip' value='{html.escape(r.get('ip','255.255.255.255'))}'></td>"
                    f"<td><input type='number' name='port' value='{r.get('port',9)}' min='1' max='65535'></td>"
                    f"<td class='actions'><input type='hidden' name='idx' value='{idx}'>"
                    f"<button class='edit' type='submit' name='action' value='update'>Save</button>"
                    f"<button class='delete' type='submit' name='action' value='delete' onclick=\"return confirm('Are you sure you want to delete this entry?');\">Delete</button>"
                    "</td></form></tr>")
    content += "</table>"
    return render_template_string(BASE_HTML, content=content, timeout=SESSION_TIMEOUT)

# ---------------- Main ----------------
if __name__=='__main__':
    app.run(host='0.0.0.0', port=8080)
