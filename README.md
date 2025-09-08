# WebWoL
WebWoL is a web interface to wake devices from sleep mode with Wake-on-LAN magic packets. It is written in Python 3.

<img width="1282" height="786" alt="03_main_screen" src="https://github.com/user-attachments/assets/23b91058-8475-4c81-8a4f-f9dd6a8723ab" />

## Features
- After the first login, password change is required (default password is `changeme`).
- Password length validation implemented (8 characters minimum).
- Password is stored in hashed form (PBKDF2 with SHA256 with unique per-password salt).
- You can set/reset the password from terminal (with `--set-password` parameter).
- Login rate limiting implemented (3 failed attempts per IP, if exceeded, IP is blocked for 5 minutes).
- Rate limiting is in-memory only - it resets when you restart the app.
- Implemented security headers that prevent basic attacks like MIME sniffing and clickjacking and only allows scripts, styles, and images from your server.
- Validation of IP and port fields when adding/editing entries.

<img width="1279" height="786" alt="01_first_login" src="https://github.com/user-attachments/assets/08d1d0fd-3a8e-4b90-8175-67d2c88a819c" />

<img width="1280" height="786" alt="02_add_servers" src="https://github.com/user-attachments/assets/186b5784-2349-4aa0-aabf-2d39f471a337" />

<img width="1282" height="786" alt="04_change_password" src="https://github.com/user-attachments/assets/48a66224-71ac-4c51-be33-f18ea8c6a906" />

## Installation

Create system user, with no login shell and only this user can read and write data into the app folder (`/opt/webwol`):
```
sudo adduser --system --group --home /opt/webwol webwol
sudo mkdir -p /opt/webwol
sudo chown -R webwol:webwol /opt/webwol
sudo mkdir -p /opt/webwol/data
sudo chown -R webwol:webwol /opt/webwol/data
sudo chmod 700 /opt/webwol/data
```

Create virtual Python environment:
```
apt install python3.12-venv
sudo -u webwol python3 -m venv /opt/webwol/venv
sudo -u webwol /opt/webwol/venv/bin/pip install wakeonlan flask flask-wtf werkzeug
```

Copy script content into `/opt/webwol/webwol.py`
```
sudo scp webwol.py /opt/webwol/
sudo chown -R webwol:webwol /opt/webwol/webwol.py
```

Create SystemD service to run WebWoL:
```
sudo nano /etc/systemd/system/webwol.service
```

Content:
```
[Unit]
Description=WebWOL - Wake-on-LAN Web Interface
After=network.target

[Service]
User=webwol
Group=webwol
WorkingDirectory=/opt/webwol
ExecStart=/opt/webwol/venv/bin/python /opt/webwol/webwol.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Activate the service:
```
sudo systemctl daemon-reload
sudo systemctl enable webwol
sudo systemctl start webwol
sudo systemctl status webwol
```

## Notes

Data are stored in `/opt/webwol/data/` (if you want to backup them):
- `password.txt` (PBKDF2 with SHA256 with unique per-password salt)
- `servers.txt` (tab delimited file containing MAC address, name of the server, broadcast IP address (default is 255.255.255.255), port (default is 9)

Set forgotten password from command line:
```
sudo -u webwol /opt/webwol/venv/bin/python /opt/webwol/webwol.py --set-password
```

Since rate limiting is in-memory only, you can restart app to reset it:
```
sudo systemctl restart webwol
```

## To do
- CSRF protection
