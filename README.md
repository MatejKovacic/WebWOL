# WebWOL
WebWOL is a web interface to wake devices from sleep mode with Wake-on-LAN magic packets.

<img width="1143" height="741" alt="image" src="https://github.com/user-attachments/assets/02eb2547-ba91-4f79-a1eb-9932b4cc4bf7" />

## Installation

First install Flask and WakeOnLAN app. Debian/Ubuntu:
```
sudo apt install python3-flask wakeonlan
```

Then copy [webwol.py](webwol.py) script to your target directory and check configuration section:
```
DATA_FILE = os.path.expanduser('~/.webwol/webwol.txt')
USERNAME = os.getenv('APP_USERNAME', 'admin')
PASSWORD = os.getenv('APP_PASSWORD', 'changeme')
```

You can also change IP address and port of the webserver (look for `app.run(host='0.0.0.0', port=8080)` at the end of the Python script).

List of computers to wake up is in `webwol.txt` file, which is tab-delimited:
- name of the computer
- MAC address
- IP address to send the magic packet to (default subnet broadcast: `255.255.255.255`)
- port to send the magic packet to (default: `9`)


## Run
```
python3 webwol.py
```

You can also create SystemD service:

`sudo nano /etc/systemd/system/webwol.service`:

```
[Unit]
Description=WebWOL - Wake-on-LAN Web Interface
After=network.target

[Service]
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/webwol
ExecStart=/usr/bin/python3 /home/YOUR_USERNAME/webwol/webwol.py
Restart=always
Environment="APP_USERNAME=admin"
Environment="APP_PASSWORD=changeme"

[Install]
WantedBy=multi-user.target
```

Reload SystemD to recognize the new service:
```
sudo systemctl daemon-reload
```

Enable and start the service:
```
sudo systemctl enable webwol
sudo systemctl start webwol
```
