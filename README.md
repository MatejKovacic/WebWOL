# WebWoL
WebWoL is a web interface to wake devices from sleep mode with Wake-on-LAN magic packets. It is written in Python.

## What is it?

Suppose you have several computers in your office and you need to access them remotely. But some of them are powered off.

So what would you do? Should you go to the office physically? Or call someone in the middle of the night to turn computers on? Not really feasible, is it?

**Well, there is a solution.** You can wake them remotely. **Wake-on-LAN** is a computer networking standard that allows a computer to be turned on or awakened from sleep mode by a special network message. Technically it works by sending a special broadcast Ethernet frame, which is called the *Magic Packet*.

When computer is "off" (technically it should be in so called *ACPI S5 state* (also known as *Soft Off*), which means that computer is in the shutdown state, but maintains a minimal power supply including power supply to the network card), network card stays partially awake, just enough to listen for this special Ethernet frame. When network card receives this "Magic Packet", it signals the motherboard’s power management controller that computer should wake (the same way as pressing the power button). And computer powers on.

<img width="1148" height="632" alt="Main screen" src="https://github.com/user-attachments/assets/1464214b-17a0-4a93-9e34-694613d78e64" />

There are some requirements, though:
- BIOS/UEFI must allow network card standby power (check your BIOS/UEFI settings and enable `Wake on LAN` or `Power On by PCI-E`).
- Network card must support and be configured for Wake-on-LAN (check your operating system how to do that!).
- Magic Packet must reach the network card, which means the machine sending WoL packets and the machine you are trying to wake must be o the same subnet and broadcast network messages should not be blocked by network router or switch).

Also please note that WoL does not work over WiFi (except if a device has support for Wake-on-Wireless LAN (WoWLAN), which is rare) and that this application is designed to sent Magic Packets over IPv4 networks only.

You can install this application on a small device (for instance RaspberryPi), which is accessible remotely (via VPN), and then you can wake your computers remotely - with a single click.

## Features
- After the first login, password change is required (default password is `changeme`).
- Password length validation implemented (8 characters minimum).
- Password is stored in hashed form (PBKDF2 with SHA256 with unique per-password salt).
- You can set/reset the password from terminal (with `--set-password` parameter).
- Login rate limiting implemented (3 failed attempts per IP, if exceeded, IP is blocked for 5 minutes).
- Rate limiting is in-memory only - it resets when you restart the app.
- Implemented security headers that prevent basic attacks like MIME sniffing and clickjacking and only allows scripts, styles, and images from your server.
- Implemented CSRF protection.
- Validation of IP and port fields when adding/editing entries.

<img width="1148" height="632" alt="First login" src="https://github.com/user-attachments/assets/2bdf4d7c-3ca5-4af2-9df1-ae4ef78c9c42" />

<img width="1148" height="632" alt="Adding computers" src="https://github.com/user-attachments/assets/b84e92eb-6994-425b-b348-41f482d37d2b" />

<img width="1148" height="632" alt="Change password" src="https://github.com/user-attachments/assets/58d26736-c8c3-4c1d-8946-fca1f9163b17" />

## Installation (on Linux systems)

Create system user, with no login shell, and only this user can read and write data into the app folder (`/opt/webwol`):
```
sudo adduser --system --group --home /opt/webwol webwol
sudo mkdir -p /opt/webwol
sudo chown -R webwol:webwol /opt/webwol
sudo mkdir -p /opt/webwol/data
sudo chown -R webwol:webwol /opt/webwol/data
sudo chmod 700 /opt/webwol/data
```

Next create virtual Python environment.

On Debian/Ubuntu systems, you need to install the `python3-venv` package first:
```
sudo apt install python3.12-venv
```
On Raspbian:
```
sudo apt-get install python3-venv
```

Then:
```
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

### How to enable WoL on Linux systems?

First, Wake-On-LAN must be enabled in BIOS.

Then check if your network card supports WoL with command `sudo ethtool enp6s0` (if your network card is `enp6s0`). You should see something like:
```
...
	Supports Wake-on: pumbg
	Wake-on: g
...
```

Meaning of the flags:
- p: PHY activity (wake when link changes)
- u: unicast packets
- m: multicast packets
- b: broadcast packets
- g: Magic Packet

If `Wake-on:` is not `g`, you can enable it with command `sudo ethtool -s enp1s0 wol g` (if your network card is `enp6s0`). Since these changes are not persistent during reboot, it is recommended to write SystemD service to enable Magic Packet support at reboot:

`sudo nano /etc/systemd/system/wol.service`:

Content:

```
[Unit]
Description=Enable Wake-on-LAN

[Service]
Type=oneshot
ExecStart=/sbin/ethtool -s enp1s0 wol g

[Install]
WantedBy=multi-user.target
```

Finally we enable and run the service:
```
sudo systemctl daemon-reload
sudo systemctl enable wol.service
sudo systemctl start wol.service
```

Please note that RaspberryPi computers do not support WoL, because their Ethernet network card is integrated into the SoC.

### How to enable WoL on MacOS?

On MacOS this feature is called *Wake for network access* (or *Wake for Ethernet network access*). You can enable this setting under `System Settings` - `Energy Saver` (or `Battery/Power Adapter`) - `Wake for network access`.

Also, the Mac computer must remain in a low-power sleep state (so called "standby"). If it is completely shut down, WoL does not work.

### How to enable WoL on Windows?

First, Wake-On-LAN must be enabled in BIOS.

Then open `Device Manager` - `Network adapters` - select your network card and go to `Properties`. Then go to `Power Management` tab, and check:
- `Allow this device to wake the computer`
- `Only allow a magic packet to wake the computer` (optional, usually safer)

Go to `Advanced` tab and look for options like:
- `Wake on Magic Packet` - `Enabled`
- `Wake on Pattern Match` - `optional`
- `Shutdown Wake-On-Lan` - `Enabled`
