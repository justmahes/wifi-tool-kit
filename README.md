# Wi-Fi Toolkit (Windows)

Small Windows desktop app to monitor Wi-Fi/network quality, run speed tests, and list devices in the ARP table.

## Features
- Monitor latency + packet loss to a target host.
- Run speed tests using `speedtest` or `speedtest-cli` if installed.
- List devices found in the local ARP table, with optional network scan.
- Wi-Fi details (SSID, signal, channel).
- Alerts (latency/loss) + system tray notifications.
- Auto logging to CSV/JSONL.
- Export monitor history and device lists to CSV.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Optional for speed tests:

```powershell
pip install speedtest-cli
```

Or install the official Ookla CLI and ensure `speedtest` is on PATH.

## Run

```powershell
python app.py
```

## Notes
- This tool only works with networks you own or are authorized to test.
- Device list uses the Windows ARP table, which only includes recently seen devices.
- For vendor lookup, download the IEEE OUI database from the Devices tab.
