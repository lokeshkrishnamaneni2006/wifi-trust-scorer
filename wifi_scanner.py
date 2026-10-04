"""
wifi_scanner.py

Scans nearby Wi-Fi networks using Windows' built-in `netsh` command
and parses the output into structured data.
"""

import subprocess
import re


def scan_networks() -> list[dict]:
    """
    Runs `netsh wlan show networks mode=bssid` and parses it into:
        [{ssid, bssid, signal, encryption, channel}, ...]
    One entry per BSSID (a single SSID can have multiple BSSIDs/APs).
    """
    result = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, shell=True
    )

    output = result.stdout
    networks = []

    current_ssid = None
    current_encryption = None
    current_bssid = None
    current_signal = None
    current_channel = None

    for line in output.splitlines():
        line = line.strip()

        ssid_match = re.match(r"SSID \d+ : (.*)", line)
        if ssid_match:
            current_ssid = ssid_match.group(1).strip()
            continue

        if line.startswith("Authentication"):
            current_encryption = line.split(":", 1)[1].strip()
            continue

        bssid_match = re.match(r"BSSID \d+\s*:\s*(.*)", line)
        if bssid_match:
            current_bssid = bssid_match.group(1).strip()
            continue

        if line.startswith("Signal"):
            signal_str = line.split(":", 1)[1].strip().replace("%", "")
            current_signal = int(signal_str) if signal_str.isdigit() else None
            continue

        if line.startswith("Channel"):
            channel_str = line.split(":", 1)[1].strip()
            current_channel = int(channel_str) if channel_str.isdigit() else None

            # Channel is usually the last field per BSSID block — save the entry here
            if current_ssid and current_bssid:
                networks.append({
                    "ssid": current_ssid,
                    "bssid": current_bssid,
                    "encryption": current_encryption,
                    "signal": current_signal,
                    "channel": current_channel,
                })
            current_bssid = None
            current_signal = None
            current_channel = None

    return networks


if __name__ == "__main__":
    import json

    results = scan_networks()
    print(json.dumps(results, indent=2))
    print(f"\n{len(results)} network(s) found")