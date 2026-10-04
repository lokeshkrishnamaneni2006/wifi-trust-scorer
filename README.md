\# Wi-Fi Network Trust Scorer



A tool that scans nearby Wi-Fi networks and scores each one for trust risk,

flagging patterns associated with evil-twin attacks, weak encryption, and

spoofable public network names.



\## Why this exists



Most people connect to Wi-Fi based on signal strength and a familiar-looking

name, with no way to tell if a network is actually what it claims to be.

This tool scans what's nearby, checks each network against known risk

patterns, and produces a readable report ranking which networks to avoid.



\## Architecture



wifi-trust-scorer/

&#x20;   wifi\_scanner.py     - Wraps Windows netsh to list nearby networks

&#x20;   state\_store.py       - SQLite history of all past scans/sightings

&#x20;   trust\_scorer.py       - Scores each network 0-10 based on risk signals

&#x20;   report.py              - Renders an HTML report

&#x20;   monitor.py               - Orchestrates the full pipeline

&#x20;   data/wifi.db               - SQLite database (created on first run)

&#x20;   reports/latest.html          - Most recent generated report



Pipeline: scan -> score -> store -> report, run from one command via

monitor.py.



Module responsibilities:

\- wifi\_scanner.py: Runs `netsh wlan show networks mode=bssid` and parses SSID, BSSID, encryption, signal, channel

\- state\_store.py: Persists every scan, so a network's history (past encryption, past BSSIDs) can be checked

\- trust\_scorer.py: Flags weak/open encryption, spoofable public SSID names, and encryption that changed since last seen for the same SSID

\- report.py: Renders a ranked HTML report, highest risk first

\- monitor.py: Entry point, runs the entire pipeline



\## Requirements



\- Windows 10/11 with a real Wi-Fi adapter

\- Python 3.8+



\## Setup



python -m pip install jinja2



\## Usage



python monitor.py



This will:

1\. Scan nearby Wi-Fi networks

2\. Score each one for trust risk

3\. Save the scan to history

4\. Generate reports/latest.html



Open the report:



start "" "reports\\latest.html"



\## Risk scoring model



Each network is scored 0-10 based on:

\- Encryption type: open/WEP score high risk, WPA2/WPA3 score low

\- Known public SSID names (e.g. "Free Public WiFi"): flagged as easily spoofed

\- Encryption changed since the SSID was last seen: scored as highest risk,

&#x20; the clearest evil-twin/downgrade signal



\## Scope and limitations



\- Relies on Windows' netsh command, so it only runs on Windows

\- A single scan only sees what netsh reports at that moment; running it

&#x20; multiple times over a day builds real history for the "changed since last

&#x20; seen" detection to catch something

\- Does not attempt to connect to or interact with any network, purely

&#x20; passive observation of broadcast information



\## Disclaimer



This tool only reads publicly broadcast Wi-Fi information (SSID, BSSID,

encryption type) that any device in range can already see. It does not

attempt to access, decrypt, or connect to any network without authorization.

