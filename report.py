"""
report.py

Generates an HTML report from scored Wi-Fi network data.
"""

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template


TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Wi-Fi Trust Report</title>
<style>
    body { font-family: -apple-system, Arial, sans-serif; background: #0f1117; color: #e6e6e6; margin: 0; padding: 2rem; }
    h1 { font-size: 1.4rem; margin-bottom: 0.2rem; }
    .meta { color: #999; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
    th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #2a2d3a; font-size: 0.9rem; }
    th { color: #999; font-weight: normal; }
    .badge { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .CRITICAL { background: #4a1420; color: #ff6b81; }
    .HIGH { background: #4a2e14; color: #ffa94d; }
    .MEDIUM { background: #3a3a14; color: #f1e05a; }
    .LOW { background: #14301f; color: #69db7c; }
    .reasons { color: #999; font-size: 0.8rem; }
</style>
</head>
<body>

<h1>Wi-Fi Trust Report</h1>
<div class="meta">Generated: {{ generated_at }} &nbsp;|&nbsp; {{ networks|length }} network(s) scanned</div>

<table>
<tr><th>SSID</th><th>BSSID</th><th>Encryption</th><th>Signal</th><th>Risk</th><th>Reasons</th></tr>
{% for n in networks %}
<tr>
    <td>{{ n.ssid }}</td>
    <td>{{ n.bssid }}</td>
    <td>{{ n.encryption or '-' }}</td>
    <td>{{ n.signal }}%</td>
    <td><span class="badge {{ n.risk_level }}">{{ n.risk_level }} ({{ n.risk_score }})</span></td>
    <td class="reasons">{{ n.reasons|join('; ') if n.reasons else '-' }}</td>
</tr>
{% endfor %}
</table>

</body>
</html>
"""


def generate_report(scored_networks: list[dict], output_path: str = "./reports/latest.html") -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    # Sort highest risk first for the report
    sorted_networks = sorted(scored_networks, key=lambda n: n["risk_score"], reverse=True)

    template = Template(TEMPLATE)
    html = template.render(
        networks=sorted_networks,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path


if __name__ == "__main__":
    fake = [
        {"ssid": "Free Public WiFi", "bssid": "aa:bb:cc:dd:ee:ff", "encryption": "Open",
         "signal": 70, "channel": 6, "risk_score": 9, "risk_level": "CRITICAL",
         "reasons": ["Weak/no encryption (Open)", "Common public SSID name"]},
        {"ssid": "Home_Router_5G", "bssid": "11:22:33:44:55:66", "encryption": "WPA2-Personal",
         "signal": 85, "channel": 11, "risk_score": 2, "risk_level": "LOW", "reasons": []},
    ]
    path = generate_report(fake)
    print(f"Report written to {path}")