"""
monitor.py

Entry point for the Wi-Fi Network Trust Scorer.
Runs the full pipeline: scan -> store -> score -> report.
"""

from wifi_scanner import scan_networks
from state_store import StateStore
from trust_scorer import score_all
from report import generate_report


def run_once(db_path: str = "./data/wifi.db", report_path: str = "./reports/latest.html"):
    print("Scanning nearby Wi-Fi networks ...")
    networks = scan_networks()
    print(f"Found {len(networks)} network(s)")

    store = StateStore(db_path)

    print("Scoring trust ...")
    scored = score_all(networks, store)

    print("Saving scan to history ...")
    scan_id = store.save_scan(networks)
    print(f"Saved as scan_id={scan_id}")

    print("Generating report ...")
    path = generate_report(scored, output_path=report_path)

    print()
    print("=== SUMMARY ===")
    for n in sorted(scored, key=lambda x: x["risk_score"], reverse=True):
        print(f"{n['ssid']:30s} {n['risk_level']:10s} ({n['risk_score']})")
    print(f"\nReport: {path}")


if __name__ == "__main__":
    run_once()