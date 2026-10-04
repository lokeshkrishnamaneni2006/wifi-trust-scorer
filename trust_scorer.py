"""
trust_scorer.py

Scores each currently-seen Wi-Fi network for trust/risk based on:
  - Encryption strength (open/WEP = risky, WPA2/WPA3 = safer)
  - Whether this SSID has been seen before with DIFFERENT encryption
    (classic evil-twin / downgrade-attack signal)
  - Whether this SSID has multiple BSSIDs seen with inconsistent encryption
  - Known public-brand SSID names (can't verify authenticity, common phishing target)
"""

COMMON_PUBLIC_SSIDS = {
    "starbucks wifi", "free wifi", "airport wifi", "free public wifi",
    "hotel wifi", "guest wifi", "xfinitywifi", "attwifi",
}

ENCRYPTION_BASE_RISK = {
    "open": 9,
    "wep": 8,
    "wpa": 5,
    "wpa2-personal": 2,
    "wpa2-enterprise": 1,
    "wpa3-personal": 1,
    "wpa3-enterprise": 1,
}
DEFAULT_ENCRYPTION_RISK = 5


def score_network(network: dict, history: list[dict]) -> dict:
    """
    Returns the network dict plus 'risk_score' (0-10) and 'risk_level',
    plus 'reasons': list of short strings explaining the score.
    """
    reasons = []
    enc = (network.get("encryption") or "").lower()
    score = ENCRYPTION_BASE_RISK.get(enc, DEFAULT_ENCRYPTION_RISK)

    if enc in ("open", "wep"):
        reasons.append(f"Weak/no encryption ({network.get('encryption')})")

    ssid_lower = (network.get("ssid") or "").lower()
    if ssid_lower in COMMON_PUBLIC_SSIDS:
        score = max(score, 6)
        reasons.append("Common public SSID name — easily spoofed")

    # Check history: has this SSID been seen before with DIFFERENT encryption?
    past_encryptions = {h["encryption"] for h in history if h.get("encryption")}
    if past_encryptions and enc not in {e.lower() for e in past_encryptions if e}:
        score = 10
        reasons.append(
            f"Encryption changed since last seen (was {', '.join(past_encryptions)}, now {network.get('encryption')})"
        )

    # Check history: same SSID, different BSSID seen before — not inherently bad
    # (could just be another AP in the same building), but flag if encryption
    # ALSO differs across those BSSIDs (handled above) -- here just note count.
    past_bssids = {h["bssid"] for h in history}
    if past_bssids and network["bssid"] not in past_bssids:
        reasons.append(f"New access point for this SSID (seen {len(past_bssids)} before)")

    score = min(score, 10)

    return {
        **network,
        "risk_score": score,
        "risk_level": _risk_level(score),
        "reasons": reasons,
    }


def _risk_level(score: int) -> str:
    if score >= 8:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def score_all(networks: list[dict], store) -> list[dict]:
    """Scores every network in a scan, pulling history for each SSID from the store."""
    scored = []
    for n in networks:
        history = store.get_history_for_ssid(n["ssid"])
        scored.append(score_network(n, history))
    return scored


if __name__ == "__main__":
    # Smoke test — no history
    fake = {"ssid": "Free Public WiFi", "bssid": "aa:bb:cc:dd:ee:ff",
             "encryption": "Open", "signal": 70, "channel": 6}
    result = score_network(fake, history=[])
    print(result)