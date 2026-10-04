"""
state_store.py

Persists Wi-Fi scan results to SQLite so the trust scorer can check
history: has this SSID been seen before, with what BSSID(s) and encryption?
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sightings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ssid        TEXT NOT NULL,
    bssid       TEXT NOT NULL,
    encryption  TEXT,
    signal      INTEGER,
    channel     INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sightings_ssid ON sightings(ssid);
"""


class StateStore:
    def __init__(self, db_path: str = "./data/wifi.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def save_scan(self, networks: list[dict]) -> int:
        ts = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            cur = conn.execute("INSERT INTO scans (timestamp) VALUES (?)", (ts,))
            scan_id = cur.lastrowid

            conn.executemany(
                """INSERT INTO sightings
                   (scan_id, ssid, bssid, encryption, signal, channel)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    (scan_id, n["ssid"], n["bssid"], n.get("encryption"),
                     n.get("signal"), n.get("channel"))
                    for n in networks
                ],
            )
            return scan_id

    def get_history_for_ssid(self, ssid: str, exclude_scan_id: int | None = None) -> list[dict]:
        """
        All past sightings of this SSID (across all previous scans),
        used to check for BSSID/encryption changes -- the evil-twin signal.
        """
        with self._conn() as conn:
            query = "SELECT * FROM sightings WHERE ssid = ?"
            params = [ssid]
            if exclude_scan_id is not None:
                query += " AND scan_id != ?"
                params.append(exclude_scan_id)
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]


if __name__ == "__main__":
    store = StateStore("./data/wifi.db")
    sid = store.save_scan([
        {"ssid": "jnn-wifi", "bssid": "f4:92:bf:14:48:24",
         "encryption": "open", "signal": 46, "channel": 11},
    ])
    print(f"Saved scan id={sid}")
    print(store.get_history_for_ssid("jnn-wifi"))