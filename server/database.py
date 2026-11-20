"""
SQLite Database interface for recording scan history and computing dashboard statistics.
"""

import sqlite3
import json
import os
from typing import List, Dict, Any

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "phishing_scans.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_percentage REAL NOT NULL,
                phishing_probability REAL NOT NULL,
                https_status TEXT,
                findings_json TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def save_scan(result: Dict[str, Any]) -> int:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (
                url, verdict, risk_level, risk_percentage,
                phishing_probability, https_status, findings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("url", ""),
            result.get("verdict", "UNKNOWN"),
            result.get("risk_level", "UNKNOWN"),
            result.get("risk_percentage", 0.0),
            result.get("phishing_probability", 0.0),
            result.get("https_analysis", {}).get("status", ""),
            json.dumps(result.get("findings", []))
        ))
        conn.commit()
        return cursor.lastrowid


def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, url, verdict, risk_level, risk_percentage,
                   phishing_probability, https_status, findings_json, scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "url": r["url"],
            "verdict": r["verdict"],
            "risk_level": r["risk_level"],
            "risk_percentage": r["risk_percentage"],
            "phishing_probability": r["phishing_probability"],
            "https_status": r["https_status"],
            "findings": json.loads(r["findings_json"]) if r["findings_json"] else [],
            "scanned_at": r["scanned_at"]
        })
    return results


def get_scan_stats() -> Dict[str, Any]:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM scans")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as cnt FROM scans WHERE verdict = 'PHISHING'")
        phishing_count = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM scans WHERE verdict = 'SUSPICIOUS'")
        suspicious_count = cursor.fetchone()["cnt"]

        cursor.execute("SELECT COUNT(*) as cnt FROM scans WHERE verdict = 'LEGITIMATE'")
        legitimate_count = cursor.fetchone()["cnt"]

    phishing_rate = round((phishing_count / total * 100), 1) if total > 0 else 0.0

    return {
        "total_scans": total,
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "legitimate_count": legitimate_count,
        "phishing_rate_percent": phishing_rate
    }


def clear_history():
    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
