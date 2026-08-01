import sqlite3
import datetime
import json
import os

DB_NAME = "bhishma_data.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            recon_data TEXT,
            enum_data TEXT,
            exploit_data TEXT,
            risk_score INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

def save_scan(target, recon, enum, exploit, risk_score=0):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cur.execute("""
        INSERT INTO scans 
        (target, timestamp, recon_data, enum_data, exploit_data, risk_score)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        target,
        timestamp,
        json.dumps(recon, indent=2),
        json.dumps(enum, indent=2),
        json.dumps(exploit, indent=2),
        risk_score
    ))

    conn.commit()
    conn.close()

def get_history():
    if not os.path.exists(DB_NAME):
        return []

    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        SELECT id, target, timestamp, risk_score
        FROM scans
        ORDER BY id DESC
    """)

    rows = cur.fetchall()
    conn.close()
    return rows
