"""
SQLite Database Storage & History Tracker
"""
import sqlite3
import os
import datetime
from typing import List, Dict, Any

DB_FILE = os.path.join(os.path.expanduser("~"), ".revlab.db")

def init_db(db_path: str = DB_FILE):
    """Initializes SQLite database schema for analysis history."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        file_format TEXT,
        architecture TEXT,
        sha256 TEXT,
        imphash TEXT,
        entropy REAL,
        is_packed INTEGER,
        packer TEXT,
        compiler TEXT,
        suspicious_imports INTEGER,
        total_strings INTEGER
    );
    """)

    conn.commit()
    conn.close()

def log_analysis(summary: Dict[str, Any], db_path: str = DB_FILE):
    """Logs a binary analysis summary into SQLite database."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
    INSERT INTO analysis_history (
        timestamp, filename, filepath, file_format, architecture, sha256, imphash,
        entropy, is_packed, packer, compiler, suspicious_imports, total_strings
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now,
        summary.get("filename", "unknown"),
        summary.get("filepath", "unknown"),
        summary.get("format", "unknown"),
        summary.get("architecture", "unknown"),
        summary.get("hashes", {}).get("sha256", "N/A"),
        summary.get("hashes", {}).get("imphash", "N/A"),
        summary.get("entropy", 0.0),
        1 if summary.get("is_packed") else 0,
        summary.get("packer", "None"),
        summary.get("compiler", "Unknown"),
        summary.get("suspicious_imports_count", 0),
        summary.get("strings_count", 0)
    ))

    conn.commit()
    conn.close()

def get_history(limit: int = 20, db_path: str = DB_FILE) -> List[Dict[str, Any]]:
    """Retrieves recent binary analysis records."""
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, timestamp, filename, file_format, architecture, sha256, entropy, is_packed, packer, suspicious_imports
    FROM analysis_history
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
