import sqlite3

def create_database():
    conn = sqlite3.connect("audit_platform.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_type TEXT,
            risk_score REAL,
            status TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_audit(audit_type, risk_score, status):
    conn = sqlite3.connect("audit_platform.db")
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_history (audit_type, risk_score, status)
        VALUES (?, ?, ?)
    """, (audit_type, risk_score, status))
    conn.commit()
    conn.close()

def get_audits():
    conn = sqlite3.connect("audit_platform.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, audit_type, risk_score, status FROM audit_history")
    rows = cursor.fetchall()
    conn.close()
    return rows

def clear_audits():
    conn = sqlite3.connect("audit_platform.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_history")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='audit_history'")
    conn.commit()
    conn.close()

def delete_audit_by_id(audit_id):
    conn = sqlite3.connect("audit_platform.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_history WHERE id = ?", (audit_id,))
    conn.commit()
    conn.close()