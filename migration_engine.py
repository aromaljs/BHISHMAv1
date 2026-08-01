import sqlite3


def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    cols = cursor.fetchall()

    for c in cols:
        if c[1] == column:
            return True

    return False


def migrate_database(db_path="bhishma_data.db"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        scan_time TEXT
    )
    """)

    new_columns = [

        ("risk_score", "INTEGER DEFAULT 0"),

        ("attack_surface", "INTEGER DEFAULT 0"),

        ("configuration_score", "INTEGER DEFAULT 0"),

        ("technology_stack", "TEXT DEFAULT ''"),

        ("services_found", "INTEGER DEFAULT 0"),

        ("verified_findings", "INTEGER DEFAULT 0"),

        ("overall_status", "TEXT DEFAULT 'UNKNOWN'")

    ]

    for column, definition in new_columns:

        if not column_exists(cur, "scans", column):

            print(f"[Migration] Adding column {column}")

            cur.execute(
                f"ALTER TABLE scans ADD COLUMN {column} {definition}"
            )

    conn.commit()
    conn.close()

    print("[Migration] Database schema is up to date.")
