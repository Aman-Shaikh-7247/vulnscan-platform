import sqlite3

conn = sqlite3.connect('scans.db')
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE scans ADD COLUMN vulnerabilities TEXT;")
    print("Column 'vulnerabilities' added successfully.")
except sqlite3.OperationalError as e:
    print("Error or column already exists:", e)

conn.commit()
conn.close()
