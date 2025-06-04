import sqlite3

conn = sqlite3.connect('scans.db')
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(scans);")
columns = cursor.fetchall()

print("Columns in 'scans' table:")
for col in columns:
    print(col)

conn.close()
