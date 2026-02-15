import sqlite3
import hashlib

conn = sqlite3.connect('sonprj.db')
cursor = conn.cursor()

password = hashlib.sha256('admin123'.encode()).hexdigest()

cursor.execute("""
    INSERT INTO users (email, password, role, is_admin, created_at)
    VALUES ('admin@example.com', ?, 'admin', 1, datetime('now'))
""", (password,))

conn.commit()
conn.close()