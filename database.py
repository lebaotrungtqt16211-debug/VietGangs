import sqlite3
from contextlib import contextmanager
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()
DB_PATH = "keys.db"

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_value TEXT UNIQUE NOT NULL,
                duration_days INTEGER NOT NULL,
                hwid TEXT,
                max_devices INTEGER DEFAULT 1,
                used_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                expires_at DATETIME,
                created_by INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_value TEXT,
                action TEXT,
                ip TEXT,
                user_agent TEXT,
                success INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)

        admin_user = os.getenv("ADMIN_USER", "admin")
        admin_pass = os.getenv("ADMIN_PASS", "Admin@123456")
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (admin_user,)).fetchone()
        if not existing:
            hashed = bcrypt.hashpw(admin_pass.encode(), bcrypt.gensalt()).decode()
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (admin_user, hashed, "admin"))
            print(f"✅ Admin created: {admin_user}")
