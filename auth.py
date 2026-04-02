import sqlite3

def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT, password TEXT, role TEXT)''')

    c.execute("INSERT OR IGNORE INTO users VALUES ('admin','admin123','admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES ('user','user123','user')")

    conn.commit()
    conn.close()

def check_user(username, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
    result = c.fetchone()
    conn.close()
    return result