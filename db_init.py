import sqlite3

def init():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    c.executemany('INSERT INTO users (username,password) VALUES (?,?)', [
        ('alice','alice123'),
        ('bob','bob123'),
        ('admin','supersecret')
    ])
    conn.commit()
    conn.close()
    print("DB initialized with sample users.")

if __name__ == '__main__':
    init()
