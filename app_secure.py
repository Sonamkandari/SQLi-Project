from flask import Flask, request, render_template
import sqlite3
from detector import is_sqli, sanitize, log_detection

app = Flask(__name__)

def query_db_param(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # SAFE: parameterized query (SQLite qmark style)
    c.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    res = c.fetchall()
    conn.close()
    return res

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search_secure', methods=['POST'])
def search_secure():
    username = request.form.get('username','')
    sqli, pattern = is_sqli(username)
    if sqli:
        # log and block
        log_detection(username, pattern, remote=request.remote_addr)
        return render_template('result.html', endpoint='SECURE (BLOCKED)', query=username, results=[("BLOCKED", "Detected SQLi pattern")])
    # Optionally sanitize (not strictly needed with params)
    username_clean = sanitize(username)
    results = query_db_param(username_clean)
    return render_template('result.html', endpoint='SECURE (ALLOWED)', query=username, results=results)

if __name__ == '__main__':
    app.run(port=5002, debug=True)
