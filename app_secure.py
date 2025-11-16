

from flask import Flask, request, render_template
import sqlite3
from detector import is_sqli, sanitize, log_detection

app = Flask(__name__)

def query_db_param(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    rows = c.fetchall()
    col_names = [desc[0] for desc in c.description]  # REAL column names

    conn.close()
    return col_names, rows

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search_secure', methods=['POST'])
def search_secure():
    username = request.form.get('username','')
    sqli, pattern = is_sqli(username)

    if sqli:
        log_detection(username, pattern, remote=request.remote_addr)
        return render_template(
            'result.html',
            endpoint='SECURE (BLOCKED)',
            query=username,
            col_names=["Status", "Reason"],
            results=[("BLOCKED", "Detected SQL injection pattern")]
        )

    clean = sanitize(username)
    col_names, rows = query_db_param(clean)

    return render_template(
        'result.html',
        endpoint='SECURE (ALLOWED)',
        query=username,
        col_names=col_names,
        results=rows
    )

@app.route('/dashboard')
def dashboard():
    logs = []
    try:
        with open("detections.log", "r") as f:
            for line in f:
                logs.append(line.strip().split("\t"))
    except:
        pass

    return render_template("dashboard.html", logs=logs)

if __name__ == '__main__':
    app.run(port=5002, debug=True)
