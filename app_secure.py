from flask import Flask, request, render_template
import sqlite3
from detector import is_sqli, sanitize, log_detection

app = Flask(__name__)

def query_db_param(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
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
        log_detection(username, pattern, remote=request.remote_addr)
        return render_template('result.html', endpoint='SECURE (BLOCKED)', query=username, results=[("BLOCKED", "Detected SQLi pattern")])
    
    username_clean = sanitize(username)
    results = query_db_param(username_clean)
    return render_template('result.html', endpoint='SECURE (ALLOWED)', query=username, results=results)

# ✅ ADD THIS ROUTE HERE
@app.route('/dashboard')
def dashboard():
    logs = []
    try:
        with open("detections.log", "r") as f:
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) == 4:
                    logs.append(parts)
    except FileNotFoundError:
        logs = []

    return render_template("dashboard.html", logs=logs)

if __name__ == '__main__':
    app.run(port=5002, debug=True)
