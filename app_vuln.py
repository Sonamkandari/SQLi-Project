

from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

def query_db_raw(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # VULNERABLE: unsafe string formatting
    sql = f"SELECT id, username FROM users WHERE username = '{username}'"
    c.execute(sql)

    rows = c.fetchall()
    col_names = [desc[0] for desc in c.description]   # Default headers

    # ----------- ⭐ UNION DETECTION + FIX ⭐ -----------
    if "UNION" in username.upper():
        # Replace header names for UNION SELECT attacks
        col_names = ["username", "password"]

    conn.close()
    return col_names, rows
    # -----------------------------------------------


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/search_vuln', methods=['POST'])
def search_vuln():
    username = request.form.get('username','')

    col_names, results = query_db_raw(username)

    return render_template(
        'result.html',
        endpoint='VULNERABLE',
        query=username,
        results=results,
        col_names=col_names
    )


if __name__ == '__main__':
    app.run(port=5001, debug=True)
