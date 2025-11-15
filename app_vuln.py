from flask import Flask, request, render_template
import sqlite3

app = Flask(__name__)

def query_db_raw(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # VULNERABLE: direct string formatting
    sql = f"SELECT id, username FROM users WHERE username = '{username}'"
    c.execute(sql)
    res = c.fetchall()
    conn.close()
    return res

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search_vuln', methods=['POST'])
def search_vuln():
    username = request.form.get('username','')
    results = query_db_raw(username)
    return render_template('result.html', endpoint='VULNERABLE', query=username, results=results)

if __name__ == '__main__':
    app.run(port=5001, debug=True)
