import os
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, make_response

app = Flask(__name__)
DB_PATH = 'database.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, bio TEXT)')
    cursor.execute('CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY, content TEXT)')
    # Dummy user
    cursor.execute('INSERT OR IGNORE INTO users (id, username, password, bio) VALUES (1, "admin", "admin123", "I am the god of this app")')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template('index.html')

# VULNERABILITY 1: SQL Injection (in search)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Unsafe query construction
    sql = f"SELECT username, bio FROM users WHERE username LIKE '%{query}%'"
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
    except Exception as e:
        results = [("Error", str(e))]
    conn.close()
    return render_template('search.html', results=results, query=query)

# VULNERABILITY 2: Stored XSS (in feedback)
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if request.method == 'POST':
        content = request.form.get('content', '')
        # Unsafe storage (no sanitization)
        cursor.execute('INSERT INTO feedback (content) VALUES (?)', (content,))
        conn.commit()
    
    cursor.execute('SELECT content FROM feedback')
    feedbacks = cursor.fetchall()
    conn.close()
    return render_template('feedback.html', feedbacks=feedbacks)

# VULNERABILITY 3: Local File Inclusion (LFI)
@app.route('/view')
def view_file():
    filename = request.args.get('file', '')
    if not filename:
        return "Please specify a file parameter (e.g., /view?file=templates/index.html)"
    
    # Path traversal vulnerability
    try:
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error reading file: {str(e)}"

# Login (for scanner auth testing)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "admin" and password == "admin123":
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('session_id', 'fake-secret-session-token')
            return resp
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    session = request.cookies.get('session_id')
    if session == 'fake-secret-session-token':
        return "<h1>Welcome to Admin Dashboard</h1><p>You are authenticated.</p>"
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
