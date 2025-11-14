# app.py  (VulnPortal - intentionally vulnerable for learning)
from flask import Flask, request, render_template, render_template_string, redirect, url_for, session, send_from_directory, flash
import sqlite3, os, hashlib, subprocess, json, secrets, requests
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "dev-secret-key"  # intentionally weak (A2)
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DB = "vulnportal.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = get_db().cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user'
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS feedback (
                    id INTEGER PRIMARY KEY, user TEXT, message TEXT, created TIMESTAMP
                )""")
    try:
        c.execute("INSERT INTO users (username,password,role) VALUES ('admin','admin123','admin')")
    except:
        pass
    get_db().commit()

# ---------------- Home ----------------
@app.route("/")
def home():
    name = request.args.get("name")  # reflected XSS if used unsafely
    greeting = f"Welcome {name}" if name else "Welcome to VulnPortal"
    return render_template("home.html", greeting=greeting)

# ---------------- Register ---------------- (weak password hashing)
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        # insecure: storing plaintext/weak hash (A2)
        pw = hashlib.md5(p.encode()).hexdigest()  # insecure MD5 (A6)
        db = get_db()
        try:
            db.execute("INSERT INTO users(username,password) VALUES('%s','%s')" % (u, pw))  # SQLi via string formatting (A1)
            db.commit()
            return redirect(url_for("login"))
        except Exception as e:
            return f"Error: {e}"
    return render_template("register.html")

# ---------------- Login ----------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username")
        p = request.form.get("password")
        pw = hashlib.md5(p.encode()).hexdigest()
        # vulnerable SQL concatenation (A1)
        q = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (u, pw)
        cur = get_db().execute(q)
        row = cur.fetchone()
        if row:
            session['user'] = row['username']
            session['role'] = row['role']
            return redirect(url_for('home'))
        else:
            return "Invalid credentials"
    return render_template("login.html")

# ---------------- Feedback (stored XSS) ----------------
@app.route("/feedback", methods=["GET","POST"])
def feedback():
    if request.method == "POST":
        msg = request.form.get("message")
        user = session.get("user","anonymous")
        # stored directly (no sanitization) -> stored XSS (A7 / A3)
        db = get_db()
        db.execute("INSERT INTO feedback(user,message,created) VALUES('%s','%s','%s')" % (user, msg, datetime.utcnow()))
        db.commit()
        return redirect(url_for("feedback"))
    cur = get_db().execute("SELECT * FROM feedback ORDER BY created DESC")
    posts = cur.fetchall()
    return render_template("feedback.html", posts=posts)

# ---------------- Upload (insecure) ----------------
ALLOWED = ['png','jpg','jpeg','gif']
@app.route("/upload", methods=["GET","POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            return "No file"
        filename = f.filename
        # insecure saving: no validation, possible path traversal (A8)
        path = os.path.join(UPLOAD_FOLDER, filename)
        f.save(path)
        return f"Saved to {path}"
    return render_template("upload.html")

# ---------------- Search (SSRF / Command injection style) ----------------
@app.route("/search")
def search():
    q = request.args.get("q","")
    # insecure: calling system command with user input (A1/A10)
    try:
        # Call grep directly with argument list to avoid shell injection
        completed = subprocess.run(['grep', '-R', q, '-n', 'sample_data'],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        result = "Searching\n" + completed.stdout
        if completed.returncode == 1:  # grep returns 1 if nothing matched
            result += "\nNo matches found."
    except Exception as e:
        result = str(e)
    return render_template("search.html", query=q, result=result)

# ---------------- Fetch (SSRF) ----------------
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    if not url:
        return "No URL provided"
    # SSRF risk; no allowlist or validation (A10)
    try:
        r = requests.get(url, timeout=5)
        return r.text[:2000]
    except Exception as e:
        return f"Error fetching: {e}"

# ---------------- Admin (broken access control + no logging) ----------------
@app.route("/admin")
def admin():
    if session.get("role") != "admin":
        # no logging of attempts (A9)
        return "Access denied", 403
    users = get_db().execute("SELECT id,username,role FROM users").fetchall()
    return render_template("admin.html", users=users)

# ---------------- Logout ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ---------------- Static file serve for demo ----------------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5006, debug=True)  # debug=True -> misconfig (A5)
