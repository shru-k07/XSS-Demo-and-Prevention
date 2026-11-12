from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, secrets
from functools import wraps
from markupsafe import escape

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-for-real-deployment")
DB = "xss_lab.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get("_csrf_token")
        submitted = request.form.get("_csrf_token")
        if not token or not submitted or not secrets.compare_digest(token, submitted):
            return "Invalid or missing CSRF token.", 400

@app.context_processor
def inject_csrf():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(16)
    return {"csrf_token": session["_csrf_token"]}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 6:
            flash("Username must be 3+ characters and password 6+ characters.")
            return redirect(url_for("register"))
        try:
            with get_db() as db:
                db.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                           (username, generate_password_hash(password)))
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That username is already taken.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["_csrf_token"] = secrets.token_hex(16)
            return redirect(url_for("dashboard"))
        flash("Incorrect username or password.")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have logged out.")
    return redirect(url_for("home"))

@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as db:
        messages = db.execute("SELECT * FROM messages ORDER BY id DESC").fetchall()
    return render_template("dashboard.html", messages=messages)

@app.route("/post", methods=["POST"])
@login_required
def post():
    message = request.form.get("message", "").strip()
    if message:
        with get_db() as db:
            db.execute("INSERT INTO messages(username,message) VALUES(?,?)",
                       (session["username"], message))
    return redirect(url_for("dashboard"))

@app.route("/lab", methods=["GET", "POST"])
@login_required
def lab():
    submitted = None
    if request.method == "POST":
        submitted = request.form.get("demo_text", "")
    return render_template("lab.html", submitted=submitted)

@app.route("/vulnerable-demo", methods=["POST"])
@login_required
def vulnerable_demo():
    # INTENTIONALLY VULNERABLE: for local classroom demonstration only.
    # Never use this pattern in a real application.
    raw = request.form.get("demo_text", "")
    return render_template("vulnerable.html", raw=raw)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
