from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-key")

DB = os.path.join(os.path.dirname(__file__), "banking.db")


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0 CHECK(balance >= 0)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount REAL NOT NULL CHECK(amount > 0),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return func(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    if "user_id" in session:
        return redirect("/dashboard")
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(password) < 8:
            flash("Username needs 3 characters and password needs 8.")
            return redirect("/register")

        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password))
                )
            flash("Registration successful. Please log in.")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("That username already exists.")
            return redirect("/register")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect("/dashboard")

        flash("Invalid username or password.")
        return redirect("/login")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as db:
        user = db.execute(
            "SELECT id, username, balance FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        transactions = db.execute(
            """SELECT transaction_type, amount, created_at
               FROM transactions WHERE user_id = ?
               ORDER BY id DESC LIMIT 10""",
            (session["user_id"],)
        ).fetchall()

    if not user:
        session.clear()
        return redirect("/login")

    return render_template(
        "dashboard.html", user=user, transactions=transactions
    )


@app.route("/transaction", methods=["POST"])
@login_required
def transaction():
    kind = request.form.get("type", "")
    try:
        amount = round(float(request.form.get("amount", "")), 2)
    except (ValueError, TypeError):
        flash("Enter a valid amount.")
        return redirect("/dashboard")

    if kind not in ("Deposit", "Withdraw") or not (0 < amount <= 100000):
        flash("Invalid transaction amount or type.")
        return redirect("/dashboard")

    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute(
            "SELECT balance FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()

        if not user:
            session.clear()
            return redirect("/login")

        if kind == "Withdraw" and user["balance"] < amount:
            flash("Insufficient balance.")
            return redirect("/dashboard")

        if kind == "Deposit":
            db.execute(
                "UPDATE users SET balance = balance + ? WHERE id = ?",
                (amount, session["user_id"])
            )
        else:
            db.execute(
                "UPDATE users SET balance = balance - ? WHERE id = ?",
                (amount, session["user_id"])
            )

        db.execute(
            """INSERT INTO transactions
               (user_id, transaction_type, amount) VALUES (?, ?, ?)""",
            (session["user_id"], kind, amount)
        )

    flash(f"{kind} successful.")
    return redirect("/dashboard")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
# GitHub webhook CI/CD test
