import sqlite3
import re
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "CHANGE_ME_SECRET_KEY"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.sqlite"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    conn.close()


login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.nickname = row["nickname"]
        self.email = row["email"]


@login_manager.user_loader
def load_user(user_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if row:
        return User(row)
    return None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        nickname = (request.form.get("nickname") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if len(nickname) < 3:
            flash("Нікнейм має бути мінімум 3 символи.", "error")
            return redirect(url_for("register"))

        if "@" not in email or "." not in email:
            flash("Введіть коректний email.", "error")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Пароль має бути мінімум 6 символів.", "error")
            return redirect(url_for("register"))

        if password != password2:
            flash("Паролі не співпадають.", "error")
            return redirect(url_for("register"))

        conn = get_db()

        exists_email = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        exists_nick = conn.execute("SELECT id FROM users WHERE nickname = ?", (nickname,)).fetchone()
        if exists_email:
            conn.close()
            flash("Такий email вже зареєстрований.", "error")
            return redirect(url_for("register"))
        if exists_nick:
            conn.close()
            flash("Такий нікнейм вже зайнятий.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        conn.execute(
            "INSERT INTO users (nickname, email, password_hash) VALUES (?, ?, ?)",
            (nickname, email, password_hash)
        )
        conn.commit()

        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        user = User(row)
        login_user(user)

        flash("Реєстрація успішна! Ви увійшли в акаунт.", "success")
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if not row:
            flash("Неправильний email або пароль.", "error")
            return redirect(url_for("login"))

        if not check_password_hash(row["password_hash"], password):
            flash("Неправильний email або пароль.", "error")
            return redirect(url_for("login"))

        user = User(row)
        login_user(user)

        flash(f"Вітаю, {user.nickname}!", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Ви вийшли з акаунта.", "success")
    return redirect(url_for("index"))


@app.route("/album")
@login_required
def album():

    return "<h2>Album page (coming soon)</h2>"


if __name__ == "__main__":
    init_db()
    app.run(debug=True)