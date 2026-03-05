import sqlite3
import uuid
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "CHANGE_ME_SECRET_KEY"  # потім винесемо в env

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.sqlite"
UPLOAD_DIR = BASE_DIR / "uploads"

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def init_db():
    UPLOAD_DIR.mkdir(exist_ok=True)

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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            parent_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            folder_id INTEGER,
            file_path TEXT NOT NULL,
            original_name TEXT NOT NULL,
            title TEXT,
            mime_type TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)

    try:
        columns = cur.execute("PRAGMA table_info(photos);").fetchall()
        col_names = [c[1] for c in columns]
        if "title" not in col_names:
            cur.execute("ALTER TABLE photos ADD COLUMN title TEXT;")
            cur.execute("UPDATE photos SET title = original_name WHERE title IS NULL;")
    except Exception:
        pass

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


def get_folder_owned(folder_id: int, user_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM folders WHERE id = ? AND user_id = ?",
        (folder_id, user_id)
    ).fetchone()
    conn.close()
    return row


def get_breadcrumbs(folder_row):
    crumbs = []
    current = folder_row
    while current is not None:
        crumbs.append(current)
        pid = current["parent_id"]
        if pid is None:
            break
        current = get_folder_owned(pid, current["user_id"])
    crumbs.reverse()
    return crumbs


def delete_folder_recursive(conn, folder_id: int, user_id: int):
    children = conn.execute(
        "SELECT id FROM folders WHERE user_id = ? AND parent_id = ?",
        (user_id, folder_id)
    ).fetchall()
    for c in children:
        delete_folder_recursive(conn, c["id"], user_id)

    photos = conn.execute(
        "SELECT id, file_path FROM photos WHERE user_id = ? AND folder_id = ?",
        (user_id, folder_id)
    ).fetchall()
    for p in photos:
        fp = BASE_DIR / p["file_path"]
        try:
            if fp.exists():
                fp.unlink()
        except Exception:
            pass
        conn.execute("DELETE FROM photos WHERE id = ? AND user_id = ?", (p["id"], user_id))

    conn.execute("DELETE FROM folders WHERE id = ? AND user_id = ?", (folder_id, user_id))


def get_photo_owned(photo_id: int, user_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM photos WHERE id = ? AND user_id = ?",
        (photo_id, user_id)
    ).fetchone()
    conn.close()
    return row


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

        login_user(User(row))
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

        if not row or not check_password_hash(row["password_hash"], password):
            flash("Неправильний email або пароль.", "error")
            return redirect(url_for("login"))

        login_user(User(row))
        flash(f"Вітаю, {row['nickname']}!", "success")
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
    user_id = current_user.id

    conn = get_db()
    folders = conn.execute(
        "SELECT * FROM folders WHERE user_id = ? AND parent_id IS NULL ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()

    photos = conn.execute(
        "SELECT * FROM photos WHERE user_id = ? AND folder_id IS NULL ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()

    conn.close()

    return render_template("album.html", folders=folders, photos=photos, current_folder=None, breadcrumbs=[])


@app.route("/album/<int:folder_id>")
@login_required
def album_folder(folder_id):
    user_id = current_user.id
    current_folder = get_folder_owned(folder_id, user_id)
    if not current_folder:
        abort(404)

    conn = get_db()
    folders = conn.execute(
        "SELECT * FROM folders WHERE user_id = ? AND parent_id = ? ORDER BY created_at DESC",
        (user_id, folder_id)
    ).fetchall()

    photos = conn.execute(
        "SELECT * FROM photos WHERE user_id = ? AND folder_id = ? ORDER BY created_at DESC",
        (user_id, folder_id)
    ).fetchall()

    conn.close()

    breadcrumbs = get_breadcrumbs(current_folder)
    return render_template("album.html", folders=folders, photos=photos, current_folder=current_folder, breadcrumbs=breadcrumbs)


@app.route("/folders/create", methods=["POST"])
@login_required
def create_folder():
    user_id = current_user.id
    name = (request.form.get("name") or "").strip()
    parent_id_raw = (request.form.get("parent_id") or "").strip()

    if name == "":
        flash("Назва папки не може бути порожньою.", "error")
        return redirect(request.referrer or url_for("album"))

    parent_id = None
    if parent_id_raw != "":
        try:
            parent_id = int(parent_id_raw)
        except ValueError:
            flash("Некоректний parent_id.", "error")
            return redirect(url_for("album"))

        parent_folder = get_folder_owned(parent_id, user_id)
        if not parent_folder:
            flash("Немає доступу до цієї папки.", "error")
            return redirect(url_for("album"))

    conn = get_db()
    conn.execute(
        "INSERT INTO folders (user_id, name, parent_id) VALUES (?, ?, ?)",
        (user_id, name, parent_id)
    )
    conn.commit()
    conn.close()

    flash("Папку створено ✅", "success")
    return redirect(request.referrer or url_for("album"))


@app.route("/folders/rename/<int:folder_id>", methods=["POST"])
@login_required
def rename_folder(folder_id):
    user_id = current_user.id
    folder = get_folder_owned(folder_id, user_id)
    if not folder:
        abort(404)

    new_name = (request.form.get("name") or "").strip()
    if new_name == "":
        flash("Нова назва не може бути порожньою.", "error")
        return redirect(request.referrer or url_for("album"))

    conn = get_db()
    conn.execute(
        "UPDATE folders SET name = ? WHERE id = ? AND user_id = ?",
        (new_name, folder_id, user_id)
    )
    conn.commit()
    conn.close()

    flash("Папку перейменовано ✅", "success")
    return redirect(request.referrer or url_for("album"))


@app.route("/folders/delete/<int:folder_id>", methods=["POST"])
@login_required
def delete_folder(folder_id):
    user_id = current_user.id
    folder = get_folder_owned(folder_id, user_id)
    if not folder:
        abort(404)

    conn = get_db()
    delete_folder_recursive(conn, folder_id, user_id)
    conn.commit()
    conn.close()

    flash("Папку видалено разом з усіма вкладеними папками ✅", "success")
    return redirect(request.referrer or url_for("album"))


@app.route("/photos/upload", methods=["POST"])
@login_required
def upload_photo():
    user_id = current_user.id

    folder_id_raw = (request.form.get("folder_id") or "").strip()
    folder_id = None
    if folder_id_raw != "":
        try:
            folder_id = int(folder_id_raw)
        except ValueError:
            flash("Некоректна папка.", "error")
            return redirect(request.referrer or url_for("album"))

        if not get_folder_owned(folder_id, user_id):
            flash("Немає доступу до цієї папки.", "error")
            return redirect(url_for("album"))

    file = request.files.get("photo")
    if not file or file.filename == "":
        flash("Оберіть файл.", "error")
        return redirect(request.referrer or url_for("album"))

    if not allowed_file(file.filename):
        flash("Дозволені формати: jpg, jpeg, png, gif, webp.", "error")
        return redirect(request.referrer or url_for("album"))

    original_display_name = file.filename.strip()

    safe_name = secure_filename(file.filename)
    ext = Path(safe_name).suffix.lower()

    unique_name = f"{uuid.uuid4().hex}{ext}"

    user_dir = UPLOAD_DIR / str(user_id)
    user_dir.mkdir(exist_ok=True)

    full_path = user_dir / unique_name
    file.save(full_path)

    rel_path = str(full_path.relative_to(BASE_DIR)).replace("\\", "/")
    mime_type = file.mimetype

    conn = get_db()
    conn.execute(
        "INSERT INTO photos (user_id, folder_id, file_path, original_name, title, mime_type) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, folder_id, rel_path, original_display_name, original_display_name, mime_type)
    )
    conn.commit()
    conn.close()

    flash("Фото завантажено ✅", "success")
    return redirect(request.referrer or url_for("album"))


@app.route("/photos/file/<int:photo_id>")
@login_required
def photo_file(photo_id):
    user_id = current_user.id
    row = get_photo_owned(photo_id, user_id)
    if not row:
        abort(404)

    full_path = BASE_DIR / row["file_path"]
    if not full_path.exists():
        abort(404)

    return send_file(full_path, mimetype=row["mime_type"] or "application/octet-stream")


@app.route("/photos/rename/<int:photo_id>", methods=["POST"])
@login_required
def rename_photo(photo_id):
    user_id = current_user.id
    row = get_photo_owned(photo_id, user_id)
    if not row:
        abort(404)

    title = (request.form.get("title") or "").strip()
    if title == "":
        flash("Назва фото не може бути порожньою.", "error")
        return redirect(request.referrer or url_for("album"))

    conn = get_db()
    conn.execute(
        "UPDATE photos SET title = ? WHERE id = ? AND user_id = ?",
        (title, photo_id, user_id)
    )
    conn.commit()
    conn.close()

    flash("Назву фото змінено ✅", "success")
    return redirect(request.referrer or url_for("album"))


@app.route("/photos/delete/<int:photo_id>", methods=["POST"])
@login_required
def delete_photo(photo_id):
    user_id = current_user.id
    row = get_photo_owned(photo_id, user_id)
    if not row:
        abort(404)

    full_path = BASE_DIR / row["file_path"]
    try:
        if full_path.exists():
            full_path.unlink()
    except Exception:
        pass

    conn = get_db()
    conn.execute("DELETE FROM photos WHERE id = ? AND user_id = ?", (photo_id, user_id))
    conn.commit()
    conn.close()

    flash("Фото видалено ✅", "success")
    return redirect(request.referrer or url_for("album"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)