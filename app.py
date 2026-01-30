from flask import Flask, request, redirect, render_template, session, url_for, flash
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter
import json
from functools import wraps

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_TO_A_RANDOM_SECRET_KEY_123"

# ✅ Local Postgres
DATABASE_URL = "postgresql+psycopg2://mallesh@localhost:5432/library_tracker"
engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="user")   # user / admin


class BookEntry(Base):
    __tablename__ = "books"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)  # ✅ NEW: who created the entry

    member_name = Column(String, nullable=False)
    date = Column(String, nullable=False)         # YYYY-MM-DD
    book_title = Column(String, nullable=False)
    author = Column(String, nullable=False)
    genre = Column(String, nullable=False)
    status = Column(String, nullable=False)       # Borrowed / Returned
    days = Column(Integer, default=0)

# Create tables if not exist (NOTE: does not alter existing tables)
Base.metadata.create_all(bind=engine)

# ---------------- HELPERS ----------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("admin_login"))
        if session.get("role") != "admin":
            return "❌ Access denied (Admin only)", 403
        return fn(*args, **kwargs)
    return wrapper

# ---------------- USER AUTH ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect("/signup")

        db = SessionLocal()
        try:
            if db.query(User).filter(User.email == email).first():
                flash("Email already exists. Please login.")
                return redirect("/login")

            user = User(
                name=name,
                email=email,
                password_hash=generate_password_hash(password),
                role="user"
            )
            db.add(user)
            db.commit()
            db.refresh(user)

            session["user_id"] = user.id
            session["user_name"] = user.name
            session["role"] = user.role
            return redirect("/")
        finally:
            db.close()

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Invalid email or password.")
                return redirect("/login")

            session["user_id"] = user.id
            session["user_name"] = user.name
            session["role"] = user.role
            return redirect("/")
        finally:
            db.close()

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------- ADMIN AUTH ----------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.email == email).first()
            if not user or not check_password_hash(user.password_hash, password):
                flash("Invalid admin credentials.")
                return redirect("/admin/login")

            if user.role != "admin":
                flash("This account is not an admin.")
                return redirect("/admin/login")

            session["user_id"] = user.id
            session["user_name"] = user.name
            session["role"] = user.role
            return redirect("/admin")
        finally:
            db.close()

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin/login")

# ---------------- APP ROUTES (USER) ----------------
@app.route("/")
@login_required
def home():
    db = SessionLocal()
    try:
        # ✅ Recommended: show only current user's entries
        books = (
            db.query(BookEntry)
            .filter(BookEntry.user_id == session.get("user_id"))
            .order_by(BookEntry.date.desc())
            .all()
        )
        return render_template("index.html", books=books, user_name=session.get("user_name"))
    finally:
        db.close()


@app.route("/add", methods=["POST"])
@login_required
def add():
    member_name = request.form["member_name"].strip()
    date = request.form["date"]
    book_title = request.form["book_title"].strip()
    author = request.form["author"].strip()
    genre = request.form["genre"].strip()
    status = request.form["status"]
    days_raw = request.form.get("days", "").strip()
    days = int(days_raw) if days_raw.isdigit() else 0

    db = SessionLocal()
    try:
        entry = BookEntry(
            user_id=session.get("user_id"),   # ✅ NEW: ownership
            member_name=member_name,
            date=date,
            book_title=book_title,
            author=author,
            genre=genre,
            status=status,
            days=days
        )
        db.add(entry)
        db.commit()
    finally:
        db.close()

    return redirect("/")


# ✅ USER DELETE (only their own entry)
@app.route("/delete/<int:book_id>", methods=["POST"])
@login_required
def delete_entry(book_id):
    db = SessionLocal()
    try:
        entry = db.query(BookEntry).filter(BookEntry.id == book_id).first()

        # Only allow delete if it belongs to logged-in user
        if not entry or entry.user_id != session.get("user_id"):
            return "Not allowed", 403

        db.delete(entry)
        db.commit()
        return redirect("/")
    finally:
        db.close()


@app.route("/analytics")
@login_required
def analytics():
    db = SessionLocal()
    try:
        # ✅ Analytics for only current user's entries
        books = db.query(BookEntry).filter(BookEntry.user_id == session.get("user_id")).all()

        total_entries = len(books)
        borrowed_count = sum(1 for b in books if b.status == "Borrowed")
        returned_count = sum(1 for b in books if b.status == "Returned")
        total_days = sum(int(b.days or 0) for b in books)

        all_genres = []
        for b in books:
            if b.genre:
                all_genres.extend([g.strip() for g in b.genre.split(",") if g.strip()])

        genre_counts = Counter(all_genres)
        labels = list(genre_counts.keys())
        counts = list(genre_counts.values())

        return render_template(
            "analytics.html",
            total_entries=total_entries,
            borrowed_count=borrowed_count,
            returned_count=returned_count,
            total_days=total_days,
            labels=json.dumps(labels),
            counts=json.dumps(counts),
            user_name=session.get("user_name")
        )
    finally:
        db.close()

# ---------------- ADMIN AREA ----------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.id.desc()).all()
        books = db.query(BookEntry).order_by(BookEntry.id.desc()).limit(50).all()
        return render_template(
            "admin_dashboard.html",
            user_name=session.get("user_name"),
            users=users,
            books=books
        )
    finally:
        db.close()

if __name__ == "__main__":
    app.run(debug=True)
