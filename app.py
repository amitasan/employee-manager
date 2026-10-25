"""Employee Management System - admin-only CRUD with authentication and validation.

Run:  pip install -r requirements.txt && python app.py
"""
import os
import re
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("EMS_DB", os.path.join(BASE_DIR, "employees.db"))
PER_PAGE = 10
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
DEPARTMENTS = ["Engineering", "Finance", "Human Resources", "Marketing",
               "Operations", "Sales", "Support"]
STATUSES = ["Active", "Inactive"]

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FORCE_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=64 * 1024,
)

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);
CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT,
    department TEXT NOT NULL,
    position TEXT NOT NULL,
    salary TEXT NOT NULL,
    hire_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    admin TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    if db.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
        username = os.environ.get("ADMIN_USERNAME", "admin")
        password = os.environ.get("ADMIN_PASSWORD")
        generated = password is None
        if generated:
            password = secrets.token_urlsafe(12)
        db.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                   (username, generate_password_hash(password)))
        db.commit()
        if generated:
            print("=" * 60)
            print(f"  First-run admin created.  Username: {username}")
            print(f"  Password: {password}   (shown once - save it)")
            print("=" * 60)
    db.commit()
    db.close()


def audit(action, detail=""):
    get_db().execute("INSERT INTO audit_log (admin, action, detail) VALUES (?, ?, ?)",
                     (session.get("admin", "?"), action, detail))


# --------------------------------------------------------------------------
# Security: CSRF, auth, headers
# --------------------------------------------------------------------------
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, "Invalid or missing CSRF token.")


@app.before_request
def keep_session_fresh():
    session.permanent = True  # sliding 30-minute idle timeout


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "admin" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'")
    return resp


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z '\-.]{0,49}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9 ()\-]{7,20}$")
POSITION_RE = re.compile(r"^[A-Za-z0-9 &/,.\-]{2,80}$")


def validate_employee(form, employee_id=None):
    """Return (clean_values, errors). Never trust the client."""
    f = {k: (form.get(k) or "").strip() for k in
         ("first_name", "last_name", "email", "phone", "department",
          "position", "salary", "hire_date", "status")}
    errors = {}

    for key, label in (("first_name", "First name"), ("last_name", "Last name")):
        if not f[key]:
            errors[key] = f"{label} is required."
        elif not NAME_RE.match(f[key]):
            errors[key] = f"{label} must be 1-50 letters (spaces, - ' . allowed)."

    f["email"] = f["email"].lower()
    if not f["email"]:
        errors["email"] = "Email is required."
    elif len(f["email"]) > 120 or not EMAIL_RE.match(f["email"]):
        errors["email"] = "Enter a valid email address."
    else:
        row = get_db().execute("SELECT id FROM employees WHERE email = ?",
                               (f["email"],)).fetchone()
        if row and row["id"] != employee_id:
            errors["email"] = "Another employee already uses this email."

    if f["phone"] and (not PHONE_RE.match(f["phone"])
                       or not 7 <= sum(c.isdigit() for c in f["phone"]) <= 15):
        errors["phone"] = "Phone must contain 7-15 digits (+, spaces, - and () allowed)."

    if f["department"] not in DEPARTMENTS:
        errors["department"] = "Choose a department from the list."

    if not POSITION_RE.match(f["position"]):
        errors["position"] = "Position must be 2-80 characters (letters, digits, & / , . -)."

    try:
        salary = Decimal(f["salary"])
        if not salary.is_finite() or salary < 0 or salary > Decimal("10000000"):
            raise InvalidOperation
        if salary != salary.quantize(Decimal("0.01")):
            errors["salary"] = "Salary can have at most 2 decimal places."
        f["salary"] = str(salary.quantize(Decimal("0.01")))
    except InvalidOperation:
        errors.setdefault("salary", "Salary must be a number between 0 and 10,000,000.")

    try:
        hired = datetime.strptime(f["hire_date"], "%Y-%m-%d").date()
        if hired > date.today():
            errors["hire_date"] = "Hire date cannot be in the future."
        elif hired.year < 1950:
            errors["hire_date"] = "Hire date is too far in the past."
    except ValueError:
        errors["hire_date"] = "Enter a valid date (YYYY-MM-DD)."

    if f["status"] not in STATUSES:
        errors["status"] = "Invalid status."

    return f, errors


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        db = get_db()
        admin = db.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        now = datetime.utcnow()
        generic = "Invalid username or password."

        if admin and admin["locked_until"] and datetime.fromisoformat(admin["locked_until"]) > now:
            flash(f"Account locked after repeated failures. Try again in {LOCKOUT_MINUTES} minutes.", "error")
        elif admin and check_password_hash(admin["password_hash"], password):
            db.execute("UPDATE admins SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                       (admin["id"],))
            db.commit()
            session.clear()  # prevent session fixation
            session["admin"] = admin["username"]
            csrf_token()
            audit("login")
            db.commit()
            return redirect(url_for("index"))
        else:
            if admin:
                attempts = admin["failed_attempts"] + 1
                locked = None
                if attempts >= MAX_FAILED_LOGINS:
                    locked = (now + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                    attempts = 0
                db.execute("UPDATE admins SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                           (attempts, locked, admin["id"]))
                db.commit()
            else:
                check_password_hash(generate_password_hash("x"), password)  # equalise timing
            flash(generic, "error")
        return render_template("login.html"), 401
    if "admin" in session:
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout")
    get_db().commit()
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Employee CRUD
# --------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    q = (request.args.get("q") or "").strip()[:60]
    dept = request.args.get("department", "")
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    where, params = [], []
    if q:
        like = f"%{q}%"
        where.append("(first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR position LIKE ?)")
        params += [like] * 4
    if dept in DEPARTMENTS:
        where.append("department = ?")
        params.append(dept)
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM employees {clause}", params).fetchone()[0]
    pages = max(1, -(-total // PER_PAGE))
    page = min(page, pages)
    rows = db.execute(
        f"SELECT * FROM employees {clause} ORDER BY last_name, first_name LIMIT ? OFFSET ?",
        params + [PER_PAGE, (page - 1) * PER_PAGE]).fetchall()
    return render_template("index.html", employees=rows, q=q, dept=dept, page=page,
                           pages=pages, total=total, departments=DEPARTMENTS)


@app.route("/employees/new", methods=["GET", "POST"])
@login_required
def create_employee():
    values, errors = {"status": "Active"}, {}
    if request.method == "POST":
        values, errors = validate_employee(request.form)
        if not errors:
            db = get_db()
            try:
                cur = db.execute(
                    "INSERT INTO employees (first_name, last_name, email, phone, department,"
                    " position, salary, hire_date, status) VALUES (?,?,?,?,?,?,?,?,?)",
                    (values["first_name"], values["last_name"], values["email"],
                     values["phone"] or None, values["department"], values["position"],
                     values["salary"], values["hire_date"], values["status"]))
                audit("create", f"employee #{cur.lastrowid}")
                db.commit()
                flash("Employee created.", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                errors["email"] = "Another employee already uses this email."
        return render_template("form.html", v=values, errors=errors, mode="create",
                               departments=DEPARTMENTS, statuses=STATUSES), 400
    return render_template("form.html", v=values, errors=errors, mode="create",
                           departments=DEPARTMENTS, statuses=STATUSES)


def get_employee_or_404(employee_id):
    row = get_db().execute("SELECT * FROM employees WHERE id = ?", (employee_id,)).fetchone()
    if row is None:
        abort(404)
    return row


@app.route("/employees/<int:employee_id>")
@login_required
def view_employee(employee_id):
    return render_template("view.html", e=get_employee_or_404(employee_id))


@app.route("/employees/<int:employee_id>/edit", methods=["GET", "POST"])
@login_required
def edit_employee(employee_id):
    emp = get_employee_or_404(employee_id)
    if request.method == "POST":
        values, errors = validate_employee(request.form, employee_id)
        if not errors:
            db = get_db()
            try:
                db.execute(
                    "UPDATE employees SET first_name=?, last_name=?, email=?, phone=?,"
                    " department=?, position=?, salary=?, hire_date=?, status=?,"
                    " updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (values["first_name"], values["last_name"], values["email"],
                     values["phone"] or None, values["department"], values["position"],
                     values["salary"], values["hire_date"], values["status"], employee_id))
                audit("update", f"employee #{employee_id}")
                db.commit()
                flash("Employee updated.", "success")
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                errors["email"] = "Another employee already uses this email."
        return render_template("form.html", v=values, errors=errors, mode="edit", e=emp,
                               departments=DEPARTMENTS, statuses=STATUSES), 400
    return render_template("form.html", v=dict(emp), errors={}, mode="edit", e=emp,
                           departments=DEPARTMENTS, statuses=STATUSES)


@app.route("/employees/<int:employee_id>/delete", methods=["POST"])
@login_required
def delete_employee(employee_id):
    get_employee_or_404(employee_id)
    db = get_db()
    db.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
    audit("delete", f"employee #{employee_id}")
    db.commit()
    flash("Employee deleted.", "success")
    return redirect(url_for("index"))


@app.route("/audit")
@login_required
def audit_view():
    rows = get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 100").fetchall()
    return render_template("audit.html", rows=rows)


@app.errorhandler(400)
@app.errorhandler(404)
def handle_error(err):
    return render_template("error.html", err=err), err.code


# --------------------------------------------------------------------------
# Templates (inline so the project is a single file)
# --------------------------------------------------------------------------
BASE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}Employee Manager{% endblock %}</title>
<style>
:root{--bg:#f5f6f8;--card:#fff;--ink:#1d2330;--mute:#667085;--line:#e3e6ec;--brand:#2f5bea;--bad:#c62828;--good:#1b7f4b}
@media(prefers-color-scheme:dark){:root{--bg:#12151c;--card:#1b1f29;--ink:#e8ebf2;--mute:#9aa3b5;--line:#2c3240;--brand:#6b8cff;--bad:#ff6b6b;--good:#4cd18a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
header{background:var(--card);border-bottom:1px solid var(--line);padding:12px 20px;display:flex;gap:16px;align-items:center}
header a.brand{font-weight:700;color:var(--ink);text-decoration:none;margin-right:auto}
header a{color:var(--mute);text-decoration:none}main{max-width:1000px;margin:24px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mute);font-weight:600;font-size:13px}
input,select{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
label{display:block;font-weight:600;margin-bottom:4px}.field{margin-bottom:14px}.err{color:var(--bad);font-size:13px;margin-top:3px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}@media(max-width:640px){.grid{grid-template-columns:1fr}}
.btn{display:inline-block;padding:8px 14px;border-radius:6px;border:1px solid var(--brand);background:var(--brand);color:#fff;text-decoration:none;cursor:pointer;font:inherit}
.btn.ghost{background:transparent;color:var(--brand)}.btn.danger{background:var(--bad);border-color:var(--bad)}.btn.sm{padding:3px 9px;font-size:13px}
.flash{padding:10px 14px;border-radius:6px;margin-bottom:14px;border:1px solid var(--line)}.flash.success{color:var(--good)}.flash.error{color:var(--bad)}
.bar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}.bar input{flex:1;min-width:160px}.bar select{width:auto}
.badge{font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid var(--line)}.row-actions{display:flex;gap:6px;white-space:nowrap}
form.inline{display:inline}.pager{display:flex;gap:10px;align-items:center;justify-content:center;margin-top:14px}
dl{display:grid;grid-template-columns:140px 1fr;gap:8px 12px}dt{color:var(--mute)}
</style></head><body>
<header><a class="brand" href="{{ url_for('index') }}">Employee Manager</a>
{% if session.admin %}<a href="{{ url_for('audit_view') }}">Audit log</a><span style="color:var(--mute)">{{ session.admin }}</span>
<form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<button class="btn ghost sm">Sign out</button></form>{% endif %}</header>
<main>{% for cat, msg in get_flashed_messages(with_categories=true) %}<div class="flash {{ cat }}">{{ msg }}</div>{% endfor %}
{% block body %}{% endblock %}</main></body></html>"""

LOGIN = """{% extends 'base.html' %}{% block title %}Sign in{% endblock %}{% block body %}
<div class="card" style="max-width:380px;margin:60px auto"><h2 style="margin-top:0">Administrator sign in</h2>
<form method="post" autocomplete="off"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<div class="field"><label for="u">Username</label><input id="u" name="username" required maxlength="50" autofocus></div>
<div class="field"><label for="p">Password</label><input id="p" name="password" type="password" required maxlength="128"></div>
<button class="btn" style="width:100%">Sign in</button></form></div>{% endblock %}"""

INDEX = """{% extends 'base.html' %}{% block body %}
<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
<h2 style="margin:0">Employees <span style="color:var(--mute);font-size:14px">({{ total }})</span></h2>
<a class="btn" href="{{ url_for('create_employee') }}">+ Add employee</a></div>
<form class="bar" method="get"><input name="q" value="{{ q }}" placeholder="Search name, email, position">
<select name="department"><option value="">All departments</option>
{% for d in departments %}<option {{ 'selected' if d == dept }}>{{ d }}</option>{% endfor %}</select>
<button class="btn ghost">Filter</button></form>
{% if employees %}<div style="overflow-x:auto"><table><tr><th>Name</th><th>Email</th><th>Department</th><th>Position</th><th>Status</th><th></th></tr>
{% for e in employees %}<tr><td><a href="{{ url_for('view_employee', employee_id=e.id) }}">{{ e.first_name }} {{ e.last_name }}</a></td>
<td>{{ e.email }}</td><td>{{ e.department }}</td><td>{{ e.position }}</td><td><span class="badge">{{ e.status }}</span></td>
<td class="row-actions"><a class="btn ghost sm" href="{{ url_for('edit_employee', employee_id=e.id) }}">Edit</a>
<form class="inline" method="post" action="{{ url_for('delete_employee', employee_id=e.id) }}"
 onsubmit="return confirm('Delete {{ e.first_name|e }} {{ e.last_name|e }}? This cannot be undone.')">
<input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="btn danger sm">Delete</button></form></td></tr>{% endfor %}</table></div>
<div class="pager">{% if page > 1 %}<a href="{{ url_for('index', q=q, department=dept, page=page-1) }}">&larr; Prev</a>{% endif %}
<span>Page {{ page }} of {{ pages }}</span>
{% if page < pages %}<a href="{{ url_for('index', q=q, department=dept, page=page+1) }}">Next &rarr;</a>{% endif %}</div>
{% else %}<p style="color:var(--mute)">No employees found.</p>{% endif %}</div>{% endblock %}"""

FORM = """{% extends 'base.html' %}{% block body %}
{% macro fld(name, label, type='text', req=True) %}<div class="field"><label for="{{ name }}">{{ label }}</label>
<input id="{{ name }}" name="{{ name }}" type="{{ type }}" value="{{ v.get(name) or '' }}" {{ 'required' if req }}
{% if name == 'salary' %}step="0.01" min="0" max="10000000"{% endif %}{% if name == 'hire_date' %}max="{{ today }}"{% endif %}>
{% if errors.get(name) %}<div class="err">{{ errors[name] }}</div>{% endif %}</div>{% endmacro %}
<div class="card"><h2 style="margin-top:0">{{ 'Edit' if mode == 'edit' else 'Add' }} employee</h2>
<form method="post" novalidate><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><div class="grid">
{{ fld('first_name','First name') }}{{ fld('last_name','Last name') }}{{ fld('email','Email','email') }}{{ fld('phone','Phone (optional)','tel',False) }}
<div class="field"><label for="department">Department</label><select id="department" name="department">
<option value="">Select...</option>{% for d in departments %}<option {{ 'selected' if v.get('department') == d }}>{{ d }}</option>{% endfor %}</select>
{% if errors.get('department') %}<div class="err">{{ errors['department'] }}</div>{% endif %}</div>
{{ fld('position','Position') }}{{ fld('salary','Annual salary','number') }}{{ fld('hire_date','Hire date','date') }}
<div class="field"><label for="status">Status</label><select id="status" name="status">
{% for s in statuses %}<option {{ 'selected' if v.get('status') == s }}>{{ s }}</option>{% endfor %}</select>
{% if errors.get('status') %}<div class="err">{{ errors['status'] }}</div>{% endif %}</div></div>
<button class="btn">Save</button> <a class="btn ghost" href="{{ url_for('index') }}">Cancel</a></form></div>{% endblock %}"""

VIEW = """{% extends 'base.html' %}{% block body %}<div class="card">
<h2 style="margin-top:0">{{ e.first_name }} {{ e.last_name }}</h2><dl>
<dt>Email</dt><dd>{{ e.email }}</dd><dt>Phone</dt><dd>{{ e.phone or '-' }}</dd><dt>Department</dt><dd>{{ e.department }}</dd>
<dt>Position</dt><dd>{{ e.position }}</dd><dt>Salary</dt><dd>{{ '{:,.2f}'.format(e.salary|float) }}</dd>
<dt>Hire date</dt><dd>{{ e.hire_date }}</dd><dt>Status</dt><dd>{{ e.status }}</dd>
<dt>Last updated</dt><dd>{{ e.updated_at }} UTC</dd></dl>
<a class="btn" href="{{ url_for('edit_employee', employee_id=e.id) }}">Edit</a>
<a class="btn ghost" href="{{ url_for('index') }}">Back</a></div>{% endblock %}"""

AUDIT = """{% extends 'base.html' %}{% block body %}<div class="card"><h2 style="margin-top:0">Audit log</h2>
<table><tr><th>Time (UTC)</th><th>Admin</th><th>Action</th><th>Detail</th></tr>
{% for r in rows %}<tr><td>{{ r.at }}</td><td>{{ r.admin }}</td><td>{{ r.action }}</td><td>{{ r.detail }}</td></tr>{% endfor %}</table>
<p><a href="{{ url_for('index') }}">&larr; Back</a></p></div>{% endblock %}"""

ERROR = """{% extends 'base.html' %}{% block body %}<div class="card"><h2 style="margin-top:0">{{ err.code }} - {{ err.name }}</h2>
<p>{{ err.description }}</p><a href="{{ url_for('index') }}">Back to employees</a></div>{% endblock %}"""

app.jinja_loader = DictLoader({
    "base.html": BASE, "login.html": LOGIN, "index.html": INDEX, "form.html": FORM,
    "view.html": VIEW, "audit.html": AUDIT, "error.html": ERROR})
app.jinja_env.globals["today"] = lambda: date.today().isoformat()


@app.context_processor
def inject_today():
    return {"today": date.today().isoformat()}


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)),
            debug=os.environ.get("FLASK_DEBUG") == "1")
