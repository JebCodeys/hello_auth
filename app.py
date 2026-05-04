from flask import Flask, render_template, request, redirect, url_for, session
import os
import cas
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-in-prod")

CAS_SERVER = os.environ.get("CAS_SERVER", "https://netid.uvm.edu/cas")
DB_PATH = os.environ.get("LOCAL_USERS_DB", os.path.join(os.path.dirname(__file__), "users.db"))

# CAS role definitions — configure via environment variables.
# Each role is a comma-separated list of net-ids:
#   ADMIN_NETIDS=abc123,xyz789
#   MODERATOR_NETIDS=def456
ROLE_NETIDS = {
    role: set(
        netid.strip()
        for netid in os.environ.get(f"{role.upper()}_NETIDS", "").split(",")
        if netid.strip()
    )
    for role in ["admin", "moderator"]
}


# --- Local user DB ---

def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS local_users (
                username      TEXT PRIMARY KEY,
                email         TEXT DEFAULT '',
                password_hash TEXT NOT NULL,
                roles         TEXT DEFAULT ''
            )
        """)
        conn.commit()
    _seed_users()


def _seed_users():
    # SEED_USERS=username:password:roles;username2:password2:roles2
    # Roles are comma-separated, e.g. viewer,moderator
    seed = os.environ.get("SEED_USERS", "")
    if not seed:
        return
    with _db() as conn:
        for entry in seed.split(";"):
            parts = entry.strip().split(":")
            if len(parts) < 2:
                continue
            username, password = parts[0].strip(), parts[1].strip()
            roles = parts[2].strip() if len(parts) > 2 else ""
            exists = conn.execute(
                "SELECT 1 FROM local_users WHERE username = ?", (username,)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO local_users (username, email, password_hash, roles) VALUES (?, ?, ?, ?)",
                    (username, "", generate_password_hash(password), roles),
                )
        conn.commit()


def create_local_user(username, password, email="", roles=""):
    with _db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO local_users (username, email, password_hash, roles) VALUES (?, ?, ?, ?)",
            (username, email, generate_password_hash(password), roles),
        )
        conn.commit()


def list_local_users():
    with _db() as conn:
        return conn.execute(
            "SELECT username, email, roles FROM local_users ORDER BY username"
        ).fetchall()


def delete_local_user(username):
    with _db() as conn:
        conn.execute("DELETE FROM local_users WHERE username = ?", (username,))
        conn.commit()


def verify_local_user(username, password):
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM local_users WHERE username = ?", (username,)
        ).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        return row
    return None


def _get_local_roles(username):
    with _db() as conn:
        row = conn.execute(
            "SELECT roles FROM local_users WHERE username = ?", (username,)
        ).fetchone()
    if not row or not row["roles"]:
        return set()
    return {r.strip() for r in row["roles"].split(",") if r.strip()}


# --- Auth helpers ---

def current_user():
    """Return session user dict {id, type} or None."""
    return session.get("user")


def current_user_id():
    u = current_user()
    return u["id"] if u else None


def get_roles():
    u = current_user()
    if not u:
        return set()
    if u["type"] == "local":
        return _get_local_roles(u["id"])
    return {role for role, members in ROLE_NETIDS.items() if u["id"] in members}


def has_role(role):
    return role in get_roles()


def _cas_client():
    service_url = url_for("login", _external=True)
    return cas.CASClient(version=2, server_url=CAS_SERVER, service_url=service_url)


# --- Routes ---

@app.route("/login", methods=["GET", "POST"])
def login():
    # Dev bypass: if DEV_NETID is set, skip CAS entirely
    dev_netid = os.environ.get("DEV_NETID")
    if dev_netid:
        session["user"] = {"id": dev_netid, "type": "cas"}
        return redirect(url_for("index"))

    ticket = request.args.get("ticket")
    action = request.args.get("action")
    client = _cas_client()

    if ticket:
        user, _attributes, _pgtiou = client.verify_ticket(ticket)
        if user:
            session["user"] = {"id": user, "type": "cas"}
            return redirect(url_for("index"))
        return render_template("login.html", error="CAS ticket validation failed."), 401

    if action == "cas":
        return redirect(client.get_login_url())

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        local = verify_local_user(username, password)
        if local:
            session["user"] = {"id": username, "type": "local"}
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid username or password."), 401

    return render_template("login.html")


@app.route("/logout")
def logout():
    u = current_user()
    session.pop("user", None)
    if u and u.get("type") == "cas":
        client = _cas_client()
        return redirect(client.get_logout_url())
    return redirect(url_for("login"))


@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    return render_template("hello.html", user=u, roles=get_roles())


@app.route("/admin")
def admin():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    if not has_role("admin"):
        return render_template("forbidden.html", user_id=u["id"], required_role="admin"), 403
    return render_template("admin.html", user=u, roles=get_roles(), local_users=list_local_users())


@app.route("/admin/users", methods=["POST"])
def admin_create_user():
    u = current_user()
    if not u or not has_role("admin"):
        uid = u["id"] if u else "?"
        return render_template("forbidden.html", user_id=uid, required_role="admin"), 403
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip()
    roles = request.form.get("roles", "").strip()
    if username and password:
        create_local_user(username, password, email, roles)
    return redirect(url_for("admin"))


@app.route("/admin/users/<username>/delete", methods=["POST"])
def admin_delete_user(username):
    u = current_user()
    if not u or not has_role("admin"):
        uid = u["id"] if u else "?"
        return render_template("forbidden.html", user_id=uid, required_role="admin"), 403
    delete_local_user(username)
    return redirect(url_for("admin"))


@app.route("/whoami")
def whoami():
    return {"user": current_user(), "roles": sorted(get_roles())}


init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5001)
