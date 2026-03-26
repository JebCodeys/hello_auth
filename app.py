from flask import Flask, render_template, request, redirect, url_for, session
import os
import cas

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-in-prod")

CAS_SERVER = os.environ.get("CAS_SERVER", "https://netid.uvm.edu/cas")

# Role definitions — configure via environment variables.
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


def get_roles(netid):
    """Return the set of role names assigned to a net-id."""
    if not netid:
        return set()
    return {role for role, members in ROLE_NETIDS.items() if netid in members}


def has_role(netid, role):
    return role in get_roles(netid)


def get_netid():
    return session.get("netid")


def _cas_client():
    service_url = url_for("login", _external=True)
    return cas.CASClient(version=2, server_url=CAS_SERVER, service_url=service_url)


@app.route("/login")
def login():
    # Dev bypass: if DEV_NETID is set, skip CAS entirely
    dev_netid = os.environ.get("DEV_NETID")
    if dev_netid:
        session["netid"] = dev_netid
        return redirect(url_for("index"))

    ticket = request.args.get("ticket")
    client = _cas_client()

    if ticket:
        user, _attributes, _pgtiou = client.verify_ticket(ticket)
        if user:
            session["netid"] = user
            return redirect(url_for("index"))
        return render_template("login.html", error="CAS ticket validation failed."), 401

    return redirect(client.get_login_url())


@app.route("/logout")
def logout():
    session.pop("netid", None)
    client = _cas_client()
    return redirect(client.get_logout_url())


@app.route("/")
def index():
    netid = get_netid()
    if not netid:
        return redirect(url_for("login"))
    return render_template("hello.html", netid=netid, roles=get_roles(netid))


@app.route("/admin")
def admin():
    netid = get_netid()
    if not netid:
        return redirect(url_for("login"))
    if not has_role(netid, "admin"):
        return render_template("forbidden.html", netid=netid, required_role="admin"), 403
    return render_template("admin.html", netid=netid, roles=get_roles(netid))


@app.route("/whoami")
def whoami():
    netid = get_netid()
    return {"netid": netid, "roles": sorted(get_roles(netid))}


if __name__ == "__main__":
    app.run(debug=True, port=5001)
