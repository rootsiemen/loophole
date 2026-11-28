# Fixture: clean Python — the scanner must report ZERO findings here.
import os
import subprocess
import hashlib
import secrets
import requests
from flask import Flask, request
from flask_wtf.csrf import CSRFProtect
from functools import wraps

app = Flask(__name__)
CSRFProtect(app)


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp

DB_PASSWORD = os.environ["DB_PASSWORD"]


def login_required(f):
    @wraps(f)
    def decorated(*a, **k):
        # session check happens here
        return f(*a, **k)
    return decorated


@app.route('/admin/panel')
@login_required
def admin_panel():
    return "ok"


def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))


def get_order(oid):
    cursor.execute("SELECT * FROM orders WHERE id = %s", (oid,))


@app.route('/run')
def run():
    subprocess.run(["/usr/bin/ping", "-c1", "example.com"], shell=False)
    return "ok"


def run_literal():
    exec("x = 1")  # EVAL001-safe: literal string, not dynamic
    compile("x = 1", "<s>", "exec")  # EVAL001-safe: literal source


@app.route('/fetch')
def fetch_url():
    r = requests.get("https://api.example.com/data", timeout=10)
    return r.text


@app.route('/read')
def read():
    return open("/data/static.txt").read()


def make_otp():
    return str(secrets.randbelow(900000) + 100000)


def hash_pw(pw):
    # Argon2/bcrypt in real code; sha256 shown only as non-password demo
    return hashlib.sha256(b"static-pepper" + pw.encode()).hexdigest()


@app.route('/calc')
def calc():
    try:
        return str(float(request.args.get('n', '0')) * 2)
    except ValueError:
        return "bad number", 400


if __name__ == '__main__':
    app.run(host="127.0.0.1")


# --- 2026 expansion: safe counterparts (must stay silent) ---
import re
import yaml
import zipfile
from werkzeug.utils import secure_filename

cfg = yaml.safe_load(text)  # DESER001-safe
cfg2 = yaml.load(text, Loader=yaml.SafeLoader)  # DESER001-safe


def unzip(zf, dest):
    for name in zf.namelist():
        target = os.path.abspath(os.path.join(dest, name))
        root = os.path.abspath(dest)
        if os.path.commonpath([target, root]) == root:
            zf.extract(name, dest)  # ZIP001-safe: path-validated


ALLOWED_EXTENSIONS = {"pdf", "png"}


def allowed_file(name):
    return "." in name and \
        name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    f = request.files.get('doc')
    if f and allowed_file(f.filename):  # UPL001-safe: allowlist checked
        f.save('/uploads/' + secure_filename(f.filename))
    return "ok"


DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")  # REDOS001-safe


# --- Issue #6: Django / FastAPI taint sources (safe counterparts) ---
# Django: tainted input used only as a query parameter, never in the SQL text.
def django_get_user_safe(request):
    uid = request.GET["id"]
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))  # SQLI002-safe


# FastAPI: same, via request.query_params.
async def fastapi_get_safe(request):
    name = request.query_params["name"]
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))  # SQLI002-safe


# Django: tainted input passed as a subprocess argument list, no shell.
def django_run_safe(request):
    cmd = request.POST["cmd"]
    subprocess.run(["/usr/bin/echo", cmd], shell=False)  # CMD002-safe
