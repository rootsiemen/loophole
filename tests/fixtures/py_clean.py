# Fixture: clean Python — the scanner must report ZERO findings here.
import os
import subprocess
import hashlib
import secrets
import requests
from flask import Flask, request
from functools import wraps

app = Flask(__name__)

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
