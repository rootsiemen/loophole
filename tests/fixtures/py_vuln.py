# Fixture: vulnerable Python (intentionally insecure — scanner must flag)
import os
import subprocess
import hashlib
import random
import requests
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "s3cr3t-p@ssw0rd-2024"  # SEC002


def get_user(uid):
    q = f"SELECT * FROM users WHERE id = {uid}"  # SQLI002 via formatted var
    cursor.execute(q)


def get_order(oid):
    cursor.execute("SELECT * FROM orders WHERE id = %s" % oid)  # SQLI002 % format


@app.route('/run')
def run():
    cmd = request.args.get('cmd')  # tainted
    os.system("ping -c1 " + cmd)  # CMD002 critical (tainted)
    return "ok"


@app.route('/convert')
def convert():
    src = request.args.get('src')  # tainted
    subprocess.run("convert " + src + " out.png", shell=True)  # CMD002


@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')  # tainted
    r = requests.get(url, verify=False)  # SSRF001 + TLS001
    return r.text


@app.route('/read')
def read():
    name = request.args.get('file')  # tainted
    return open('/data/' + name).read()  # PATH001 (tainted)


@app.route('/calc')
def calc():
    expr = request.args.get('expr')  # tainted
    return str(eval(expr))  # EVAL001 critical (tainted)


def make_otp():
    return str(random.randint(100000, 999999))  # RAND002


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # CRY001 password hash


@app.route('/admin/panel')
def admin_panel():  # vuln: no access control here
    return "secret admin stuff"


if __name__ == '__main__':
    app.run(debug=True)  # DBG001
