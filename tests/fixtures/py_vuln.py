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


# --- 2026 expansion: new-rule coverage ---
import pickle
import yaml
import zipfile
import ssl
import re
import ldap
import xml.dom.minidom
import jwt
from flask import redirect
from pymongo import MongoClient

blob = pickle.loads(data)  # DESER001
cfg = yaml.load(text)  # DESER001 (no SafeLoader)

zipfile.ZipFile(f).extractall('/tmp/out')  # ZIP001

users = MongoClient().db.users


@app.route('/find')
def find():
    return str(users.find_one({"user": request.args.get('u')}))  # NOSQL001


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['doc']  # UPL001
    f.save('/uploads/' + f.filename)
    return "saved"


@app.route('/go')
def go():
    return redirect(request.args.get('next'))  # REDIR001


payload = jwt.decode(tok, "secret", algorithms=["none"])  # JWT002

ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # TLS002

cipher = AES.new(key, AES.MODE_ECB)  # CRY005


def log_attempt(token):
    app.logger.info("login token: " + token)  # LOG001


def ldap_lookup(user):
    return conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, "(uid=" + user + ")")  # LDAP001


EMAIL_RE = re.compile(r"(a+)+$")  # REDOS001

doc = xml.dom.minidom.parseString(xml_data)  # XXE001
