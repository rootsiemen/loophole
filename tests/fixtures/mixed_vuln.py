# Fixture: mixed vulnerabilities — secrets & misc (scanner must flag)
import os

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # SEC004

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
-----END RSA PRIVATE KEY-----"""  # SEC003

# high-entropy token under a secret-like name (SEC005)
token = "xK9#mQ2$vL8@nB4!zR6^tY1&uI3*oP5"

from flask import Flask, request
app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')  # tainted
    return open('/files/' + '../../' + name).read()  # PATH002 (tainted + ..)


@app.after_request
def add_cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'  # CORS001
    return resp


DEBUG = True  # DBG001
