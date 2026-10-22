// Fixture: vulnerable JavaScript (intentionally insecure — scanner must flag)
const express = require('express');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

const API_KEY = "sk-live-9f2k4m7q8w3e5r6t7y2u9i4o6p1"; // SEC001
const app = express();

app.get('/search', (req, res) => {
  const q = req.query.q;
  db.query("SELECT * FROM users WHERE name = '" + q + "'", (err, rows) => { // SQLI001
    res.json(rows);
  });
});

app.get('/admin/users', (req, res) => { // vuln: exposed admin route
  res.json(allUsers);
});

app.get('/profile', (req, res) => {
  const bio = req.body.bio;
  document.getElementById('bio').innerHTML = bio; // XSS001 (tainted)
});

app.get('/page', (req, res) => {
  const el = document.createElement('div');
  el.innerHTML = '<b>static</b>'; // OK — static literal, must NOT flag
  res.send('ok');
});

app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  exec(cmd, (err, out) => res.send(out)); // CMD001 critical (tainted)
});

app.get('/calc', (req, res) => {
  res.send(String(eval(req.query.expr))); // EVAL001 critical (tainted)
});

app.get('/me', (req, res) => {
  const token = jwt.decode(req.headers.authorization); // JWT001
  if (token && token.admin) return res.json({ ok: true });
  res.status(403).end();
});

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // CORS001
  next();
});

const https = require('https');
https.get('https://internal/api', { rejectUnauthorized: false }); // TLS001

app.get('/boom', (req, res) => {
  try { risky(); } catch (err) { res.status(500).send(err.stack); } // ERR001
});

function makeSessionToken() {
  return Math.random().toString(36).slice(2); // RAND001
}

function renderBio(bio) {
  return '<div dangerouslySetInnerHTML={{ __html: bio }} />'; // XSS003
}

// --- 2026 expansion: new-rule coverage ---
const _ = require('lodash');
_.merge({}, req.body); // PROTO001

app.post('/login', (req, res) => { // NOSQL001
  User.findOne({ user: req.body.user, pass: req.body.pass }, (err, u) => {
    res.json({ ok: !!u });
  });
});

app.get('/go', (req, res) => {
  res.redirect(req.query.next); // REDIR001
});

const weakToken = jwt.verify(req.body.tok, 'secret',
  { algorithms: ['none', 'HS256'] }); // JWT002

const multer = require('multer');
const upload = multer({ dest: 'uploads/' }); // UPL001

const EMAIL_RE = /(a+)+$/; // REDOS001

function debugLogin(password) {
  console.log('login attempt for', password); // LOG001
}

const AdmZip = require('adm-zip');
new AdmZip('up.zip').extractAllTo('/tmp/out', true); // ZIP001

const tlsOpts = { minVersion: 'TLSv1.1' }; // TLS002

const crypto2 = require('crypto');
const ecbCipher = crypto2.createCipheriv('aes-256-ecb', key, null); // CRY005

const ldapClient = require('ldapjs').createClient({ url: 'ldap://dc' });
app.post('/directory', (req, res) => {
  ldapClient.search('dc=example,dc=com', { filter: `(uid=${req.body.user})` }, () => {}); // LDAP001
});
