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
