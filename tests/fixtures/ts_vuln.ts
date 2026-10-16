// Fixture: vulnerable TypeScript — taint flows (intentionally insecure)
import express from 'express';
import * as fs from 'fs';

const app = express();

app.get('/search', (req, res) => {
  const q = req.query.q as string; // tainted
  db.query(`SELECT * FROM items WHERE name LIKE '%${q}%'`, (e, r) => { // SQLI001
    res.json(r);
  });
});

app.get('/fetch', (req, res) => {
  const target = req.query.url as string; // tainted
  fetch(target).then(() => res.send('ok')); // SSRF001 (tainted)
});

app.get('/read', (req, res) => {
  const f = req.query.file as string; // tainted
  fs.readFile('/data/' + f, 'utf8', (e, d) => res.send(d)); // PATH001 (tainted)
});

app.get('/walk', (req, res) => {
  const f = req.query.file as string; // tainted
  fs.readFile('/data/' + '../' + f, 'utf8', (e, d) => res.send(d)); // PATH002
});
