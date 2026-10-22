// Fixture: clean Go — the scanner must report ZERO findings here.
package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"math/big"
	"net/http"
	"os/exec"
	"regexp"
)

var db *sql.DB

func getUser(id string) {
	db.Query("SELECT * FROM users WHERE id = $1", id) // parameterized
}

func handle(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id") // tainted but safely parameterized
	db.QueryRow("SELECT * FROM t WHERE id = $1", id)
}

func runIt() {
	exec.Command("/usr/bin/ls", "-la").Run() // direct binary, no shell
}

func strongCrypto(key []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	_ = block
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil { // random IV
		return
	}
}

func makeToken() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return ""
	}
	return n.String()
}

func secureClient() {
	tr := &http.Transport{}
	_ = tr
	_ = http.DefaultClient
}

// --- 2026 expansion: safe counterparts (must stay silent) ---
var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`) // REDOS001-safe

func modernTLSClient() {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}} // TLS002-safe
	_ = tr
}
