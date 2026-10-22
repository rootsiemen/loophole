// Fixture: vulnerable Go (intentionally insecure — scanner must flag)
package main

import (
	"crypto/des"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os/exec"
	"regexp"
)

var db *sql.DB

func getUser(name string) {
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name) // SQLI003
	db.Query(q)
}

func handle(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id") // tainted
	db.Query("SELECT * FROM t WHERE id = " + id) // SQLI003 concat (tainted)
}

func runIt(userCmd string) {
	exec.Command("sh", "-c", userCmd).Run() // CMD003 critical
}

func weakCrypto() {
	block, _ := des.NewCipher([]byte("12345678")) // CRY003
	_ = block
	iv := []byte("0123456789abcdef") // CRY004 hardcoded IV
	_ = iv
}

func makeToken() string {
	token := fmt.Sprintf("%06d", rand.Intn(1000000)) // RAND003
	return token
}

func insecureClient() {
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // TLS001
	_ = tr
}

// --- 2026 expansion: new-rule coverage ---
func oldTLSClient() {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10}} // TLS002
	_ = tr
}

var emailRe = regexp.MustCompile(`^(a+)+$`) // REDOS001

func logToken(token string) {
	log.Printf("user token: %s", token) // LOG001
}
