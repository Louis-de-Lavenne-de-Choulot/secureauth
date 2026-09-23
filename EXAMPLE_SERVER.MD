````markdown
```go
module github.com/you/myapp

go 1.26

require (
	github.com/Louis-de-Lavenne-de-Choulot/secureauth v0.0.0
	modernc.org/sqlite v1.33.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	filippo.io/nistec v0.0.4 // indirect
	github.com/bytemare/ecc v0.9.0 // indirect
	github.com/bytemare/hash v0.6.2 // indirect
	github.com/bytemare/hash2curve v0.5.4 // indirect
	github.com/bytemare/ksf v0.5.0 // indirect
	github.com/bytemare/opaque v0.18.0 // indirect
	github.com/bytemare/secp256k1 v0.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gtank/ristretto255 v0.2.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
)

replace github.com/Louis-de-Lavenne-de-Choulot/secureauth => ../secureauth

```

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	secureauth "github.com/Louis-de-Lavenne-de-Choulot/secureauth"
	_ "modernc.org/sqlite"
)

const (
	secretsDir = "secrets"
	tlsDir     = "tls"
	dataDir    = "data"
)

func main() {
	must(os.MkdirAll(secretsDir, 0o700))
	must(os.MkdirAll(tlsDir, 0o700))
	must(os.MkdirAll(dataDir, 0o700))

	masterKey := loadOrGenMasterKey()
	ensureTLSCert()

	certDER, err := os.ReadFile(secretsDir + "/server.crt.der")
	must(err)

	// The OPAQUE server key material is generated and sealed by the library on first boot;
	// The BootstrapToken gates creation of the first user. If left empty, Init
	// generates one and prints it to stdout exactly once.
	sa, err := secureauth.Init("sqlite",
		"file:"+dataDir+"/auth.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
		secureauth.InitOptions{
			MasterKey:      masterKey,
			ServerID:       "secureauth",
			TLSCertificate: certDER,

			// TrustedProxies controls which peers are allowed to set the
			// X-Forwarded-For header that the library uses for client-IP
			// extraction (audit log and rate limiter). When running behind
			// Nginx on the same host, "127.0.0.1/32" and "::1/128" are
			// already trusted by default; you only need to add ranges here
			// if your reverse proxy is on a different machine.
			//
			// TrustedProxies: []string{"10.0.0.0/8", "172.16.0.0/12"},
		})
	must(err)

	// Minimal pages. The library refuses templates that contain their own
	// <script> tags; the server injects the import map + module loader at
	// the placeholder. If you want per-page JS, extend handleIndex in the
	// library to substitute a second placeholder with your page script.
	must(sa.SetLoginPageTemplate(loginHTML))
	must(sa.SetUsersPageTemplate(usersHTML))
	must(sa.SetRolesPageTemplate(rolesHTML))
	must(sa.SetAuthorizationsPageTemplate(authsHTML))

	mux := http.NewServeMux()

	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		// Serve a minimal 1x1 transparent ICO so browsers stop 404-ing.
		ico := "\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00\x68\x04" +
			"\x00\x00\x16\x00\x00\x00\x28\x00\x00\x00\x10\x00\x00\x00\x20\x00" +
			"\x00\x00\x01\x00\x20\x00\x00\x00\x00\x00\x40\x04\x00\x00\x00\x00" +
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
			string(make([]byte, 0x440))
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = io.WriteString(w, ico)
	})

	secureauth.SecureAuthAndCommHandler(sa, mux)

	srv := &http.Server{
		Addr:              "localhost:8443",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}

	log.Println("open https://localhost:8443/login")
	log.Fatal(srv.ListenAndServeTLS(tlsDir+"/server.crt", tlsDir+"/server.key"))
}

// ---- secrets ---------------------------------------------------------------

func loadOrGenMasterKey() []byte {
	path := secretsDir + "/master.key"
	if b, err := os.ReadFile(path); err == nil {
		k, err := hex.DecodeString(string(trimNL(b)))
		must(err)
		if len(k) != 32 {
			log.Fatalf("%s must be 64 hex chars", path)
		}
		return k
	}
	k := make([]byte, 32)
	_, err := rand.Read(k)
	must(err)
	must(os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600))
	log.Printf("generated %s - back this up, it decrypts all sessions", path)
	return k
}

func ensureTLSCert() {
	crtPath, keyPath := tlsDir+"/server.crt", tlsDir+"/server.key"
	if fileExists(crtPath) && fileExists(keyPath) {
		writeCertDER(crtPath)
		return
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	must(err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	must(err)

	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	must(os.WriteFile(crtPath, crtPEM, 0o644))

	keyDER, err := x509.MarshalECPrivateKey(priv)
	must(err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	must(os.WriteFile(keyPath, keyPEM, 0o600))

	writeCertDER(crtPath)
	log.Printf("generated self-signed cert for localhost in %s/", tlsDir)
}

func writeCertDER(crtPath string) {
	pemBytes, err := os.ReadFile(crtPath)
	must(err)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		log.Fatalf("bad PEM in %s", crtPath)
	}
	must(os.WriteFile(secretsDir+"/server.crt.der", block.Bytes, 0o644))
}

// ---- helpers ---------------------------------------------------------------

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 {
		c := b[len(b)-1]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			b = b[:len(b)-1]
			continue
		}
		break
	}
	return b
}

// ---- minimal templates -----------------------------------------------------

var loginHTML = fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
<h1>Sign in</h1>
<form id="f">
  <p><input name="username" placeholder="username" autocomplete="username" required></p>
  <p><input name="password" type="password" placeholder="password" autocomplete="current-password" required></p>
  <p><button type="submit">Sign in</button></p>
</form>
<pre id="out"></pre>
%s
</body></html>`, "{loginjs}")

var usersHTML = fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>Users</title></head>
<body>
<h1>Users</h1><pre id="out">Open devtools - call SecureAuth.getUsers() from the console.</pre>
%s
</body></html>`, "{usersjs}")

var rolesHTML = fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>Roles</title></head>
<body><h1>Roles</h1>%s</body></html>`, "{rolesjs}")

var authsHTML = fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><title>Authorizations</title></head>
<body><h1>Authorizations</h1>%s</body></html>`, "{authorizationsjs}")
```

---

## Running behind a reverse proxy

The example above binds to `localhost:8443` and serves HTTPS directly. That is fine for local development, but in production you almost always want a real reverse proxy on port 443 that terminates TLS with a valid certificate. **Nginx on the same host is the recommended setup.**

### Why the bootstrap endpoint needs special handling

`/api/bootstrap/credentials` is the only endpoint in the library that deliberately restricts *who* can read it, based on the **source IP address** of the HTTP request. It only discloses the first-admin credentials to loopback callers. This is intentional — see the "First-run bootstrap" section of the README — and exists so that an attacker who reaches your server before you do cannot race you for the first login.

When Nginx is in front of the app, every request arrives from `127.0.0.1` (Nginx itself), but Nginx also adds an `X-Forwarded-For` header carrying the *browser's* real IP. The library's `ClientIP()` helper trusts `X-Forwarded-For` from loopback peers, so the effective client IP becomes the browser's public address, and the loopback check fails.

Result: the login page loads, `/api/login/init` works, but the automatic first-admin bootstrap never fires because `/api/bootstrap/credentials` returns `{"available":false}`.

### Fixing it — two options

#### Option A — SSH tunnel (safest)

Leave Nginx in place for normal traffic, but bootstrap the first admin through a direct loopback connection. On your workstation:

```bash
ssh -N -L 8443:127.0.0.1:8443 user@your-server
```

Leave that terminal open, then open `https://127.0.0.1:8443/login` in your browser. Accept the self-signed cert warning (that is the app's own cert, unchanged). The request reaches the Go process directly, `X-Forwarded-For` is absent, the loopback check passes, and the bootstrap completes. Close the tunnel afterwards; `/api/bootstrap/credentials` will permanently return `{"available":false}` once the record is consumed.

#### Option B — Strip `X-Forwarded-For` on the bootstrap endpoint only

Add a dedicated `location` block ahead of `location /`. Nginx runs on the same host as the app, so if you clear the client-IP headers the app sees `r.RemoteAddr == "127.0.0.1"` and the loopback check passes.

```nginx
# Nginx server block for myapp.example.com
# Full config in the README, section 7.

location = /api/bootstrap/credentials {
    proxy_pass https://127.0.0.1:8443;
    proxy_ssl_verify off;
    proxy_ssl_server_name on;
    proxy_http_version 1.1;
    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    # Deliberately clear the client-IP headers so the Go app sees the
    # request as originating from loopback. Without this, the
    # /api/bootstrap/credentials loopback check fails and the automatic
    # first-admin bootstrap never runs.
    proxy_set_header X-Forwarded-For   "";
    proxy_set_header X-Real-IP         "";
}
```

**Trade-off:** while the bootstrap record is unconsumed, anyone who knows the URL can read the first-admin credentials during that window. In practice the window is the few minutes between first `systemctl start` and your first successful login. Complete the bootstrap immediately and it becomes inert. If that window is unacceptable for your threat model, use Option A.

### Full Nginx configuration

See section **7. Deployment behind a reverse proxy** in the README for the complete server block, including WebSocket-safe timeouts, HSTS, and the ACME challenge path.
````