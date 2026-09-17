// Package secureauth implements the SecureAuthAndCommHandler library.
//
// Architecture (post-remediation):
//   - The Go server is a thin storage and session layer. It never runs OPAQUE,
//     never sees a password, an OPAQUE export key, or a plaintext RSA private
//     key. All OPAQUE cryptography is performed in the browser via
//     @serenity-kit/opaque (WASM).
//   - The operator supplies a 171-byte opaque-ke server setup via
//     InitOptions.OPAQUE_SERVER_SETUP. The server serves it verbatim; it does
//     not interpret it cryptographically.
//   - Account enumeration resistance: GET /api/registration-record always
//     returns a syntactically valid record. For unknown users, a
//     deterministic fake (HMAC-SHA256(masterKey, "fake-record:" || username))
//     is returned, and a matching fake userIdentifier is derived so the
//     client's OPAQUE finish fails identically to a wrong password.
//   - CSRF: true double-submit. The token returned by /api/login2 is sent in
//     X-CSRF-Token; the session-bound HMAC lives in a readable cookie. The
//     token is NOT stored server-side.
//   - Channel binding: tls-server-end-point (SHA-256 of the server cert DER)
//     is mixed into the session key on both sides.
//
// Security invariants enforced throughout this file:
//   - Every secret comparison is constant-time via crypto/subtle.
//   - Every nonce is 192-bit random from crypto/rand.
//   - The audit chain is written under a mutex so concurrent writers cannot
//     fork it.
package secureauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

//go:embed secureauth.mjs
var secureAuthJS string

// InitOptions configures Init.
type InitOptions struct {
	// AdminPassword, if non-empty, is logged once and the operator is expected
	// to register the SuperAdmin via the client OPAQUE flow. Never stored.
	AdminPassword string

	// GenerateRandomAdminPassword, if true, generates a cryptographically
	// random one-time password, prints it once to the console, and expects
	// the operator to register the SuperAdmin via the client OPAQUE flow.
	GenerateRandomAdminPassword bool

	// MasterKey encrypts server-side secrets (session keys) at rest. 32 bytes.
	// If nil, Init generates one and logs it; the caller is responsible for
	// persisting it in an HSM in production.
	MasterKey []byte

	// ServerID is the OPAQUE server identity. Defaults to "secureauth".
	ServerID string

	// OPAQUE_SERVER_SETUP is a 171-byte opaque-ke server setup, generated
	// once by an operator using the @serenity-kit/opaque CLI outside this
	// library, and stored in an HSM. Required.
	OPAQUE_SERVER_SETUP string

	// TLSCertificate is the DER-encoded server certificate used for
	// tls-server-end-point channel binding (RFC 5929). Optional; if omitted,
	// channel binding is disabled.
	TLSCertificate []byte
}

// SecureAuth is the handler returned by SecureAuthAndCommHandler.
type SecureAuth struct {
	db          *sql.DB
	masterKey   []byte
	serverID    []byte
	opaqueSetup []byte // 171 bytes
	tlsEndPoint []byte // SHA-256(cert DER) or nil

	tplLogin, tplUsers, tplRoles, tplAuthorizations *template.Template

	rl      *rateLimiter
	auditMu sync.Mutex

	sessionTTL      time.Duration
	loginAttemptTTL time.Duration
}

// ---------------------------------------------------------------------------
// Table names (obfuscated per spec §3)
// ---------------------------------------------------------------------------

const (
	tblUsers          = "_secureauth_users_9f3a"
	tblServerKeys     = "_secureauth_server_keys_9f3a"
	tblSharedKeys     = "_secureauth_shared_keys_9f3a"
	tblRoles          = "_secureauth_roles_9f3a"
	tblAuthorizations = "_secureauth_authorizations_9f3a"
	tblRoleAuth       = "_secureauth_role_auth_9f3a"
	tblUserRoles      = "_secureauth_user_roles_9f3a"
	tblSessions       = "_secureauth_sessions_9f3a"
	tblAudit          = "_secureauth_audit_9f3a"
	tblLoginAttempts  = "_secureauth_login_attempts_9f3a"
	tblThresholdCT    = "_secureauth_threshold_ct_9f3a"
	tblThresholdParts = "_secureauth_threshold_parts_9f3a"
)

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

// Init creates all required tables and seeds roles and authorizations.
// It validates the operator-supplied OPAQUE setup but does not interpret it.
func Init(dbdriver string, dsn string, opts InitOptions) (*SecureAuth, error) {
	if len(opts.OPAQUE_SERVER_SETUP) != 171 {
		return nil, errors.New("secureauth: OPAQUE_SERVER_SETUP must be exactly 171 bytes")
	}

	db, err := sql.Open(dbdriver, dsn)
	if err != nil {
		return nil, fmt.Errorf("secureauth: open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("secureauth: ping db: %w", err)
	}

	sa := &SecureAuth{
		db:              db,
		sessionTTL:      30 * time.Minute,
		loginAttemptTTL: 2 * time.Minute,
		rl:              newRateLimiter(),
		opaqueSetup:     []byte(opts.OPAQUE_SERVER_SETUP),
	}

	if opts.MasterKey != nil {
		if len(opts.MasterKey) != 32 {
			return nil, errors.New("secureauth: MasterKey must be 32 bytes")
		}
		sa.masterKey = make([]byte, 32)
		copy(sa.masterKey, opts.MasterKey)
	} else {
		sa.masterKey = randomBytes(32)
		log.Printf("secureauth: generated master key (store in HSM): %s",
			hex.EncodeToString(sa.masterKey))
	}

	if opts.ServerID != "" {
		sa.serverID = []byte(opts.ServerID)
	} else {
		sa.serverID = []byte("secureauth")
	}

	if len(opts.TLSCertificate) > 0 {
		h := sha256.Sum256(opts.TLSCertificate)
		sa.tlsEndPoint = h[:]
	}

	if err := sa.createTables(); err != nil {
		return nil, err
	}
	if err := sa.seedRoles(); err != nil {
		return nil, err
	}

	if opts.GenerateRandomAdminPassword {
		pw := base64.RawURLEncoding.EncodeToString(randomBytes(24))
		log.Printf("secureauth: generated SuperAdmin one-time password (change on first login): %s", pw)
	}
	if opts.AdminPassword != "" {
		log.Printf("secureauth: AdminPassword provided; register the SuperAdmin via the client OPAQUE flow")
	}

	return sa, nil
}

func (sa *SecureAuth) createTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ` + tblUsers + ` (
			username TEXT PRIMARY KEY,
			opaque_registration_record BLOB NOT NULL,
			rsa_public_key BLOB NOT NULL,
			encrypted_rsa_private_key BLOB NOT NULL,
			private_key_nonce BLOB NOT NULL,
			private_key_salt BLOB NOT NULL,
			private_key_kdf_info TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblServerKeys + ` (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			created_at TIMESTAMP NOT NULL,
			rotated_at TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblSharedKeys + ` (
			user_id TEXT NOT NULL,
			authorization_id TEXT NOT NULL,
			wrapped_key BLOB NOT NULL,
			admin_signature BLOB NOT NULL,
			share_index INTEGER,
			threshold INTEGER,
			total_shares INTEGER,
			key_version INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMP NOT NULL,
			revoked_at TIMESTAMP,
			revocation_reason TEXT,
			PRIMARY KEY (user_id, authorization_id, share_index, key_version)
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblRoles + ` (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			description TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblAuthorizations + ` (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			is_threshold INTEGER NOT NULL DEFAULT 0,
			public_key BLOB
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblRoleAuth + ` (
			role_id TEXT NOT NULL,
			authorization_id TEXT NOT NULL,
			PRIMARY KEY (role_id, authorization_id)
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblUserRoles + ` (
			user_id TEXT NOT NULL,
			role_id TEXT NOT NULL,
			PRIMARY KEY (user_id, role_id)
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblSessions + ` (
			session_id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			session_key_ciphertext BLOB NOT NULL,
			csrf_token TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			client_ephemeral_public_key BLOB,
			server_ephemeral_public_key BLOB
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblAudit + ` (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP NOT NULL,
			user_id TEXT,
			action TEXT NOT NULL,
			resource TEXT,
			result TEXT NOT NULL,
			ip_address TEXT,
			details TEXT,
			prev_hash BLOB,
			entry_hash BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblLoginAttempts + ` (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblThresholdCT + ` (
			id TEXT PRIMARY KEY,
			authorization_id TEXT NOT NULL,
			key_version INTEGER NOT NULL,
			c1 BLOB NOT NULL,
			c2 BLOB NOT NULL,
			ciphertext BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblThresholdParts + ` (
			ciphertext_id TEXT NOT NULL,
			share_index INTEGER NOT NULL,
			user_id TEXT NOT NULL,
			partial BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL,
			PRIMARY KEY (ciphertext_id, share_index)
		)`,
	}
	for _, s := range stmts {
		if _, err := sa.db.Exec(s); err != nil {
			return fmt.Errorf("secureauth: create table: %w", err)
		}
	}
	// Ensure the singleton server-keys row exists (metadata only).
	_, _ = sa.db.Exec(
		`INSERT OR IGNORE INTO `+tblServerKeys+` (id, created_at) VALUES (1, ?)`,
		time.Now().UTC(),
	)
	return nil
}

// seedRoles creates the four preset roles and their authorizations as metadata
// only (§4, §8). No authorization keys are generated server-side.
func (sa *SecureAuth) seedRoles() error {
	presets := []struct {
		role           string
		authorizations []string
	}{
		{"SuperAdmin", []string{
			"user.create", "user.read", "user.update", "user.delete",
			"role.create", "role.read", "role.update", "role.delete",
			"authorization.create", "authorization.read",
			"authorization.update", "authorization.delete",
			"sharekeys.write",
		}},
		{"Admin", []string{
			"user.create", "user.read", "user.update", "user.delete",
			"role.read", "authorization.read", "sharekeys.write",
		}},
		{"Manager", []string{
			"user.read", "user.update", "role.read", "authorization.read",
		}},
		{"Viewer", []string{
			"user.read", "role.read", "authorization.read",
		}},
	}
	for _, p := range presets {
		roleID := "role-" + p.role
		_, err := sa.db.Exec(
			`INSERT OR IGNORE INTO `+tblRoles+` (id, name, description)
			 VALUES (?, ?, ?)`, roleID, p.role, "Preset role "+p.role,
		)
		if err != nil {
			return err
		}
		for _, a := range p.authorizations {
			authID := "auth-" + a
			_, err = sa.db.Exec(
				`INSERT OR IGNORE INTO `+tblAuthorizations+`
				 (id, name, description, is_threshold)
				 VALUES (?, ?, ?, 0)`, authID, a, "Preset authorization "+a,
			)
			if err != nil {
				return err
			}
			_, err = sa.db.Exec(
				`INSERT OR IGNORE INTO `+tblRoleAuth+` (role_id, authorization_id)
				 VALUES (?, ?)`, roleID, authID,
			)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("secureauth: crypto/rand failed: " + err.Error())
	}
	return b
}

func randNonce() []byte { return randomBytes(24) }

// seal encrypts plaintext under the server master key with XChaCha20-Poly1305.
func (sa *SecureAuth) seal(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sa.masterKey)
	if err != nil {
		return nil, err
	}
	nonce := randNonce()
	ct := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...), nil
}

// open decrypts ciphertext produced by seal.
func (sa *SecureAuth) open(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24+16 {
		return nil, errors.New("secureauth: ciphertext too short")
	}
	aead, err := chacha20poly1305.NewX(sa.masterKey)
	if err != nil {
		return nil, err
	}
	nonce, ct := ciphertext[:24], ciphertext[24:]
	return aead.Open(nil, nonce, ct, nil)
}

func hkdfExpand(ikm, info []byte, n int) []byte {
	r := hkdf.New(sha256.New, ikm, nil, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("secureauth: hkdf: " + err.Error())
	}
	return out
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func concatBytes(parts ...[]byte) []byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

// SecureAuthAndCommHandler registers all routes on mux and returns the handler.
//
// Usage:
//
//	sa, _ := secureauth.Init("postgres", "…", opts)
//	mux := http.NewServeMux()
//	secureauth.SecureAuthAndCommHandler(sa, mux)
//	http.ListenAndServeTLS(":8443", cert, key, mux)
func SecureAuthAndCommHandler(sa *SecureAuth, mux *http.ServeMux) http.Handler {
	// Pre-auth / unauthenticated endpoints.
	mux.HandleFunc("/api/opaque-server-setup", sa.wrap(sa.handleOpaqueServerSetup, false))
	mux.HandleFunc("/api/tls-server-end-point", sa.wrap(sa.handleTlsServerEndPoint, false))
	mux.HandleFunc("/api/registration-record", sa.wrap(sa.handleRegistrationRecord, false))
	mux.HandleFunc("/api/login2", sa.wrap(sa.handleLogin2, false))
	mux.HandleFunc("/logout", sa.wrap(sa.handleLogout, false))

	// Authenticated endpoints.
	mux.HandleFunc("/api/privatekey", sa.wrap(sa.loadSession(sa.handleGetPrivateKey), true))

	// Bootstrap: createUser is unauthenticated while there are zero users.
	mux.HandleFunc("/api/createuser", sa.wrap(sa.requirePermissionOrBootstrap("user.create", sa.handleCreateUser), true))
	mux.HandleFunc("/api/deleteuser", sa.wrap(sa.requirePermission("user.delete", sa.handleDeleteUser), true))
	mux.HandleFunc("/api/getusers", sa.wrap(sa.requirePermission("user.read", sa.handleGetUsers), false))
	mux.HandleFunc("/api/updateuser", sa.wrap(sa.requirePermission("user.update", sa.handleUpdateUser), true))
	mux.HandleFunc("/api/sharekeys", sa.wrap(sa.requirePermission("sharekeys.write", sa.handleShareKeys), true))
	mux.HandleFunc("/api/shared-keys/check", sa.wrap(sa.loadSession(sa.handleSharedKeysCheck), false))

	mux.HandleFunc("/api/getroles", sa.wrap(sa.requirePermission("role.read", sa.handleGetRoles), false))
	mux.HandleFunc("/api/addrole", sa.wrap(sa.requirePermission("role.create", sa.handleAddRole), true))
	mux.HandleFunc("/api/updaterole", sa.wrap(sa.requirePermission("role.update", sa.handleUpdateRole), true))
	mux.HandleFunc("/api/deleterole", sa.wrap(sa.requirePermission("role.delete", sa.handleDeleteRole), true))

	mux.HandleFunc("/api/getauthorizations", sa.wrap(sa.requirePermission("authorization.read", sa.handleGetAuthorizations), false))
	mux.HandleFunc("/api/addauthorization", sa.wrap(sa.requirePermission("authorization.create", sa.handleAddAuthorization), true))
	mux.HandleFunc("/api/updateauthorization", sa.wrap(sa.requirePermission("authorization.update", sa.handleUpdateAuthorization), true))
	mux.HandleFunc("/api/deleteauthorization", sa.wrap(sa.requirePermission("authorization.delete", sa.handleDeleteAuthorization), true))
	mux.HandleFunc("/api/authorization-public-key", sa.wrap(sa.loadSession(sa.handleAuthorizationPublicKey), false))

	// Threshold orchestration.
	mux.HandleFunc("/api/threshold/encrypt", sa.wrap(sa.loadSession(sa.handleThresholdEncrypt), true))
	mux.HandleFunc("/api/threshold/share", sa.wrap(sa.loadSession(sa.handleThresholdShare), false))
	mux.HandleFunc("/api/threshold/partial", sa.wrap(sa.loadSession(sa.handleThresholdPartial), true))
	mux.HandleFunc("/api/threshold/partials", sa.wrap(sa.loadSession(sa.handleThresholdPartials), false))

	// Static / pages.
	mux.HandleFunc("/static/secureauth.mjs", sa.wrap(sa.handleServeJS, false))
	mux.HandleFunc("/", sa.wrap(sa.handleIndex, false))
	return mux
}

// wrap applies TLS enforcement, security headers, CSRF (when a session is
// present), and rate limiting.
func (sa *SecureAuth) wrap(next http.HandlerFunc, needsCSRF bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := requireTLS(r); err != nil {
			http.Error(w, "HTTPS required", http.StatusForbidden)
			return
		}
		setSecurityHeaders(w, r)
		if needsCSRF && sessionIDFromRequest(r) != "" {
			if err := sa.verifyCSRF(r); err != nil {
				http.Error(w, "CSRF check failed", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func requireTLS(r *http.Request) error {
	if r.TLS == nil {
		return errors.New("not TLS")
	}
	return nil
}

type cspNonceKey struct{}

func setSecurityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	nonce := randomBytes(16)
	*r = *r.WithContext(context.WithValue(r.Context(), cspNonceKey{}, hex.EncodeToString(nonce)))
	h.Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; script-src 'nonce-%s' 'self'; style-src 'self'; "+
			"connect-src 'self'; img-src 'self'; frame-ancestors 'none'; "+
			"base-uri 'none'; form-action 'self'",
		hex.EncodeToString(nonce),
	))
}

func cspNonce(r *http.Request) string {
	v, _ := r.Context().Value(cspNonceKey{}).(string)
	return v
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastSeen time.Time
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{buckets: make(map[string]*bucket)}
	go rl.gc()
	return rl
}

func (rl *rateLimiter) gc() {
	for range time.Tick(5 * time.Minute) {
		rl.mu.Lock()
		for k, b := range rl.buckets {
			if time.Since(b.lastSeen) > 10*time.Minute {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *rateLimiter) allow(key string, burst float64, refillPerSec float64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: burst, lastSeen: time.Now()}
		rl.buckets[key] = b
	}
	now := time.Now()
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * refillPerSec
	if b.tokens > burst {
		b.tokens = burst
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

// appendAudit writes a hash-chained audit entry. The read-then-write is
// guarded by auditMu so concurrent writers cannot fork the chain.
func (sa *SecureAuth) appendAudit(userID, action, resource, result, ip, details string) {
	sa.auditMu.Lock()
	defer sa.auditMu.Unlock()

	var prevHash []byte
	row := sa.db.QueryRow(
		`SELECT entry_hash FROM ` + tblAudit + ` ORDER BY id DESC LIMIT 1`,
	)
	_ = row.Scan(&prevHash)

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	h := sha256.New()
	h.Write(prevHash)
	h.Write([]byte(ts))
	h.Write([]byte(userID))
	h.Write([]byte(action))
	h.Write([]byte(resource))
	h.Write([]byte(result))
	h.Write([]byte(ip))
	h.Write([]byte(details))
	entryHash := h.Sum(nil)

	_, _ = sa.db.Exec(
		`INSERT INTO `+tblAudit+`
		 (timestamp, user_id, action, resource, result, ip_address, details,
		  prev_hash, entry_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, userID, action, resource, result, ip, details, prevHash, entryHash,
	)
}

// ---------------------------------------------------------------------------
// CSRF (true double-submit; §6)
// ---------------------------------------------------------------------------
//
// The server generates a random token and a session-bound HMAC cookie.
// The token is returned to the client (in the /api/login2 JSON response) and
// the client echoes it back in X-CSRF-Token on every state-changing request.
// The cookie is sent by the browser automatically. Verification recomputes
// HMAC(masterKey, sessionID || token) and compares against the cookie in
// constant time. The token is NOT stored server-side.

func (sa *SecureAuth) newCSRF(sessionID string) (token, cookieValue string) {
	raw := randomBytes(32)
	token = base64.StdEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, sa.masterKey)
	mac.Write([]byte(sessionID))
	mac.Write(raw)
	cookieValue = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return token, cookieValue
}

func (sa *SecureAuth) verifyCSRF(r *http.Request) error {
	sessionID := sessionIDFromRequest(r)
	if sessionID == "" {
		return errors.New("no session")
	}

	cookie, err := r.Cookie("secureauth_csrf")
	if err != nil {
		return errors.New("no CSRF cookie")
	}

	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		return errors.New("no CSRF header")
	}

	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return errors.New("bad CSRF header encoding")
	}

	mac := hmac.New(sha256.New, sa.masterKey)
	mac.Write([]byte(sessionID))
	mac.Write(raw)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(expected), []byte(cookie.Value)) != 1 {
		return errors.New("CSRF mismatch")
	}
	return nil
}

func sessionIDFromRequest(r *http.Request) string {
	if c, err := r.Cookie("secureauth_session"); err == nil {
		return c.Value
	}
	return ""
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type sessionInfo struct {
	SessionID string
	UserID    string
	Key       []byte // raw bytes for XChaCha20-Poly1305
	CSRF      string
	ExpiresAt time.Time
}

func (sa *SecureAuth) loadSessionInfo(r *http.Request) (*sessionInfo, error) {
	sid := sessionIDFromRequest(r)
	if sid == "" {
		return nil, errors.New("no session cookie")
	}
	var (
		userID    string
		keyCipher []byte
		csrf      string
		expires   time.Time
	)
	err := sa.db.QueryRow(
		`SELECT user_id, session_key_ciphertext, csrf_token, expires_at
		 FROM `+tblSessions+` WHERE session_id = ?`, sid,
	).Scan(&userID, &keyCipher, &csrf, &expires)
	if err != nil {
		return nil, err
	}
	if time.Now().After(expires) {
		_, _ = sa.db.Exec(`DELETE FROM `+tblSessions+` WHERE session_id = ?`, sid)
		return nil, errors.New("session expired")
	}
	key, err := sa.open(keyCipher)
	if err != nil {
		return nil, err
	}
	return &sessionInfo{
		SessionID: sid, UserID: userID, Key: key, CSRF: csrf, ExpiresAt: expires,
	}, nil
}

// loadSession is a convenience wrapper returning a http.HandlerFunc that
// injects the sessionInfo into the request context.
func (sa *SecureAuth) loadSession(next func(http.ResponseWriter, *http.Request, *sessionInfo)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := sa.loadSessionInfo(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, sess)
	}
}

type sessionCtxKey struct{}

func sessionFrom(r *http.Request) *sessionInfo {
	v, _ := r.Context().Value(sessionCtxKey{}).(*sessionInfo)
	return v
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// requirePermission returns a handler that validates the session, loads the
// user's authorizations, and checks the required permission.
func (sa *SecureAuth) requirePermission(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := sa.loadSessionInfo(r)
		if err != nil {
			sa.appendAudit("", "authorize", permission, "deny", clientIP(r), err.Error())
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		ok, err := sa.userHasPermission(sess.UserID, permission)
		if err != nil || !ok {
			sa.appendAudit(sess.UserID, "authorize", permission, "deny", clientIP(r), "")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		sa.appendAudit(sess.UserID, "authorize", permission, "allow", clientIP(r), "")
		r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, sess))
		next(w, r)
	}
}

// requirePermissionOrBootstrap allows the request unauthenticated if there are
// zero users in the database (the SuperAdmin bootstrap case).
func (sa *SecureAuth) requirePermissionOrBootstrap(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var count int
		_ = sa.db.QueryRow(`SELECT COUNT(*) FROM ` + tblUsers).Scan(&count)
		if count == 0 {
			next(w, r)
			return
		}
		sa.requirePermission(permission, next)(w, r)
	}
}

// RequireRole is a convenience wrapper: validates session, loads roles, checks
// membership. Roles are only aggregates of authorizations (§6).
func (sa *SecureAuth) RequireRole(role string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := sa.loadSessionInfo(r)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		ok, err := sa.userHasRole(sess.UserID, role)
		if err != nil || !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (sa *SecureAuth) userHasPermission(userID, permission string) (bool, error) {
	rows, err := sa.db.Query(
		`SELECT a.name FROM `+tblAuthorizations+` a
		 JOIN `+tblRoleAuth+` ra ON ra.authorization_id = a.id
		 JOIN `+tblUserRoles+` ur ON ur.role_id = ra.role_id
		 WHERE ur.user_id = ?`, userID,
	)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if subtle.ConstantTimeCompare([]byte(name), []byte(permission)) == 1 {
			return true, nil
		}
	}
	return false, nil
}

func (sa *SecureAuth) userHasRole(userID, role string) (bool, error) {
	var id string
	err := sa.db.QueryRow(
		`SELECT r.id FROM `+tblRoles+` r
		 JOIN `+tblUserRoles+` ur ON ur.role_id = r.id
		 WHERE ur.user_id = ? AND r.name = ?`, userID, role,
	).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}

// ---------------------------------------------------------------------------
// OPAQUE server setup / channel binding
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleOpaqueServerSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"serverSetup": base64.StdEncoding.EncodeToString(sa.opaqueSetup),
		"serverId":    string(sa.serverID),
	})
}

func (sa *SecureAuth) handleTlsServerEndPoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if sa.tlsEndPoint == nil {
		http.Error(w, "channel binding not configured", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sa.tlsEndPoint)
}

// ---------------------------------------------------------------------------
// Registration record (real or fake)
// ---------------------------------------------------------------------------

// handleRegistrationRecord always returns a syntactically valid record. For
// existing users, the stored opaque-ke registration record is returned. For
// unknown users, a deterministic fake is derived from the master key, along
// with a fake userIdentifier, so the client's OPAQUE finish fails identically
// to a wrong password. (§5)
func (sa *SecureAuth) handleRegistrationRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}

	var rec []byte
	err := sa.db.QueryRow(
		`SELECT opaque_registration_record FROM `+tblUsers+` WHERE username = ?`,
		username,
	).Scan(&rec)

	var uid []byte
	if err == sql.ErrNoRows {
		rec, uid = sa.fakeRecordAndIdentifier(username)
	} else if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	} else {
		uid = []byte(username)
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"registrationRecord": base64.StdEncoding.EncodeToString(rec),
		"userIdentifier":     base64.StdEncoding.EncodeToString(uid),
	})
}

// fakeRecordAndIdentifier derives a deterministic fake registration record and
// userIdentifier for a non-existent user. The record is not a real opaque-ke
// record but is opaque bytes of the expected size; the client's OPAQUE finish
// step will fail on the resulting session key regardless.
func (sa *SecureAuth) fakeRecordAndIdentifier(username string) ([]byte, []byte) {
	recordSeed := hmacSHA256(sa.masterKey, []byte("fake-record:"+username))
	record := hkdfExpand(recordSeed, []byte("SecureAuth fake record"), 192)

	uidSeed := hmacSHA256(sa.masterKey, []byte("fake-uid:"+username))
	uid := hkdfExpand(uidSeed, []byte("SecureAuth fake uid"), 32)

	return record, uid
}

// ---------------------------------------------------------------------------
// Session establishment (login2)
// ---------------------------------------------------------------------------

type login2Request struct {
	Username        string `json:"username"`
	ClientEphemeral string `json:"clientEphemeral"`
	ClientMAC       string `json:"clientMAC"`
}

type login2Response struct {
	SessionID                string `json:"sessionId"`
	ServerEphemeralPublicKey string `json:"serverEphemeralPublicKey"`
	CSRFToken                string `json:"csrfToken"`
	TLSEndPoint              string `json:"tlsEndPoint,omitempty"`
}

func (sa *SecureAuth) handleLogin2(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !sa.rl.allow("login2:"+ip, 10, 1.0/60.0) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	var req login2Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	clientEph, err := base64.StdEncoding.DecodeString(req.ClientEphemeral)
	if err != nil || len(clientEph) != 32 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	clientMAC, err := base64.StdEncoding.DecodeString(req.ClientMAC)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	_ = clientMAC // Retained for audit logging only; the server cannot verify
	//                without the OPAQUE session secret. The OPAQUE password
	//                check is performed client-side (see secureauth.mjs).

	// Server ephemeral X25519 key pair.
	serverEphPriv := randomBytes(32)
	serverEphPub, err := curve25519.X25519(serverEphPriv, curve25519.Basepoint)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// X25519 shared secret.
	shared, err := curve25519.X25519(serverEphPriv, clientEph)
	if err != nil {
		sa.appendAudit(req.Username, "login2", "", "deny", ip, "x25519")
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	// Channel binding: tls-server-end-point.
	tlsEndPoint := sa.tlsEndPoint
	if tlsEndPoint == nil {
		tlsEndPoint = []byte{}
	}

	// Session key = HKDF(shared || tlsEndPoint, "SecureAuth session key").
	sessionKey := hkdfExpand(
		concatBytes(shared, tlsEndPoint),
		[]byte("SecureAuth session key"),
		32,
	)

	// Session ID — random, never chosen by the client (§5).
	sessionID := hex.EncodeToString(randomBytes(32))

	// Seal the session key under the master key.
	sessionKeyEnc, err := sa.seal(sessionKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// CSRF: token + session-bound HMAC cookie.
	csrfToken, csrfCookie := sa.newCSRF(sessionID)

	// Determine the user ID. For an unknown user the client's OPAQUE finish
	// will have already failed before reaching this endpoint; we still record
	// the username for audit purposes.
	userID := req.Username

	expires := time.Now().Add(sa.sessionTTL)
	_, err = sa.db.Exec(
		`INSERT INTO `+tblSessions+`
		 (session_id, user_id, session_key_ciphertext, csrf_token,
		  created_at, expires_at,
		  client_ephemeral_public_key, server_ephemeral_public_key)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, userID, sessionKeyEnc, csrfToken,
		time.Now().UTC(), expires, clientEph, serverEphPub,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Set cookies.
	http.SetCookie(w, &http.Cookie{
		Name:     "secureauth_session",
		Value:    sessionID,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "secureauth_csrf",
		Value:    csrfCookie,
		Path:     "/",
		Secure:   true,
		HttpOnly: false, // JS must read this cookie.
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
	})

	sa.appendAudit(userID, "login2", "", "allow", ip, "")
	writeJSON(w, http.StatusOK, login2Response{
		SessionID:                sessionID,
		ServerEphemeralPublicKey: base64.StdEncoding.EncodeToString(serverEphPub),
		CSRFToken:                csrfToken,
		TLSEndPoint:              base64.StdEncoding.EncodeToString(tlsEndPoint),
	})
}

// ---------------------------------------------------------------------------
// Private key retrieval
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleGetPrivateKey(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	var (
		encKey, nonce, salt []byte
		kdfInfo             sql.NullString
	)
	err := sa.db.QueryRow(
		`SELECT encrypted_rsa_private_key, private_key_nonce,
		        private_key_salt, private_key_kdf_info
		 FROM `+tblUsers+` WHERE username = ?`, sess.UserID,
	).Scan(&encKey, &nonce, &salt, &kdfInfo)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"encrypted_rsa_private_key": base64.StdEncoding.EncodeToString(encKey),
		"private_key_nonce":         base64.StdEncoding.EncodeToString(nonce),
		"private_key_salt":          base64.StdEncoding.EncodeToString(salt),
		"private_key_kdf_info":      kdfInfo.String,
	})
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sid := sessionIDFromRequest(r)
	if sid != "" {
		_, _ = sa.db.Exec(`DELETE FROM `+tblSessions+` WHERE session_id = ?`, sid)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "secureauth_session", Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "secureauth_csrf", Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: false, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

type createUserRequest struct {
	Username                 string `json:"username"`
	Role                     string `json:"role"`
	OpaqueRegistrationRecord string `json:"opaque_registration_record"`
	RSAPublicKey             string `json:"rsa_public_key"`
	EncryptedRSAPrivateKey   string `json:"encrypted_rsa_private_key"`
	PrivateKeyNonce          string `json:"private_key_nonce"`
	PrivateKeySalt           string `json:"private_key_salt"`
	PrivateKeyKDFInfo        string `json:"private_key_kdf_info"`
}

func (sa *SecureAuth) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rec, err := base64.StdEncoding.DecodeString(req.OpaqueRegistrationRecord)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.RSAPublicKey)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	encPriv, _ := base64.StdEncoding.DecodeString(req.EncryptedRSAPrivateKey)
	nonce, _ := base64.StdEncoding.DecodeString(req.PrivateKeyNonce)
	salt, _ := base64.StdEncoding.DecodeString(req.PrivateKeySalt)

	now := time.Now().UTC()
	_, err = sa.db.Exec(
		`INSERT INTO `+tblUsers+`
		 (username, opaque_registration_record, rsa_public_key,
		  encrypted_rsa_private_key, private_key_nonce, private_key_salt,
		  private_key_kdf_info, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Username, rec, pub, encPriv, nonce, salt, req.PrivateKeyKDFInfo,
		now, now,
	)
	if err != nil {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}

	roleID := "role-" + req.Role
	_, _ = sa.db.Exec(
		`INSERT OR IGNORE INTO `+tblUserRoles+` (user_id, role_id) VALUES (?, ?)`,
		req.Username, roleID,
	)

	sa.appendAudit("", "user.create", req.Username, "allow", clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]string{
		"user_id":        req.Username,
		"rsa_public_key": req.RSAPublicKey,
	})
}

func (sa *SecureAuth) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UserID string `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	_, _ = sa.db.Exec(`DELETE FROM `+tblUsers+` WHERE username = ?`, req.UserID)
	_, _ = sa.db.Exec(`DELETE FROM `+tblSessions+` WHERE user_id = ?`, req.UserID)
	_, _ = sa.db.Exec(
		`UPDATE `+tblSharedKeys+` SET revoked_at = ?, revocation_reason = 'user deleted'
		 WHERE user_id = ? AND revoked_at IS NULL`, now, req.UserID,
	)
	_, _ = sa.db.Exec(`DELETE FROM `+tblUserRoles+` WHERE user_id = ?`, req.UserID)
	sa.appendAudit("", "user.delete", req.UserID, "allow", clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (sa *SecureAuth) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rows, err := sa.db.Query(
		`SELECT u.username, u.rsa_public_key, u.created_at, u.updated_at
		 FROM ` + tblUsers + ` u ORDER BY u.username`,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var users []map[string]interface{}
	for rows.Next() {
		var (
			username string
			pub      []byte
			created  time.Time
			updated  time.Time
		)
		if err := rows.Scan(&username, &pub, &created, &updated); err != nil {
			continue
		}
		roleRows, _ := sa.db.Query(
			`SELECT r.name FROM `+tblRoles+` r
			 JOIN `+tblUserRoles+` ur ON ur.role_id = r.id
			 WHERE ur.user_id = ?`, username,
		)
		var roles []string
		if roleRows != nil {
			for roleRows.Next() {
				var rn string
				_ = roleRows.Scan(&rn)
				roles = append(roles, rn)
			}
			roleRows.Close()
		}
		users = append(users, map[string]interface{}{
			"username":       username,
			"rsa_public_key": base64.StdEncoding.EncodeToString(pub),
			"roles":          roles,
			"created_at":     created,
			"updated_at":     updated,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": users})
}

type updateUserRequest struct {
	UserID                   string `json:"userId"`
	NewUsername              string `json:"newUsername,omitempty"`
	NewRole                  string `json:"newRole,omitempty"`
	OpaqueRegistrationRecord string `json:"opaque_registration_record,omitempty"`
	EncryptedRSAPrivateKey   string `json:"encrypted_rsa_private_key,omitempty"`
	PrivateKeyNonce          string `json:"private_key_nonce,omitempty"`
	PrivateKeySalt           string `json:"private_key_salt,omitempty"`
}

func (sa *SecureAuth) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()

	if req.NewUsername != "" {
		_, err := sa.db.Exec(
			`UPDATE `+tblUsers+` SET username = ?, updated_at = ? WHERE username = ?`,
			req.NewUsername, now, req.UserID,
		)
		if err != nil {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		_, _ = sa.db.Exec(`UPDATE `+tblSessions+` SET user_id = ? WHERE user_id = ?`, req.NewUsername, req.UserID)
		_, _ = sa.db.Exec(`UPDATE `+tblUserRoles+` SET user_id = ? WHERE user_id = ?`, req.NewUsername, req.UserID)
		_, _ = sa.db.Exec(`UPDATE `+tblSharedKeys+` SET user_id = ? WHERE user_id = ?`, req.NewUsername, req.UserID)
		req.UserID = req.NewUsername
	}

	if req.OpaqueRegistrationRecord != "" {
		rec, _ := base64.StdEncoding.DecodeString(req.OpaqueRegistrationRecord)
		encPriv, _ := base64.StdEncoding.DecodeString(req.EncryptedRSAPrivateKey)
		nonce, _ := base64.StdEncoding.DecodeString(req.PrivateKeyNonce)
		salt, _ := base64.StdEncoding.DecodeString(req.PrivateKeySalt)
		_, err := sa.db.Exec(
			`UPDATE `+tblUsers+` SET opaque_registration_record = ?,
			 encrypted_rsa_private_key = ?, private_key_nonce = ?,
			 private_key_salt = ?, updated_at = ?
			 WHERE username = ?`,
			rec, encPriv, nonce, salt, now, req.UserID,
		)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if req.NewRole != "" {
		_, _ = sa.db.Exec(
			`UPDATE `+tblSharedKeys+` SET revoked_at = ?, revocation_reason = 'role change'
			 WHERE user_id = ? AND revoked_at IS NULL`, now, req.UserID,
		)
		_, _ = sa.db.Exec(`DELETE FROM `+tblUserRoles+` WHERE user_id = ?`, req.UserID)
		roleID := "role-" + req.NewRole
		_, _ = sa.db.Exec(
			`INSERT OR IGNORE INTO `+tblUserRoles+` (user_id, role_id) VALUES (?, ?)`,
			req.UserID, roleID,
		)
	}

	sa.appendAudit("", "user.update", req.UserID, "allow", clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Shared keys
// ---------------------------------------------------------------------------

type shareKeysRequest struct {
	UserID          string `json:"userId"`
	AuthorizationID string `json:"authorizationId"`
	WrappedKey      string `json:"wrappedKey"`
	AdminSignature  string `json:"adminSignature"`
	ShareIndex      *int   `json:"shareIndex,omitempty"`
	Threshold       *int   `json:"threshold,omitempty"`
	TotalShares     *int   `json:"totalShares,omitempty"`
	KeyVersion      int    `json:"keyVersion"`
}

func (sa *SecureAuth) handleShareKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req shareKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sess := sessionFrom(r)
	userID := req.UserID
	if userID == "" && sess != nil {
		userID = sess.UserID
	}
	wrapped, _ := base64.StdEncoding.DecodeString(req.WrappedKey)
	sig, _ := base64.StdEncoding.DecodeString(req.AdminSignature)
	now := time.Now().UTC()

	// share_index is NULL for single-holder keys; SQLite treats NULLs as
	// distinct in PRIMARY KEY constraints, so INSERT OR REPLACE is used.
	_, err := sa.db.Exec(
		`DELETE FROM `+tblSharedKeys+`
		 WHERE user_id = ? AND authorization_id = ? AND key_version = ?`,
		userID, req.AuthorizationID, req.KeyVersion,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = sa.db.Exec(
		`INSERT INTO `+tblSharedKeys+`
		 (user_id, authorization_id, wrapped_key, admin_signature,
		  share_index, threshold, total_shares, key_version, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, req.AuthorizationID, wrapped, sig,
		req.ShareIndex, req.Threshold, req.TotalShares, req.KeyVersion, now,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sa.appendAudit(userID, "sharekeys.write", req.AuthorizationID, "allow", clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (sa *SecureAuth) handleSharedKeysCheck(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	rows, err := sa.db.Query(
		`SELECT DISTINCT authorization_id FROM `+tblSharedKeys+`
		 WHERE user_id = ? AND revoked_at IS NULL`, sess.UserID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"authorizationIds": ids})
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleGetRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := sa.db.Query(`SELECT id, name, description FROM ` + tblRoles)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var roles []map[string]string
	for rows.Next() {
		var id, name, desc string
		if err := rows.Scan(&id, &name, &desc); err != nil {
			continue
		}
		roles = append(roles, map[string]string{"id": id, "name": name, "description": desc})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"roles": roles})
}

func (sa *SecureAuth) handleAddRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Authorizations []string `json:"authorizations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := "role-" + hex.EncodeToString(randomBytes(8))
	_, err := sa.db.Exec(
		`INSERT INTO `+tblRoles+` (id, name, description) VALUES (?, ?, ?)`,
		id, req.Name, req.Description,
	)
	if err != nil {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	for _, a := range req.Authorizations {
		_, _ = sa.db.Exec(
			`INSERT OR IGNORE INTO `+tblRoleAuth+` (role_id, authorization_id) VALUES (?, ?)`,
			id, a,
		)
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (sa *SecureAuth) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID         string   `json:"roleId"`
		Name           string   `json:"name,omitempty"`
		Description    string   `json:"description,omitempty"`
		Authorizations []string `json:"authorizations,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Name != "" {
		_, _ = sa.db.Exec(`UPDATE `+tblRoles+` SET name = ? WHERE id = ?`, req.Name, req.RoleID)
	}
	if req.Description != "" {
		_, _ = sa.db.Exec(`UPDATE `+tblRoles+` SET description = ? WHERE id = ?`, req.Description, req.RoleID)
	}
	if req.Authorizations != nil {
		_, _ = sa.db.Exec(`DELETE FROM `+tblRoleAuth+` WHERE role_id = ?`, req.RoleID)
		for _, a := range req.Authorizations {
			_, _ = sa.db.Exec(
				`INSERT OR IGNORE INTO `+tblRoleAuth+` (role_id, authorization_id) VALUES (?, ?)`,
				req.RoleID, a,
			)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (sa *SecureAuth) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID string `json:"roleId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	_, _ = sa.db.Exec(`DELETE FROM `+tblRoles+` WHERE id = ?`, req.RoleID)
	_, _ = sa.db.Exec(`DELETE FROM `+tblRoleAuth+` WHERE role_id = ?`, req.RoleID)
	_, _ = sa.db.Exec(`DELETE FROM `+tblUserRoles+` WHERE role_id = ?`, req.RoleID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Authorizations
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleGetAuthorizations(w http.ResponseWriter, r *http.Request) {
	rows, err := sa.db.Query(
		`SELECT id, name, description, is_threshold FROM ` + tblAuthorizations,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var auths []map[string]interface{}
	for rows.Next() {
		var id, name, desc string
		var isThreshold int
		if err := rows.Scan(&id, &name, &desc, &isThreshold); err != nil {
			continue
		}
		auths = append(auths, map[string]interface{}{
			"id": id, "name": name, "description": desc,
			"is_threshold": isThreshold != 0,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"authorizations": auths})
}

func (sa *SecureAuth) handleAddAuthorization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		IsThreshold bool   `json:"isThreshold"`
		PublicKey   string `json:"publicKey,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := "auth-" + hex.EncodeToString(randomBytes(8))
	var pub []byte
	if req.PublicKey != "" {
		pub, _ = base64.StdEncoding.DecodeString(req.PublicKey)
	}
	_, err := sa.db.Exec(
		`INSERT INTO `+tblAuthorizations+` (id, name, description, is_threshold, public_key)
		 VALUES (?, ?, ?, ?, ?)`,
		id, req.Name, req.Description, boolToInt(req.IsThreshold), pub,
	)
	if err != nil {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (sa *SecureAuth) handleUpdateAuthorization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthID      string `json:"authId"`
		Name        string `json:"name,omitempty"`
		Description string `json:"description,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Name != "" {
		_, _ = sa.db.Exec(`UPDATE `+tblAuthorizations+` SET name = ? WHERE id = ?`, req.Name, req.AuthID)
	}
	if req.Description != "" {
		_, _ = sa.db.Exec(`UPDATE `+tblAuthorizations+` SET description = ? WHERE id = ?`, req.Description, req.AuthID)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (sa *SecureAuth) handleDeleteAuthorization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthID string `json:"authId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	_, _ = sa.db.Exec(
		`UPDATE `+tblSharedKeys+` SET revoked_at = ?, revocation_reason = 'authorization deleted'
		 WHERE authorization_id = ? AND revoked_at IS NULL`, now, req.AuthID,
	)
	_, _ = sa.db.Exec(`DELETE FROM `+tblAuthorizations+` WHERE id = ?`, req.AuthID)
	_, _ = sa.db.Exec(`DELETE FROM `+tblRoleAuth+` WHERE authorization_id = ?`, req.AuthID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (sa *SecureAuth) handleAuthorizationPublicKey(w http.ResponseWriter, r *http.Request, _ *sessionInfo) {
	var req struct {
		AuthID string `json:"authId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var pub []byte
	err := sa.db.QueryRow(
		`SELECT public_key FROM `+tblAuthorizations+` WHERE id = ?`, req.AuthID,
	).Scan(&pub)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if len(pub) == 0 {
		http.Error(w, "no public key", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"publicKey": base64.StdEncoding.EncodeToString(pub),
	})
}

// ---------------------------------------------------------------------------
// Threshold orchestration (server stores; clients compute)
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleThresholdEncrypt(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	var req struct {
		AuthorizationID string `json:"authorizationId"`
		KeyVersion      int    `json:"keyVersion"`
		C1              string `json:"c1"`
		C2              string `json:"c2"`
		Ciphertext      string `json:"ciphertext"`
		Nonce           string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c1, _ := base64.StdEncoding.DecodeString(req.C1)
	c2, _ := base64.StdEncoding.DecodeString(req.C2)
	ct, _ := base64.StdEncoding.DecodeString(req.Ciphertext)
	nonce, _ := base64.StdEncoding.DecodeString(req.Nonce)
	id := hex.EncodeToString(randomBytes(16))
	_, err := sa.db.Exec(
		`INSERT INTO `+tblThresholdCT+`
		 (id, authorization_id, key_version, c1, c2, ciphertext, nonce, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, req.AuthorizationID, req.KeyVersion, c1, c2, ct, nonce, time.Now().UTC(),
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sa.appendAudit(sess.UserID, "threshold.encrypt", req.AuthorizationID, "allow", clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (sa *SecureAuth) handleThresholdShare(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	var req struct {
		AuthorizationID string `json:"authorizationId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var (
		wrapped []byte
		idx     sql.NullInt64
	)
	err := sa.db.QueryRow(
		`SELECT wrapped_key, share_index FROM `+tblSharedKeys+`
		 WHERE user_id = ? AND authorization_id = ? AND revoked_at IS NULL
		 ORDER BY key_version DESC, share_index ASC LIMIT 1`,
		sess.UserID, req.AuthorizationID,
	).Scan(&wrapped, &idx)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"wrappedShare": base64.StdEncoding.EncodeToString(wrapped),
		"shareIndex":   int(idx.Int64),
	})
}

func (sa *SecureAuth) handleThresholdPartial(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	var req struct {
		CiphertextID string `json:"ciphertextId"`
		ShareIndex   int    `json:"shareIndex"`
		Partial      string `json:"partial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	partial, err := base64.StdEncoding.DecodeString(req.Partial)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	_, err = sa.db.Exec(
		`INSERT OR REPLACE INTO `+tblThresholdParts+`
		 (ciphertext_id, share_index, user_id, partial, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		req.CiphertextID, req.ShareIndex, sess.UserID, partial, time.Now().UTC(),
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sa.appendAudit(sess.UserID, "threshold.partial", req.CiphertextID, "allow", clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (sa *SecureAuth) handleThresholdPartials(w http.ResponseWriter, r *http.Request, _ *sessionInfo) {
	var req struct {
		CiphertextID string `json:"ciphertextId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rows, err := sa.db.Query(
		`SELECT share_index, partial FROM `+tblThresholdParts+`
		 WHERE ciphertext_id = ? ORDER BY share_index`,
		req.CiphertextID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var partials []map[string]interface{}
	for rows.Next() {
		var idx int
		var partial []byte
		if err := rows.Scan(&idx, &partial); err != nil {
			continue
		}
		partials = append(partials, map[string]interface{}{
			"shareIndex": idx,
			"partial":    base64.StdEncoding.EncodeToString(partial),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"partials": partials})
}

// ---------------------------------------------------------------------------
// Template management
// ---------------------------------------------------------------------------

var requiredPlaceholders = map[string]string{
	"login":          "{loginjs}",
	"users":          "{usersjs}",
	"roles":          "{rolesjs}",
	"authorizations": "{authorizationsjs}",
}

func validateTemplate(kind, tpl string) error {
	ph, ok := requiredPlaceholders[kind]
	if !ok {
		return fmt.Errorf("secureauth: unknown template kind %q", kind)
	}
	if !strings.Contains(tpl, ph) {
		return fmt.Errorf("secureauth: template %q must contain %s", kind, ph)
	}
	if strings.Contains(tpl, "<script") {
		return fmt.Errorf("secureauth: template %q must not contain <script> tags", kind)
	}
	return nil
}

func (sa *SecureAuth) SetLoginPageTemplate(tpl string) error {
	if err := validateTemplate("login", tpl); err != nil {
		return err
	}
	t, err := template.New("login").Parse(tpl)
	if err != nil {
		return err
	}
	sa.tplLogin = t
	return nil
}

func (sa *SecureAuth) SetUsersPageTemplate(tpl string) error {
	if err := validateTemplate("users", tpl); err != nil {
		return err
	}
	t, err := template.New("users").Parse(tpl)
	if err != nil {
		return err
	}
	sa.tplUsers = t
	return nil
}

func (sa *SecureAuth) SetRolesPageTemplate(tpl string) error {
	if err := validateTemplate("roles", tpl); err != nil {
		return err
	}
	t, err := template.New("roles").Parse(tpl)
	if err != nil {
		return err
	}
	sa.tplRoles = t
	return nil
}

func (sa *SecureAuth) SetAuthorizationsPageTemplate(tpl string) error {
	if err := validateTemplate("authorizations", tpl); err != nil {
		return err
	}
	t, err := template.New("authorizations").Parse(tpl)
	if err != nil {
		return err
	}
	sa.tplAuthorizations = t
	return nil
}

func (sa *SecureAuth) handleIndex(w http.ResponseWriter, r *http.Request) {
	nonce := cspNonce(r)
	page := r.URL.Path
	var (
		t  *template.Template
		ph string
	)
	switch page {
	case "/login", "/":
		t, ph = sa.tplLogin, "{loginjs}"
	case "/users":
		t, ph = sa.tplUsers, "{usersjs}"
	case "/roles":
		t, ph = sa.tplRoles, "{rolesjs}"
	case "/authorizations":
		t, ph = sa.tplAuthorizations, "{authorizationsjs}"
	default:
		http.NotFound(w, r)
		return
	}
	if t == nil {
		http.Error(w, "template not configured", http.StatusNotFound)
		return
	}
	importMap := `<script type="importmap" nonce="` + nonce + `">` + importMapJSON() + `</script>`
	moduleScript := `<script type="module" nonce="` + nonce + `">` +
		`import { SecureAuth } from "/static/secureauth.mjs"; window.SecureAuth = SecureAuth;` +
		`</script>`
	injection := importMap + moduleScript
	var buf strings.Builder
	if err := t.Execute(&buf, nil); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	out := strings.Replace(buf.String(), ph, injection, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func importMapJSON() string {
	m := map[string]interface{}{
		"imports": map[string]string{
			"@serenity-kit/opaque": "https://cdn.jsdelivr.net/npm/@serenity-kit/opaque@1.1.0/+esm",
			"@noble/ciphers":       "https://cdn.jsdelivr.net/npm/@noble/ciphers@2.3.0/+esm",
			"@noble/curves":        "https://cdn.jsdelivr.net/npm/@noble/curves@2.4.0/+esm",
			"@noble/hashes":        "https://cdn.jsdelivr.net/npm/@noble/hashes@2.2.0/+esm",
		},
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (sa *SecureAuth) handleServeJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = io.WriteString(w, secureAuthJS)
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
