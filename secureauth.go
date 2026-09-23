package secureauth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

//go:embed secureauth.mjs
var secureAuthJS string

//go:embed opaque.mjs
var opaqueJS string

//go:embed qrcode-generator.js
var qrcodeGeneratorJS string

var (
	aadOPAQUEKey  = []byte("secureauth:opaque-server-key-material:v1")
	aadSessionKey = []byte("secureauth:session-key:v1")
)

var hkdfSalt = []byte("SecureAuth HKDF salt v1")

type InitOptions struct {
	MasterKey      []byte
	ServerID       string
	BootstrapToken string
	TLSCertificate []byte
	TrustedProxies []string
	Debug          bool
	Require2FA     bool // if true, users must set up TOTP before accessing anything
	TOTPIssuer     string
}

type SecureAuth struct {
	db             *sql.DB
	masterKey      []byte
	serverID       []byte
	opaqueConf     *opaque.Configuration
	opaqueServer   *opaque.Server
	tlsEndPoint    []byte
	bootstrapToken []byte
	debug          bool
	require2FA     bool
	totpIssuer     string

	trustedProxies []*net.IPNet

	tplLogin, tplUsers, tplRoles, tplAuthorizations *template.Template
	tplTOTPSetup, tplTOTPVerify                     *template.Template

	rl          *rateLimiter
	auditMu     sync.Mutex
	bootstrapMu sync.Mutex

	sessionTTL          time.Duration
	loginAttemptTTL     time.Duration
	loginReturnEndpoint string
}

const maxBodyBytes = 256 * 1024

// ---------------------------------------------------------------------------
// Table names
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
	tblPendingRegs    = "_secureauth_pending_regs_9f3a"
	tblEncryptedData  = "_secureauth_encrypted_data_9f3a"
	tblBootstrap      = "_secureauth_bootstrap_9f3a"
	tblTOTPChallenges = "_secureauth_totp_challenges_9f3a"
)

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func Init(dbdriver string, dsn string, opts InitOptions) (*SecureAuth, error) {
	if len(opts.MasterKey) != 32 {
		return nil, errors.New("secureauth: MasterKey must be exactly 32 bytes")
	}
	if len(opts.TLSCertificate) == 0 && !opts.Debug {
		return nil, errors.New("secureauth: TLSCertificate is required for channel binding")
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
		debug:           opts.Debug,
		require2FA:      opts.Require2FA,
	}
	sa.masterKey = make([]byte, 32)
	copy(sa.masterKey, opts.MasterKey)

	if opts.ServerID != "" {
		sa.serverID = []byte(opts.ServerID)
	} else {
		sa.serverID = []byte("secureauth")
	}

	issuer := opts.TOTPIssuer
	if issuer == "" {
		issuer = string(sa.serverID)
	}
	sa.totpIssuer = sanitizeTOTPIssuer(issuer)

	for _, cidr := range opts.TrustedProxies {
		_, netw, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("secureauth: bad TrustedProxies CIDR %q: %w", cidr, err)
		}
		sa.trustedProxies = append(sa.trustedProxies, netw)
	}

	switch {
	case len(opts.TLSCertificate) > 0:
		h := sha256.Sum256(opts.TLSCertificate)
		sa.tlsEndPoint = h[:]
	case opts.Debug:
		// Debug mode with no cert: derive a fixed, well-known channel-binding
		// value so client and server agree on the transcript input. This value
		// MUST NOT be used outside debug — it provides no binding.
		h := sha256.Sum256([]byte("secureauth:debug:no-channel-binding:v1"))
		sa.tlsEndPoint = h[:]
		log.Printf("secureauth: DEBUG — no TLS certificate, using fixed channel binding")
	default:
		return nil, errors.New("secureauth: TLSCertificate is required for channel binding")
	}

	if opts.BootstrapToken == "" {
		opts.BootstrapToken = base64.RawURLEncoding.EncodeToString(randomBytes(24))
		log.Printf("secureauth: generated bootstrap token (use X-Bootstrap-Token to create the first user): %s", opts.BootstrapToken)
	}
	sa.bootstrapToken = []byte(opts.BootstrapToken)

	conf := &opaque.Configuration{
		OPRF: opaque.RistrettoSha512,
		AKE:  opaque.RistrettoSha512,
		KSF:  ksf.Argon2id,
		KDF:  crypto.SHA512,
		MAC:  crypto.SHA512,
		Hash: crypto.SHA512,
		// Non-nil empty slice so bytemare emits the I2OSP(len(context), 2)
		// || context field inside the OPAQUE-3DH preamble.
		Context: []byte{},
	}
	sa.opaqueConf = conf

	srv, err := conf.Server()
	if err != nil {
		return nil, fmt.Errorf("secureauth: instantiate OPAQUE server: %w", err)
	}
	sa.opaqueServer = srv

	if err := sa.createTables(); err != nil {
		return nil, err
	}
	if err := sa.seedRoles(); err != nil {
		return nil, err
	}
	if err := sa.loadOrGenerateOPAQUEKeyMaterial(); err != nil {
		return nil, err
	}

	if err := sa.installDefaultTemplates(); err != nil {
		return nil, err
	}

	if err := sa.maybeProvisionFirstAdmin(); err != nil {
		return nil, err
	}

	return sa, nil
}

func (sa *SecureAuth) loadOrGenerateOPAQUEKeyMaterial() error {
	var sealed []byte
	err := sa.db.QueryRow(
		`SELECT opaque_server_key_material FROM ` + tblServerKeys + ` WHERE id = 1`,
	).Scan(&sealed)

	if err == nil && len(sealed) > 0 {
		raw, err := sa.open(sealed, aadOPAQUEKey)
		if err != nil {
			return fmt.Errorf("secureauth: decrypt server key material: %w", err)
		}
		skm, err := sa.opaqueConf.DecodeServerKeyMaterial(raw)
		if err != nil {
			return fmt.Errorf("secureauth: decode server key material: %w", err)
		}
		return sa.opaqueServer.SetKeyMaterial(skm)
	}
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("secureauth: load server key material: %w", err)
	}

	priv, pub := sa.opaqueConf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		PrivateKey:     priv,
		PublicKeyBytes: pub.Encode(),
		OPRFGlobalSeed: sa.opaqueConf.GenerateOPRFSeed(),
		Identity:       sa.serverID,
	}
	sealed, err = sa.seal(skm.Encode(), aadOPAQUEKey)
	if err != nil {
		return fmt.Errorf("secureauth: seal server key material: %w", err)
	}
	_, err = sa.db.Exec(
		`UPDATE `+tblServerKeys+` SET opaque_server_key_material = ? WHERE id = 1`,
		sealed,
	)
	if err != nil {
		return fmt.Errorf("secureauth: persist server key material: %w", err)
	}
	return sa.opaqueServer.SetKeyMaterial(skm)
}

func (sa *SecureAuth) createTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS ` + tblUsers + ` (
			username TEXT PRIMARY KEY,
			opaque_registration_record BLOB NOT NULL,
			opaque_credential_id BLOB NOT NULL,
			rsa_public_key BLOB NOT NULL,
			encrypted_rsa_private_key BLOB NOT NULL,
			private_key_nonce BLOB NOT NULL,
			private_key_salt BLOB NOT NULL,
			private_key_kdf_info TEXT,
			rsa_signing_public_key BLOB,
			encrypted_rsa_signing_private_key BLOB,
			signing_key_nonce BLOB,
			signing_key_salt BLOB,
			signing_key_kdf_info TEXT,
			ksf_salt BLOB,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblServerKeys + ` (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			opaque_server_key_material BLOB,
			created_at TIMESTAMP NOT NULL,
			rotated_at TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblSharedKeys + ` (
			user_id TEXT NOT NULL,
			authorization_id TEXT NOT NULL,
			wrapped_key BLOB NOT NULL,
			admin_signature BLOB NOT NULL,
			key_version INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMP NOT NULL,
			revoked_at TIMESTAMP,
			revocation_reason TEXT,
			PRIMARY KEY (user_id, authorization_id, key_version)
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblRoles + ` (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			description TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblAuthorizations + ` (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			description TEXT
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
			paake_transcript_hash BLOB,
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
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			credential_id BLOB NOT NULL,
			client_mac BLOB NOT NULL,
			session_secret BLOB NOT NULL,
			transcript_hash BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblPendingRegs + ` (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			credential_id BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblEncryptedData + ` (
			id TEXT PRIMARY KEY,
			authorization_id TEXT NOT NULL,
			owner_id TEXT NOT NULL,
			key_version INTEGER NOT NULL DEFAULT 1,
			nonce BLOB NOT NULL,
			ciphertext BLOB NOT NULL,
			label TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblBootstrap + ` (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			username TEXT NOT NULL,
			sealed_password BLOB NOT NULL,
			sealed_masterkeys BLOB,
			consumed INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ` + tblTOTPChallenges + ` (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := sa.db.Exec(s); err != nil {
			return fmt.Errorf("secureauth: create table: %w", err)
		}
	}

	migrations := []string{
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN opaque_credential_id BLOB`,
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN rsa_signing_public_key BLOB`,
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN encrypted_rsa_signing_private_key BLOB`,
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN signing_key_nonce BLOB`,
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN signing_key_salt BLOB`,
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN signing_key_kdf_info TEXT`,
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN ksf_salt BLOB`,
		`ALTER TABLE ` + tblSessions + ` ADD COLUMN paake_transcript_hash BLOB`,
		`ALTER TABLE ` + tblServerKeys + ` ADD COLUMN opaque_server_key_material BLOB`,
		// TOTP columns on users table
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN totp_secret BLOB`,
		`ALTER TABLE ` + tblUsers + ` ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`,
		// 2FA pending flag on sessions (set after password but before TOTP)
		`ALTER TABLE ` + tblSessions + ` ADD COLUMN totp_pending INTEGER NOT NULL DEFAULT 0`,
	}
	for _, m := range migrations {
		_, _ = sa.db.Exec(m)
	}

	_, _ = sa.db.Exec(
		`INSERT OR IGNORE INTO `+tblServerKeys+` (id, created_at) VALUES (1, ?)`,
		time.Now().UTC(),
	)
	return nil
}

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
				 (id, name, description)
				 VALUES (?, ?, ?)`, authID, a, "Preset authorization "+a,
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
// First-admin bootstrap
// ---------------------------------------------------------------------------

func (sa *SecureAuth) maybeProvisionFirstAdmin() error {
	var count int
	_ = sa.db.QueryRow(`SELECT COUNT(*) FROM ` + tblUsers).Scan(&count)
	if count > 0 {
		return nil
	}

	_, _ = sa.db.Exec(`CREATE TABLE IF NOT EXISTS ` + tblBootstrap + ` (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		username TEXT NOT NULL,
		sealed_password BLOB NOT NULL,
		sealed_masterkeys BLOB,
		consumed INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP NOT NULL
	)`)

	var bsCount int
	_ = sa.db.QueryRow(`SELECT COUNT(*) FROM ` + tblBootstrap + ` WHERE id = 1 AND consumed = 0`).Scan(&bsCount)
	if bsCount > 0 {
		return nil
	}

	username := os.Getenv("SECUREAUTH_ADMIN_USERNAME")
	password := os.Getenv("SECUREAUTH_ADMIN_PASSWORD")

	generated := false
	if username == "" || password == "" {
		username = "admin-" + hex.EncodeToString(randomBytes(4))
		password = base64.RawURLEncoding.EncodeToString(randomBytes(18))
		generated = true
	}

	if generated {
		log.Printf("secureauth: *** FIRST-RUN CREDENTIALS (shown once) ***")
		log.Printf("secureauth: admin username: %s", username)
		log.Printf("secureauth: admin password: %s", password)
		log.Printf("secureauth: *** store these securely — they will not be shown again ***")
	}

	sealedPwd, err := sa.seal([]byte(password), []byte("secureauth:bootstrap-password:v1"))
	if err != nil {
		return fmt.Errorf("secureauth: seal bootstrap password: %w", err)
	}

	authRows, err := sa.db.Query(`SELECT id FROM ` + tblAuthorizations)
	if err != nil {
		return fmt.Errorf("secureauth: list authorizations for bootstrap: %w", err)
	}
	defer authRows.Close()

	type authMK struct {
		AuthID    string
		Masterkey []byte
	}
	var mks []authMK
	for authRows.Next() {
		var id string
		if err := authRows.Scan(&id); err != nil {
			continue
		}
		mks = append(mks, authMK{AuthID: id, Masterkey: randomBytes(32)})
	}

	mkMap := make(map[string]string, len(mks))
	for _, m := range mks {
		mkMap[m.AuthID] = base64.StdEncoding.EncodeToString(m.Masterkey)
	}
	mkJSON, err := json.Marshal(mkMap)
	if err != nil {
		return fmt.Errorf("secureauth: marshal bootstrap masterkeys: %w", err)
	}
	sealedMK, err := sa.seal(mkJSON, []byte("secureauth:bootstrap-masterkeys:v1"))
	if err != nil {
		return fmt.Errorf("secureauth: seal bootstrap masterkeys: %w", err)
	}

	for i := range mks {
		for j := range mks[i].Masterkey {
			mks[i].Masterkey[j] = 0
		}
	}

	_, err = sa.db.Exec(
		`INSERT OR REPLACE INTO `+tblBootstrap+`
		 (id, username, sealed_password, sealed_masterkeys, consumed, created_at)
		 VALUES (1, ?, ?, ?, 0, ?)`,
		username, sealedPwd, sealedMK, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("secureauth: persist bootstrap record: %w", err)
	}

	log.Printf("secureauth: first-admin bootstrap record created for user %q", username)
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

func (sa *SecureAuth) seal(plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sa.masterKey)
	if err != nil {
		return nil, err
	}
	nonce := randNonce()
	ct := aead.Seal(nil, nonce, plaintext, aad)
	return append(nonce, ct...), nil
}

func (sa *SecureAuth) open(ciphertext, aad []byte) ([]byte, error) {
	if len(ciphertext) < 24+16 {
		return nil, errors.New("secureauth: ciphertext too short")
	}
	aead, err := chacha20poly1305.NewX(sa.masterKey)
	if err != nil {
		return nil, err
	}
	nonce, ct := ciphertext[:24], ciphertext[24:]
	return aead.Open(nil, nonce, ct, aad)
}

func hkdfExpand(ikm, info []byte, n int) []byte {
	r := hkdf.New(sha256.New, ikm, hkdfSalt, info)
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

func validateUsername(u string) error {
	if len(u) < 3 || len(u) > 64 {
		return errors.New("secureauth: username must be 3-64 characters")
	}
	for _, c := range u {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '-':
		default:
			return errors.New("secureauth: username contains invalid characters")
		}
	}
	return nil
}

func (sa *SecureAuth) userLogTag(username string) string {
	h := hmacSHA256(sa.masterKey, []byte("log-tag:"+username))
	return hex.EncodeToString(h[:8])
}

func auditActor(r *http.Request, fallback string) string {
	if sess := sessionFrom(r); sess != nil && sess.UserID != "" {
		return sess.UserID
	}
	return fallback
}

func (sa *SecureAuth) hasRegisteredUsers(ctx context.Context) (bool, error) {
	var count int
	if err := sa.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM `+tblUsers).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// authorizationName returns the name of an authorization row, or sql.ErrNoRows.
func (sa *SecureAuth) authorizationName(authID string) (string, error) {
	var name string
	err := sa.db.QueryRow(
		`SELECT name FROM `+tblAuthorizations+` WHERE id = ?`, authID,
	).Scan(&name)
	return name, err
}

// revokeStaleSharedKeysTx revokes any shared key row whose (user, authorization)
// pair is no longer backed by a role grant. It must be called after any change
// to tblUserRoles or tblRoleAuth, inside the same transaction.
func revokeStaleSharedKeysTx(tx *sql.Tx, now time.Time) error {
	_, err := tx.Exec(`
		UPDATE `+tblSharedKeys+` SET revoked_at = ?, revocation_reason = 'permissions changed'
		WHERE revoked_at IS NULL
		  -- Only consider keys whose authorization is actually role-granted.
		  AND EXISTS (
			SELECT 1 FROM `+tblRoleAuth+` ra
			WHERE ra.authorization_id = `+tblSharedKeys+`.authorization_id
		  )
		  -- ...and revoke only if the user no longer holds any role that grants it.
		  AND NOT EXISTS (
			SELECT 1 FROM `+tblRoleAuth+` ra
			JOIN `+tblUserRoles+` ur ON ur.role_id = ra.role_id
			WHERE ra.authorization_id = `+tblSharedKeys+`.authorization_id
			  AND ur.user_id = `+tblSharedKeys+`.user_id
		  )`, now)
	return err
}

// ---------------------------------------------------------------------------
// Programmatic authorization & role registration
//
// These functions let a host application declare its own authorizations and
// roles before the first admin bootstraps. When a pending bootstrap record
// exists, a fresh 32-byte masterkey is generated for each newly registered
// authorization and sealed inside the bootstrap payload, so the first admin
// automatically receives a wrapped copy of it during first login. This is
// the programmatic equivalent of seeding additional authorizations at Init
// time.
//
// After bootstrap has completed, RegisterAuthorization inserts the row but
// does not create a masterkey (post-bootstrap masterkey distribution is
// handled by the HTTP API and the browser client). To avoid name collisions
// and to keep the data store usable from day one, register all custom
// authorizations before the first admin logs in.
// ---------------------------------------------------------------------------

// RegisterAuthorization registers an authorization with an explicit ID.
//
// id must be non-empty and unique. name must be non-empty and unique. Both
// are enforced by the database; the function returns a descriptive error if
// either collides with an existing row.
//
// Idempotent: calling RegisterAuthorization with the same (id, name) pair
// that is already present is a no-op that returns nil.
//
// Intended to be called after Init but before the first admin bootstraps.
// See the package comment above for the post-bootstrap caveat.
func (sa *SecureAuth) RegisterAuthorization(id, name, description string) error {
	if id == "" || name == "" {
		return errors.New("secureauth: RegisterAuthorization: id and name are required")
	}

	sa.bootstrapMu.Lock()
	defer sa.bootstrapMu.Unlock()

	tx, err := sa.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("secureauth: RegisterAuthorization: begin tx: %w", err)
	}
	defer tx.Rollback()

	var existingName string
	errID := tx.QueryRow(
		`SELECT name FROM `+tblAuthorizations+` WHERE id = ?`, id,
	).Scan(&existingName)
	switch {
	case errID == nil:
		if existingName != name {
			return fmt.Errorf(
				"secureauth: authorization id %q already registered with name %q",
				id, existingName,
			)
		}
		// Same id, same name → idempotent. Fall through to masterkey check.
	case errID == sql.ErrNoRows:
		var existingID string
		errName := tx.QueryRow(
			`SELECT id FROM `+tblAuthorizations+` WHERE name = ?`, name,
		).Scan(&existingID)
		if errName == nil {
			return fmt.Errorf(
				"secureauth: authorization name %q already registered as id %q",
				name, existingID,
			)
		}
		if errName != sql.ErrNoRows {
			return fmt.Errorf("secureauth: RegisterAuthorization: lookup by name: %w", errName)
		}
		if _, err := tx.Exec(
			`INSERT INTO `+tblAuthorizations+` (id, name, description) VALUES (?, ?, ?)`,
			id, name, description,
		); err != nil {
			return fmt.Errorf("secureauth: insert authorization: %w", err)
		}
	default:
		return fmt.Errorf("secureauth: RegisterAuthorization: lookup by id: %w", errID)
	}

	if err := sa.addBootstrapMasterkeyTx(tx, id); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("secureauth: RegisterAuthorization: commit: %w", err)
	}
	return nil
}

// RegisterAuthorizationByName is a convenience wrapper that derives the ID
// as "auth-" + name, matching the convention used by the preset
// authorizations. Returns the derived ID on success.
func (sa *SecureAuth) RegisterAuthorizationByName(name, description string) (string, error) {
	if name == "" {
		return "", errors.New("secureauth: RegisterAuthorizationByName: name is required")
	}
	id := "auth-" + name
	if err := sa.RegisterAuthorization(id, name, description); err != nil {
		return "", err
	}
	return id, nil
}

// RegisterRole registers a role with an explicit ID and links it to the
// given authorization IDs. Each authorization ID must already be registered
// (via RegisterAuthorization, RegisterAuthorizationByName, or the presets).
//
// Intended to be called after Init but before the first admin bootstraps,
// although it is safe to call at any time. Unlike RegisterAuthorization,
// registering a role never touches the bootstrap masterkeys.
//
// Idempotent: calling RegisterRole with the same (id, name) pair that is
// already present is a no-op for the role row, but the authorization links
// are still ensured (existing links are preserved, new ones are added).
func (sa *SecureAuth) RegisterRole(id, name, description string, authorizationIDs []string) error {
	if id == "" || name == "" {
		return errors.New("secureauth: RegisterRole: id and name are required")
	}

	tx, err := sa.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("secureauth: RegisterRole: begin tx: %w", err)
	}
	defer tx.Rollback()

	for _, authID := range authorizationIDs {
		var one int
		err := tx.QueryRow(
			`SELECT 1 FROM `+tblAuthorizations+` WHERE id = ?`, authID,
		).Scan(&one)
		if err == sql.ErrNoRows {
			return fmt.Errorf(
				"secureauth: RegisterRole: authorization %q not registered",
				authID,
			)
		}
		if err != nil {
			return fmt.Errorf("secureauth: RegisterRole: lookup authorization %q: %w", authID, err)
		}
	}

	var existingName string
	errID := tx.QueryRow(
		`SELECT name FROM `+tblRoles+` WHERE id = ?`, id,
	).Scan(&existingName)
	switch {
	case errID == nil:
		if existingName != name {
			return fmt.Errorf(
				"secureauth: role id %q already registered with name %q",
				id, existingName,
			)
		}
		// Same id, same name → idempotent. Fall through to link insertion.
	case errID == sql.ErrNoRows:
		var existingID string
		errName := tx.QueryRow(
			`SELECT id FROM `+tblRoles+` WHERE name = ?`, name,
		).Scan(&existingID)
		if errName == nil {
			return fmt.Errorf(
				"secureauth: role name %q already registered as id %q",
				name, existingID,
			)
		}
		if errName != sql.ErrNoRows {
			return fmt.Errorf("secureauth: RegisterRole: lookup by name: %w", errName)
		}
		if _, err := tx.Exec(
			`INSERT INTO `+tblRoles+` (id, name, description) VALUES (?, ?, ?)`,
			id, name, description,
		); err != nil {
			return fmt.Errorf("secureauth: insert role: %w", err)
		}
	default:
		return fmt.Errorf("secureauth: RegisterRole: lookup by id: %w", errID)
	}

	for _, authID := range authorizationIDs {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO `+tblRoleAuth+` (role_id, authorization_id) VALUES (?, ?)`,
			id, authID,
		); err != nil {
			return fmt.Errorf("secureauth: link role %q to authorization %q: %w", id, authID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("secureauth: RegisterRole: commit: %w", err)
	}
	return nil
}

// RegisterRoleByName is a convenience wrapper that derives the role ID as
// "role-" + name and resolves each authorization name to its registered ID.
// Returns the derived role ID on success.
func (sa *SecureAuth) RegisterRoleByName(name, description string, authorizationNames []string) (string, error) {
	if name == "" {
		return "", errors.New("secureauth: RegisterRoleByName: name is required")
	}

	authIDs := make([]string, 0, len(authorizationNames))
	for _, n := range authorizationNames {
		var authID string
		err := sa.db.QueryRow(
			`SELECT id FROM `+tblAuthorizations+` WHERE name = ?`, n,
		).Scan(&authID)
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("secureauth: RegisterRoleByName: authorization %q not registered", n)
		}
		if err != nil {
			return "", fmt.Errorf("secureauth: RegisterRoleByName: lookup authorization %q: %w", n, err)
		}
		authIDs = append(authIDs, authID)
	}

	id := "role-" + name
	if err := sa.RegisterRole(id, name, description, authIDs); err != nil {
		return "", err
	}
	return id, nil
}

// addBootstrapMasterkeyTx ensures the pending bootstrap record (if any) holds
// a fresh masterkey for the given authorization ID. It is a no-op when no
// bootstrap record exists or when bootstrap has already been consumed, and
// when the authorization already has a masterkey in the sealed blob.
func (sa *SecureAuth) addBootstrapMasterkeyTx(tx *sql.Tx, authID string) error {
	var consumed int
	var sealedMK []byte
	err := tx.QueryRow(
		`SELECT consumed, sealed_masterkeys FROM `+tblBootstrap+` WHERE id = 1`,
	).Scan(&consumed, &sealedMK)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("secureauth: addBootstrapMasterkeyTx: load bootstrap record: %w", err)
	}
	if consumed != 0 {
		return nil
	}

	mkMap := make(map[string]string)
	if len(sealedMK) > 0 {
		raw, err := sa.open(sealedMK, []byte("secureauth:bootstrap-masterkeys:v1"))
		if err != nil {
			return fmt.Errorf("secureauth: addBootstrapMasterkeyTx: open masterkeys: %w", err)
		}
		if err := json.Unmarshal(raw, &mkMap); err != nil {
			return fmt.Errorf("secureauth: addBootstrapMasterkeyTx: unmarshal masterkeys: %w", err)
		}
	}
	if _, ok := mkMap[authID]; ok {
		return nil
	}

	mk := randomBytes(32)
	mkMap[authID] = base64.StdEncoding.EncodeToString(mk)
	for i := range mk {
		mk[i] = 0
	}

	raw, err := json.Marshal(mkMap)
	if err != nil {
		return fmt.Errorf("secureauth: addBootstrapMasterkeyTx: marshal masterkeys: %w", err)
	}
	sealed, err := sa.seal(raw, []byte("secureauth:bootstrap-masterkeys:v1"))
	if err != nil {
		return fmt.Errorf("secureauth: addBootstrapMasterkeyTx: seal masterkeys: %w", err)
	}
	if _, err := tx.Exec(
		`UPDATE `+tblBootstrap+` SET sealed_masterkeys = ? WHERE id = 1`,
		sealed,
	); err != nil {
		return fmt.Errorf("secureauth: addBootstrapMasterkeyTx: persist masterkeys: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Host-application integration helpers
//
// These functions are exposed so a host application built on top of
// SecureAuth can perform the same checks and emit the same audit entries as
// SecureAuth's own handlers, without needing access to the private API.
// ---------------------------------------------------------------------------

// AppendAudit appends one entry to the tamper-evident audit chain. Exposed
// so host applications can log their own mutations into the same hash chain
// as SecureAuth's built-in operations (see VerifyAuditChain).
//
// (action, resource, result, details) are free-form; SecureAuth itself uses
// action ∈ {"authorize", "login2", "user.create", ...} and result ∈
// {"allow", "deny"}. Hosts should follow the same convention.
func (sa *SecureAuth) AppendAudit(userID, action, resource, result, ip, details string) {
	sa.appendAudit(userID, action, resource, result, ip, details)
}

// UserHasPermission reports whether userID currently holds the named
// authorization, without requiring an *http.Request. Role-based only; see
// UserHasAuthorization for the role-or-shared-key variant.
func (sa *SecureAuth) UserHasPermission(userID, permission string) (bool, error) {
	return sa.userHasPermission(userID, permission)
}

// AuthorizationNameByID resolves an authorization ID to its name. Returns
// sql.ErrNoRows when the ID is unknown.
func (sa *SecureAuth) AuthorizationNameByID(authID string) (string, error) {
	return sa.authorizationName(authID)
}

// UserExists reports whether a username is registered. Used by hosts to
// validate share targets before storing wrapped keys for them.
func (sa *SecureAuth) UserExists(username string) (bool, error) {
	var one int
	err := sa.db.QueryRow(
		`SELECT 1 FROM `+tblUsers+` WHERE username = ?`, username,
	).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238 / RFC 4226) — pure-stdlib implementation
// ---------------------------------------------------------------------------

// totpGenerateSecret creates a random 20-byte TOTP secret and seals it with
// the server master key before storage.
func (sa *SecureAuth) totpGenerateSecret() (raw []byte, sealed []byte, err error) {
	raw = randomBytes(20)
	sealed, err = sa.seal(raw, []byte("secureauth:totp-secret:v1"))
	return
}

// totpOpenSecret decrypts a sealed TOTP secret.
func (sa *SecureAuth) totpOpenSecret(sealed []byte) ([]byte, error) {
	return sa.open(sealed, []byte("secureauth:totp-secret:v1"))
}

// totpHOTP implements RFC 4226.
func totpHOTP(secret []byte, counter uint64, digits int) string {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg)
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	d := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, code%d)
}

// totpVerify checks the provided 6-digit code against the secret, accepting
// a window of ±1 step (30s) to tolerate clock skew.
func totpVerify(secret []byte, code string, t time.Time) bool {
	if len(code) != 6 {
		return false
	}
	step := uint64(t.Unix() / 30)
	for _, s := range []uint64{step - 1, step, step + 1} {
		if subtle.ConstantTimeCompare([]byte(totpHOTP(secret, s, 6)), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// SetTOTPIssuer overrides the display name shown by authenticator apps for
// this server. Call it once at startup, before serving requests — it is not
// synchronised and concurrent calls would race.
//
// An empty string restores the default (ServerID).
func (sa *SecureAuth) SetTOTPIssuer(issuer string) {
	if issuer == "" {
		issuer = string(sa.serverID)
	}
	sa.totpIssuer = sanitizeTOTPIssuer(issuer)
}

// sanitizeTOTPIssuer removes characters that would break the otpauth://
// label format. Google's key-uri spec uses ":" as the separator between the
// issuer and the account name, so an unescaped colon in the issuer would
// make authenticator apps show a truncated or garbled label.
func sanitizeTOTPIssuer(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	issuer = strings.ReplaceAll(issuer, ":", "")
	if issuer == "" {
		return "SecureAuth"
	}
	return issuer
}

// totpProvisioningURI returns an otpauth:// URI for QR code generation.
func totpProvisioningURI(secret []byte, username, issuer string) string {
	b32 := base32.StdEncoding.WithPadding(base32.StdPadding).EncodeToString(secret)
	label := url.PathEscape(issuer + ":" + username)
	v := url.Values{}
	v.Set("secret", b32)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// sessionIsTOTPPending reports whether the session has completed password auth
// but is still waiting for TOTP verification.
func (sa *SecureAuth) sessionIsTOTPPending(sessionID string) bool {
	var pending int
	_ = sa.db.QueryRow(
		`SELECT totp_pending FROM `+tblSessions+` WHERE session_id = ?`, sessionID,
	).Scan(&pending)
	return pending == 1
}

// userHasTOTP reports whether the user has TOTP enabled.
func (sa *SecureAuth) userHasTOTP(username string) (bool, error) {
	var enabled int
	err := sa.db.QueryRow(
		`SELECT totp_enabled FROM `+tblUsers+` WHERE username = ?`, username,
	).Scan(&enabled)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return enabled == 1, err
}

// ---------------------------------------------------------------------------
// 2FA HTTP handlers  (served under /api/2fa/*)
// ---------------------------------------------------------------------------

// handleTOTPStatus — GET /api/2fa/status
// Returns whether the current user has TOTP enabled.
func (sa *SecureAuth) handleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, err := sa.loadSessionInfo(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	enabled, err := sa.userHasTOTP(sess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":    enabled,
		"required":   sa.require2FA,
		"configured": enabled,
	})
}

// handleTOTPSetupBegin — POST /api/2fa/setup/begin
// Generates a fresh TOTP secret, seals it in a temporary challenge row,
// and returns the provisioning URI + base32 secret for QR display.
func (sa *SecureAuth) handleTOTPSetupBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, err := sa.loadSessionInfo(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// If 2FA is enforced and the session is still pending verification,
	// we allow setup to proceed (that's the point of the redirect).
	// But if there's an *existing* pending TOTP challenge, delete it first.
	_, _ = sa.db.Exec(
		`DELETE FROM `+tblTOTPChallenges+` WHERE session_id = ?`, sess.SessionID,
	)

	raw, sealed, err := sa.totpGenerateSecret()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	challengeID := hex.EncodeToString(randomBytes(32))
	_, err = sa.db.Exec(
		`INSERT INTO `+tblTOTPChallenges+`
		 (id, session_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		challengeID, sess.SessionID,
		time.Now().UTC(), time.Now().Add(10*time.Minute).UTC(),
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Seal the temporary secret keyed to the challenge ID so it can't be
	// replayed across sessions.
	sealedForChallenge, err := sa.seal(sealed, []byte("secureauth:totp-setup-challenge:"+challengeID))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	uri := totpProvisioningURI(raw, sess.UserID, sa.totpIssuer)
	b32 := base32.StdEncoding.WithPadding(base32.StdPadding).EncodeToString(raw)

	// Wipe plaintext secret from memory
	for i := range raw {
		raw[i] = 0
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"challengeId":     challengeID,
		"provisioningUri": uri,
		"secret":          b32,
		"sealedSecret":    base64.StdEncoding.EncodeToString(sealedForChallenge),
	})
}

// handleTOTPSetupFinish — POST /api/2fa/setup/finish
// Verifies the user's first TOTP code, then persists the sealed secret
// and marks totp_enabled = 1.
func (sa *SecureAuth) handleTOTPSetupFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, err := sa.loadSessionInfo(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		ChallengeID  string `json:"challengeId"`
		SealedSecret string `json:"sealedSecret"`
		Code         string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Verify the challenge belongs to this session and is unexpired.
	var storedSessionID string
	var expires time.Time
	err = sa.db.QueryRow(
		`SELECT session_id, expires_at FROM `+tblTOTPChallenges+` WHERE id = ?`,
		req.ChallengeID,
	).Scan(&storedSessionID, &expires)
	if err != nil || storedSessionID != sess.SessionID || time.Now().After(expires) {
		http.Error(w, "invalid or expired challenge", http.StatusBadRequest)
		return
	}
	_, _ = sa.db.Exec(`DELETE FROM `+tblTOTPChallenges+` WHERE id = ?`, req.ChallengeID)

	// Unseal the temporary secret.
	sealedForChallenge, err := base64.StdEncoding.DecodeString(req.SealedSecret)
	if err != nil {
		http.Error(w, "bad request: sealedSecret", http.StatusBadRequest)
		return
	}
	innerSealed, err := sa.open(sealedForChallenge, []byte("secureauth:totp-setup-challenge:"+req.ChallengeID))
	if err != nil {
		http.Error(w, "bad request: cannot unseal secret", http.StatusBadRequest)
		return
	}
	raw, err := sa.totpOpenSecret(innerSealed)
	if err != nil {
		http.Error(w, "bad request: cannot open secret", http.StatusBadRequest)
		return
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()

	if !totpVerify(raw, req.Code, time.Now()) {
		sa.appendAudit(sess.UserID, "2fa.setup", "", "deny", sa.clientIP(r), "invalid code")
		http.Error(w, "invalid TOTP code", http.StatusUnauthorized)
		return
	}

	// Persist the sealed secret and mark TOTP enabled. Also clear any
	// totp_pending flag on the current session.
	_, err = sa.db.Exec(
		`UPDATE `+tblUsers+` SET totp_secret = ?, totp_enabled = 1 WHERE username = ?`,
		innerSealed, sess.UserID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, _ = sa.db.Exec(
		`UPDATE `+tblSessions+` SET totp_pending = 0 WHERE session_id = ?`, sess.SessionID,
	)

	sa.appendAudit(sess.UserID, "2fa.setup", "", "allow", sa.clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleTOTPVerify — POST /api/2fa/verify
// Called immediately after login when the user has TOTP enabled (or when
// they are redirected to /2fa/verify from a pending session).
func (sa *SecureAuth) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := sa.clientIP(r)
	if !sa.rl.allow("2fa-verify:"+ip, 10, 1.0/60.0) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	sess, err := sa.loadSessionInfo(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var sealedSecret []byte
	err = sa.db.QueryRow(
		`SELECT totp_secret FROM `+tblUsers+` WHERE username = ? AND totp_enabled = 1`,
		sess.UserID,
	).Scan(&sealedSecret)
	if err != nil {
		http.Error(w, "2FA not configured", http.StatusBadRequest)
		return
	}

	raw, err := sa.totpOpenSecret(sealedSecret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()

	if !totpVerify(raw, req.Code, time.Now()) {
		if !sa.rl.allow("2fa-fail:"+sess.UserID, 5, 1.0/120.0) {
			// Too many failures: invalidate the session entirely.
			_, _ = sa.db.Exec(`DELETE FROM `+tblSessions+` WHERE session_id = ?`, sess.SessionID)
			http.SetCookie(w, &http.Cookie{
				Name: "secureauth_session", Value: "", Path: "/", MaxAge: -1,
				Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
			sa.appendAudit(sess.UserID, "2fa.verify", "", "deny", ip, "too many failures — session terminated")
			http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
			return
		}
		sa.appendAudit(sess.UserID, "2fa.verify", "", "deny", ip, "invalid code")
		http.Error(w, "invalid TOTP code", http.StatusUnauthorized)
		return
	}

	_, _ = sa.db.Exec(
		`UPDATE `+tblSessions+` SET totp_pending = 0 WHERE session_id = ?`, sess.SessionID,
	)
	sa.appendAudit(sess.UserID, "2fa.verify", "", "allow", ip, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleTOTPDisable — POST /api/2fa/disable
// Disables TOTP for the authenticated user (requires a valid current code).
func (sa *SecureAuth) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, err := sa.loadSessionInfo(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// If 2FA is enforced server-side, nobody can disable it.
	if sa.require2FA {
		http.Error(w, "2FA is enforced and cannot be disabled", http.StatusForbidden)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var sealedSecret []byte
	err = sa.db.QueryRow(
		`SELECT totp_secret FROM `+tblUsers+` WHERE username = ? AND totp_enabled = 1`,
		sess.UserID,
	).Scan(&sealedSecret)
	if err != nil {
		http.Error(w, "2FA not configured", http.StatusBadRequest)
		return
	}
	raw, err := sa.totpOpenSecret(sealedSecret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()

	if !totpVerify(raw, req.Code, time.Now()) {
		sa.appendAudit(sess.UserID, "2fa.disable", "", "deny", sa.clientIP(r), "invalid code")
		http.Error(w, "invalid TOTP code", http.StatusUnauthorized)
		return
	}

	_, err = sa.db.Exec(
		`UPDATE `+tblUsers+` SET totp_secret = NULL, totp_enabled = 0 WHERE username = ?`,
		sess.UserID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sa.appendAudit(sess.UserID, "2fa.disable", "", "allow", sa.clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

func SecureAuthAndCommHandler(sa *SecureAuth, mux *http.ServeMux) http.Handler {
	mux.HandleFunc("/api/server-id", sa.wrap(sa.handleServerID, false))
	mux.HandleFunc("/api/tls-server-end-point", sa.wrap(sa.handleTlsServerEndPoint, false))
	mux.HandleFunc("/api/register/init", sa.wrap(sa.handleRegisterInit, false))
	mux.HandleFunc("/api/login/init", sa.wrap(sa.handleLoginInit, false))
	mux.HandleFunc("/api/login2", sa.wrap(sa.handleLogin2, false))

	// /logout must be CSRF-exempt: a stale session cookie can otherwise
	// block the browser from ever clearing it (no CSRF token is available
	// until after a successful login).
	mux.HandleFunc("/logout", sa.wrap(sa.handleLogout, false))

	mux.HandleFunc("/api/privatekey", sa.wrap(sa.loadSession(sa.handleGetPrivateKey), true))

	mux.HandleFunc("/api/createuser", sa.wrap(sa.requirePermissionOrBootstrap("user.create", sa.handleCreateUser), true))
	mux.HandleFunc("/api/deleteuser", sa.wrap(sa.requirePermission("user.delete", sa.handleDeleteUser), true))
	mux.HandleFunc("/api/getusers", sa.wrap(sa.requirePermission("user.read", sa.handleGetUsers), false))
	mux.HandleFunc("/api/updateuser", sa.wrap(sa.requirePermission("user.update", sa.handleUpdateUser), true))

	mux.HandleFunc("/api/sharekeys", sa.wrap(sa.requirePermission("sharekeys.write", sa.handleShareKeys), true))
	mux.HandleFunc("/api/shared-keys/check", sa.wrap(sa.loadSession(sa.handleSharedKeysCheck), false))
	mux.HandleFunc("/api/get-wrapped-masterkey", sa.wrap(sa.loadSession(sa.handleGetWrappedMasterkey), false))

	mux.HandleFunc("/api/getroles", sa.wrap(sa.requirePermission("role.read", sa.handleGetRoles), false))
	mux.HandleFunc("/api/addrole", sa.wrap(sa.requirePermission("role.create", sa.handleAddRole), true))
	mux.HandleFunc("/api/updaterole", sa.wrap(sa.requirePermission("role.update", sa.handleUpdateRole), true))
	mux.HandleFunc("/api/deleterole", sa.wrap(sa.requirePermission("role.delete", sa.handleDeleteRole), true))

	mux.HandleFunc("/api/getauthorizations", sa.wrap(sa.requirePermission("authorization.read", sa.handleGetAuthorizations), false))
	mux.HandleFunc("/api/addauthorization", sa.wrap(sa.requirePermission("authorization.create", sa.handleAddAuthorization), true))
	mux.HandleFunc("/api/updateauthorization", sa.wrap(sa.requirePermission("authorization.update", sa.handleUpdateAuthorization), true))
	mux.HandleFunc("/api/deleteauthorization", sa.wrap(sa.requirePermission("authorization.delete", sa.handleDeleteAuthorization), true))

	mux.HandleFunc("/api/data/put", sa.wrap(sa.loadSession(sa.handleDataPut), true))
	mux.HandleFunc("/api/data/get", sa.wrap(sa.loadSession(sa.handleDataGet), false))
	mux.HandleFunc("/api/data/delete", sa.wrap(sa.loadSession(sa.handleDataDelete), true))
	mux.HandleFunc("/api/data/list", sa.wrap(sa.loadSession(sa.handleDataList), false))

	mux.HandleFunc("/api/bootstrap/credentials", sa.wrap(sa.handleBootstrapCredentials, false))
	mux.HandleFunc("/api/bootstrap/masterkeys-pending", sa.wrap(sa.handleBootstrapMasterkeysPending, false))
	mux.HandleFunc("/api/bootstrap/first-user", sa.wrap(sa.handleBootstrapFirstUser, true))

	// 2FA endpoints — status and verify are accessible even with totp_pending
	// sessions; setup/finish and disable require a fully-authenticated session.
	mux.HandleFunc("/api/2fa/status", sa.wrap(sa.handleTOTPStatus, false))
	mux.HandleFunc("/api/2fa/setup/begin", sa.wrap(sa.handleTOTPSetupBegin, true))
	mux.HandleFunc("/api/2fa/setup/finish", sa.wrap(sa.handleTOTPSetupFinish, true))
	mux.HandleFunc("/api/2fa/verify", sa.wrap(sa.handleTOTPVerify, true))
	mux.HandleFunc("/api/2fa/disable", sa.wrap(sa.handleTOTPDisable, true))

	mux.HandleFunc("/static/secureauth.mjs", sa.wrap(sa.handleServeSecureAuthJS, false))
	mux.HandleFunc("/static/opaque.mjs", sa.wrap(sa.handleServeOpaqueJS, false))
	mux.HandleFunc("/static/qrcode-generator.js", sa.wrap(sa.handleServeQRCodeGeneratorJS, false))
	mux.HandleFunc("/", sa.wrap(sa.handleIndex, false))
	return mux
}

func (sa *SecureAuth) wrap(next http.HandlerFunc, needsCSRF bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		if err := requireTLS(r); err != nil {
			http.Error(w, "HTTPS required", http.StatusForbidden)
			return
		}
		r = sa.setSecurityHeaders(w, r) // ← was setSecurityHeaders(w, r)

		if needsCSRF && sessionIDFromRequest(r) != "" {
			if _, err := sa.loadSessionInfo(r); err == nil {
				if err := sa.verifyCSRF(r); err != nil {
					http.Error(w, "CSRF check failed", http.StatusForbidden)
					return
				}
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

func (sa *SecureAuth) setSecurityHeaders(w http.ResponseWriter, r *http.Request) *http.Request {
	nonce := hex.EncodeToString(randomBytes(16))
	r = r.WithContext(context.WithValue(r.Context(), cspNonceKey{}, nonce))

	h := w.Header()
	if !sa.debug {
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; "+
			"script-src 'nonce-%s' 'self' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; "+
			"style-src 'self' 'unsafe-inline'; "+
			"connect-src 'self' https://cdn.jsdelivr.net; "+
			"img-src 'self'; "+
			"frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
		nonce,
	))
	return r
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

func (sa *SecureAuth) auditHash(prevHash []byte, ts, userID, action, resource, result, ip, details string) []byte {
	mac := hmac.New(sha256.New, sa.masterKey)
	mac.Write(prevHash)
	mac.Write([]byte(ts))
	mac.Write([]byte(userID))
	mac.Write([]byte(action))
	mac.Write([]byte(resource))
	mac.Write([]byte(result))
	mac.Write([]byte(ip))
	mac.Write([]byte(details))
	return mac.Sum(nil)
}

func (sa *SecureAuth) appendAudit(userID, action, resource, result, ip, details string) {
	sa.auditMu.Lock()
	defer sa.auditMu.Unlock()

	var prevHash []byte
	row := sa.db.QueryRow(
		`SELECT entry_hash FROM ` + tblAudit + ` ORDER BY id DESC LIMIT 1`,
	)
	_ = row.Scan(&prevHash)

	ts := time.Now().UTC().Format(time.RFC3339Nano)
	entryHash := sa.auditHash(prevHash, ts, userID, action, resource, result, ip, details)

	_, _ = sa.db.Exec(
		`INSERT INTO `+tblAudit+`
		 (timestamp, user_id, action, resource, result, ip_address, details,
		  prev_hash, entry_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, userID, action, resource, result, ip, details, prevHash, entryHash,
	)
}

func (sa *SecureAuth) VerifyAuditChain() error {
	rows, err := sa.db.Query(
		`SELECT prev_hash, entry_hash, timestamp, user_id, action, resource,
		        result, ip_address, details
		 FROM ` + tblAudit + ` ORDER BY id`,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	var prev []byte
	for rows.Next() {
		var (
			prevHash, entryHash                               []byte
			ts, userID, action, resource, result, ip, details string
		)
		if err := rows.Scan(&prevHash, &entryHash, &ts, &userID, &action,
			&resource, &result, &ip, &details); err != nil {
			return err
		}
		if !hmac.Equal(prevHash, prev) {
			return errors.New("secureauth: audit chain broken (prev_hash mismatch)")
		}
		expected := sa.auditHash(prevHash, ts, userID, action, resource, result, ip, details)
		if !hmac.Equal(expected, entryHash) {
			return errors.New("secureauth: audit chain broken (entry_hash mismatch)")
		}
		prev = entryHash
	}
	return rows.Err()
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

func (sa *SecureAuth) newCSRF(sessionID string) (token, cookieValue string) {
	raw := randomBytes(32)
	token = base64.StdEncoding.EncodeToString(raw)
	// Same value goes in the cookie and the DB. Classic double-submit.
	return token, token
}

func (sa *SecureAuth) verifyCSRF(r *http.Request) error {
	sessionID := sessionIDFromRequest(r)
	if sessionID == "" {
		return errors.New("no session")
	}
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		return errors.New("no CSRF header")
	}
	var stored string
	err := sa.db.QueryRow(
		`SELECT csrf_token FROM `+tblSessions+` WHERE session_id = ?`, sessionID,
	).Scan(&stored)
	if err != nil {
		return errors.New("no session row")
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(header)) != 1 {
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
	SessionID   string
	UserID      string
	Key         []byte
	CSRF        string
	ExpiresAt   time.Time
	TOTPPending bool // password auth done but TOTP not yet verified
}

func (sa *SecureAuth) loadSessionInfo(r *http.Request) (*sessionInfo, error) {
	sid := sessionIDFromRequest(r)
	if sid == "" {
		return nil, errors.New("no session cookie")
	}
	var (
		userID      string
		keyCipher   []byte
		csrf        string
		expires     time.Time
		totpPending int
	)
	err := sa.db.QueryRow(
		`SELECT user_id, session_key_ciphertext, csrf_token, expires_at, totp_pending
		 FROM `+tblSessions+` WHERE session_id = ?`, sid,
	).Scan(&userID, &keyCipher, &csrf, &expires, &totpPending)
	if err != nil {
		return nil, err
	}
	if time.Now().After(expires) {
		_, _ = sa.db.Exec(`DELETE FROM `+tblSessions+` WHERE session_id = ?`, sid)
		return nil, errors.New("session expired")
	}
	key, err := sa.open(keyCipher, aadSessionKey)
	if err != nil {
		return nil, err
	}
	return &sessionInfo{
		SessionID:   sid,
		UserID:      userID,
		Key:         key,
		CSRF:        csrf,
		ExpiresAt:   expires,
		TOTPPending: totpPending == 1,
	}, nil
}

func (sa *SecureAuth) loadSession(next func(http.ResponseWriter, *http.Request, *sessionInfo)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := sa.loadSessionInfo(r)
		if err != nil {
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if sess.TOTPPending {
			sa.respondTOTPRequired(w, sess.UserID)
			return
		}
		next(w, r, sess)
	}
}

// respondTOTPRequired writes the JSON envelope that the client uses to detect
// that it must complete 2FA before proceeding.
func (sa *SecureAuth) respondTOTPRequired(w http.ResponseWriter, userID string) {
	// Check whether the user has TOTP configured or needs to set it up.
	configured, _ := sa.userHasTOTP(userID)
	writeJSON(w, http.StatusForbidden, map[string]interface{}{
		"error":          "totp_required",
		"totpConfigured": configured,
	})
}

type sessionCtxKey struct{}

func sessionFrom(r *http.Request) *sessionInfo {
	v, _ := r.Context().Value(sessionCtxKey{}).(*sessionInfo)
	return v
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func (sa *SecureAuth) requirePermission(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := sa.loadSessionInfo(r)
		if err != nil {
			sa.appendAudit("", "authorize", permission, "deny", sa.clientIP(r), err.Error())
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if sess.TOTPPending {
			sa.respondTOTPRequired(w, sess.UserID)
			return
		}
		ok, err := sa.userHasPermission(sess.UserID, permission)
		if err != nil || !ok {
			sa.appendAudit(sess.UserID, "authorize", permission, "deny", sa.clientIP(r), "")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		sa.appendAudit(sess.UserID, "authorize", permission, "allow", sa.clientIP(r), "")
		r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, sess))
		next(w, r)
	}
}

func (sa *SecureAuth) requirePermissionOrBootstrap(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hasUsers, err := sa.hasRegisteredUsers(r.Context())
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !hasUsers {
			got := r.Header.Get("X-Bootstrap-Token")
			if subtle.ConstantTimeCompare([]byte(got), sa.bootstrapToken) != 1 {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next(w, r)
			return
		}

		sess, err := sa.loadSessionInfo(r)
		if err != nil {
			http.Error(w, "Forbidden: Invalid permissions or bootstrap already complete", http.StatusForbidden)
			return
		}
		ok, err := sa.userHasPermission(sess.UserID, permission)
		if err != nil || !ok {
			http.Error(w, "Forbidden: Invalid permissions or bootstrap already complete", http.StatusForbidden)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionCtxKey{}, sess))
		next(w, r)
	}
}

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

func (sa *SecureAuth) UserHasAuthorization(r *http.Request, authorizationName string) (bool, error) {
	sess, err := sa.loadSessionInfo(r)
	if err != nil {
		return false, err
	}
	if ok, err := sa.userHasPermission(sess.UserID, authorizationName); err != nil {
		return false, err
	} else if ok {
		return true, nil
	}
	var authID string
	err = sa.db.QueryRow(
		`SELECT id FROM `+tblAuthorizations+` WHERE name = ?`,
		authorizationName,
	).Scan(&authID)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return sa.userHasActiveKey(sess.UserID, authID), nil
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

func (sa *SecureAuth) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)

	trusted := false
	if peer != nil {
		if len(sa.trustedProxies) > 0 {
			for _, n := range sa.trustedProxies {
				if n.Contains(peer) {
					trusted = true
					break
				}
			}
		} else if peer.IsLoopback() || peer.IsPrivate() {
			trusted = true
		}
	}
	if trusted {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	return r.RemoteAddr
}

// ---------------------------------------------------------------------------
// OPAQUE endpoints
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleServerID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"serverId": string(sa.serverID),
	})
}

func (sa *SecureAuth) handleTlsServerEndPoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sa.tlsEndPoint)
}

func (sa *SecureAuth) handleRegisterInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := sa.clientIP(r)
	if !sa.rl.allow("register-init:"+ip, 10, 1.0/60.0) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username            string `json:"username"`
		RegistrationRequest string `json:"registrationRequest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := validateUsername(req.Username); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	rrBytes, err := base64.StdEncoding.DecodeString(req.RegistrationRequest)
	if err != nil {
		log.Printf("secureauth: register/init: base64 decode failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	des, err := sa.opaqueConf.Deserializer()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rr, err := des.RegistrationRequest(rrBytes)
	if err != nil {
		log.Printf("secureauth: register/init: deserialize RegistrationRequest failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var credID []byte
	err = sa.db.QueryRow(
		`SELECT opaque_credential_id FROM `+tblUsers+` WHERE username = ?`,
		req.Username,
	).Scan(&credID)
	if err == sql.ErrNoRows {
		credID = opaque.RandomBytes(32)
	} else if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp, err := sa.opaqueServer.RegistrationResponse(rr, credID, nil)
	if err != nil {
		log.Printf("secureauth: register/init: RegistrationResponse failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	pendingID := hex.EncodeToString(randomBytes(32))
	_, err = sa.db.Exec(
		`INSERT INTO `+tblPendingRegs+`
		 (id, username, credential_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		pendingID, req.Username, credID,
		time.Now().UTC(), time.Now().Add(10*time.Minute),
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"registrationResponse": base64.StdEncoding.EncodeToString(resp.Serialize()),
		"pendingRegId":         pendingID,
	})
}

func (sa *SecureAuth) handleLoginInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		KE1      string `json:"ke1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	ip := sa.clientIP(r)
	if !sa.rl.allow("login-init-ip:"+ip, 10, 1.0/60.0) ||
		!sa.rl.allow("login-init-user:"+req.Username, 5, 1.0/60.0) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	ke1Bytes, err := base64.StdEncoding.DecodeString(req.KE1)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	des, err := sa.opaqueConf.Deserializer()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ke1, err := des.KE1(ke1Bytes)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	record, credID, err := sa.loadClientRecord(req.Username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Fetch the stored per-user KSF salt. For a non-existent user, return a
	// random salt so the response is indistinguishable from an existing user
	// whose salt is also random. For legacy rows with NULL ksf_salt, fall
	// back to 32 zero bytes (matches the pre-migration fixed-salt behaviour).
	var ksfSalt []byte
	err = sa.db.QueryRow(
		`SELECT ksf_salt FROM `+tblUsers+` WHERE username = ?`, req.Username,
	).Scan(&ksfSalt)
	if err == sql.ErrNoRows {
		ksfSalt = randomBytes(32)
	} else if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if len(ksfSalt) == 0 {
		ksfSalt = make([]byte, 32)
	}

	ke2, output, err := sa.opaqueServer.GenerateKE2(ke1, record)
	if err != nil {
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}
	attemptID := hex.EncodeToString(randomBytes(32))
	transcriptHash := sha256.Sum256(concatBytes(ke1Bytes, ke2.Serialize()))
	expires := time.Now().Add(sa.loginAttemptTTL)

	_, err = sa.db.Exec(
		`INSERT INTO `+tblLoginAttempts+`
		 (id, username, credential_id, client_mac, session_secret,
		  transcript_hash, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		attemptID, req.Username, credID,
		output.ClientMAC, output.SessionSecret,
		transcriptHash[:], time.Now().UTC(), expires,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"loginAttemptId": attemptID,
		"ke2":            base64.StdEncoding.EncodeToString(ke2.Serialize()),
		"ksfSalt":        base64.StdEncoding.EncodeToString(ksfSalt),
	})
}

func (sa *SecureAuth) loadClientRecord(username string) (*opaque.ClientRecord, []byte, error) {
	var (
		recBytes []byte
		credID   []byte
	)
	err := sa.db.QueryRow(
		`SELECT opaque_registration_record, opaque_credential_id
         FROM `+tblUsers+` WHERE username = ?`, username,
	).Scan(&recBytes, &credID)

	if err == sql.ErrNoRows {
		fakeCredID := sa.fakeCredentialID(username)
		fakeRecord, err := sa.opaqueConf.GetFakeRecord(fakeCredID)
		if err != nil {
			return nil, nil, err
		}
		return fakeRecord, fakeCredID, nil
	}
	if err != nil {
		return nil, nil, err
	}

	des, err := sa.opaqueConf.Deserializer()
	if err != nil {
		return nil, nil, err
	}
	regRecord, err := des.RegistrationRecord(recBytes)
	if err != nil {
		return nil, nil, err
	}
	return &opaque.ClientRecord{
		CredentialIdentifier: credID,
		ClientIdentity:       []byte(username),
		RegistrationRecord:   regRecord,
	}, credID, nil
}

func (sa *SecureAuth) fakeCredentialID(username string) []byte {
	return hmacSHA256(sa.masterKey, []byte("fake-cred-id:"+username))
}

func (sa *SecureAuth) handleLogin2(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := sa.clientIP(r)
	if !sa.rl.allow("login2:"+ip, 10, 1.0/60.0) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	var req struct {
		LoginAttemptID  string `json:"loginAttemptId"`
		KE3             string `json:"ke3"`
		ClientEphemeral string `json:"clientEphemeral"`
		ClientMAC       string `json:"clientMAC"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var (
		username       string
		credID         []byte
		storedMAC      []byte
		storedSecret   []byte
		transcriptHash []byte
		expires        time.Time
	)
	err := sa.db.QueryRow(
		`SELECT username, credential_id, client_mac, session_secret,
		        transcript_hash, expires_at
		 FROM `+tblLoginAttempts+` WHERE id = ?`, req.LoginAttemptID,
	).Scan(&username, &credID, &storedMAC, &storedSecret, &transcriptHash, &expires)
	if err != nil {
		sa.genericAuthFailure(w)
		return
	}
	if time.Now().After(expires) {
		_, _ = sa.db.Exec(`DELETE FROM `+tblLoginAttempts+` WHERE id = ?`, req.LoginAttemptID)
		sa.genericAuthFailure(w)
		return
	}
	_, _ = sa.db.Exec(`DELETE FROM `+tblLoginAttempts+` WHERE id = ?`, req.LoginAttemptID)

	if !sa.rl.allow("login2-user:"+username, 5, 1.0/60.0) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}

	ke3Bytes, err := base64.StdEncoding.DecodeString(req.KE3)
	if err != nil {
		sa.genericAuthFailure(w)
		return
	}
	des, err := sa.opaqueConf.Deserializer()
	if err != nil {
		sa.genericAuthFailure(w)
		return
	}
	ke3, err := des.KE3(ke3Bytes)
	if err != nil {
		sa.genericAuthFailure(w)
		return
	}

	if err := sa.opaqueServer.LoginFinish(ke3, storedMAC); err != nil {
		sa.recordFailedAttempt(username, ip)
		sa.genericAuthFailure(w)
		return
	}

	clientEph, err := base64.StdEncoding.DecodeString(req.ClientEphemeral)
	if err != nil || len(clientEph) != 32 {
		sa.genericAuthFailure(w)
		return
	}
	clientMAC, err := base64.StdEncoding.DecodeString(req.ClientMAC)
	if err != nil {
		sa.genericAuthFailure(w)
		return
	}

	macKey := hkdfExpand(storedSecret, []byte("SecureAuth client MAC"), 32)
	expectedMAC := hmacSHA256(macKey, clientEph)
	if subtle.ConstantTimeCompare(expectedMAC, clientMAC) != 1 {
		sa.recordFailedAttempt(username, ip)
		sa.genericAuthFailure(w)
		return
	}

	serverEphPriv := randomBytes(32)
	serverEphPub, err := curve25519.X25519(serverEphPriv, curve25519.Basepoint)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	shared, err := curve25519.X25519(serverEphPriv, clientEph)
	if err != nil {
		sa.genericAuthFailure(w)
		return
	}

	if sa.tlsEndPoint == nil {
		http.Error(w, "channel binding not configured", http.StatusInternalServerError)
		return
	}

	serverNonce := randomBytes(16)
	clientNonce := randomBytes(16)
	sessionIDraw := hmacSHA256(storedSecret,
		concatBytes(transcriptHash, serverNonce, clientNonce))
	sessionID := hex.EncodeToString(sessionIDraw)

	sessionKey := hkdfExpand(
		concatBytes(shared, storedSecret, transcriptHash, sa.tlsEndPoint),
		[]byte("SecureAuth session key"),
		32,
	)

	sessionKeyEnc, err := sa.seal(sessionKey, aadSessionKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Check if user has TOTP enabled — if so, the session starts as pending.
	totpEnabled, err := sa.userHasTOTP(username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Also check whether 2FA is enforced but not yet set up (first login).
	totpRequired := totpEnabled || (sa.require2FA)
	totpPendingInt := 0
	if totpEnabled {
		totpPendingInt = 1
	}
	// If 2FA is enforced but not yet configured, the session is also
	// "pending" — the user must set up 2FA before accessing anything else.
	if sa.require2FA && !totpEnabled {
		totpPendingInt = 1
	}

	csrfToken, csrfCookie := sa.newCSRF(sessionID)
	expiresAt := time.Now().Add(sa.sessionTTL)

	_, err = sa.db.Exec(
		`INSERT INTO `+tblSessions+`
		 (session_id, user_id, session_key_ciphertext, csrf_token,
		  created_at, expires_at, paake_transcript_hash,
		  client_ephemeral_public_key, server_ephemeral_public_key,
		  totp_pending)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, username, sessionKeyEnc, csrfToken,
		time.Now().UTC(), expiresAt, transcriptHash, clientEph, serverEphPub,
		totpPendingInt,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: "secureauth_session", Value: sessionID, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Expires: expiresAt,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "secureauth_csrf", Value: csrfCookie, Path: "/",
		Secure: true, HttpOnly: false, SameSite: http.SameSiteLaxMode,
		Expires: expiresAt,
	})

	sa.appendAudit(username, "login2", "", "allow", ip, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"sessionId":                sessionID,
		"serverEphemeralPublicKey": base64.StdEncoding.EncodeToString(serverEphPub),
		"csrfToken":                csrfToken,
		"totpRequired":             totpRequired,
		"totpConfigured":           totpEnabled,
	})
}

func (sa *SecureAuth) genericAuthFailure(w http.ResponseWriter) {
	http.Error(w, "authentication failed", http.StatusUnauthorized)
}

func (sa *SecureAuth) recordFailedAttempt(username, ip string) {
	sa.appendAudit(username, "login2", "", "deny", ip, "")
}

// ---------------------------------------------------------------------------
// Private key retrieval
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleGetPrivateKey(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	var (
		encKey, nonce, salt             []byte
		kdfInfo                         sql.NullString
		encSignKey, signNonce, signSalt []byte
		signKDFInfo                     sql.NullString
	)
	err := sa.db.QueryRow(
		`SELECT encrypted_rsa_private_key, private_key_nonce,
		        private_key_salt, private_key_kdf_info,
		        encrypted_rsa_signing_private_key, signing_key_nonce,
		        signing_key_salt, signing_key_kdf_info
		 FROM `+tblUsers+` WHERE username = ?`, sess.UserID,
	).Scan(&encKey, &nonce, &salt, &kdfInfo,
		&encSignKey, &signNonce, &signSalt, &signKDFInfo)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"encrypted_rsa_private_key":         base64.StdEncoding.EncodeToString(encKey),
		"private_key_nonce":                 base64.StdEncoding.EncodeToString(nonce),
		"private_key_salt":                  base64.StdEncoding.EncodeToString(salt),
		"private_key_kdf_info":              kdfInfo.String,
		"encrypted_rsa_signing_private_key": base64.StdEncoding.EncodeToString(encSignKey),
		"signing_key_nonce":                 base64.StdEncoding.EncodeToString(signNonce),
		"signing_key_salt":                  base64.StdEncoding.EncodeToString(signSalt),
		"signing_key_kdf_info":              signKDFInfo.String,
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
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "secureauth_csrf", Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: false, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// User management
// ---------------------------------------------------------------------------

// createUserRequest accepts either a single legacy `role` string or a
// `roles` array. If both are present, `roles` wins and `role` is ignored.
// At least one role must be supplied.
type createUserRequest struct {
	Username               string   `json:"username"`
	Role                   string   `json:"role,omitempty"`
	Roles                  []string `json:"roles,omitempty"`
	PendingRegID           string   `json:"pendingRegId"`
	RegistrationRecord     string   `json:"registration_record"`
	RSAPublicKey           string   `json:"rsa_public_key"`
	EncryptedRSAPrivateKey string   `json:"encrypted_rsa_private_key"`
	PrivateKeyNonce        string   `json:"private_key_nonce"`
	PrivateKeySalt         string   `json:"private_key_salt"`
	PrivateKeyKDFInfo      string   `json:"private_key_kdf_info"`
	RSASigningPublicKey    string   `json:"rsa_signing_public_key"`
	EncryptedRSASigningKey string   `json:"encrypted_rsa_signing_private_key"`
	SigningKeyNonce        string   `json:"signing_key_nonce"`
	SigningKeySalt         string   `json:"signing_key_salt"`
	SigningKeyKDFInfo      string   `json:"signing_key_kdf_info"`
	KSFSalt                string   `json:"ksf_salt"`
}

func (sa *SecureAuth) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if err := validateUsername(req.Username); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Resolve the effective role set. Prefer the new `roles` array; fall
	// back to the legacy single `role` string for backward compatibility.
	roleNames := req.Roles
	if len(roleNames) == 0 && req.Role != "" {
		roleNames = []string{req.Role}
	}
	if len(roleNames) == 0 {
		http.Error(w, "bad request: at least one role required", http.StatusBadRequest)
		return
	}

	ksfSalt, err := base64.StdEncoding.DecodeString(req.KSFSalt)
	if err != nil || len(ksfSalt) == 0 {
		http.Error(w, "bad request: ksf_salt required", http.StatusBadRequest)
		return
	}

	var (
		credID  []byte
		pending string
	)
	err = sa.db.QueryRow(
		`SELECT credential_id, username FROM `+tblPendingRegs+` WHERE id = ?`,
		req.PendingRegID,
	).Scan(&credID, &pending)
	if err != nil || pending != req.Username {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	recBytes, err := base64.StdEncoding.DecodeString(req.RegistrationRecord)
	if err != nil || len(recBytes) == 0 {
		http.Error(w, "bad request: registration_record required", http.StatusBadRequest)
		return
	}
	des, err := sa.opaqueConf.Deserializer()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := des.RegistrationRecord(recBytes); err != nil {
		http.Error(w, "bad request: registration_record invalid", http.StatusBadRequest)
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
	signPub, _ := base64.StdEncoding.DecodeString(req.RSASigningPublicKey)
	signEncPriv, _ := base64.StdEncoding.DecodeString(req.EncryptedRSASigningKey)
	signNonce, _ := base64.StdEncoding.DecodeString(req.SigningKeyNonce)
	signSalt, _ := base64.StdEncoding.DecodeString(req.SigningKeySalt)

	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, _ = tx.Exec(`DELETE FROM `+tblPendingRegs+` WHERE id = ?`, req.PendingRegID)

	now := time.Now().UTC()
	_, err = tx.Exec(
		`INSERT INTO `+tblUsers+`
		 (username, opaque_registration_record, opaque_credential_id,
		  rsa_public_key, encrypted_rsa_private_key, private_key_nonce,
		  private_key_salt, private_key_kdf_info,
		  rsa_signing_public_key, encrypted_rsa_signing_private_key,
		  signing_key_nonce, signing_key_salt, signing_key_kdf_info,
		  ksf_salt,
		  created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		req.Username, recBytes, credID,
		pub, encPriv, nonce, salt, req.PrivateKeyKDFInfo,
		signPub, signEncPriv, signNonce, signSalt, req.SigningKeyKDFInfo,
		ksfSalt,
		now, now,
	)
	if err != nil {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}

	for _, roleName := range roleNames {
		roleID := "role-" + roleName
		_, _ = tx.Exec(
			`INSERT OR IGNORE INTO `+tblUserRoles+` (user_id, role_id) VALUES (?, ?)`,
			req.Username, roleID,
		)
	}

	if err := revokeStaleSharedKeysTx(tx, now); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	actor := auditActor(r, "bootstrap")
	sa.appendAudit(actor, "user.create", req.Username, "allow", sa.clientIP(r), "")
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
	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, _ = tx.Exec(`DELETE FROM `+tblUsers+` WHERE username = ?`, req.UserID)
	_, _ = tx.Exec(`DELETE FROM `+tblSessions+` WHERE user_id = ?`, req.UserID)
	_, _ = tx.Exec(
		`UPDATE `+tblSharedKeys+` SET revoked_at = ?, revocation_reason = 'user deleted'
		 WHERE user_id = ? AND revoked_at IS NULL`, now, req.UserID,
	)
	_, _ = tx.Exec(`DELETE FROM `+tblUserRoles+` WHERE user_id = ?`, req.UserID)

	if err := revokeStaleSharedKeysTx(tx, now); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	actor := auditActor(r, "")
	sa.appendAudit(actor, "user.delete", req.UserID, "allow", sa.clientIP(r), "")
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

// updateUserRequest accepts either a legacy single `newRole` string or a
// `newRoles` array. If both are present, `newRoles` wins and `newRole` is
// ignored. An empty (or absent) role field means "leave roles unchanged".
//
// It intentionally has no NewUsername field: renaming a user would
// invalidate the OPAQUE envelope (bound to the client identity), so the
// library forbids it. Unknown JSON fields (including newUsername) are
// ignored by encoding/json.
type updateUserRequest struct {
	UserID                 string   `json:"userId"`
	NewRole                string   `json:"newRole,omitempty"`
	NewRoles               []string `json:"newRoles,omitempty"`
	PendingRegID           string   `json:"pendingRegId,omitempty"`
	RegistrationRecord     string   `json:"registration_record,omitempty"`
	EncryptedRSAPrivateKey string   `json:"encrypted_rsa_private_key,omitempty"`
	PrivateKeyNonce        string   `json:"private_key_nonce,omitempty"`
	PrivateKeySalt         string   `json:"private_key_salt,omitempty"`
	EncryptedRSASigningKey string   `json:"encrypted_rsa_signing_private_key,omitempty"`
	SigningKeyNonce        string   `json:"signing_key_nonce,omitempty"`
	SigningKeySalt         string   `json:"signing_key_salt,omitempty"`
	KSFSalt                string   `json:"ksf_salt,omitempty"`
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

	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if req.PendingRegID != "" {
		var credID []byte
		var pendingUser string
		err := tx.QueryRow(
			`SELECT credential_id, username FROM `+tblPendingRegs+` WHERE id = ?`,
			req.PendingRegID,
		).Scan(&credID, &pendingUser)
		if err != nil || pendingUser != req.UserID {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		_, _ = tx.Exec(`DELETE FROM `+tblPendingRegs+` WHERE id = ?`, req.PendingRegID)

		if req.RegistrationRecord == "" {
			http.Error(w, "bad request: registration_record required", http.StatusBadRequest)
			return
		}
		recBytes, err := base64.StdEncoding.DecodeString(req.RegistrationRecord)
		if err != nil || len(recBytes) == 0 {
			http.Error(w, "bad request: registration_record invalid", http.StatusBadRequest)
			return
		}
		des, err := sa.opaqueConf.Deserializer()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if _, err := des.RegistrationRecord(recBytes); err != nil {
			http.Error(w, "bad request: registration_record invalid", http.StatusBadRequest)
			return
		}

		ksfSalt, err := base64.StdEncoding.DecodeString(req.KSFSalt)
		if err != nil || len(ksfSalt) == 0 {
			http.Error(w, "bad request: ksf_salt required", http.StatusBadRequest)
			return
		}

		encPriv, _ := base64.StdEncoding.DecodeString(req.EncryptedRSAPrivateKey)
		nonce, _ := base64.StdEncoding.DecodeString(req.PrivateKeyNonce)
		salt, _ := base64.StdEncoding.DecodeString(req.PrivateKeySalt)
		signEncPriv, _ := base64.StdEncoding.DecodeString(req.EncryptedRSASigningKey)
		signNonce, _ := base64.StdEncoding.DecodeString(req.SigningKeyNonce)
		signSalt, _ := base64.StdEncoding.DecodeString(req.SigningKeySalt)

		_, err = tx.Exec(
			`UPDATE `+tblUsers+` SET
			 opaque_registration_record = ?,
			 encrypted_rsa_private_key = ?, private_key_nonce = ?,
			 private_key_salt = ?,
			 encrypted_rsa_signing_private_key = ?, signing_key_nonce = ?,
			 signing_key_salt = ?,
			 ksf_salt = ?,
			 updated_at = ?
			 WHERE username = ?`,
			recBytes,
			encPriv, nonce, salt,
			signEncPriv, signNonce, signSalt,
			ksfSalt,
			now, req.UserID,
		)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = credID
	}

	// Resolve the effective role set. Prefer the new `newRoles` array;
	// fall back to the legacy single `newRole` string. An empty result
	// means "leave roles unchanged".
	roleNames := req.NewRoles
	if len(roleNames) == 0 && req.NewRole != "" {
		roleNames = []string{req.NewRole}
	}
	if len(roleNames) > 0 {
		_, _ = tx.Exec(`DELETE FROM `+tblUserRoles+` WHERE user_id = ?`, req.UserID)
		for _, roleName := range roleNames {
			roleID := "role-" + roleName
			_, _ = tx.Exec(
				`INSERT OR IGNORE INTO `+tblUserRoles+` (user_id, role_id) VALUES (?, ?)`,
				req.UserID, roleID,
			)
		}
	}

	if err := revokeStaleSharedKeysTx(tx, now); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	actor := auditActor(r, "")
	sa.appendAudit(actor, "user.update", req.UserID, "allow", sa.clientIP(r), "")
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
	if sess == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	userID := req.UserID
	if userID == "" {
		userID = sess.UserID
	}

	var signPubBytes []byte
	err := sa.db.QueryRow(
		`SELECT rsa_signing_public_key FROM `+tblUsers+` WHERE username = ?`,
		sess.UserID,
	).Scan(&signPubBytes)
	if err != nil || len(signPubBytes) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	pubAny, err := x509.ParsePKIXPublicKey(signPubBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rsaPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	wrapped, _ := base64.StdEncoding.DecodeString(req.WrappedKey)
	sig, _ := base64.StdEncoding.DecodeString(req.AdminSignature)

	digest := sha256.Sum256(wrapped)
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], sig, nil); err != nil {
		sa.appendAudit(sess.UserID, "sharekeys.write", req.AuthorizationID,
			"deny", sa.clientIP(r), "bad signature")
		http.Error(w, "bad signature", http.StatusBadRequest)
		return
	}

	var targetPub []byte
	err = sa.db.QueryRow(
		`SELECT rsa_public_key FROM `+tblUsers+` WHERE username = ?`, userID,
	).Scan(&targetPub)
	if err != nil {
		http.Error(w, "target user not found", http.StatusNotFound)
		return
	}

	authName, err := sa.authorizationName(req.AuthorizationID)
	if err != nil {
		http.Error(w, "authorization not found", http.StatusNotFound)
		return
	}

	hasAuth, err := sa.userHasPermission(userID, authName)
	if err != nil || !hasAuth {
		sa.appendAudit(sess.UserID, "sharekeys.write", req.AuthorizationID,
			"deny", sa.clientIP(r), "target user lacks authorization")
		http.Error(w, "target user does not have this authorization", http.StatusForbidden)
		return
	}

	now := time.Now().UTC()
	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, _ = tx.Exec(
		`DELETE FROM `+tblSharedKeys+`
		 WHERE user_id = ? AND authorization_id = ? AND key_version = ?`,
		userID, req.AuthorizationID, req.KeyVersion,
	)
	_, err = tx.Exec(
		`INSERT INTO `+tblSharedKeys+`
		 (user_id, authorization_id, wrapped_key, admin_signature,
		  key_version, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		userID, req.AuthorizationID, wrapped, sig, req.KeyVersion, now,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	actor := auditActor(r, "")
	sa.appendAudit(actor, "sharekeys.write", req.AuthorizationID, "allow",
		sa.clientIP(r), "target="+userID)
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

func (sa *SecureAuth) handleGetWrappedMasterkey(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AuthorizationID string `json:"authorizationId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	authName, err := sa.authorizationName(req.AuthorizationID)
	if err != nil {
		http.Error(w, "authorization not found", http.StatusNotFound)
		return
	}

	// Accept role permission OR an active shared key. The per-resource
	// authorizations created by the host application (auth-client-*,
	// auth-fiche-*) are never linked to any role — the shared key itself
	// is the grant. Requiring role permission would lock every normal
	// user out of their own content.
	roleOK, err := sa.userHasPermission(sess.UserID, authName)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !roleOK && !sa.userHasActiveKey(sess.UserID, req.AuthorizationID) {
		sa.appendAudit(sess.UserID, "masterkey.get", req.AuthorizationID,
			"deny", sa.clientIP(r), "lacks authorization")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var wrapped []byte
	var keyVersion int
	err = sa.db.QueryRow(
		`SELECT wrapped_key, key_version FROM `+tblSharedKeys+`
		 WHERE user_id = ? AND authorization_id = ? AND revoked_at IS NULL
		 ORDER BY key_version DESC LIMIT 1`,
		sess.UserID, req.AuthorizationID,
	).Scan(&wrapped, &keyVersion)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	sa.appendAudit(sess.UserID, "masterkey.get", req.AuthorizationID, "allow", sa.clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"wrappedKey": base64.StdEncoding.EncodeToString(wrapped),
		"keyVersion": keyVersion,
	})
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

	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		`INSERT INTO `+tblRoles+` (id, name, description) VALUES (?, ?, ?)`,
		id, req.Name, req.Description,
	)
	if err != nil {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	for _, a := range req.Authorizations {
		_, _ = tx.Exec(
			`INSERT OR IGNORE INTO `+tblRoleAuth+` (role_id, authorization_id) VALUES (?, ?)`,
			id, a,
		)
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
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

	now := time.Now().UTC()
	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if req.Name != "" {
		_, _ = tx.Exec(`UPDATE `+tblRoles+` SET name = ? WHERE id = ?`, req.Name, req.RoleID)
	}
	if req.Description != "" {
		_, _ = tx.Exec(`UPDATE `+tblRoles+` SET description = ? WHERE id = ?`, req.Description, req.RoleID)
	}
	if req.Authorizations != nil {
		_, _ = tx.Exec(`DELETE FROM `+tblRoleAuth+` WHERE role_id = ?`, req.RoleID)
		for _, a := range req.Authorizations {
			_, _ = tx.Exec(
				`INSERT OR IGNORE INTO `+tblRoleAuth+` (role_id, authorization_id) VALUES (?, ?)`,
				req.RoleID, a,
			)
		}
	}

	// Revoke any shared key whose (user, authorization) is no longer backed
	// by a role grant. This handles authorization removals from the updated
	// role, and any other stale rows as a side effect.
	if err := revokeStaleSharedKeysTx(tx, now); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
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

	now := time.Now().UTC()
	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, _ = tx.Exec(`DELETE FROM `+tblRoles+` WHERE id = ?`, req.RoleID)
	_, _ = tx.Exec(`DELETE FROM `+tblRoleAuth+` WHERE role_id = ?`, req.RoleID)
	_, _ = tx.Exec(`DELETE FROM `+tblUserRoles+` WHERE role_id = ?`, req.RoleID)

	if err := revokeStaleSharedKeysTx(tx, now); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Authorizations
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleGetAuthorizations(w http.ResponseWriter, r *http.Request) {
	rows, err := sa.db.Query(
		`SELECT id, name, description FROM ` + tblAuthorizations,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var auths []map[string]interface{}
	for rows.Next() {
		var id, name, desc string
		if err := rows.Scan(&id, &name, &desc); err != nil {
			continue
		}
		auths = append(auths, map[string]interface{}{
			"id": id, "name": name, "description": desc,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"authorizations": auths})
}

func (sa *SecureAuth) handleAddAuthorization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := "auth-" + hex.EncodeToString(randomBytes(8))
	_, err := sa.db.Exec(
		`INSERT INTO `+tblAuthorizations+` (id, name, description)
		 VALUES (?, ?, ?)`,
		id, req.Name, req.Description,
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
	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, _ = tx.Exec(
		`UPDATE `+tblSharedKeys+` SET revoked_at = ?, revocation_reason = 'authorization deleted'
		 WHERE authorization_id = ? AND revoked_at IS NULL`, now, req.AuthID,
	)
	_, _ = tx.Exec(`DELETE FROM `+tblAuthorizations+` WHERE id = ?`, req.AuthID)
	_, _ = tx.Exec(`DELETE FROM `+tblRoleAuth+` WHERE authorization_id = ?`, req.AuthID)

	if err := revokeStaleSharedKeysTx(tx, now); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------------------------------------------------------------------------
// Encrypted data store
// ---------------------------------------------------------------------------

func (sa *SecureAuth) userHasActiveKey(userID, authorizationID string) bool {
	var count int
	_ = sa.db.QueryRow(
		`SELECT COUNT(*) FROM `+tblSharedKeys+`
		 WHERE user_id = ? AND authorization_id = ? AND revoked_at IS NULL`,
		userID, authorizationID,
	).Scan(&count)
	return count > 0
}

// checkDataAccess verifies that the session user both has the permission the
// authorization grants and holds a non-revoked shared key for it. Returns
// (authName, true) on success.
func (sa *SecureAuth) checkDataAccess(sess *sessionInfo, authID string) (string, bool) {
	authName, err := sa.authorizationName(authID)
	if err != nil {
		return "", false
	}
	ok, err := sa.userHasPermission(sess.UserID, authName)
	if err != nil || !ok {
		return authName, false
	}
	if !sa.userHasActiveKey(sess.UserID, authID) {
		return authName, false
	}
	return authName, true
}

func (sa *SecureAuth) handleDataPut(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AuthorizationID string `json:"authorizationId"`
		ID              string `json:"id,omitempty"`
		KeyVersion      int    `json:"keyVersion"`
		Nonce           string `json:"nonce"`
		Ciphertext      string `json:"ciphertext"`
		Label           string `json:"label,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if _, ok := sa.checkDataAccess(sess, req.AuthorizationID); !ok {
		sa.appendAudit(sess.UserID, "data.put", req.AuthorizationID,
			"deny", sa.clientIP(r), "no permission or active key")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		http.Error(w, "bad request: nonce", http.StatusBadRequest)
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "bad request: ciphertext", http.StatusBadRequest)
		return
	}
	id := req.ID
	if id == "" {
		id = hex.EncodeToString(randomBytes(16))
	}
	now := time.Now().UTC()

	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Reject cross-authorization overwrite: if a row with this id already
	// exists, its authorization_id must match the request.
	var existingAuthID string
	err = tx.QueryRow(
		`SELECT authorization_id FROM `+tblEncryptedData+` WHERE id = ?`, id,
	).Scan(&existingAuthID)
	if err == nil && existingAuthID != req.AuthorizationID {
		http.Error(w, "conflict: id belongs to a different authorization", http.StatusConflict)
		return
	}
	if err != nil && err != sql.ErrNoRows {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec(
		`INSERT INTO `+tblEncryptedData+`
		 (id, authorization_id, owner_id, key_version, nonce, ciphertext, label, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   nonce=excluded.nonce, ciphertext=excluded.ciphertext,
		   label=excluded.label, key_version=excluded.key_version,
		   updated_at=excluded.updated_at`,
		id, req.AuthorizationID, sess.UserID, req.KeyVersion, nonce, ct, req.Label, now, now,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sa.appendAudit(sess.UserID, "data.put", req.AuthorizationID, "allow", sa.clientIP(r), "id="+id)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (sa *SecureAuth) handleDataGet(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var (
		authID     string
		keyVersion int
		nonce      []byte
		ct         []byte
		label      sql.NullString
	)
	err := sa.db.QueryRow(
		`SELECT authorization_id, key_version, nonce, ciphertext, label
		 FROM `+tblEncryptedData+` WHERE id = ?`, req.ID,
	).Scan(&authID, &keyVersion, &nonce, &ct, &label)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if _, ok := sa.checkDataAccess(sess, authID); !ok {
		sa.appendAudit(sess.UserID, "data.get", authID,
			"deny", sa.clientIP(r), "no permission or active key for id="+req.ID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sa.appendAudit(sess.UserID, "data.get", authID, "allow", sa.clientIP(r), "id="+req.ID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":              req.ID,
		"authorizationId": authID,
		"keyVersion":      keyVersion,
		"nonce":           base64.StdEncoding.EncodeToString(nonce),
		"ciphertext":      base64.StdEncoding.EncodeToString(ct),
		"label":           label.String,
	})
}

func (sa *SecureAuth) handleDataDelete(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var authID string
	err = tx.QueryRow(
		`SELECT authorization_id FROM `+tblEncryptedData+` WHERE id = ?`, req.ID,
	).Scan(&authID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if _, ok := sa.checkDataAccess(sess, authID); !ok {
		sa.appendAudit(sess.UserID, "data.delete", authID,
			"deny", sa.clientIP(r), "no permission or active key for id="+req.ID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_, _ = tx.Exec(`DELETE FROM `+tblEncryptedData+` WHERE id = ?`, req.ID)
	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sa.appendAudit(sess.UserID, "data.delete", authID, "allow", sa.clientIP(r), "id="+req.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (sa *SecureAuth) handleDataList(w http.ResponseWriter, r *http.Request, sess *sessionInfo) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AuthorizationID string `json:"authorizationId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, ok := sa.checkDataAccess(sess, req.AuthorizationID); !ok {
		sa.appendAudit(sess.UserID, "data.list", req.AuthorizationID,
			"deny", sa.clientIP(r), "no permission or active key")
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rows, err := sa.db.Query(
		`SELECT id, label, key_version, updated_at FROM `+tblEncryptedData+`
		 WHERE authorization_id = ? ORDER BY updated_at DESC`, req.AuthorizationID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var records []map[string]interface{}
	for rows.Next() {
		var id string
		var label sql.NullString
		var kv int
		var upd time.Time
		if err := rows.Scan(&id, &label, &kv, &upd); err != nil {
			continue
		}
		records = append(records, map[string]interface{}{
			"id":         id,
			"label":      label.String,
			"keyVersion": kv,
			"updatedAt":  upd,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"records": records})
}

// ---------------------------------------------------------------------------
// Bootstrap endpoints
// ---------------------------------------------------------------------------

func (sa *SecureAuth) handleBootstrapCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	notAvailable := func() {
		writeJSON(w, http.StatusOK, map[string]interface{}{"available": false})
	}

	var count int
	_ = sa.db.QueryRow(`SELECT COUNT(*) FROM ` + tblUsers).Scan(&count)
	if count > 0 {
		notAvailable()
		return
	}

	var username string
	var sealedPwd []byte
	var consumed int
	err := sa.db.QueryRow(
		`SELECT username, sealed_password, consumed FROM `+tblBootstrap+` WHERE id = 1`,
	).Scan(&username, &sealedPwd, &consumed)
	if err != nil || consumed != 0 {
		notAvailable()
		return
	}

	pwd, err := sa.open(sealedPwd, []byte("secureauth:bootstrap-password:v1"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available":      true,
		"username":       username,
		"password":       string(pwd),
		"bootstrapToken": string(sa.bootstrapToken),
	})
}

func (sa *SecureAuth) handleBootstrapFirstUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, err := sa.loadSessionInfo(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var consumed int
	err = sa.db.QueryRow(
		`SELECT consumed FROM ` + tblBootstrap + ` WHERE id = 1`,
	).Scan(&consumed)
	if err != nil || consumed != 0 {
		http.Error(w, "bootstrap already completed", http.StatusGone)
		return
	}

	var req struct {
		WrappedKeys []struct {
			AuthorizationID string `json:"authorizationId"`
			WrappedKey      string `json:"wrappedKey"`
			AdminSignature  string `json:"adminSignature"`
			KeyVersion      int    `json:"keyVersion"`
		} `json:"wrappedKeys"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var signPubBytes []byte
	err = sa.db.QueryRow(
		`SELECT rsa_signing_public_key FROM `+tblUsers+` WHERE username = ?`,
		sess.UserID,
	).Scan(&signPubBytes)
	if err != nil || len(signPubBytes) == 0 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	pubAny, err := x509.ParsePKIXPublicKey(signPubBytes)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rsaPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	tx, err := sa.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	for _, wk := range req.WrappedKeys {
		wrapped, _ := base64.StdEncoding.DecodeString(wk.WrappedKey)
		sig, _ := base64.StdEncoding.DecodeString(wk.AdminSignature)
		digest := sha256.Sum256(wrapped)
		if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], sig, nil); err != nil {
			sa.appendAudit(sess.UserID, "bootstrap.first-user", wk.AuthorizationID,
				"deny", sa.clientIP(r), "bad signature")
			http.Error(w, "bad signature for authorizationId="+wk.AuthorizationID, http.StatusBadRequest)
			return
		}
		_, _ = tx.Exec(
			`DELETE FROM `+tblSharedKeys+`
			 WHERE user_id = ? AND authorization_id = ? AND key_version = ?`,
			sess.UserID, wk.AuthorizationID, wk.KeyVersion,
		)
		_, err = tx.Exec(
			`INSERT INTO `+tblSharedKeys+`
			 (user_id, authorization_id, wrapped_key, admin_signature, key_version, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			sess.UserID, wk.AuthorizationID, wrapped, sig, wk.KeyVersion, now,
		)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	_, _ = tx.Exec(`UPDATE ` + tblBootstrap + ` SET consumed = 1 WHERE id = 1`)

	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sa.appendAudit(sess.UserID, "bootstrap.first-user", "", "allow", sa.clientIP(r),
		fmt.Sprintf("wrapped %d keys", len(req.WrappedKeys)))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (sa *SecureAuth) handleBootstrapMasterkeysPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, err := sa.loadSessionInfo(r)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var consumed int
	var sealedMK []byte
	err = sa.db.QueryRow(
		`SELECT consumed, sealed_masterkeys FROM `+tblBootstrap+` WHERE id = 1`,
	).Scan(&consumed, &sealedMK)
	if err != nil || consumed != 0 {
		http.Error(w, "not available", http.StatusGone)
		return
	}

	mkJSON, err := sa.open(sealedMK, []byte("secureauth:bootstrap-masterkeys:v1"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var mkMap map[string]string
	if err := json.Unmarshal(mkJSON, &mkMap); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sa.appendAudit(sess.UserID, "bootstrap.masterkeys-pending", "", "allow", sa.clientIP(r), "")
	writeJSON(w, http.StatusOK, map[string]interface{}{"masterkeys": mkMap})
}

// ---------------------------------------------------------------------------
// Template management
// ---------------------------------------------------------------------------

var requiredPlaceholders = map[string]string{
	"login":          "{loginjs}",
	"users":          "{usersjs}",
	"roles":          "{rolesjs}",
	"authorizations": "{authorizationsjs}",
	"totpsetup":      "{totpsetupjs}",
	"totpverify":     "{totpverifyjs}",
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

func (sa *SecureAuth) SetLoginReturnEndpoint(endpoint string) {
	sa.loginReturnEndpoint = endpoint
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
	case "/2fa/setup":
		t, ph = sa.tplTOTPSetup, "{totpsetupjs}"
	case "/2fa/verify":
		t, ph = sa.tplTOTPVerify, "{totpverifyjs}"
	default:
		http.NotFound(w, r)
		return
	}
	if t == nil {
		http.Error(w, "template not configured", http.StatusNotFound)
		return
	}

	importMap := `<script type="importmap" nonce="` + nonce + `">` + importMapJSON() + `</script>`

	// Inline guard for the login page: this is a classic (non-module) script,
	// so it runs synchronously at parse time and does not depend on the
	// module graph loading successfully. It unconditionally cancels the
	// first submission of the login form, so that if the real handler in
	// the module script ever fails to attach (blocked import, CDN outage,
	// extension interference, JS exception during module init, ...), the
	// browser still cannot fall back to a native form submission that would
	// put the password in the URL bar. When the module script does load, its
	// own submit handler runs after this one and performs the actual login.
	guardScript := ""
	if page == "/login" || page == "/" {
		guardScript = `<script nonce="` + nonce + `">` +
			`(function(){` +
			`var f=document.querySelector("form#f");if(!f)return;` +
			`f.addEventListener("submit",function(e){` +
			`e.preventDefault();` +
			`var o=document.querySelector("#out");` +
			`if(o&&!o.textContent)o.textContent="Loading\u2026 please wait";` +
			`});` +
			`})();` +
			`</script>`
	}

	// Boot: import the module and start init(). Expose the resulting promise
	// on window.__sa_ready so the per-page script can await it.
	bootScript := `<script type="module" nonce="` + nonce + `">` +
		`import { SecureAuth } from "/static/secureauth.mjs"; ` +
		`window.SecureAuth = SecureAuth; ` +
		`window.__sa_ready = SecureAuth.init().catch(function (e) { ` +
		`console.error("SecureAuth.init failed", e); }); ` +
		`</script>`

	pageScript := ""
	if body, ok := pageScripts[page]; ok && body != "" {
		pageScript = `<script type="module" nonce="` + nonce + `">` + body + `</script>`
		// Substitute the return endpoint in any page that redirects on success.
		switch page {
		case "/login", "/", "/2fa/setup", "/2fa/verify":
			pageScript = strings.Replace(pageScript, "{loginReturnEndpoint}", sa.loginReturnEndpoint, 1)
		}
	}

	injection := importMap + guardScript + bootScript + pageScript

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
			"@noble/ciphers/": "https://cdn.jsdelivr.net/npm/@noble/ciphers@2.3.0/",
			"@noble/curves/":  "https://cdn.jsdelivr.net/npm/@noble/curves@2.4.0/",
			"@noble/hashes/":  "https://cdn.jsdelivr.net/npm/@noble/hashes@2.2.0/",
		},
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// ---------------------------------------------------------------------------
// Per-page module scripts (injected after the boot script)
//
// These are raw Go strings; no backticks. They run with top-level await
// after SecureAuth.init() has resolved.
// ---------------------------------------------------------------------------

// sharedShellScript adds a nav bar to non-login pages. Prepended to users,
// roles, and authorizations page scripts.
const sharedShellScript = `
(function () {
  var nav = document.createElement("nav");
  nav.innerHTML =
    '<a href="/users">Users</a> | ' +
    '<a href="/roles">Roles</a> | ' +
    '<a href="/authorizations">Authorizations</a> | ' +
    '<button id="sa-logout">Logout</button>';
  document.body.insertBefore(nav, document.body.firstChild);
  document.getElementById("sa-logout").addEventListener("click", async function () {
    try { await window.SecureAuth.logout(); } catch (e) {}
    location.href = "/login";
  });
})();
`

var loginPageScript = `
(function () {
  var form = document.querySelector("form#f");
  var out = document.querySelector("#out");
  if (!form) return;
  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    var fd = new FormData(form);
    out.textContent = "Signing in\u2026";
    try {
      if (window.__sa_ready) await window.__sa_ready;
      var result = await window.SecureAuth.login(fd.get("username"), fd.get("password"));
      sessionStorage.setItem("secureauth_logged_in", "1");
      if (result && result.totpRequired) {
        out.textContent = "Redirecting to 2FA\u2026";
        var dest = result.totpConfigured ? "/2fa/verify" : "/2fa/setup";
        setTimeout(function () { location.href = dest; }, 200);
      } else {
        out.textContent = "Signed in. Redirecting\u2026";
        setTimeout(function () { location.href = "{loginReturnEndpoint}"; }, 200);
      }
    } catch (err) {
      console.error(err);
      out.textContent = "Login failed: " + err.message;
    }
  });
})();
`

// usersPageScript now supports multi-role selection on both create and edit.
// The wrapper createUserMulti works around the underlying single-role
// SecureAuth.createUser by creating the user with the first role and then
// immediately calling updateUser with the full set.
const usersPageScript = sharedShellScript + `
(function () {
  var sa = window.SecureAuth;
  var root = document.querySelector("#out");
  if (!root) {
    root = document.createElement("div");
    document.body.appendChild(root);
  }
  root.innerHTML = "";

  // Multi-role wrapper around the single-role SecureAuth.createUser.
  var _origCreate = sa.createUser.bind(sa);
  async function createUserMulti(username, password, roles) {
    if (!Array.isArray(roles)) roles = [roles];
    roles = roles.filter(function (r) { return !!r; });
    if (roles.length === 0) throw new Error("at least one role required");
    await _origCreate(username, password, roles[0]);
    if (roles.length > 1) {
      await sa.updateUser(username, { newRoles: roles });
    }
  }

  // --- create user ---
  var createForm = document.createElement("form");
  createForm.innerHTML =
    '<h3>Create user</h3>' +
    '<input name="username" placeholder="username" required> ' +
    '<input name="password" type="password" placeholder="password" required> ' +
    '<fieldset><legend>Roles</legend>' +
      '<label><input type="checkbox" name="roles" value="Viewer"> Viewer</label> ' +
      '<label><input type="checkbox" name="roles" value="Manager"> Manager</label> ' +
      '<label><input type="checkbox" name="roles" value="Admin"> Admin</label> ' +
      '<label><input type="checkbox" name="roles" value="SuperAdmin"> SuperAdmin</label>' +
    '</fieldset> ' +
    '<button>Create</button>';
  createForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    var fd = new FormData(createForm);
    var roles = fd.getAll("roles");
    if (roles.length === 0) { alert("Pick at least one role"); return; }
    try {
      await createUserMulti(fd.get("username"), fd.get("password"), roles);
      createForm.reset();
      refresh();
    } catch (err) {
      alert("Create failed: " + err.message);
    }
  });
  root.appendChild(createForm);

  // --- table ---
  var table = document.createElement("table");
  table.border = "1";
  table.style.borderCollapse = "collapse";
  table.style.marginTop = "12px";
  table.innerHTML = "<thead><tr>" +
    "<th>Username</th><th>Roles</th><th>Actions</th>" +
    "</tr></thead>";
  var tbody = document.createElement("tbody");
  table.appendChild(tbody);
  root.appendChild(table);

  // --- edit panel ---
  var editPanel = document.createElement("div");
  editPanel.style.marginTop = "12px";
  root.appendChild(editPanel);

  async function refresh() {
    tbody.innerHTML = "";
    try {
      var res = await sa.getUsers();
      var users = res.users || [];
      for (var i = 0; i < users.length; i++) {
        tbody.appendChild(renderRow(users[i]));
      }
    } catch (err) {
      var tr = document.createElement("tr");
      var td = document.createElement("td");
      td.colSpan = 3;
      td.textContent = "Error: " + err.message;
      tr.appendChild(td);
      tbody.appendChild(tr);
    }
  }

  function renderRow(u) {
    var tr = document.createElement("tr");
    var td1 = document.createElement("td");
    td1.textContent = u.username;
    var td2 = document.createElement("td");
    td2.textContent = (u.roles || []).join(", ");
    var td3 = document.createElement("td");

    var editBtn = document.createElement("button");
    editBtn.textContent = "Edit";
    editBtn.addEventListener("click", function () { showEdit(u); });
    td3.appendChild(editBtn);

    var delBtn = document.createElement("button");
    delBtn.textContent = "Delete";
    delBtn.style.marginLeft = "4px";
    delBtn.addEventListener("click", async function () {
      if (!confirm("Delete user " + u.username + "?")) return;
      try { await sa.deleteUser(u.username); refresh(); }
      catch (err) { alert("Delete failed: " + err.message); }
    });
    td3.appendChild(delBtn);

    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
    return tr;
  }

  function showEdit(u) {
    editPanel.innerHTML = "";
    var h = document.createElement("h3");
    h.textContent = "Edit " + u.username;
    editPanel.appendChild(h);

    var currentRoles = (u.roles || []).slice();
    function checked(role) {
      return currentRoles.indexOf(role) >= 0 ? " checked" : "";
    }

    var form = document.createElement("form");
    form.innerHTML =
      '<fieldset><legend>Roles</legend>' +
        '<label><input type="checkbox" name="newRoles" value="Viewer"' + checked("Viewer") + '> Viewer</label> ' +
        '<label><input type="checkbox" name="newRoles" value="Manager"' + checked("Manager") + '> Manager</label> ' +
        '<label><input type="checkbox" name="newRoles" value="Admin"' + checked("Admin") + '> Admin</label> ' +
        '<label><input type="checkbox" name="newRoles" value="SuperAdmin"' + checked("SuperAdmin") + '> SuperAdmin</label>' +
      '</fieldset> ' +
      '<label>New password: <input name="password" type="password" placeholder="(unchanged)"></label> ' +
      '<button>Save</button> <button type="button" id="sa-cancel">Cancel</button>';
    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      var fd = new FormData(form);
      var changes = {};
      var newRoles = fd.getAll("newRoles");
      var rolesChanged = newRoles.length !== currentRoles.length ||
        newRoles.some(function (r) { return currentRoles.indexOf(r) < 0; });
      if (rolesChanged) {
        if (newRoles.length === 0) { alert("Pick at least one role"); return; }
        changes.newRoles = newRoles;
      }
      var np = fd.get("password");
      if (np) changes.password = np;
      if (Object.keys(changes).length === 0) { editPanel.innerHTML = ""; return; }
      try {
        await sa.updateUser(u.username, changes);
        editPanel.innerHTML = "";
        refresh();
      } catch (err) {
        alert("Update failed: " + err.message);
      }
    });
    form.querySelector("#sa-cancel").addEventListener("click", function () {
      editPanel.innerHTML = "";
    });
    editPanel.appendChild(form);
  }

  refresh();
})();
`

const rolesPageScript = sharedShellScript + `
(function () {
  var sa = window.SecureAuth;
  var container = document.createElement("div");
  container.innerHTML =
    '<h2>Roles</h2>' +
    '<form id="sa-role-add">' +
      '<input name="name" placeholder="role name" required> ' +
      '<input name="description" placeholder="description"> ' +
      '<button>Add role</button>' +
    '</form>' +
    '<div id="sa-role-list">loading\u2026</div>';
  document.body.appendChild(container);

  var list = container.querySelector("#sa-role-list");
  var addForm = container.querySelector("#sa-role-add");

  addForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    var fd = new FormData(addForm);
    try {
      await sa.addRole({ name: fd.get("name"), description: fd.get("description") });
      addForm.reset();
      refresh();
    } catch (err) { alert("Add failed: " + err.message); }
  });

  async function refresh() {
    list.innerHTML = "loading\u2026";
    try {
      var res = await sa.getRoles();
      var roles = res.roles || [];
      list.innerHTML = "";
      var table = document.createElement("table");
      table.border = "1";
      table.style.borderCollapse = "collapse";
      table.innerHTML = "<thead><tr><th>ID</th><th>Name</th>" +
        "<th>Description</th><th>Actions</th></tr></thead>";
      var tbody = document.createElement("tbody");
      for (var i = 0; i < roles.length; i++) {
        var r = roles[i];
        var tr = document.createElement("tr");
        var td1 = document.createElement("td"); td1.textContent = r.id;
        var td2 = document.createElement("td"); td2.textContent = r.name;
        var td3 = document.createElement("td"); td3.textContent = r.description || "";
        var td4 = document.createElement("td");

        var delBtn = document.createElement("button");
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", async function (role) {
          return async function () {
            if (!confirm("Delete role " + role.name + "?")) return;
            try { await sa.deleteRole(role.id); refresh(); }
            catch (err) { alert("Delete failed: " + err.message); }
          };
        }(r));
        td4.appendChild(delBtn);

        tr.appendChild(td1); tr.appendChild(td2);
        tr.appendChild(td3); tr.appendChild(td4);
        tbody.appendChild(tr);
      }
      table.appendChild(tbody);
      list.appendChild(table);
    } catch (err) {
      list.textContent = "Error: " + err.message;
    }
  }

  refresh();
})();
`

const authsPageScript = sharedShellScript + `
(function () {
  var sa = window.SecureAuth;
  var container = document.createElement("div");
  container.innerHTML =
    '<h2>Authorizations</h2>' +
    '<form id="sa-auth-add">' +
      '<input name="name" placeholder="authorization name" required> ' +
      '<input name="description" placeholder="description"> ' +
      '<button>Add authorization</button>' +
    '</form>' +
    '<div id="sa-auth-list">loading\u2026</div>' +
    '<h2 style="margin-top:24px">Data store</h2>' +
    '<p>Select an authorization and use the buttons below to encrypt,' +
    ' fetch, list and delete records.</p>' +
    '<select id="sa-data-auth"><option value="">(choose auth)</option></select> ' +
    '<input id="sa-data-label" placeholder="label"> ' +
    '<input id="sa-data-plaintext" placeholder="plaintext"> ' +
    '<button id="sa-data-put">Encrypt &amp; store</button> ' +
    '<input id="sa-data-id" placeholder="record id"> ' +
    '<button id="sa-data-get">Fetch &amp; decrypt</button> ' +
    '<button id="sa-data-del">Delete</button> ' +
    '<button id="sa-data-list">List</button>' +
    '<pre id="sa-data-out"></pre>';
  document.body.appendChild(container);

  var list = container.querySelector("#sa-auth-list");
  var addForm = container.querySelector("#sa-auth-add");
  var dataAuth = container.querySelector("#sa-data-auth");
  var dataOut = container.querySelector("#sa-data-out");

  addForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    var fd = new FormData(addForm);
    try {
      await sa.addAuthorization({
        name: fd.get("name"), description: fd.get("description")
      });
      addForm.reset();
      refresh();
    } catch (err) { alert("Add failed: " + err.message); }
  });

  async function refresh() {
    list.innerHTML = "loading\u2026";
    try {
      var res = await sa.getAuthorizations();
      var auths = res.authorizations || [];
      list.innerHTML = "";
      dataAuth.innerHTML = '<option value="">(choose auth)</option>';

      var table = document.createElement("table");
      table.border = "1";
      table.style.borderCollapse = "collapse";
      table.innerHTML = "<thead><tr><th>ID</th><th>Name</th>" +
        "<th>Description</th><th>Actions</th></tr></thead>";
      var tbody = document.createElement("tbody");
      for (var i = 0; i < auths.length; i++) {
        (function (a) {
          var tr = document.createElement("tr");
          var td1 = document.createElement("td"); td1.textContent = a.id;
          var td2 = document.createElement("td"); td2.textContent = a.name;
          var td3 = document.createElement("td"); td3.textContent = a.description || "";
          var td4 = document.createElement("td");

          var shareBtn = document.createElement("button");
          shareBtn.textContent = "Share";
          shareBtn.addEventListener("click", async function () {
            var target = prompt("Share with which username?");
            if (!target) return;
            try { await sa.shareAuthorizationMasterkey(a.id, target); alert("Shared"); }
            catch (err) { alert("Share failed: " + err.message); }
          });
          td4.appendChild(shareBtn);

          var bootBtn = document.createElement("button");
          bootBtn.textContent = "Bootstrap all";
          bootBtn.style.marginLeft = "4px";
          bootBtn.addEventListener("click", async function () {
            try { await sa.bootstrapAuthorizationKeys(a.id); alert("Bootstrapped"); }
            catch (err) { alert("Bootstrap failed: " + err.message); }
          });
          td4.appendChild(bootBtn);

          var delBtn = document.createElement("button");
          delBtn.textContent = "Delete";
          delBtn.style.marginLeft = "4px";
          delBtn.addEventListener("click", async function () {
            if (!confirm("Delete authorization " + a.name + "?")) return;
            try { await sa.deleteAuthorization(a.id); refresh(); }
            catch (err) { alert("Delete failed: " + err.message); }
          });
          td4.appendChild(delBtn);

          tr.appendChild(td1); tr.appendChild(td2);
          tr.appendChild(td3); tr.appendChild(td4);
          tbody.appendChild(tr);

          var opt = document.createElement("option");
          opt.value = a.id;
          opt.textContent = a.name + " (" + a.id + ")";
          dataAuth.appendChild(opt);
        })(auths[i]);
      }
      table.appendChild(tbody);
      list.appendChild(table);
    } catch (err) {
      list.textContent = "Error: " + err.message;
    }
  }

  container.querySelector("#sa-data-put").addEventListener("click", async function () {
    var authId = dataAuth.value;
    var pt = container.querySelector("#sa-data-plaintext").value;
    var label = container.querySelector("#sa-data-label").value;
    if (!authId) { alert("pick an authorization"); return; }
    try {
      var r = await sa.encryptAndStore(authId, pt, { label: label });
      dataOut.textContent = "stored id=" + r.id;
      container.querySelector("#sa-data-id").value = r.id;
    } catch (err) { dataOut.textContent = "Error: " + err.message; }
  });

  container.querySelector("#sa-data-get").addEventListener("click", async function () {
    var id = container.querySelector("#sa-data-id").value;
    if (!id) return;
    try { dataOut.textContent = await sa.fetchAndDecrypt(id); }
    catch (err) { dataOut.textContent = "Error: " + err.message; }
  });

  container.querySelector("#sa-data-del").addEventListener("click", async function () {
    var id = container.querySelector("#sa-data-id").value;
    if (!id) return;
    try { await sa.deleteData(id); dataOut.textContent = "deleted " + id; }
    catch (err) { dataOut.textContent = "Error: " + err.message; }
  });

  container.querySelector("#sa-data-list").addEventListener("click", async function () {
    var authId = dataAuth.value;
    if (!authId) return;
    try {
      var r = await sa.listData(authId);
      dataOut.textContent = JSON.stringify(r, null, 2);
    } catch (err) { dataOut.textContent = "Error: " + err.message; }
  });

  refresh();
})();
`

var pageScripts = map[string]string{
	"/login":          loginPageScript,
	"/users":          usersPageScript,
	"/roles":          rolesPageScript,
	"/authorizations": authsPageScript,
	"/2fa/setup":      totpSetupPageScript,
	"/2fa/verify":     totpVerifyPageScript,
}

func (sa *SecureAuth) handleServeSecureAuthJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = io.WriteString(w, secureAuthJS)
}

func (sa *SecureAuth) handleServeOpaqueJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = io.WriteString(w, opaqueJS)
}

func (sa *SecureAuth) handleServeQRCodeGeneratorJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = io.WriteString(w, qrcodeGeneratorJS)
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Built-in default templates
// ---------------------------------------------------------------------------

const defaultCSS = `
:root {
  --sa-bg: #f6f8fa;
  --sa-surface: #ffffff;
  --sa-surface-2: #f6f8fa;
  --sa-border: #d0d7de;
  --sa-border-muted: #eaeef2;
  --sa-fg: #1f2328;
  --sa-fg-muted: #59636e;
  --sa-accent: #0969da;
  --sa-accent-hover: #0550ae;
  --sa-danger: #cf222e;
  --sa-radius: 8px;
  --sa-radius-lg: 12px;
  --sa-shadow: 0 4px 16px rgba(31, 35, 40, .08);
}
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans",
    Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
  font-size: 15px;
  line-height: 1.55;
  color: var(--sa-fg);
  background: var(--sa-bg);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
a { color: var(--sa-accent); text-decoration: none; }
a:hover { text-decoration: underline; }
h1, h2, h3 {
  font-weight: 600;
  line-height: 1.25;
  margin: 0 0 6px;
  letter-spacing: -.01em;
}
h1 { font-size: 24px; }
h2 { font-size: 18px; }
h3 { font-size: 15px; }
p { margin: 0 0 12px; }
.sa-muted { color: var(--sa-fg-muted); }

body > nav {
  display: flex;
  align-items: center;
  font-size: 0;
  padding: 10px 24px;
  background: var(--sa-surface);
  border-bottom: 1px solid var(--sa-border);
  position: sticky;
  top: 0;
  z-index: 10;
}
body > nav > a,
body > nav > button {
  font-size: 14px;
  font-weight: 500;
  color: var(--sa-fg);
  padding: 6px 12px;
  border-radius: 6px;
  border: 0;
  background: transparent;
  cursor: pointer;
  text-decoration: none;
  line-height: 1.4;
  font-family: inherit;
}
body > nav > a:hover,
body > nav > button:hover {
  background: var(--sa-bg);
  color: var(--sa-accent);
  text-decoration: none;
}
body > nav > button {
  margin-left: auto;
  border: 1px solid var(--sa-border);
  background: var(--sa-surface);
}
body > nav > button:hover {
  border-color: var(--sa-accent);
  color: var(--sa-accent);
}

.sa-container,
body > div:not([class]) {
  max-width: 1080px;
  margin: 0 auto;
  padding: 32px 24px 64px;
}
.sa-page-head { margin-bottom: 24px; }
.sa-page-head h1 { margin: 0 0 4px; }
.sa-page-head p { margin: 0; color: var(--sa-fg-muted); }

form { margin: 0 0 20px; }
input, select, textarea {
  font: inherit;
  color: var(--sa-fg);
  background: var(--sa-surface);
  border: 1px solid var(--sa-border);
  border-radius: var(--sa-radius);
  padding: 8px 12px;
  margin: 0 8px 8px 0;
  transition: border-color .15s, box-shadow .15s;
  outline: none;
  vertical-align: middle;
}
input:focus, select:focus, textarea:focus {
  border-color: var(--sa-accent);
  box-shadow: 0 0 0 3px rgba(9, 105, 218, .15);
}
input::placeholder { color: #8c959f; }

button {
  font: inherit;
  font-weight: 500;
  color: var(--sa-fg);
  background: var(--sa-surface);
  border: 1px solid var(--sa-border);
  border-radius: var(--sa-radius);
  padding: 7px 14px;
  margin: 0 6px 8px 0;
  cursor: pointer;
  transition: background .12s, border-color .12s, color .12s;
  vertical-align: middle;
  line-height: 1.4;
}
button:hover { background: var(--sa-bg); border-color: #afb8c1; }
button:active { transform: translateY(1px); }
form button[type="submit"] {
  background: var(--sa-accent);
  border-color: var(--sa-accent);
  color: #fff;
}
form button[type="submit"]:hover {
  background: var(--sa-accent-hover);
  border-color: var(--sa-accent-hover);
}

table {
  border-collapse: separate !important;
  border-spacing: 0 !important;
  width: 100%;
  margin: 8px 0 20px;
  background: var(--sa-surface);
  border: 1px solid var(--sa-border);
  border-radius: var(--sa-radius-lg);
  overflow: hidden;
  font-size: 14px;
}
table thead th {
  text-align: left;
  background: var(--sa-surface-2);
  color: var(--sa-fg-muted);
  font-weight: 600;
  font-size: 12px;
  letter-spacing: .04em;
  text-transform: uppercase;
  padding: 10px 14px;
  border-bottom: 1px solid var(--sa-border);
}
table tbody td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--sa-border-muted);
  vertical-align: middle;
}
table tbody tr:last-child td { border-bottom: 0; }
table tbody tr:hover { background: var(--sa-surface-2); }

pre, .sa-status {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
    "Liberation Mono", monospace;
  font-size: 13px;
  color: var(--sa-fg-muted);
  margin: 8px 0 0;
  white-space: pre-wrap;
  word-break: break-word;
}

body.sa-auth-body {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background:
    radial-gradient(1200px 600px at 50% -250px, #dbeafe 0%, rgba(219, 234, 254, 0) 55%),
    var(--sa-bg);
}
.sa-auth-card {
  width: 100%;
  max-width: 380px;
  background: var(--sa-surface);
  border: 1px solid var(--sa-border);
  border-radius: var(--sa-radius-lg);
  box-shadow: var(--sa-shadow);
  padding: 32px 28px 28px;
}
.sa-auth-brand {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--sa-accent);
  margin-bottom: 16px;
}
.sa-auth-card h1 { font-size: 22px; margin: 0 0 6px; }
.sa-auth-card .sa-muted { margin: 0 0 22px; }
.sa-field { display: block; margin-bottom: 14px; }
.sa-field > .sa-label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: var(--sa-fg);
  margin-bottom: 6px;
}
.sa-field input {
  display: block;
  width: 100%;
  margin: 0;
}
.sa-auth-card form { margin: 0; }
.sa-auth-card form button[type="submit"] {
  display: block;
  width: 100%;
  padding: 10px 14px;
  margin: 18px 0 0;
  font-size: 15px;
}
.sa-auth-foot {
  margin-top: 18px;
  font-size: 12px;
  text-align: center;
  color: var(--sa-fg-muted);
}
`

const defaultLoginHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · SecureAuth</title>
<style>` + defaultCSS + `</style>
</head>
<body class="sa-auth-body">
<main class="sa-auth-card">
  <div class="sa-auth-brand">SecureAuth</div>
  <h1>Sign in</h1>
  <p class="sa-muted">Enter your credentials to continue.</p>
  <form id="f" method="post" action="/login">
    <label class="sa-field">
      <span class="sa-label">Username</span>
      <input name="username" autocomplete="username" required>
    </label>
    <label class="sa-field">
      <span class="sa-label">Password</span>
      <input name="password" type="password" autocomplete="current-password" required>
    </label>
    <button type="submit">Sign in</button>
  </form>
  <pre id="out" class="sa-status"></pre>
  <div class="sa-auth-foot">Protected with OPAQUE · End-to-end encrypted</div>
</main>
{loginjs}
</body>
</html>`

const defaultUsersHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Users · SecureAuth</title>
<style>` + defaultCSS + `</style>
</head>
<body>
<main class="sa-container">
  <div class="sa-page-head">
    <h1>Users</h1>
    <p>Create, update and remove user accounts and their roles.</p>
  </div>
  <div id="out"></div>
</main>
{usersjs}
</body>
</html>`

const defaultRolesHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Roles · SecureAuth</title>
<style>` + defaultCSS + `</style>
</head>
<body>
{rolesjs}
</body>
</html>`

const defaultAuthorizationsHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorizations · SecureAuth</title>
<style>` + defaultCSS + `</style>
</head>
<body>
{authorizationsjs}
</body>
</html>`

// SetTOTPSetupPageTemplate lets the host override the 2FA setup page.
// The template must contain {totpsetupjs}.
func (sa *SecureAuth) SetTOTPSetupPageTemplate(tpl string) error {
	if err := validateTemplate("totpsetup", tpl); err != nil {
		return err
	}
	t, err := template.New("totpsetup").Parse(tpl)
	if err != nil {
		return err
	}
	sa.tplTOTPSetup = t
	return nil
}

// SetTOTPVerifyPageTemplate lets the host override the 2FA verification page.
// The template must contain {totpverifyjs}.
func (sa *SecureAuth) SetTOTPVerifyPageTemplate(tpl string) error {
	if err := validateTemplate("totpverify", tpl); err != nil {
		return err
	}
	t, err := template.New("totpverify").Parse(tpl)
	if err != nil {
		return err
	}
	sa.tplTOTPVerify = t
	return nil
}

// installDefaultTemplates wires up the built-in fallback pages. It is called
// from Init so that a host application can use SecureAuth without calling
// any Set*PageTemplate method. Hosts that do call them will simply override
// the defaults.
func (sa *SecureAuth) installDefaultTemplates() error {
	if err := sa.SetLoginPageTemplate(defaultLoginHTML); err != nil {
		return err
	}
	if err := sa.SetUsersPageTemplate(defaultUsersHTML); err != nil {
		return err
	}
	if err := sa.SetRolesPageTemplate(defaultRolesHTML); err != nil {
		return err
	}
	if err := sa.SetAuthorizationsPageTemplate(defaultAuthorizationsHTML); err != nil {
		return err
	}
	if err := sa.SetTOTPSetupPageTemplate(defaultTOTPSetupHTML); err != nil {
		return err
	}
	if err := sa.SetTOTPVerifyPageTemplate(defaultTOTPVerifyHTML); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// TOTP guard script (shared between setup and verify pages)
// ---------------------------------------------------------------------------

// The loginReturnEndpoint substitution also covers the TOTP verify page so it
// knows where to go after successful verification.
const totpVerifyPageScript = `
(function () {
  var form = document.querySelector("form#f");
  var out = document.querySelector("#out");
  if (!form) return;
  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    var fd = new FormData(form);
    var code = (fd.get("code") || "").replace(/\s/g, "");
    if (out) out.textContent = "Verifying\u2026";
    try {
      if (window.__sa_ready) await window.__sa_ready;
      await window.SecureAuth.verify2fa(code);
      if (out) out.textContent = "Verified. Redirecting\u2026";
      setTimeout(function () { location.href = "{loginReturnEndpoint}"; }, 200);
    } catch (err) {
      if (out) out.textContent = "Error: " + err.message;
    }
  });
})();
`

const totpSetupPageScript = `
(function () {
  // Step 1: load the QR + secret from the server.
  async function beginSetup() {
    if (window.__sa_ready) await window.__sa_ready;
    try {
      var data = await window.SecureAuth.begin2faSetup();
      var qrDiv = document.querySelector("#sa-qr");
      var uriEl = document.querySelector("#sa-uri");
      var secEl = document.querySelector("#sa-secret");
      if (qrDiv) {
  // Show the URI immediately as a fallback so the page is never blank.
  qrDiv.innerHTML =
    "<a href=\"" + data.provisioningUri +
    "\" style=\"word-break:break-all;font-size:12px\">" +
    data.provisioningUri + "</a>";

  try {
    if (typeof window.qrcode === "undefined") {
      await new Promise(function (resolve, reject) {
        var s = document.createElement("script");
        s.src = "/static/qrcode-generator.js";
        s.onload = resolve;
        s.onerror = function () {
          reject(new Error("qrcode-generator.js failed to load"));
        };
        document.head.appendChild(s);
      });
    }

    // typeNumber 0 = auto-size, 'M' = ~15% error correction (standard for otpauth).
    var qr = window.qrcode(0, "M");
    qr.addData(data.provisioningUri);
    qr.make();

    var count = qr.getModuleCount();
    var cell  = Math.max(2, Math.floor(220 / count));
    var side  = cell * count;

    var canvas = document.createElement("canvas");
    canvas.width  = side;
    canvas.height = side;
    var ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff";
    ctx.fillRect(0, 0, side, side);
    ctx.fillStyle = "#000";
    for (var r = 0; r < count; r++) {
      for (var c = 0; c < count; c++) {
        if (qr.isDark(r, c)) {
          ctx.fillRect(c * cell, r * cell, cell, cell);
        }
      }
    }
    qrDiv.innerHTML = "";
    qrDiv.appendChild(canvas);
  } catch (err) {
    console.error("2FA QR render failed:", err);
    // Fallback URI is already on screen; nothing else to do.
  }
}
      if (uriEl) uriEl.textContent = data.provisioningUri;
      if (secEl) secEl.textContent = data.secret;
      // Store challenge data for the finish step.
      window.__sa2faData = data;
    } catch (err) {
      var out = document.querySelector("#out");
      if (out) out.textContent = "Error loading setup: " + err.message;
    }
  }
  beginSetup();

  // Step 2: handle the confirmation form.
  var form = document.querySelector("form#f");
  var out = document.querySelector("#out");
  if (form) {
    form.addEventListener("submit", async function (e) {
      e.preventDefault();
      var fd = new FormData(form);
      var code = (fd.get("code") || "").replace(/\s/g, "");
      if (out) out.textContent = "Confirming\u2026";
      try {
        if (!window.__sa2faData) throw new Error("Setup not initialized");
        await window.SecureAuth.finish2faSetup(window.__sa2faData, code);
        if (out) out.textContent = "2FA enabled! Redirecting\u2026";
        setTimeout(function () { location.href = "{loginReturnEndpoint}"; }, 800);
      } catch (err) {
        if (out) out.textContent = "Error: " + err.message;
      }
    });
  }
})();
`

// ---------------------------------------------------------------------------
// Default TOTP HTML pages
// ---------------------------------------------------------------------------

const defaultTOTPVerifyHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Two-factor authentication · SecureAuth</title>
<style>` + defaultCSS + `</style>
</head>
<body class="sa-auth-body">
<main class="sa-auth-card">
  <div class="sa-auth-brand">SecureAuth</div>
  <h1>Two-factor authentication</h1>
  <p class="sa-muted">Enter the 6-digit code from your authenticator app.</p>
  <form id="f" method="post" action="/2fa/verify">
    <label class="sa-field">
      <span class="sa-label">Authenticator code</span>
      <input name="code" inputmode="numeric" pattern="[0-9 ]*" autocomplete="one-time-code"
             placeholder="000 000" required maxlength="7">
    </label>
    <button type="submit">Verify</button>
  </form>
  <pre id="out" class="sa-status"></pre>
  <div class="sa-auth-foot">Lost access? Contact your administrator.</div>
</main>
{totpverifyjs}
</body>
</html>`

const defaultTOTPSetupHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Set up two-factor authentication · SecureAuth</title>
<style>` + defaultCSS + `
#sa-qr { margin: 12px 0; min-height: 60px; }
#sa-qr canvas { display: block; }
.sa-code-box {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 13px;
  background: var(--sa-surface-2);
  border: 1px solid var(--sa-border);
  border-radius: var(--sa-radius);
  padding: 8px 12px;
  word-break: break-all;
  margin: 6px 0 14px;
  user-select: all;
}
</style>
</head>
<body class="sa-auth-body">
<main class="sa-auth-card" style="max-width:460px">
  <div class="sa-auth-brand">SecureAuth</div>
  <h1>Set up 2FA</h1>
  <p class="sa-muted">Scan this QR code with any authenticator app (Google Authenticator, Authy, 1Password, etc.).</p>
  <div id="sa-qr">Loading&hellip;</div>
  <p style="margin:0 0 4px;font-size:13px;color:var(--sa-fg-muted)">Or enter this key manually:</p>
  <div id="sa-secret" class="sa-code-box">&hellip;</div>
  <p style="margin:0 0 14px;font-size:13px;color:var(--sa-fg-muted)">Then enter the 6-digit code to confirm setup.</p>
  <form id="f" method="post" action="/2fa/setup/finish">
    <label class="sa-field">
      <span class="sa-label">Confirmation code</span>
      <input name="code" inputmode="numeric" pattern="[0-9 ]*" autocomplete="one-time-code"
             placeholder="000 000" required maxlength="7">
    </label>
    <button type="submit">Enable 2FA</button>
  </form>
  <pre id="out" class="sa-status"></pre>
</main>
{totpsetupjs}
</body>
</html>`
