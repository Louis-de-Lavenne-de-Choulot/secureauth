# SecureAuth

An OPAQUE-based authentication and authorization library for Go web applications. Passwords never leave the browser in a form the server can read, sessions are end-to-end encrypted, and per-authorization masterkeys are wrapped under each user's RSA key.

SecureAuth ships as:

- A **Go server library** (`secureauth.go`) that plugs into your `http.ServeMux`.
- A **browser client** (`secureauth.mjs`) that performs registration, login, session management and encrypted data operations.

This README documents only the **public API**. Internal packages, database table names, and cipher-suite details are out of scope.

---

## Table of contents

1. [Quick start](#quick-start)
2. [Server-side Go API](#server-side-go-api)
   - [InitOptions](#initoptions)
   - [Init](#init)
   - [SecureAuthAndCommHandler](#secureauthandcommhandler)
   - [SecureAuth methods](#secureauth-methods)
   - [Programmatic authorization and role registration](#programmatic-authorization-and-role-registration)
   - [Template requirements](#template-requirements)
3. [Client-side JavaScript API](#client-side-javascript-api)
   - [SecureAuth.init](#secureauthinit)
   - [Authentication](#authentication)
   - [User management](#user-management)
   - [Role management](#role-management)
   - [Authorization management](#authorization-management)
   - [Masterkey sharing](#masterkey-sharing)
   - [Encrypted data store](#encrypted-data-store)
   - [Low-level helpers](#low-level-helpers)
4. [Roles and permissions model](#roles-and-permissions-model)
5. [First-run bootstrap](#first-run-bootstrap)
6. [Error handling](#error-handling)

---

## Quick start

**Server (Go):**

```go
package main

import (
    "crypto/rand"
    "log"
    "net/http"

    "your/app/secureauth"
)

func main() {
    masterKey := make([]byte, 32)
    if _, err := rand.Read(masterKey); err != nil {
        log.Fatal(err)
    }

    tlsCert, err := os.ReadFile("/etc/ssl/myapp/fullchain.pem")
    if err != nil {
        log.Fatal(err)
    }

    sa, err := secureauth.Init(
        "sqlite3",
        "file:secureauth.db?cache=shared&_fk=1",
        secureauth.InitOptions{
            MasterKey:      masterKey,
            ServerID:       "myapp.example.com",
            BootstrapToken: "", // generated and printed on first run if empty
            TLSCertificate: tlsCert,
        },
    )
    if err != nil {
        log.Fatal(err)
    }

    mux := http.NewServeMux()
    handler := secureauth.SecureAuthAndCommHandler(sa, mux)

    log.Fatal(http.ListenAndServeTLS(":8443", "/etc/ssl/myapp/cert.pem", "/etc/ssl/myapp/key.pem", handler))
}
```

**Client (browser):** every page must bootstrap the library once:

```html
<script type="module">
  import { SecureAuth } from "/static/secureauth.mjs";
  window.SecureAuth = SecureAuth;
  await SecureAuth.init();
</script>
```

Then use `window.SecureAuth.login(...)`, `window.SecureAuth.createUser(...)`, etc.

---

## Server-side Go API

### `InitOptions`

Configuration passed to `Init`.

| Field | Type | Required | Description |
|---|---|---|---|
| `MasterKey` | `[]byte` | **yes** | Exactly 32 bytes. Encrypts the OPAQUE server key material, the bootstrap record, and session keys. Losing this key loses everything. Store it in a KMS/secret manager, never in source control. |
| `ServerID` | `string` | no | The OPAQUE server identity. Shown to clients via `/api/server-id` and bound into the OPAQUE transcript. Defaults to `"secureauth"`. Must match on all replicas. |
| `BootstrapToken` | `string` | no | Shared secret required by `X-Bootstrap-Token` header to create the first user. If empty, a random token is generated and printed to the log at startup. |
| `TLSCertificate` | `[]byte` | **yes** | The PEM (or DER) bytes of the TLS certificate your server presents. Its SHA-256 is bound into the session key derivation. Must match the actual certificate, otherwise logins fail after a certificate rotation. |
| `TrustedProxies` | `[]string` | no | CIDR ranges whose `X-Forwarded-For` header is trusted for client-IP extraction (used in the audit log and rate limiter). If empty, only loopback and RFC 1918 addresses are trusted. |

### `Init`

```go
func Init(dbdriver string, dsn string, opts InitOptions) (*SecureAuth, error)
```

Creates tables if they don't exist, seeds the four preset roles and their authorizations, generates OPAQUE server key material on first run, generates the first-admin bootstrap record if there are no users yet, and installs the default HTML templates.

| Parameter | Description |
|---|---|
| `dbdriver` | Database driver name registered with `database/sql`. Tested with `"sqlite3"`. The schema uses SQLite-compatible types; Postgres/MySQL require review of the `CREATE TABLE` statements. |
| `dsn` | Driver-specific connection string. |
| `opts` | See `InitOptions` above. |

Returns a `*SecureAuth` ready to be registered with a mux. On any error, returns `nil` and a descriptive error.

### `SecureAuthAndCommHandler`

```go
func SecureAuthAndCommHandler(sa *SecureAuth, mux *http.ServeMux) http.Handler
```

Registers all SecureAuth HTTP routes on `mux` and returns it. Call this once from your `main`. Routes registered:

| Path | Method | Auth | Purpose |
|---|---|---|---|
| `/api/server-id` | GET | — | Returns the OPAQUE server ID. |
| `/api/tls-server-end-point` | GET | — | Returns the SHA-256 of the TLS certificate. |
| `/api/register/init` | POST | — | Starts an OPAQUE registration. |
| `/api/login/init` | POST | — | Starts an OPAQUE login (returns KE2 + KSF salt). |
| `/api/login2` | POST | — | Completes OPAQUE login, issues session cookies. |
| `/logout` | POST | — | Deletes the session row and clears cookies. |
| `/api/privatekey` | GET | session | Returns the user's encrypted RSA private keys. |
| `/api/createuser` | POST | `user.create` or bootstrap | Creates a user. |
| `/api/deleteuser` | POST | `user.delete` | Deletes a user. |
| `/api/getusers` | POST | `user.read` | Lists users. |
| `/api/updateuser` | POST | `user.update` | Updates a user's role, keys or password. |
| `/api/sharekeys` | POST | `sharekeys.write` | Stores an admin-signed wrapped masterkey. |
| `/api/shared-keys/check` | GET | session | Lists authorizations the user holds keys for. |
| `/api/get-wrapped-masterkey` | POST | session | Returns the user's wrapped masterkey for an authorization. |
| `/api/getroles` | GET | `role.read` | Lists roles. |
| `/api/addrole` | POST | `role.create` | Creates a role. |
| `/api/updaterole` | POST | `role.update` | Updates a role's name, description or authorizations. |
| `/api/deleterole` | POST | `role.delete` | Deletes a role. |
| `/api/getauthorizations` | GET | `authorization.read` | Lists authorizations. |
| `/api/addauthorization` | POST | `authorization.create` | Creates an authorization. |
| `/api/updateauthorization` | POST | `authorization.update` | Updates an authorization. |
| `/api/deleteauthorization` | POST | `authorization.delete` | Deletes an authorization. |
| `/api/data/put` | POST | session | Stores an encrypted record. |
| `/api/data/get` | POST | session | Retrieves an encrypted record. |
| `/api/data/delete` | POST | session | Deletes an encrypted record. |
| `/api/data/list` | POST | session | Lists records for an authorization. |
| `/api/bootstrap/credentials` | GET | — | Returns first-run admin credentials (only while uninitialized). |
| `/api/bootstrap/masterkeys-pending` | GET | session | Returns pending masterkeys for the first admin. |
| `/api/bootstrap/first-user` | POST | session | Commits the first admin's wrapped masterkeys. |
| `/static/secureauth.mjs` | GET | — | Serves the browser client. |
| `/static/opaque.mjs` | GET | — | Serves the OPAQUE browser implementation. |
| `/`, `/login`, `/users`, `/roles`, `/authorizations` | GET | — | Serves the built-in HTML pages. |

The handler returned by `SecureAuthAndCommHandler` **must be served over HTTPS** — every route rejects plain HTTP with `403`.

### `SecureAuth` methods

#### `SetLoginPageTemplate(tpl string) error`

Overrides the built-in login page. See [Template requirements](#template-requirements) below for the mandatory placeholder. Returns a non-nil error if the template is malformed or missing the placeholder.

#### `SetUsersPageTemplate(tpl string) error`

Overrides the built-in `/users` page. Must contain `{usersjs}`.

#### `SetRolesPageTemplate(tpl string) error`

Overrides the built-in `/roles` page. Must contain `{rolesjs}`.

#### `SetAuthorizationsPageTemplate(tpl string) error`

Overrides the built-in `/authorizations` page. Must contain `{authorizationsjs}`.

#### `VerifyAuditChain() error`

Walks the audit log and verifies its HMAC chain. Returns `nil` if intact, or a descriptive error if any row was modified, reordered, or removed. Run this from a scheduled job and alert on failures.

```go
if err := sa.VerifyAuditChain(); err != nil {
    log.Printf("AUDIT CHAIN BROKEN: %v", err)
}
```

#### `RequireRole(role string, next http.HandlerFunc) http.HandlerFunc`

Middleware that requires the session user to have the given role name. Use this to protect your own routes:

```go
mux.HandleFunc("/admin/panel", sa.RequireRole("SuperAdmin", adminPanelHandler))
```

The wrapped handler runs only if the caller has an active session and holds the role. Otherwise a plain `403 Forbidden` is returned.

#### `UserHasAuthorization(r *http.Request, authorizationName string) (bool, error)`

Checks whether the caller of `r` holds an authorization by name (e.g. `"user.create"`). Useful when you want to gate your own logic:

```go
ok, err := sa.UserHasAuthorization(r, "sharekeys.write")
if err != nil || !ok {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

### Programmatic authorization and role registration

These four methods let a host application declare its own authorizations and roles from Go code, before or after the first admin bootstraps. They exist so that application-specific permissions (`logs.read`, `billing.write`, custom roles like `Auditor`) can be wired up at startup without going through the browser UI, and — crucially — so their masterkeys can be generated and sealed into the first-admin bootstrap payload automatically.

All four methods are safe to call concurrently with each other and with incoming HTTP requests, and each uses its own SQL transaction.

#### `RegisterAuthorization(id, name, description string) error`

Registers an authorization with an explicit ID.

| Parameter | Description |
|---|---|
| `id` | Primary key. Must be non-empty and unique. Conventionally `"auth-" + name`, but any non-empty string works. |
| `name` | The permission string checked by `userHasPermission` and the built-in route middleware. Must be non-empty and unique. |
| `description` | Free-form text, shown in the `/authorizations` UI. |

**Behaviour:**

- If the `(id, name)` pair already exists, this is a **no-op** that returns `nil`.
- If `id` exists under a different `name`, or `name` exists under a different `id`, returns a descriptive error and touches nothing.
- When a **pending bootstrap record exists** (i.e. no user has logged in as the first admin yet), a fresh 32-byte masterkey is generated for the new authorization and sealed into the bootstrap payload. The first admin automatically receives a wrapped copy of that masterkey on first login.
- When bootstrap has already completed, the authorization row is inserted but **no masterkey is created**. Post-bootstrap masterkey distribution is handled by the `/api/addauthorization` HTTP route and the browser client.

**Intended use:** call this after `Init` and before the first admin logs in, so that every custom authorization is automatically distributed to the first admin.

#### `RegisterAuthorizationByName(name, description string) (string, error)`

Convenience wrapper. Derives the ID as `"auth-" + name`, matching the preset-authorization convention, and calls `RegisterAuthorization`. Returns the derived ID on success.

#### `RegisterRole(id, name, description string, authorizationIDs []string) error`

Registers a role with an explicit ID and links it to the given authorization IDs.

| Parameter | Description |
|---|---|
| `id` | Primary key. Must be non-empty and unique. Conventionally `"role-" + name`. |
| `name` | Role name, as checked by `RequireRole` and shown in the `/roles` UI. Must be non-empty and unique. |
| `description` | Free-form text. |
| `authorizationIDs` | Slice of authorization IDs (e.g. `"auth-logs.read"`). Each must already be registered — either a preset or a prior `RegisterAuthorization` call. An unknown ID causes the function to return an error and touch nothing. |

**Behaviour:**

- If the `(id, name)` pair already exists, the role row is left alone but the authorization links are still ensured. Existing links are preserved, new ones are added.
- If `id` or `name` collides with a different pair, returns a descriptive error and touches nothing.
- Registering a role never touches the bootstrap masterkeys.

#### `RegisterRoleByName(name, description string, authorizationNames []string) (string, error)`

Convenience wrapper. Derives the role ID as `"role-" + name`, resolves each authorization name to its registered ID, and calls `RegisterRole`. Returns the derived role ID on success.

**Example:**

```go
sa, err := secureauth.Init("sqlite3", dsn, secureauth.InitOptions{
    MasterKey:      masterKey,
    TLSCertificate: tlsCert,
    ServerID:       "myapp.example.com",
})
if err != nil {
    log.Fatal(err)
}

// Declare application-specific authorizations. Each gets a fresh 32-byte
// masterkey sealed into the pending bootstrap payload, so the first admin
// receives it automatically.
if _, err := sa.RegisterAuthorizationByName("logs.read", "Read application logs"); err != nil {
    log.Fatal(err)
}
if _, err := sa.RegisterAuthorizationByName("logs.write", "Write application logs"); err != nil {
    log.Fatal(err)
}
if _, err := sa.RegisterAuthorizationByName("billing.read", "Read billing records"); err != nil {
    log.Fatal(err)
}

// Group them into a role.
if _, err := sa.RegisterRoleByName(
    "Auditor",
    "Read-only access to logs and billing",
    []string{"logs.read", "billing.read"},
); err != nil {
    log.Fatal(err)
}

mux := http.NewServeMux()
handler := secureauth.SecureAuthAndCommHandler(sa, mux)
log.Fatal(http.ListenAndServeTLS(":8443", certFile, keyFile, handler))
```

When the first admin logs in, the browser client fetches the pending masterkeys (including `auth-logs.read`, `auth-logs.write`, `auth-billing.read`), wraps each under the admin's RSA-OAEP public key, signs the wrap with the admin's RSA-PSS signing key, and commits. From that point on the admin can use those authorizations with the encrypted data store, share them with other users via `shareAuthorizationMasterkey`, or assign them to further roles.

**Post-bootstrap caveat:** if you call `RegisterAuthorization` after the first admin already exists, the authorization row is created but no masterkey is generated. If you also use the browser `/authorizations` page to create authorizations, prefer registering everything programmatically before the first login to avoid name collisions with the client-generated random IDs.

### Template requirements

Custom page templates passed to any `Set*PageTemplate` method must satisfy three rules:

1. **Must contain the mandatory placeholder for that page.** The library replaces the placeholder with an import map and the client bootstrap script. The placeholders are:

   | Setter | Required placeholder |
   |---|---|
   | `SetLoginPageTemplate` | `{loginjs}` |
   | `SetUsersPageTemplate` | `{usersjs}` |
   | `SetRolesPageTemplate` | `{rolesjs}` |
   | `SetAuthorizationsPageTemplate` | `{authorizationsjs}` |

2. **Must not contain any `<script>` tag.** The library injects its own script tags with a per-request CSP nonce. Any `<script>` you write yourself will be blocked by the CSP and will cause `Set*PageTemplate` to return an error.

3. **Must be valid Go `html/template`** — parsed with `template.New(...).Parse(tpl)`. The template is executed with a `nil` data value, so it may not reference `.Field` values. It exists only as a static shell.

Minimal valid login template:

```html
<!doctype html>
<html>
<head><title>Sign in</title></head>
<body>
  <form id="f">
    <input name="username" required>
    <input name="password" type="password" required>
    <button>Sign in</button>
  </form>
  <pre id="out"></pre>
  {loginjs}
</body>
</html>
```

If you do not call any `Set*PageTemplate` method, the library installs its own defaults in `Init` and everything works out of the box.

---

## Client-side JavaScript API

Import the module once per page and call `init` before anything else:

```html
<script type="module">
  import { SecureAuth } from "/static/secureauth.mjs";
  window.SecureAuth = SecureAuth;
  await SecureAuth.init();
</script>
```

All methods below are on `window.SecureAuth` and return Promises.

### `SecureAuth.init()`

```js
await SecureAuth.init();
```

Idempotent. Fetches the server ID and TLS endpoint, checks the bootstrap endpoint, and — if the server is uninitialized and no user exists yet — automatically creates the first admin and logs in. You must call this before any other method on a fresh page load. Calling it again is a no-op.

### Authentication

#### `login(username, password)`

```js
await SecureAuth.login("alice", "correct horse battery staple");
```

Performs the full OPAQUE login flow, derives the session key, decrypts the user's long-term RSA private keys in memory, and installs the `secureauth_session` and `secureauth_csrf` cookies. Returns `{ sessionId }`.

Throws if the credentials are invalid, the session cannot be established, or the server is misconfigured. On success, `SecureAuth` is ready to call the other methods.

#### `logout()`

```js
await SecureAuth.logout();
```

Deletes the session server-side, clears cookies and zeroises all in-memory key material. Always resolves even if the network call fails.

### User management

#### `createUser(username, password, role)`

```js
await SecureAuth.createUser("bob", "hunter2", "Viewer");
```

Creates a user. `role` must be one of the existing role names (see [Roles and permissions model](#roles-and-permissions-model)). Returns `{ username, rsa_public_key }`.

Requires the caller to hold `user.create`, **or** to be performing the first-run bootstrap.

#### `getUsers()`

```js
const { users } = await SecureAuth.getUsers();
```

Returns `{ users: [{ username, rsa_public_key, roles: [...], created_at, updated_at }, ...] }`. Requires `user.read`.

#### `updateUser(userId, changes)`

```js
await SecureAuth.updateUser("bob", { newRole: "Admin" });
await SecureAuth.updateUser("bob", { password: "new-password" });
await SecureAuth.updateUser("bob", { newRole: "Admin", password: "new-password" });
```

Updates a user. The `changes` object accepts:

| Key | Type | Effect |
|---|---|---|
| `newRole` | `string` | Replaces the user's roles with the named role. |
| `password` | `string` | Re-runs OPAQUE registration with the new password, re-encrypts the user's RSA keys under the new OPAQUE export key, and rotates the KSF salt. |

A username change is **not** supported: the OPAQUE envelope is bound to the client identity, so renaming would silently lock the user out. Requires `user.update`.

#### `deleteUser(userId)`

```js
await SecureAuth.deleteUser("bob");
```

Deletes a user, their sessions, their role assignments and revokes all their shared keys. Requires `user.delete`.

### Role management

#### `getRoles()`

```js
const { roles } = await SecureAuth.getRoles();
```

Returns `{ roles: [{ id, name, description }, ...] }`. Requires `role.read`.

#### `addRole(roleData)`

```js
await SecureAuth.addRole({
  name: "Auditor",
  description: "Read-only access to logs",
  authorizations: ["auth-user.read", "auth-role.read"],
});
```

Creates a role. `authorizations` is an array of **authorization IDs** (`auth-...`), not names. Returns `{ id }`. Requires `role.create`.

Roles can also be declared programmatically from Go with `RegisterRole` / `RegisterRoleByName` — see [Programmatic authorization and role registration](#programmatic-authorization-and-role-registration).

#### `updateRole(roleId, changes)`

```js
await SecureAuth.updateRole("role-Auditor", {
  name: "SeniorAuditor",
  description: "Updated description",
  authorizations: ["auth-user.read"],
});
```

Any field may be omitted. Passing `authorizations` replaces the role's authorization set. Shared keys that no longer correspond to a valid user/authorization pair are automatically revoked. Requires `role.update`.

#### `deleteRole(roleId)`

```js
await SecureAuth.deleteRole("role-Auditor");
```

Deletes a role, its authorization links and its user assignments. Shared keys backed by that role are revoked. Requires `role.delete`.

### Authorization management

#### `getAuthorizations()`

```js
const { authorizations } = await SecureAuth.getAuthorizations();
```

Returns `{ authorizations: [{ id, name, description }, ...] }`. Requires `authorization.read`.

#### `addAuthorization(authData)`

```js
await SecureAuth.addAuthorization({
  name: "logs.read",
  description: "Read application logs",
});
```

Creates an authorization, generates a fresh 32-byte masterkey for it, wraps the masterkey under the caller's own RSA-OAEP public key, signs the wrapped blob with the caller's RSA-PSS signing key, and stores it as a shared key for the caller. Returns `{ id }`. Requires `authorization.create` **and** `sharekeys.write` (implicit for admins).

After this call, the caller can immediately use the new authorization with the encrypted data store.

Authorizations can also be declared programmatically from Go with `RegisterAuthorization` / `RegisterAuthorizationByName` — see [Programmatic authorization and role registration](#programmatic-authorization-and-role-registration). Prefer the Go-side API for authorizations that must exist before the first admin bootstraps.

#### `updateAuthorization(authId, changes)`

```js
await SecureAuth.updateAuthorization("auth-logs.read", { name: "audit.read" });
```

Updates name and/or description. Does not touch stored masterkeys. Requires `authorization.update`.

#### `deleteAuthorization(authId)`

```js
await SecureAuth.deleteAuthorization("auth-logs.read");
```

Deletes the authorization, revokes every shared key for it, and removes its role links. Records stored under it in the encrypted data store are **not** deleted; they become orphaned and unreachable through the API. Requires `authorization.delete`.

### Masterkey sharing

These methods wrap an existing authorization's masterkey for another user and store the wrapped blob. They require the caller to already hold the masterkey and to have `sharekeys.write`.

#### `shareAuthorizationMasterkey(authId, targetUsername)`

```js
await SecureAuth.shareAuthorizationMasterkey("auth-logs.read", "bob");
```

Shares the masterkey for `authId` with the single user `targetUsername`. The target user must already hold the authorization's underlying permission, otherwise the server rejects the share.

#### `bootstrapAuthorizationKeys(authId)`

```js
await SecureAuth.bootstrapAuthorizationKeys("auth-logs.read");
```

Same as `shareAuthorizationMasterkey`, but shares with **every** other user that currently holds the authorization. Useful right after creating an authorization to backfill keys for an existing team. Users that don't hold the permission are silently skipped.

### Encrypted data store

Records are encrypted client-side under the authorization's masterkey using XChaCha20-Poly1305. The server stores only `nonce || ciphertext` and has no way to decrypt it.

#### `encryptAndStore(authId, plaintext, options)`

```js
const { id } = await SecureAuth.encryptAndStore(
  "auth-logs.read",
  "sensitive log line",
  { label: "2025-09-18 access log", id: "" },
);
```

| Argument | Type | Description |
|---|---|---|
| `authId` | `string` | Authorization ID to encrypt under. The caller must hold an active shared key. |
| `plaintext` | `string \| Uint8Array` | Data to encrypt. |
| `options.label` | `string` | Optional human-readable label stored unencrypted alongside the record. |
| `options.id` | `string` | Optional explicit record ID. If omitted, the server generates a random one. |

Returns `{ id }`. The caller must have both the permission the authorization grants and a non-revoked shared key.

#### `fetchAndDecrypt(recordId)`

```js
const text = await SecureAuth.fetchAndDecrypt(id);
```

Returns the decrypted plaintext as a string. Throws if the record does not exist, the caller does not hold a valid key, or the ciphertext was tampered with.

#### `deleteData(recordId)`

```js
await SecureAuth.deleteData(id);
```

Deletes a record. Requires the caller to hold the authorization's permission and an active shared key.

#### `listData(authId)`

```js
const { records } = await SecureAuth.listData("auth-logs.read");
```

Returns `{ records: [{ id, label, keyVersion, updatedAt }, ...] }` sorted by `updatedAt` descending. The ciphertext is not returned — use `fetchAndDecrypt` for that.

### Low-level helpers

#### `sendEncryptedRequest(endpoint, payload)`

```js
const response = await SecureAuth.sendEncryptedRequest(
  "/my/custom/endpoint",
  { action: "delete-everything", id: 42 },
);
```

Sends `payload` JSON-encoded and encrypted under the current session key to a POST endpoint. The body is `{ nonce, ciphertext }` base64-encoded. Use this when you want to hand your custom backend route a payload that no intermediary can read. The endpoint must call `SecureAuth`'s session loader and decrypt with the same session key.

#### `getDecryptedResponse(response)`

```js
const decoded = await SecureAuth.getDecryptedResponse(response);
```

Counterpart to `sendEncryptedRequest`: decrypts a `{ nonce, ciphertext }` response using the current session key and parses the JSON.

#### `exportEncryptedPrivateKey()`

```js
const blob = await SecureAuth.exportEncryptedPrivateKey();
```

Returns the user's server-stored RSA private keys as opaque encrypted blobs. The format mirrors the `/api/privatekey` response. This is a low-level building block used internally by `login`; most applications do not need it.

#### `setBootstrapToken(token)`

```js
SecureAuth.setBootstrapToken("generated-token-from-server-log");
```

Manually sets the bootstrap token used by the automatic first-run flow. Useful when the token was read from the server log rather than from `/api/bootstrap/credentials`.

---

## Roles and permissions model

SecureAuth ships with four preset roles and a fixed set of preset authorizations:

| Role | Authorizations |
|---|---|
| `SuperAdmin` | `user.create`, `user.read`, `user.update`, `user.delete`, `role.create`, `role.read`, `role.update`, `role.delete`, `authorization.create`, `authorization.read`, `authorization.update`, `authorization.delete`, `sharekeys.write` |
| `Admin` | `user.create`, `user.read`, `user.update`, `user.delete`, `role.read`, `authorization.read`, `sharekeys.write` |
| `Manager` | `user.read`, `user.update`, `role.read`, `authorization.read` |
| `Viewer` | `user.read`, `role.read`, `authorization.read` |

A user has exactly one role at a time. You can add custom roles and authorizations either programmatically from Go via `RegisterAuthorization` and `RegisterRole` (recommended before first bootstrap, so masterkeys are provisioned automatically), or at runtime through the `/roles` and `/authorizations` pages of the built-in UI. The preset roles and authorizations are seeded once per database and are never overwritten.

**Authorizations do two things at once:**

1. They gate API access — a route that requires `user.delete` checks that the session user's role grants an authorization with that name.
2. They gate the encrypted data store — each authorization has its own masterkey, wrapped for every user who holds it. Permission changes automatically revoke stale shared keys.

When you change a user's role, add or remove authorizations from a role, or delete a role, SecureAuth re-evaluates which shared keys are still justified and revokes the rest.

---

## First-run bootstrap

On a database with no users, `Init` creates a bootstrap record containing:

- A generated admin username.
- A generated admin password.
- A random bootstrap token.
- A fresh masterkey for every preset authorization, plus any authorization registered via `RegisterAuthorization` / `RegisterAuthorizationByName` before the first login.

The credentials and token are written to the server log **once**:

```
secureauth: *** FIRST-RUN CREDENTIALS (shown once) ***
secureauth: admin username: admin-3f9a7c1e
secureauth: admin password: 6Kp8xQ2vL9wR...
secureauth: *** store these securely — they will not be shown again ***
secureauth: generated bootstrap token (use X-Bootstrap-Token to create the first user): ...
```

You can also set `SECUREAUTH_ADMIN_USERNAME` and `SECUREAUTH_ADMIN_PASSWORD` environment variables before the first `Init` to control the credentials yourself.

The browser client automates the rest: on the first page load against an uninitialized server, `SecureAuth.init()` fetches `/api/bootstrap/credentials`, creates the first admin, logs in as that admin, wraps every pending masterkey under the admin's RSA public key, and commits them. After the first admin exists, `/api/bootstrap/credentials` returns `{ available: false }` and the bootstrap path is inert.

**Programmatic bootstrap alternative:** if you would rather not rely on the browser flow, register everything you need from Go (`RegisterAuthorization`, `RegisterRole`) before serving traffic, then create the first admin explicitly. The `RegisterAuthorization` call ensures the sealed bootstrap payload contains a masterkey for every declared authorization, so the first admin's browser client only needs to fetch `/api/bootstrap/masterkeys-pending` and commit once.

**Operational note:** until the first user is created, `/api/bootstrap/credentials` returns the admin password and bootstrap token to any unauthenticated caller. Never expose the server before a trusted admin has completed the first login. If your deployment model cannot guarantee that, set `SECUREAUTH_ADMIN_USERNAME` and `SECUREAUTH_ADMIN_PASSWORD` and complete the first login out of band.

---

## Error handling

All client methods throw a plain `Error` on failure with a message beginning with `SecureAuth:`. HTTP failures include the status code and the server response body:

```
SecureAuth: /api/createuser -> 409 conflict
```

Wrap calls in `try`/`catch`:

```js
try {
  await window.SecureAuth.createUser("bob", "hunter2", "Viewer");
} catch (err) {
  alert(err.message);
}
```

Server handlers return:

| Status | Meaning |
|---|---|
| `400 Bad Request` | Malformed body, invalid username, missing required field. |
| `401 Unauthorized` | Login failed (wrong password, expired attempt, MAC mismatch). |
| `403 Forbidden` | Missing permission, CSRF failure, plaintext HTTP. |
| `404 Not Found` | Referenced record or authorization does not exist. |
| `409 Conflict` | Duplicate user/role/authorization, or a data-store ID already bound to a different authorization. |
| `410 Gone` | Bootstrap endpoint called after bootstrap has completed. |
| `429 Too Many Requests` | Rate limit exceeded. |
| `500 Internal Server Error` | Database or crypto failure. Check server logs. |

The programmatic Go API (`RegisterAuthorization`, `RegisterRole`, `RegisterAuthorizationByName`, `RegisterRoleByName`) returns plain Go `error` values with the prefix `secureauth:`. Typical errors are name or ID collisions, unknown authorization IDs passed to `RegisterRole`, and database failures.

Rate limits are applied per source IP (or per username for login attempts) and are returned as `429`. The default budget is:

- **Registration init**: 10 requests burst, 1 refill per minute.
- **Login init**: 10 per IP and 5 per username, 1 refill per minute.
- **Login finish**: 10 per IP and 5 per username, 1 refill per minute.

If you run behind a proxy, list its CIDRs in `TrustedProxies` so the client IP is extracted correctly.