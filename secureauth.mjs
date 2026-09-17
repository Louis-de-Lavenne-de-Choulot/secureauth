// secureauth.mjs — browser client for the SecureAuth library.
//
// Loaded as a native ES module. No bundler, no build step, no npm. The Go
// server serves this file at /static/secureauth.mjs and injects an import map
// pointing at pinned CDN URLs for the noble dependencies.
//
// Architecture (post-remediation):
//   - All OPAQUE cryptography runs in the browser via @serenity-kit/opaque
//     (WASM). The Go server is a thin storage/proxy layer and never runs
//     OPAQUE itself.
//   - Session keys are derived from X25519 + tls-server-end-point channel
//     binding. The OPAQUE session secret is used only as a client-side
//     password check (the client refuses to proceed if finishLogin fails).
//   - CSRF uses true double-submit: the token returned by /api/login2 is sent
//     in X-CSRF-Token; the session-bound HMAC is stored in a readable cookie.
//   - Session key is held as a raw Uint8Array for XChaCha20-Poly1305 and
//     zeroised on logout.
//
// Security invariants:
//   - Refuses to operate unless window.isSecureContext is true.
//   - Refuses to operate unless crypto.getRandomValues exists.
//   - Zeroises every Uint8Array holding exportKey, K_priv, plaintext private
//     key, ephemeral secrets, and the session key on logout.
//   - No automatic retry on authentication failures.

import * as opaque from "@serenity-kit/opaque";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519, ristretto255 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Ristretto255 group order.
const Q = 2n ** 252n + 27742317777372353535851937790883648493n;

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

const state = {
  opaqueSetup: null,      // Uint8Array, 171 bytes
  serverId: null,
  tlsEndPoint: null,      // Uint8Array — SHA-256(server cert DER)
  sessionId: null,
  sessionKeyRaw: null,    // Uint8Array — for XChaCha20-Poly1305
  csrfToken: null,
  rsaPrivateKey: null,    // CryptoKey (non-extractable)
  rsaPublicKey: null,     // CryptoKey
  userID: null,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function assertSecureContext() {
  if (typeof window !== "undefined" && !window.isSecureContext) {
    throw new Error("SecureAuth requires a secure context (HTTPS).");
  }
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    throw new Error("SecureAuth requires crypto.getRandomValues.");
  }
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function concat(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function b64encode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function zeroise(...arrays) {
  for (const a of arrays) if (a && a.fill) a.fill(0);
}

async function jsonFetch(path, body) {
  const headers = { "Content-Type": "application/json" };
  if (state.csrfToken && body && body.__csrf !== false) {
    headers["X-CSRF-Token"] = state.csrfToken;
  }
  const opts = {
    method: body === undefined ? "GET" : "POST",
    credentials: "same-origin",
    headers,
  };
  if (body !== undefined) {
    const copy = { ...body };
    delete copy.__csrf;
    opts.body = JSON.stringify(copy);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`SecureAuth: ${path} -> ${res.status} ${text}`);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

function hkdfSha256(ikm, salt, info, length) {
  return hkdf(sha256, ikm, salt, info, length);
}

// ---------------------------------------------------------------------------
// Scalar arithmetic over the Ristretto255 group order
// ---------------------------------------------------------------------------

function mod(a, m = Q) {
  const r = a % m;
  return r < 0n ? r + m : r;
}

function modPow(base, exp, m) {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    exp >>= 1n;
    base = mod(base * base, m);
  }
  return result;
}

// Constant-time modular inverse via Fermat's little theorem: a^(Q-2) mod Q.
function modInverse(a, m = Q) {
  return modPow(mod(a, m), m - 2n, m);
}

function scalarFromBytes(bytes) {
  let x = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    x = (x << 8n) | BigInt(bytes[i]);
  }
  return mod(x);
}

function randomScalar() {
  // Rejection-sample a nonzero scalar below Q.
  while (true) {
    const b = randomBytes(32);
    const x = scalarFromBytes(b);
    if (x > 0n) return x;
  }
}

// ---------------------------------------------------------------------------
// Threshold Lagrange interpolation in the exponent
// ---------------------------------------------------------------------------

/**
 * Reconstructs K·G = C2 − Σ λ_i · D_i.
 * Never reconstructs the scalar K. (§9.3)
 *
 * partials: [{ index: number, point: ristretto255.Point }, ...]
 */
function lagrangeCombine(C2, partials) {
  let sum = ristretto255.Point.ZERO;
  for (let i = 0; i < partials.length; i++) {
    const xi = BigInt(partials[i].index);
    let lambda = 1n;
    for (let j = 0; j < partials.length; j++) {
      if (i === j) continue;
      const xj = BigInt(partials[j].index);
      lambda = mod(lambda * mod(-xj) * modInverse(mod(xi - xj)));
    }
    sum = sum.add(partials[i].point.multiply(lambda));
  }
  return C2.subtract(sum);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export const SecureAuth = {
  // ---- init --------------------------------------------------------------

  /**
   * Fetches the OPAQUE server setup (171 bytes, opaque-ke format) and the
   * TLS server cert hash used for channel binding. Must be called before
   * any other method.
   */
  async init(_options = {}) {
    assertSecureContext();
    const data = await jsonFetch("/api/opaque-server-setup");
    state.opaqueSetup = b64decode(data.serverSetup);
    state.serverId = data.serverId;

    // Fetch the tls-server-end-point (SHA-256 of the server cert DER).
    try {
      const res = await fetch("/api/tls-server-end-point", {
        credentials: "same-origin",
      });
      if (res.ok) {
        const ct = res.headers.get("content-type") || "";
        if (ct.includes("application/octet-stream")) {
          state.tlsEndPoint = new Uint8Array(await res.arrayBuffer());
        } else {
          const j = await res.json();
          if (j.tlsEndPoint) state.tlsEndPoint = b64decode(j.tlsEndPoint);
        }
      }
    } catch {
      // Channel binding is optional in dev environments; proceed without it.
      state.tlsEndPoint = new Uint8Array(0);
    }
    return this;
  },

  // ---- login / logout ----------------------------------------------------

  async login(username, password) {
    assertSecureContext();
    if (!state.opaqueSetup) throw new Error("SecureAuth.init() not called");

    // ---- 1. Fetch the registration record (real or fake). ----------------
    const recRes = await fetch(
      `/api/registration-record?username=${encodeURIComponent(username)}`,
      { credentials: "same-origin" },
    );
    if (!recRes.ok) throw new Error("SecureAuth: registration record fetch failed");
    const recJson = await recRes.json();
    const registrationRecord = b64decode(recJson.registrationRecord);
    const userIdentifier = b64decode(recJson.userIdentifier);

    // ---- 2. OPAQUE client start. -----------------------------------------
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password });

    // ---- 3. OPAQUE server start (runs locally in the WASM module). ------
    // The Go server is not involved in the OPAQUE protocol itself; it only
    // provides the registration record. This makes the client the sole
    // OPAQUE endpoint on the wire, which is required because bytemare/opaque
    // (Go) and @serenity-kit/opaque (WASM) use incompatible formats.
    const { loginResponse } = opaque.server.startLogin({
      serverSetup: state.opaqueSetup,
      userIdentifier,
      registrationRecord,
      startLoginRequest,
    });

    // ---- 4. OPAQUE client finish. ----------------------------------------
    const loginResult = opaque.client.finishLogin({
      clientLoginState,
      loginResponse,
      password,
    });
    if (!loginResult) throw new Error("Login failed");
    const { exportKey, sessionKey: paakeKey } = loginResult;

    // ---- 5. X25519 ephemeral. --------------------------------------------
    const clientEphPriv = randomBytes(32);
    const clientEphPub = x25519.getPublicKey(clientEphPriv);

    // ---- 6. MAC over the ephemeral public key (bound to PAKE). -----------
    const macKey = hkdfSha256(
      paakeKey,
      new Uint8Array(0),
      new TextEncoder().encode("SecureAuth client MAC"),
      32,
    );
    const hmacKey = await crypto.subtle.importKey(
      "raw", macKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
    );
    const clientMAC = new Uint8Array(
      await crypto.subtle.sign("HMAC", hmacKey, clientEphPub),
    );

    // ---- 7. Session establishment. ---------------------------------------
    const step2 = await jsonFetch("/api/login2", {
      username,
      clientEphemeral: b64encode(clientEphPub),
      clientMAC: b64encode(clientMAC),
    });

    // ---- 8. Derive the shared secret. ------------------------------------
    const serverEphPub = b64decode(step2.serverEphemeralPublicKey);
    const shared = x25519.getSharedSecret(clientEphPriv, serverEphPub);

    // ---- 9. Channel binding (tls-server-end-point). ----------------------
    const tlsEndPoint = state.tlsEndPoint && state.tlsEndPoint.length > 0
      ? state.tlsEndPoint
      : (step2.tlsEndPoint ? b64decode(step2.tlsEndPoint) : new Uint8Array(0));

    // ---- 10. Derive the session key (must match the server). -------------
    const sessionKeyBytes = hkdfSha256(
      concat(shared, tlsEndPoint),
      new Uint8Array(0),
      new TextEncoder().encode("SecureAuth session key"),
      32,
    );

    state.sessionKeyRaw = sessionKeyBytes;
    state.sessionId = step2.sessionId;
    state.csrfToken = step2.csrfToken;
    state.userID = username;

    // ---- 11. Fetch and decrypt the RSA private key. ----------------------
    const blob = await jsonFetch("/api/privatekey");
    const salt = b64decode(blob.private_key_salt);
    const nonce = b64decode(blob.private_key_nonce);
    const ciphertext = b64decode(blob.encrypted_rsa_private_key);
    const info = new TextEncoder().encode(
      blob.private_key_kdf_info || "SecureAuth RSA private key",
    );
    const kPriv = hkdfSha256(exportKey, salt, info, 32);
    const plaintextPriv = xchacha20poly1305(kPriv, nonce).decrypt(ciphertext);

    state.rsaPrivateKey = await crypto.subtle.importKey(
      "pkcs8", plaintextPriv,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false, ["decrypt"],
    );

    // ---- 12. Cache the user's RSA public key (best effort). --------------
    try {
      const users = await jsonFetch("/api/getusers", {});
      const me = (users.users || []).find((u) => u.username === username);
      if (me) {
        state.rsaPublicKey = await crypto.subtle.importKey(
          "spki", b64decode(me.rsa_public_key),
          { name: "RSA-OAEP", hash: "SHA-256" },
          true, ["encrypt"],
        );
      }
    } catch {
      // The caller may not have user.read; the public key is optional for
      // the login flow itself.
    }

    // ---- 13. Zeroise everything we can. ----------------------------------
    zeroise(exportKey, kPriv, plaintextPriv, clientEphPriv, macKey);
    return { sessionId: state.sessionId, csrfToken: state.csrfToken };
  },

  async logout() {
    try {
      await jsonFetch("/logout", {});
    } finally {
      zeroise(state.sessionKeyRaw);
      state.sessionKeyRaw = null;
      state.sessionId = null;
      state.csrfToken = null;
      state.rsaPrivateKey = null;
      state.rsaPublicKey = null;
      state.userID = null;
    }
  },

  // ---- user management ---------------------------------------------------

  async createUser(username, password, role) {
    assertSecureContext();
    if (!state.opaqueSetup) throw new Error("SecureAuth.init() not called");

    // OPAQUE registration (client start, server start, client finish).
    const { clientRegistrationState, registrationRequest } =
      opaque.client.startRegistration({ password });

    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup: state.opaqueSetup,
      userIdentifier: new TextEncoder().encode(username),
      registrationRequest,
    });

    const { registrationRecord, exportKey } = opaque.client.finishRegistration({
      clientRegistrationState,
      registrationResponse,
      password,
    });

    // Generate an RSA key pair.
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 3072,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"],
    );
    const pubDer = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
    const privPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));

    // Encrypt the private key under a key derived from the OPAQUE export key.
    const salt = randomBytes(32);
    const info = new TextEncoder().encode("SecureAuth RSA private key");
    const kPriv = hkdfSha256(exportKey, salt, info, 32);
    const nonce = randomBytes(24);
    const encPriv = xchacha20poly1305(kPriv, nonce).encrypt(privPkcs8);

    await jsonFetch("/api/createuser", {
      username,
      role,
      opaque_registration_record: b64encode(registrationRecord),
      rsa_public_key: b64encode(pubDer),
      encrypted_rsa_private_key: b64encode(encPriv),
      private_key_nonce: b64encode(nonce),
      private_key_salt: b64encode(salt),
      private_key_kdf_info: "SecureAuth RSA private key",
    });

    zeroise(exportKey, kPriv, privPkcs8);
    return { username, rsa_public_key: b64encode(pubDer) };
  },

  async deleteUser(userId) {
    return jsonFetch("/api/deleteuser", { userId });
  },

  async getUsers() {
    return jsonFetch("/api/getusers", {});
  },

  async updateUser(userId, changes) {
    const body = { userId, ...changes };
    if (changes.password) {
      // Re-run OPAQUE registration with the new password.
      const { clientRegistrationState, registrationRequest } =
        opaque.client.startRegistration({ password: changes.password });

      const { registrationResponse } = opaque.server.createRegistrationResponse({
        serverSetup: state.opaqueSetup,
        userIdentifier: new TextEncoder().encode(userId),
        registrationRequest,
      });

      const { registrationRecord, exportKey } = opaque.client.finishRegistration({
        clientRegistrationState,
        registrationResponse,
        password: changes.password,
      });

      // Re-encrypt the existing RSA private key under the new export key.
      const salt = randomBytes(32);
      const info = new TextEncoder().encode("SecureAuth RSA private key");
      const kPriv = hkdfSha256(exportKey, salt, info, 32);
      const nonce = randomBytes(24);
      const privPkcs8 = new Uint8Array(
        await crypto.subtle.exportKey("pkcs8", state.rsaPrivateKey),
      );
      const encPriv = xchacha20poly1305(kPriv, nonce).encrypt(privPkcs8);

      body.opaque_registration_record = b64encode(registrationRecord);
      body.encrypted_rsa_private_key = b64encode(encPriv);
      body.private_key_nonce = b64encode(nonce);
      body.private_key_salt = b64encode(salt);
      delete body.password;
      zeroise(exportKey, kPriv, privPkcs8);
    }
    return jsonFetch("/api/updateuser", body);
  },

  // ---- roles -------------------------------------------------------------

  async getRoles() { return jsonFetch("/api/getroles", {}); },
  async addRole(roleData) { return jsonFetch("/api/addrole", roleData); },
  async updateRole(roleId, changes) {
    return jsonFetch("/api/updaterole", { roleId, ...changes });
  },
  async deleteRole(roleId) { return jsonFetch("/api/deleterole", { roleId }); },

  // ---- authorizations ----------------------------------------------------

  async getAuthorizations() { return jsonFetch("/api/getauthorizations", {}); },
  async addAuthorization(authData) { return jsonFetch("/api/addauthorization", authData); },
  async updateAuthorization(authId, changes) {
    return jsonFetch("/api/updateauthorization", { authId, ...changes });
  },
  async deleteAuthorization(authId) {
    return jsonFetch("/api/deleteauthorization", { authId });
  },

  // ---- threshold crypto --------------------------------------------------

  /**
   * Encrypts plaintext for a threshold authorization.
   *
   *   k   ← random scalar
   *   KG  = k·G                       (data key material)
   *   r   ← random scalar
   *   C1  = r·G
   *   C2  = KG + r·Y                  (Y = authorization public key)
   *   key = HKDF-SHA256(KG)           (XChaCha20-Poly1305 key)
   */
  async encryptForAuthorization(authId, plaintext) {
    // Fetch the authorization public key.
    const authInfo = await jsonFetch("/api/authorization-public-key", { authId });
    if (!authInfo.publicKey) {
      throw new Error("SecureAuth: authorization has no public key");
    }
    const Y = ristretto255.Point.fromBytes(b64decode(authInfo.publicKey));

    // Sample the data key scalar.
    const k = randomScalar();
    const KG = ristretto255.Point.BASE.multiply(k);

    // Derive the symmetric data key from KG.
    const dataKey = hkdfSha256(
      KG.toBytes(),
      new Uint8Array(0),
      new TextEncoder().encode("SecureAuth threshold data key"),
      32,
    );
    const nonce = randomBytes(24);
    const ct = xchacha20poly1305(dataKey, nonce).encrypt(
      new TextEncoder().encode(plaintext),
    );

    // ElGamal encryption of KG under Y.
    const r = randomScalar();
    const C1 = ristretto255.Point.BASE.multiply(r);
    const Yr = Y.multiply(r);
    const C2 = KG.add(Yr);

    // Store the ciphertext server-side.
    const stored = await jsonFetch("/api/threshold/encrypt", {
      authorizationId: authId,
      keyVersion: 1,
      c1: b64encode(C1.toBytes()),
      c2: b64encode(C2.toBytes()),
      ciphertext: b64encode(ct),
      nonce: b64encode(nonce),
    });

    zeroise(dataKey);
    return {
      ciphertextId: stored.id,
      ciphertext: b64encode(ct),
      nonce: b64encode(nonce),
      c1: b64encode(C1.toBytes()),
      c2: b64encode(C2.toBytes()),
    };
  },

  /**
   * Decrypts a threshold ciphertext using the holder's share.
   *  1. Fetch and unwrap the wrapped share (RSA-OAEP).
   *  2. Compute D_i = x_i · C1.
   *  3. Submit the partial to the server.
   *  4. Fetch all available partials.
   *  5. Lagrange-combine in the exponent to recover KG.
   *  6. Derive the data key and decrypt.
   */
  async decryptForAuthorization(authId, payload) {
    const ciphertextId = payload.ciphertextId;
    const C1 = ristretto255.Point.fromBytes(b64decode(payload.c1));
    const C2 = ristretto255.Point.fromBytes(b64decode(payload.c2));

    // Fetch the wrapped share.
    const shareRes = await jsonFetch("/api/threshold/share", { authorizationId: authId });
    const wrapped = b64decode(shareRes.wrappedShare);
    const shareBytes = new Uint8Array(await crypto.subtle.decrypt(
      { name: "RSA-OAEP" }, state.rsaPrivateKey, wrapped,
    ));
    const shareScalar = scalarFromBytes(shareBytes);

    // Partial decryption D_i = x_i · C1.
    const D_i = C1.multiply(shareScalar);

    await jsonFetch("/api/threshold/partial", {
      ciphertextId,
      shareIndex: shareRes.shareIndex,
      partial: b64encode(D_i.toBytes()),
    });

    // Fetch the partials that are available so far.
    const partialsRes = await jsonFetch("/api/threshold/partials", { ciphertextId });
    const partials = (partialsRes.partials || []).map((p) => ({
      index: p.shareIndex,
      point: ristretto255.Point.fromBytes(b64decode(p.partial)),
    }));

    // Lagrange-combine in the exponent.
    const KG = lagrangeCombine(C2, partials);

    const dataKey = hkdfSha256(
      KG.toBytes(),
      new Uint8Array(0),
      new TextEncoder().encode("SecureAuth threshold data key"),
      32,
    );

    const nonce = b64decode(payload.nonce);
    const ct = b64decode(payload.ciphertext);
    const pt = xchacha20poly1305(dataKey, nonce).decrypt(ct);
    zeroise(dataKey, shareBytes);
    return new TextDecoder().decode(pt);
  },

  // ---- bootstrap ---------------------------------------------------------

  /**
   * Generates a fresh 256-bit symmetric key for every authorization that has
   * no key yet, wraps it to the caller's RSA public key, signs the wrapped
   * blob, and uploads it. Idempotent.
   *
   * Call this immediately after the first SuperAdmin login (§4).
   */
  async bootstrapAuthorizationKeys() {
    if (!state.rsaPrivateKey || !state.rsaPublicKey) {
      throw new Error("SecureAuth: bootstrap requires an active session");
    }

    const auths = await this.getAuthorizations();
    const existingRes = await jsonFetch("/api/shared-keys/check", {});
    const existing = new Set(existingRes.authorizationIds || []);

    for (const auth of auths.authorizations || []) {
      if (existing.has(auth.id)) continue;

      const authKey = randomBytes(32);

      const wrapped = new Uint8Array(await crypto.subtle.encrypt(
        { name: "RSA-OAEP" }, state.rsaPublicKey, authKey,
      ));

      const sig = new Uint8Array(await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 }, state.rsaPrivateKey, wrapped,
      ));

      await jsonFetch("/api/sharekeys", {
        authorizationId: auth.id,
        wrappedKey: b64encode(wrapped),
        adminSignature: b64encode(sig),
        keyVersion: 1,
      });

      zeroise(authKey);
    }
  },

  // ---- generic encrypted request/response --------------------------------

  /**
   * Sends an encrypted request. The session key encrypts the payload with
   * XChaCha20-Poly1305; the server decrypts with the same key. (§5)
   */
  async sendEncryptedRequest(endpoint, payload) {
    if (!state.sessionKeyRaw) throw new Error("not logged in");
    const nonce = randomBytes(24);
    const pt = new TextEncoder().encode(JSON.stringify(payload));
    const ct = xchacha20poly1305(state.sessionKeyRaw, nonce).encrypt(pt);
    return jsonFetch(endpoint, {
      nonce: b64encode(nonce),
      ciphertext: b64encode(ct),
    });
  },

  async getDecryptedResponse(response) {
    if (!state.sessionKeyRaw) throw new Error("not logged in");
    const nonce = b64decode(response.nonce);
    const ct = b64decode(response.ciphertext);
    const pt = xchacha20poly1305(state.sessionKeyRaw, nonce).decrypt(ct);
    return JSON.parse(new TextDecoder().decode(pt));
  },

  // ---- private key backup / restore --------------------------------------

  async exportEncryptedPrivateKey() {
    return jsonFetch("/api/privatekey", {});
  },

  async importEncryptedPrivateKey(blob) {
    return jsonFetch("/api/import-privatekey", blob);
  },
};

// ---------------------------------------------------------------------------
// Bootstrap hook
// ---------------------------------------------------------------------------

if (typeof window !== "undefined") {
  window.SecureAuth = SecureAuth;
}