// secureauth.mjs — browser client for the SecureAuth library.
//
// OPAQUE protocol is delegated to ./opaque.mjs (byte-compatible with
// github.com/bytemare/opaque, ristretto255-SHA512 / SHA-512 / Argon2id).
//
// This file contains ONLY the SecureAuth client surface:
//   * HTTP plumbing & CSRF
//   * RSA-OAEP / RSA-PSS key handling
//   * X25519 + HKDF-SHA256 session-key derivation
//   * XChaCha20-Poly1305 encrypted data store
//   * bootstrap / user / role / authorization management
//
// It also re-exports a small set of low-level primitives (b64 helpers,
// randomBytes, concat, hkdfSha256, hmacSha256, jsonFetch, RSA wrap/sign
// helpers, getCsrfToken) so downstream applications can build their own
// layers on top of SecureAuth without re-implementing cryptography or
// HTTP plumbing. Nothing application-specific lives in this file.

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";

import {
  createClientState,
  opaqueStartRegistration,
  opaqueFinishRegistration,
  opaqueStartLogin,
  opaqueFinishLogin,
} from "/static/opaque.mjs";

// ===========================================================================
// Protocol constants
// ===========================================================================

const KSF_PARAMS = { t: 3, m: 65536, p: 4 };
const KSF_LENGTH = 64;
const KSF_SALT_LENGTH = 32;

const OPAQUE_CONTEXT = new Uint8Array(0);

const HKDF_SALT = new TextEncoder().encode("SecureAuth HKDF salt v1");

// ===========================================================================
// State
// ===========================================================================

const state = {
  serverId: null,
  tlsEndPoint: null,
  sessionId: null,
  sessionKeyRaw: null,
  rsaPrivateKey: null,
  rsaSigningKey: null,
  rsaPublicKey: null,
  rsaPrivateKeyPkcs8: null,
  rsaSigningKeyPkcs8: null,
  userID: null,
  bootstrapToken: null,
  initPromise: null,
  bootstrapInProgress: false,
  masterkeyCache: {},
};

// ===========================================================================
// Primitive helpers (exported for downstream applications)
// ===========================================================================

export function assertSecureContext() {
  if (typeof window !== "undefined" && !window.isSecureContext) {
    throw new Error("SecureAuth requires a secure context (HTTPS).");
  }
  if (typeof crypto === "undefined" || !crypto.getRandomValues) {
    throw new Error("SecureAuth requires crypto.getRandomValues.");
  }
}

export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function concat(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function b64encode(x) {
  // Accept Uint8Array, ArrayBuffer, DataView, any ArrayBufferView,
  // Array<number>, and strings. WebCrypto returns ArrayBuffer from
  // subtle.sign / encrypt / decrypt / digest, and ArrayBuffer has no
  // Symbol.iterator — the source of "bytes is not iterable".
  let bytes;
  if (x instanceof Uint8Array) {
    bytes = x;
  } else if (x instanceof ArrayBuffer) {
    bytes = new Uint8Array(x);
  } else if (ArrayBuffer.isView(x)) {
    bytes = new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  } else if (Array.isArray(x)) {
    bytes = Uint8Array.from(x);
  } else if (typeof x === "string") {
    bytes = new TextEncoder().encode(x);
  } else if (x && typeof x.length === "number") {
    bytes = Uint8Array.from(x);
  } else {
    throw new TypeError(
      "b64encode: expected bytes-like input, got " +
        Object.prototype.toString.call(x),
    );
  }

  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

export function b64decode(x) {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) {
    return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  }
  if (typeof x !== "string") {
    throw new TypeError("b64decode: expected base64 string");
  }
  const bin = atob(x);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function zeroise(...arrays) {
  for (const a of arrays) if (a && a.fill) a.fill(0);
}

export function utf8(s) {
  return new TextEncoder().encode(s);
}

export function getCsrfToken() {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(/(?:^|;\s*)secureauth_csrf=([^;]*)/);
  return m ? decodeURIComponent(m[1]) : null;
}

export function hkdfSha256(ikm, salt, info, length) {
  return hkdf(sha256, ikm, salt, info, length);
}

export async function hmacSha256(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
}

// jsonFetch: GET when body is undefined, POST otherwise. JSON in, JSON out.
// `__csrf: false` in the body suppresses the CSRF header (used by /logout
// and by the pre-session bootstrap path). `__method` overrides the method.
export async function jsonFetch(path, body) {
  const headers = {};
  const csrf = getCsrfToken();
  const isJSON = body !== undefined;
  if (isJSON) headers["Content-Type"] = "application/json";
  if (csrf && (body === undefined || body.__csrf !== false)) {
    headers["X-CSRF-Token"] = csrf;
  }
  const method = (body && body.__method) || (isJSON ? "POST" : "GET");
  const opts = { method, credentials: "same-origin", headers };
  if (isJSON) {
    const copy = { ...body };
    delete copy.__csrf;
    delete copy.__method;
    delete copy.__bootstrap;
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

// ===========================================================================
// OPAQUE wrappers
// ===========================================================================

function newOpaqueState() {
  return createClientState({ context: OPAQUE_CONTEXT });
}

function opaqueStartReg(clientState, password) {
  return opaqueStartRegistration(clientState, utf8(password));
}

function opaqueFinishReg(clientState, registrationResponseBytes, username, ksfSalt) {
  const { record, exportKey } = opaqueFinishRegistration(
    clientState,
    registrationResponseBytes,
    utf8(username),
    utf8(state.serverId || "secureauth"),
    { ksfSalt, ksfParams: KSF_PARAMS, ksfLength: KSF_LENGTH },
  );
  const registrationRecord = concat(
    record.clientPublicKey,
    record.maskingKey,
    record.envelope,
  );
  return { registrationRecord, exportKey };
}

function opaqueStartLog(clientState, password) {
  return opaqueStartLogin(clientState, utf8(password));
}

async function opaqueFinishLog(loginResponseBytes, clientState, username, ksfSalt) {
  const encoder = new TextEncoder();
  return await opaqueFinishLogin({
    state: clientState,
    serverResponseMessage: loginResponseBytes,
    serverIdentity: encoder.encode(state.serverId || "secureauth"),
    clientIdentity: encoder.encode(username),
    context: OPAQUE_CONTEXT,
    options: { ksfSalt, ksfParams: KSF_PARAMS, ksfLength: KSF_LENGTH },
  });
}

// ===========================================================================
// RSA helpers
//
// The unwrap/sign helpers now take the CryptoKey explicitly so they can be
// used outside the SecureAuth session lifecycle. Downstream code that needs
// the session keys can obtain them via SecureAuth.currentRsaPrivateKey() /
// SecureAuth.currentRsaSigningKey().
// ===========================================================================

export async function rsaWrapMasterkey(masterkeyBytes, rsaPublicKeyDer) {
  const pubKey = await crypto.subtle.importKey(
    "spki",
    rsaPublicKeyDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
  return new Uint8Array(
    await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, masterkeyBytes),
  );
}

export async function rsaUnwrapMasterkey(wrappedBytes, rsaPrivateKey) {
  if (!rsaPrivateKey) {
    throw new Error("SecureAuth: no RSA private key provided");
  }
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      rsaPrivateKey,
      wrappedBytes,
    ),
  );
}

// WebCrypto hashes the input internally with SHA-256 before applying PSS.
// The Go server does sha256.Sum256(wrapped) then rsa.VerifyPSS, so we must
// pass the raw bytes here, not a pre-computed digest.
export async function rsaSignWrapped(wrappedBytes, rsaSigningKey) {
  if (!rsaSigningKey) {
    throw new Error("SecureAuth: no RSA signing key provided");
  }
  return new Uint8Array(
    await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      rsaSigningKey,
      wrappedBytes,
    ),
  );
}

// ===========================================================================
// Masterkey resolution
// ===========================================================================

async function resolveMasterkey(authId) {
  if (state.masterkeyCache[authId]) return state.masterkeyCache[authId];
  const res = await jsonFetch("/api/get-wrapped-masterkey", {
    authorizationId: authId,
  });
  const wrapped = b64decode(res.wrappedKey);
  const masterkey = await rsaUnwrapMasterkey(wrapped, state.rsaPrivateKey);
  state.masterkeyCache[authId] = masterkey;
  return masterkey;
}

async function ensureOwnRsaPublicKey() {
  if (state.rsaPublicKey) return state.rsaPublicKey;
  try {
    const users = await jsonFetch("/api/getusers", {});
    const me = (users.users || []).find((u) => u.username === state.userID);
    if (me) {
      state.rsaPublicKey = await crypto.subtle.importKey(
        "spki",
        b64decode(me.rsa_public_key),
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"],
      );
    }
  } catch {
    /* user.read may not be granted */
  }
  if (!state.rsaPublicKey) {
    throw new Error(
      "SecureAuth: RSA public key unavailable — cannot wrap a masterkey. " +
        "Grant the `user.read` authorization to this account.",
    );
  }
  return state.rsaPublicKey;
}

// ===========================================================================
// Public SecureAuth client
// ===========================================================================

export const SecureAuth = {
  // -------------------------------------------------------------------------
  // init / bootstrap
  // -------------------------------------------------------------------------
  async init(_options = {}) {
    if (state.initPromise) return state.initPromise;
    state.initPromise = (async () => {
      assertSecureContext();

      try {
        const idRes = await jsonFetch("/api/server-id");
        state.serverId = idRes.serverId;
      } catch (e) {
        console.warn("secureauth: could not fetch server-id", e);
      }

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
        state.tlsEndPoint = new Uint8Array(0);
      }

      await this._maybeBootstrap();
      return this;
    })();
    return state.initPromise;
  },

  async _maybeBootstrap() {
    let creds;
    try {
      const res = await fetch("/api/bootstrap/credentials", {
        credentials: "same-origin",
      });
      if (!res.ok) return;
      creds = await res.json();
    } catch {
      return;
    }
    if (!creds.available) return;
    const bUser = creds.username;
    const bPass = creds.password;
    if (!bUser || !bPass) return;
    if (creds.bootstrapToken) state.bootstrapToken = creds.bootstrapToken;

    try {
      await fetch("/logout", {
        method: "POST",
        credentials: "same-origin",
      });
    } catch {}

    console.info("secureauth: performing first-admin bootstrap...");
    state.bootstrapInProgress = true;
    try {
      await this.createUser(bUser, bPass, "SuperAdmin");
      await this.login(bUser, bPass);

      const pendingRes = await fetch("/api/bootstrap/masterkeys-pending", {
        credentials: "same-origin",
        headers: { "X-CSRF-Token": getCsrfToken() || "" },
      });
      if (!pendingRes.ok) {
        throw new Error("SecureAuth: bootstrap masterkeys-pending failed");
      }
      const { masterkeys } = await pendingRes.json();

      const spkiDer = await this.ownRsaPublicKeyDer();
      const wrappedKeys = [];
      const signKey = state.rsaSigningKey;
      for (const [authId, mkB64] of Object.entries(masterkeys || {})) {
        const masterkey = b64decode(mkB64);
        const wrapped = await rsaWrapMasterkey(masterkey, spkiDer);
        const sig = await rsaSignWrapped(wrapped, signKey);
        wrappedKeys.push({
          authorizationId: authId,
          wrappedKey: b64encode(wrapped),
          adminSignature: b64encode(sig),
          keyVersion: 1,
        });
        zeroise(masterkey);
      }

      const commitRes = await fetch("/api/bootstrap/first-user", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": getCsrfToken() || "",
        },
        body: JSON.stringify({ wrappedKeys }),
      });
      if (!commitRes.ok) {
        const t = await commitRes.text().catch(() => "");
        throw new Error("SecureAuth: bootstrap/first-user failed: " + t);
      }
      console.info("secureauth: first-admin bootstrap complete.");
    } finally {
      state.bootstrapInProgress = false;
    }
  },

  async _ensureInit() {
    if (state.bootstrapInProgress) return;
    if (state.initPromise) {
      await state.initPromise;
      return;
    }
    await this.init();
  },

  // -------------------------------------------------------------------------
  // login
  // -------------------------------------------------------------------------
  async login(username, password) {
    assertSecureContext();
    await this._ensureInit();

    const clientState = newOpaqueState();
    const ke1 = opaqueStartLog(clientState, password);

    const initRes = await jsonFetch("/api/login/init", {
      username,
      ke1: b64encode(ke1),
    });
    const { loginAttemptId, ke2, ksfSalt } = initRes;
    const ke2Bytes = b64decode(ke2);
    const ksfSaltBytes = b64decode(ksfSalt);

    const { finishLoginRequest, sessionKey, exportKey } = await opaqueFinishLog(
      ke2Bytes,
      clientState,
      username,
      ksfSaltBytes,
    );

    const transcriptHash = sha256(concat(ke1, ke2Bytes));

    const clientEphPriv = randomBytes(32);
    const clientEphPub = x25519.getPublicKey(clientEphPriv);

    const macKey = hkdfSha256(
      sessionKey,
      HKDF_SALT,
      utf8("SecureAuth client MAC"),
      32,
    );
    const clientMAC = await hmacSha256(macKey, clientEphPub);

    const step2 = await jsonFetch("/api/login2", {
      loginAttemptId,
      ke3: b64encode(finishLoginRequest),
      clientEphemeral: b64encode(clientEphPub),
      clientMAC: b64encode(clientMAC),
    });

    const serverEphPub = b64decode(step2.serverEphemeralPublicKey);
    const shared = x25519.getSharedSecret(clientEphPriv, serverEphPub);

    const tlsEndPoint =
      state.tlsEndPoint && state.tlsEndPoint.length > 0
        ? state.tlsEndPoint
        : new Uint8Array(0);

    const sessionKeyBytes = hkdfSha256(
      concat(shared, sessionKey, transcriptHash, tlsEndPoint),
      HKDF_SALT,
      utf8("SecureAuth session key"),
      32,
    );

    state.sessionKeyRaw = sessionKeyBytes;
    state.sessionId = step2.sessionId;
    state.userID = username;

    const blob = await jsonFetch("/api/privatekey");

    const salt = b64decode(blob.private_key_salt);
    const nonce = b64decode(blob.private_key_nonce);
    const ciphertext = b64decode(blob.encrypted_rsa_private_key);
    const info = utf8(blob.private_key_kdf_info || "SecureAuth RSA private key");
    const kPriv = hkdfSha256(exportKey, salt, info, 32);
    const plaintextPriv = xchacha20poly1305(kPriv, nonce).decrypt(ciphertext);

    state.rsaPrivateKeyPkcs8 = new Uint8Array(plaintextPriv);
    state.rsaPrivateKey = await crypto.subtle.importKey(
      "pkcs8",
      plaintextPriv,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"],
    );

    if (blob.encrypted_rsa_signing_private_key) {
      const sSalt = b64decode(blob.signing_key_salt);
      const sNonce = b64decode(blob.signing_key_nonce);
      const sCt = b64decode(blob.encrypted_rsa_signing_private_key);
      const sInfo = utf8(
        blob.signing_key_kdf_info || "SecureAuth RSA signing private key",
      );
      const kSign = hkdfSha256(exportKey, sSalt, sInfo, 32);
      const sPlain = xchacha20poly1305(kSign, sNonce).decrypt(sCt);

      state.rsaSigningKeyPkcs8 = new Uint8Array(sPlain);
      state.rsaSigningKey = await crypto.subtle.importKey(
        "pkcs8",
        sPlain,
        { name: "RSA-PSS", hash: "SHA-256" },
        false,
        ["sign"],
      );
      zeroise(kSign, sPlain);
    }

    try {
      const users = await jsonFetch("/api/getusers", {});
      const me = (users.users || []).find((u) => u.username === username);
      if (me) {
        state.rsaPublicKey = await crypto.subtle.importKey(
          "spki",
          b64decode(me.rsa_public_key),
          { name: "RSA-OAEP", hash: "SHA-256" },
          true,
          ["encrypt"],
        );
      }
    } catch {
      /* user.read may not be granted */
    }

    zeroise(exportKey, sessionKey, kPriv, plaintextPriv, clientEphPriv, macKey);
    return { sessionId: state.sessionId };
  },

  // -------------------------------------------------------------------------
  // logout
  // -------------------------------------------------------------------------
  async logout() {
    try {
      await jsonFetch("/logout", { __csrf: false });
    } finally {
      zeroise(state.sessionKeyRaw);
      zeroise(state.rsaPrivateKeyPkcs8, state.rsaSigningKeyPkcs8);
      state.sessionKeyRaw = null;
      state.sessionId = null;
      state.rsaPrivateKey = null;
      state.rsaSigningKey = null;
      state.rsaPublicKey = null;
      state.rsaPrivateKeyPkcs8 = null;
      state.rsaSigningKeyPkcs8 = null;
      state.userID = null;
      for (const k of Object.keys(state.masterkeyCache)) {
        if (state.masterkeyCache[k]?.fill) state.masterkeyCache[k].fill(0);
        delete state.masterkeyCache[k];
      }
    }
  },

  // -------------------------------------------------------------------------
  // createUser
  // -------------------------------------------------------------------------
  async createUser(username, password, role) {
    assertSecureContext();
    await this._ensureInit();

    const clientState = newOpaqueState();
    const registrationRequest = opaqueStartReg(clientState, password);

    const initRes = await jsonFetch("/api/register/init", {
      username,
      registrationRequest: b64encode(registrationRequest),
    });
    const { registrationResponse, pendingRegId } = initRes;

    const ksfSalt = randomBytes(KSF_SALT_LENGTH);
    const { registrationRecord, exportKey } = opaqueFinishReg(
      clientState,
      b64decode(registrationResponse),
      username,
      ksfSalt,
    );

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
    const pubDer = new Uint8Array(
      await crypto.subtle.exportKey("spki", keyPair.publicKey),
    );
    const privPkcs8 = new Uint8Array(
      await crypto.subtle.exportKey("pkcs8", keyPair.privateKey),
    );

    const salt = randomBytes(32);
    const info = utf8("SecureAuth RSA private key");
    const kPriv = hkdfSha256(exportKey, salt, info, 32);
    const nonce = randomBytes(24);
    const encPriv = xchacha20poly1305(kPriv, nonce).encrypt(privPkcs8);

    const signKeyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 3072,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const signPubDer = new Uint8Array(
      await crypto.subtle.exportKey("spki", signKeyPair.publicKey),
    );
    const signPrivPkcs8 = new Uint8Array(
      await crypto.subtle.exportKey("pkcs8", signKeyPair.privateKey),
    );

    const signSalt = randomBytes(32);
    const signInfo = utf8("SecureAuth RSA signing private key");
    const kSign = hkdfSha256(exportKey, signSalt, signInfo, 32);
    const signNonce = randomBytes(24);
    const encSignPriv = xchacha20poly1305(kSign, signNonce).encrypt(
      signPrivPkcs8,
    );

    const body = {
      username,
      role,
      pendingRegId,
      registration_record: b64encode(registrationRecord),
      rsa_public_key: b64encode(pubDer),
      encrypted_rsa_private_key: b64encode(encPriv),
      private_key_nonce: b64encode(nonce),
      private_key_salt: b64encode(salt),
      private_key_kdf_info: "SecureAuth RSA private key",
      rsa_signing_public_key: b64encode(signPubDer),
      encrypted_rsa_signing_private_key: b64encode(encSignPriv),
      signing_key_nonce: b64encode(signNonce),
      signing_key_salt: b64encode(signSalt),
      signing_key_kdf_info: "SecureAuth RSA signing private key",
      ksf_salt: b64encode(ksfSalt),
    };

    const headers = { "Content-Type": "application/json" };
    if (state.bootstrapToken) {
      headers["X-Bootstrap-Token"] = state.bootstrapToken;
    }
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;

    const res = await fetch("/api/createuser", {
      method: "POST",
      credentials: "same-origin",
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`SecureAuth: createuser -> ${res.status} ${text}`);
    }

    zeroise(exportKey, kPriv, kSign, privPkcs8, signPrivPkcs8);
    return { username, rsa_public_key: b64encode(pubDer) };
  },

  // -------------------------------------------------------------------------
  // users
  // -------------------------------------------------------------------------
  async deleteUser(userId) {
    return jsonFetch("/api/deleteuser", { userId });
  },
  async getUsers() {
    return jsonFetch("/api/getusers", {});
  },
  async updateUser(userId, changes) {
    const body = { userId, ...changes };
    if (changes.password) {
      const clientState = newOpaqueState();
      const registrationRequest = opaqueStartReg(clientState, changes.password);

      const initRes = await jsonFetch("/api/register/init", {
        username: userId,
        registrationRequest: b64encode(registrationRequest),
      });
      const { registrationResponse, pendingRegId } = initRes;

      const ksfSalt = randomBytes(KSF_SALT_LENGTH);
      const { registrationRecord, exportKey } = opaqueFinishReg(
        clientState,
        b64decode(registrationResponse),
        userId,
        ksfSalt,
      );

      if (!state.rsaPrivateKeyPkcs8) {
        throw new Error(
          "SecureAuth: cannot re-encrypt RSA private key — PKCS#8 bytes unavailable",
        );
      }

      const salt = randomBytes(32);
      const info = utf8("SecureAuth RSA private key");
      const kPriv = hkdfSha256(exportKey, salt, info, 32);
      const nonce = randomBytes(24);
      const encPriv = xchacha20poly1305(kPriv, nonce).encrypt(
        state.rsaPrivateKeyPkcs8,
      );

      let encSignPriv = null,
        signNonce = null,
        signSalt = null;
      if (state.rsaSigningKeyPkcs8) {
        const sSalt = randomBytes(32);
        const sInfo = utf8("SecureAuth RSA signing private key");
        const kSign = hkdfSha256(exportKey, sSalt, sInfo, 32);
        const sNonce = randomBytes(24);
        encSignPriv = xchacha20poly1305(kSign, sNonce).encrypt(
          state.rsaSigningKeyPkcs8,
        );
        signNonce = sNonce;
        signSalt = sSalt;
        zeroise(kSign);
      }

      body.pendingRegId = pendingRegId;
      body.registration_record = b64encode(registrationRecord);
      body.encrypted_rsa_private_key = b64encode(encPriv);
      body.private_key_nonce = b64encode(nonce);
      body.private_key_salt = b64encode(salt);
      body.ksf_salt = b64encode(ksfSalt);
      if (encSignPriv) {
        body.encrypted_rsa_signing_private_key = b64encode(encSignPriv);
        body.signing_key_nonce = b64encode(signNonce);
        body.signing_key_salt = b64encode(signSalt);
      }
      delete body.password;
      zeroise(exportKey, kPriv);
    }
    return jsonFetch("/api/updateuser", body);
  },

  // -------------------------------------------------------------------------
  // roles / authorizations
  // -------------------------------------------------------------------------
  async getRoles() {
    return jsonFetch("/api/getroles", {});
  },
  async addRole(roleData) {
    return jsonFetch("/api/addrole", roleData);
  },
  async updateRole(roleId, changes) {
    return jsonFetch("/api/updaterole", { roleId, ...changes });
  },
  async deleteRole(roleId) {
    return jsonFetch("/api/deleterole", { roleId });
  },

  async getAuthorizations() {
    return jsonFetch("/api/getauthorizations", {});
  },
  async addAuthorization(authData) {
    const res = await jsonFetch("/api/addauthorization", authData);
    const authId = res.id;
    const masterkey = randomBytes(32);
    try {
      const spkiDer = await this.ownRsaPublicKeyDer();
      const wrapped = await rsaWrapMasterkey(masterkey, spkiDer);
      const sig = await rsaSignWrapped(wrapped, state.rsaSigningKey);
      await jsonFetch("/api/sharekeys", {
        authorizationId: authId,
        wrappedKey: b64encode(wrapped),
        adminSignature: b64encode(sig),
        keyVersion: 1,
      });
    } finally {
      zeroise(masterkey);
    }
    return res;
  },
  async updateAuthorization(authId, changes) {
    return jsonFetch("/api/updateauthorization", { authId, ...changes });
  },
  async deleteAuthorization(authId) {
    return jsonFetch("/api/deleteauthorization", { authId });
  },

  async shareAuthorizationMasterkey(authId, targetUsername) {
    const masterkey = await resolveMasterkey(authId);
    const targetPubDer = await this.userRsaPublicKeyDer(targetUsername);
    const wrapped = await rsaWrapMasterkey(masterkey, targetPubDer);
    const sig = await rsaSignWrapped(wrapped, state.rsaSigningKey);
    await jsonFetch("/api/sharekeys", {
      userId: targetUsername,
      authorizationId: authId,
      wrappedKey: b64encode(wrapped),
      adminSignature: b64encode(sig),
      keyVersion: 1,
    });
  },

  async bootstrapAuthorizationKeys(authId) {
    const masterkey = await resolveMasterkey(authId);
    const users = await this.getUsers();
    for (const u of users.users || []) {
      if (u.username === state.userID) continue;
      try {
        const targetPubDer = b64decode(u.rsa_public_key);
        const wrapped = await rsaWrapMasterkey(masterkey, targetPubDer);
        const sig = await rsaSignWrapped(wrapped, state.rsaSigningKey);
        await jsonFetch("/api/sharekeys", {
          userId: u.username,
          authorizationId: authId,
          wrappedKey: b64encode(wrapped),
          adminSignature: b64encode(sig),
          keyVersion: 1,
        });
      } catch {
        /* target user may not hold the authorization */
      }
    }
  },

  // -------------------------------------------------------------------------
  // encrypted data store
  // -------------------------------------------------------------------------
  async encryptAndStore(authId, plaintext, { label = "", id = "" } = {}) {
    const masterkey = await resolveMasterkey(authId);
    const nonce = randomBytes(24);
    const pt = typeof plaintext === "string" ? utf8(plaintext) : plaintext;
    const ct = xchacha20poly1305(masterkey, nonce).encrypt(pt);
    return jsonFetch("/api/data/put", {
      authorizationId: authId,
      id: id || undefined,
      keyVersion: 1,
      nonce: b64encode(nonce),
      ciphertext: b64encode(ct),
      label,
    });
  },
  async fetchAndDecrypt(recordId) {
    const rec = await jsonFetch("/api/data/get", { id: recordId });
    const masterkey = await resolveMasterkey(rec.authorizationId);
    const nonce = b64decode(rec.nonce);
    const ct = b64decode(rec.ciphertext);
    const pt = xchacha20poly1305(masterkey, nonce).decrypt(ct);
    return new TextDecoder().decode(pt);
  },
  async deleteData(recordId) {
    return jsonFetch("/api/data/delete", { id: recordId });
  },
  async listData(authId) {
    return jsonFetch("/api/data/list", { authorizationId: authId });
  },

  // -------------------------------------------------------------------------
  // Accessors for downstream applications
  // -------------------------------------------------------------------------
  currentUser() {
    return state.userID;
  },
  currentSessionId() {
    return state.sessionId;
  },
  currentRsaPrivateKey() {
    return state.rsaPrivateKey;
  },
  currentRsaSigningKey() {
    return state.rsaSigningKey;
  },
  currentRsaPublicKey() {
    return state.rsaPublicKey;
  },

  async ownRsaPublicKeyDer() {
    const pub = await ensureOwnRsaPublicKey();
    return new Uint8Array(await crypto.subtle.exportKey("spki", pub));
  },

  async userRsaPublicKeyDer(username) {
    const users = await jsonFetch("/api/getusers", {});
    const u = (users.users || []).find((x) => x.username === username);
    if (!u) throw new Error("SecureAuth: user not found: " + username);
    return b64decode(u.rsa_public_key);
  },

  // resolveMasterkey(authId) unwraps the caller's shared key for the given
  // authorization ID and caches the plaintext in session memory. Downstream
  // applications use this to obtain per-resource masterkeys.
  async getMasterkey(authId) {
    return resolveMasterkey(authId);
  },

  forgetMasterkey(authId) {
    const mk = state.masterkeyCache[authId];
    if (mk) {
      zeroise(mk);
      delete state.masterkeyCache[authId];
    }
  },

  // setBootstrapToken is exposed for hosts that want to seed the token from
  // an out-of-band channel instead of the auto-bootstrap path.
  setBootstrapToken(token) {
    state.bootstrapToken = token;
  },
};

if (typeof window !== "undefined") {
  window.SecureAuth = SecureAuth;
}