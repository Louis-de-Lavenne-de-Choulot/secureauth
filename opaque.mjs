// opaque.mjs — OPAQUE client interoperable with github.com/bytemare/opaque.
//
// Default ciphersuite:
//   OPRF : ristretto255-SHA512
//   AKE  : ristretto255
//   Hash : SHA-512
//   KDF  : HKDF-SHA-512
//   MAC  : HMAC-SHA-512
//   KSF  : Argon2id
//
// All imports use the explicit ".js" subpaths required by @noble/* v2.

import { ristretto255, ristretto255_hasher } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { expand_message_xmd } from "@noble/curves/abstract/hash-to-curve.js";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils.js";
import { mod } from "@noble/curves/abstract/modular.js";

// =============================================================================
// Constants (ristretto255 / SHA-512)
// =============================================================================

const Nh = 64; // SHA-512 output
const Nn = 32; // Nonce length
const Npk = 32; // Ristretto element length
const Nsk = 32; // Ristretto scalar length
const Nseed = 32; // Seed length for DeriveKeyPair
const L = 2n ** 252n + 27742317777372353535851937790883648493n; // ristretto255 order

// RFC 9497 OPRF DSTs
const OPRF_SUITE = concatBytes(
  utf8ToBytes("OPRFV1-"),
  new Uint8Array([0]),
  utf8ToBytes("-ristretto255-SHA512"),
);
const DST_H2G = concatBytes(utf8ToBytes("HashToGroup-"), OPRF_SUITE);

// OPAQUE label tags — must match internal/tag on the Go side
const LBL_PREFIX = "OPAQUE-";
const TAG_MASKING_KEY = "MaskingKey";
const TAG_AUTH_KEY = "AuthKey";
const TAG_EXPORT_KEY = "ExportKey";
const TAG_PRIVATE_KEY = "PrivateKey";
const TAG_SESSION_KEY = "SessionKey";
const TAG_SERVER_MAC = "ServerMAC";
const TAG_CLIENT_MAC = "ClientMAC";
const TAG_HANDSHAKE = "HandshakeSecret";
const TAG_CRED_PAD = "CredentialResponsePad";
const TAG_DERIVE_DH = "DeriveDiffieHellmanKeyPair";
const VERSION_TAG = utf8ToBytes("OPAQUEv1-");

// Message sizes (bytes)
const SZ_REG_REQ = Npk; // 32
const SZ_REG_RESP = Npk + Npk; // 64
const SZ_REG_RECORD = Npk + Nh + Nn + Nh; // 192
const SZ_KE1 = Npk + Nn + Npk; // 96
const SZ_CRED_RESP = Npk + Nn + (Npk + Nn + Nh); // 192
const SZ_KE2 = SZ_CRED_RESP + Nn + Npk + Nh; // 320
const SZ_KE3 = Nh; // 64

// =============================================================================
// Encoding helpers
// =============================================================================

const I2OSP2 = (n) => new Uint8Array([(n >>> 8) & 0xff, n & 0xff]);
const I2OSP1 = (n) => new Uint8Array([n & 0xff]);

function ctEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// =============================================================================
// Scalar / group helpers
// =============================================================================

const Pt = ristretto255.Point;

const rndScalar = () => {
  for (;;) {
    const s = mod(bytesToNumberLE(randomBytes(64)), L);
    if (s !== 0n) return s;
  }
};
const scBytes = (s) => numberToBytesLE(s, 32);
const scFrom = (b) => mod(bytesToNumberLE(b), L);
const ptBytes = (p) => p.toBytes();
const ptFrom = (b) => Pt.fromBytes(b);

// =============================================================================
// HKDF / Expand-Label
// =============================================================================

/** HKDF-Extract with SHA-512. */
export function hkdfExtractOnly(salt, ikm) {
  return hmac(sha512, salt ?? new Uint8Array(Nh), ikm);
}

/** Raw HKDF-Expand with SHA-512. */
export function hkdfExpand(prk, info, length) {
  const N = Math.ceil(length / Nh);
  let prev = new Uint8Array(0);
  const chunks = [];
  for (let i = 1; i <= N; i++) {
    prev = hmac(sha512, prk, concatBytes(prev, info, I2OSP1(i)));
    chunks.push(prev);
  }
  return concatBytes(...chunks).slice(0, length);
}

/**
 * RFC 9807 Expand-Label.
 * info = length(2) || len(label)(1) || "OPAQUE-" || label || len(ctx)(1) || ctx
 */
export function opaqueExpandLabel(secret, label, context, length) {
  const full = concatBytes(utf8ToBytes(LBL_PREFIX), utf8ToBytes(label));
  const info = concatBytes(
    I2OSP2(length),
    I2OSP1(full.length),
    full,
    I2OSP1(context.length),
    context,
  );
  return hkdfExpand(secret, info, length);
}

/** Raw HKDF-Expand (matches Go's `conf.KDF.Expand`). */
export function opaqueExpand(secret, info, length) {
  return hkdfExpand(secret, info, length);
}

/** DeriveSecret(secret, label) = Expand-Label(secret, label, "", Nh). */
export function opaqueDeriveSecret(
  secret,
  label,
  transcript = new Uint8Array(0),
) {
  return opaqueExpandLabel(secret, label, sha512(transcript), Nh);
}

// =============================================================================
// OPRF (RFC 9497)
// =============================================================================

/** HashToGroup with the ristretto255-SHA512 DST. */
export function opaqueHashToGroup(msg) {
  return ristretto255_hasher.hashToCurve(msg, { DST: DST_H2G });
}

/** RFC 9807 §2.1 DeriveKeyPair (Expand-Label based). */
export function opaqueDeriveKeyPair(seed, info) {
  for (let counter = 0; counter < 256; counter++) {
    const deriveInput = concatBytes(seed, I2OSP1(counter));
    const skBytes = opaqueExpandLabel(
      deriveInput,
      info,
      new Uint8Array(0),
      Nsk,
    );
    const sk = mod(bytesToNumberLE(skBytes), L);
    if (sk === 0n) continue;
    const pk = Pt.BASE.multiply(sk);
    return { sk, pk };
  }
  throw new Error("opaqueDeriveKeyPair: counter exhausted");
}

/** DeriveDiffieHellmanKeyPair(seed) — OPAQUE-specific label. */
export function opaqueDeriveDHKeyPair(seed) {
  return opaqueDeriveKeyPair(seed, TAG_DERIVE_DH);
}

/**
 * Client-side OPRF blind.
 * Returns { blind, blindedElement }.
 */
export function opaqueBlind(password, blindScalar) {
  const blind = blindScalar ?? rndScalar();
  const input = opaqueHashToGroup(password);
  const blinded = input.multiply(blind);
  return { blind, blinded };
}

/** Server-side OPRF evaluation: evaluated = oprfKey * blinded. */
export function opaqueBlindEvaluate(oprfKey, blindedElement) {
  return blindedElement.multiply(oprfKey);
}

/**
 * Client-side OPRF finalize.
 * Returns the 64-byte randomized password output.
 */
export function opaqueOPRFFinalize(password, blind, evaluatedElement) {
  const unblinded = evaluatedElement.multiply(modInverse(blind, L));
  const ub = ptBytes(unblinded);
  const hashInput = concatBytes(
    I2OSP2(password.length),
    password,
    I2OSP2(ub.length),
    ub,
    utf8ToBytes("Finalize"),
  );
  return sha512(hashInput);
}

// =============================================================================
// KSF (Key Stretching)
// =============================================================================

/** Default KSF: Argon2id. `params = { t, m, p }`. */
export function opaqueStretch(secret, salt, length, params) {
  return argon2id(secret, salt, {
    t: params?.t ?? 1,
    m: params?.m ?? 65536,
    p: params?.p ?? 4,
    dkLen: length,
  });
}

// =============================================================================
// Envelope
// =============================================================================

function createCleartextCredentials(serverPk, serverId, clientId) {
  return concatBytes(
    serverPk,
    I2OSP2(serverId.length),
    serverId,
    I2OSP2(clientId.length),
    clientId,
  );
}

/** Derive the auth key from the randomized password. */
export function opaqueDeriveAuthKey(prk) {
  return opaqueExpandLabel(prk, TAG_AUTH_KEY, new Uint8Array(0), Nh);
}

/**
 * Client-side envelope creation for registration.
 * Returns { clientSk, clientPkBytes, maskingKey, exportKey, envelope }.
 */
export function opaqueCreateEnvelope(
  prk,
  serverPk,
  clientIdIn,
  serverIdIn,
  nonce,
) {
  const maskingKey = opaqueExpandLabel(
    prk,
    TAG_MASKING_KEY,
    new Uint8Array(0),
    Nh,
  );
  const authKey = opaqueExpandLabel(prk, TAG_AUTH_KEY, new Uint8Array(0), Nh);
  const exportKey = opaqueExpandLabel(
    prk,
    TAG_EXPORT_KEY,
    new Uint8Array(0),
    Nh,
  );
  const seed = opaqueExpandLabel(
    prk,
    TAG_PRIVATE_KEY,
    new Uint8Array(0),
    Nseed,
  );

  const { sk: clientSk, pk: clientPk } = opaqueDeriveDHKeyPair(seed);
  const clientPkBytes = ptBytes(clientPk);

  const clientId = clientIdIn && clientIdIn.length ? clientIdIn : clientPkBytes;
  const serverId = serverIdIn && serverIdIn.length ? serverIdIn : serverPk;

  const cleartext = createCleartextCredentials(serverPk, serverId, clientId);
  const authTag = hmac(sha512, authKey, concatBytes(nonce, cleartext));

  return {
    clientSk,
    clientPkBytes,
    maskingKey,
    exportKey,
    envelope: concatBytes(nonce, authTag),
  };
}

/**
 * Client-side envelope recovery during login.
 * Throws if the auth tag doesn't verify.
 */
export function opaqueRecoverEnvelope(
  prk,
  serverPk,
  clientIdIn,
  serverIdIn,
  envelope,
) {
  if (envelope.length !== Nn + Nh) throw new Error("envelope: bad length");

  const nonce = envelope.slice(0, Nn);
  const authTag = envelope.slice(Nn);

  const maskingKey = opaqueExpandLabel(
    prk,
    TAG_MASKING_KEY,
    new Uint8Array(0),
    Nh,
  );
  const authKey = opaqueExpandLabel(prk, TAG_AUTH_KEY, new Uint8Array(0), Nh);
  const exportKey = opaqueExpandLabel(
    prk,
    TAG_EXPORT_KEY,
    new Uint8Array(0),
    Nh,
  );
  const seed = opaqueExpandLabel(
    prk,
    TAG_PRIVATE_KEY,
    new Uint8Array(0),
    Nseed,
  );

  const { sk: clientSk, pk: clientPk } = opaqueDeriveDHKeyPair(seed);
  const clientPkBytes = ptBytes(clientPk);

  const clientId = clientIdIn && clientIdIn.length ? clientIdIn : clientPkBytes;
  const serverId = serverIdIn && serverIdIn.length ? serverIdIn : serverPk;

  const cleartext = createCleartextCredentials(serverPk, serverId, clientId);
  const expectedTag = hmac(sha512, authKey, concatBytes(nonce, cleartext));

  if (!ctEq(expectedTag, authTag))
    throw new Error("envelope: auth tag mismatch");

  return { clientSk, clientPkBytes, maskingKey, exportKey };
}

// =============================================================================
// Masking (server public key + envelope)
// =============================================================================

/** Server side: mask `serverPk || envelope`. */
export function opaqueMask(maskingKey, maskingNonce, serverPk, envelope) {
  const len = serverPk.length + envelope.length;
  const info = concatBytes(maskingNonce, utf8ToBytes(TAG_CRED_PAD));
  const pad = hkdfExpand(maskingKey, info, len);
  const plain = concatBytes(serverPk, envelope);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = plain[i] ^ pad[i];
  return out;
}

/** Client side: unmask `maskedResponse`. */
export function opaqueUnmask(maskingKey, maskingNonce, maskedResponse) {
  const info = concatBytes(maskingNonce, utf8ToBytes(TAG_CRED_PAD));
  const pad = hkdfExpand(maskingKey, info, maskedResponse.length);
  const out = new Uint8Array(maskedResponse.length);
  for (let i = 0; i < maskedResponse.length; i++)
    out[i] = maskedResponse[i] ^ pad[i];
  return { serverPubKey: out.slice(0, Npk), envelope: out.slice(Npk) };
}

// =============================================================================
// AKE (OPAQUE-3DH)
// =============================================================================

/** Build the preamble for the server/client MACs. */
export function opaquePreamble(context, clientId, ke1, serverId, innerKe2) {
  return concatBytes(
    VERSION_TAG,
    I2OSP2(context.length),
    context,
    I2OSP2(clientId.length),
    clientId,
    ke1,
    I2OSP2(serverId.length),
    serverId,
    innerKe2,
  );
}

// =============================================================================
// Client state and flows
// =============================================================================

export function createClientState(config = {}) {
  return {
    context: config.context ?? new Uint8Array(0),
    ksfParams: config.ksfParams ?? { t: 1, m: 65536, p: 4 },
    ksfLength: config.ksfLength ?? Nh,
    ksfSalt: config.ksfSalt ?? null,
    kdfSalt: config.kdfSalt ?? new Uint8Array(0),

    password: null,
    blind: null,
    clientKeyshareSk: null,
    clientNonce: null,
    ke1: null,
    clientSk: null,
    clientPk: null,
    serverPubKey: null,
    exportKey: null,
    sessionKey: null,
  };
}

// --- Registration -----------------------------------------------------------

export function opaqueStartRegistration(state, password, options = {}) {
  if (state.blind) throw new Error("client already in registration");
  state.password = password;
  const { blind, blinded } = opaqueBlind(password, options.oprfBlind);
  state.blind = blind;
  return ptBytes(blinded);
}

export function opaqueFinishRegistration(
  state,
  responseBytes,
  clientIdentity,
  serverIdentity,
  options = {},
) {
  if (responseBytes.length !== SZ_REG_RESP)
    throw new Error("RegistrationResponse: bad length");

  const evaluatedBytes = responseBytes.slice(0, Npk);
  const serverPubKey = responseBytes.slice(Npk);

  const oprfOutput = opaqueOPRFFinalize(
    state.password,
    state.blind,
    ptFrom(evaluatedBytes),
  );
  const ksfSalt = options.ksfSalt ?? randomBytes(Nh);
  const ksfLen = options.ksfLength ?? state.ksfLength;
  const ksfParams = options.ksfParams ?? state.ksfParams;
  const stretched = opaqueStretch(oprfOutput, ksfSalt, ksfLen, ksfParams);
  const kdfSalt = options.kdfSalt ?? state.kdfSalt;
  const prk = hkdfExtractOnly(kdfSalt, concatBytes(oprfOutput, stretched));

  const envelopeNonce = options.envelopeNonce ?? randomBytes(Nn);
  const env = opaqueCreateEnvelope(
    prk,
    serverPubKey,
    clientIdentity,
    serverIdentity,
    envelopeNonce,
  );

  state.exportKey = env.exportKey;
  state.clientSk = env.clientSk;
  state.clientPk = env.clientPkBytes;
  state.serverPubKey = serverPubKey;

  const record = {
    clientPublicKey: env.clientPkBytes,
    maskingKey: env.maskingKey,
    envelope: env.envelope,
  };

  return { record, exportKey: env.exportKey, ksfSalt, envelopeNonce };
}

// --- Login ------------------------------------------------------------------

export function opaqueStartLogin(state, password, options = {}) {
  if (state.blind) throw new Error("client already in login");
  state.password = password;

  const { blind, blinded } = opaqueBlind(password, options.oprfBlind);
  state.blind = blind;

  const clientNonce = options.clientNonce ?? randomBytes(Nn);
  const clientKeyshareSk = options.clientKeyshareSk ?? rndScalar();
  state.clientKeyshareSk = clientKeyshareSk;
  state.clientNonce = clientNonce;

  const ke1 = concatBytes(
    ptBytes(blinded),
    clientNonce,
    ptBytes(Pt.BASE.multiply(clientKeyshareSk)),
  );
  state.ke1 = ke1;
  return ke1;
}

export async function opaqueFinishLogin({
  state,
  serverResponseMessage,
  clientIdentity,
  serverIdentity,
  context,
  options = {},
}) {
  if (serverResponseMessage.length !== SZ_KE2) {
    throw new Error(
      `KE2: invalid message length (expected ${SZ_KE2}, got ${serverResponseMessage.length})`,
    );
  }

  // 1. Unpack KE2 components
  const evaluatedBytes = serverResponseMessage.slice(0, Npk);
  const maskingNonce = serverResponseMessage.slice(Npk, Npk + Nn);
  const maskedResponse = serverResponseMessage.slice(
    Npk + Nn,
    Npk + Nn + (Npk + Nn + Nh),
  );
  const serverNonce = serverResponseMessage.slice(
    Npk + Nn + (Npk + Nn + Nh),
    Npk + Nn + (Npk + Nn + Nh) + Nn,
  );
  const serverKeysharePkBytes = serverResponseMessage.slice(
    Npk + Nn + (Npk + Nn + Nh) + Nn,
    Npk + Nn + (Npk + Nn + Nh) + Nn + Npk,
  );
  const serverMac = serverResponseMessage.slice(
    Npk + Nn + (Npk + Nn + Nh) + Nn + Npk,
  );

  // 2. OPRF Finalization & Password Stretching
  const oprfOutput = opaqueOPRFFinalize(
    state.password,
    state.blind,
    ptFrom(evaluatedBytes),
  );
  const ksfSalt = options.ksfSalt ?? state.ksfSalt;
  if (!ksfSalt || ksfSalt.length === 0) {
    throw new Error(
      "opaqueFinishLogin: no KSF salt available — the server must " +
        "return ksfSalt from /api/login/init and it must be passed " +
        "through options.ksfSalt or state.ksfSalt",
    );
  }
  const ksfLen = options.ksfLength ?? state.ksfLength;
  const ksfParams = options.ksfParams ?? state.ksfParams;
  const stretched = opaqueStretch(oprfOutput, ksfSalt, ksfLen, ksfParams);
  const kdfSalt = options.kdfSalt ?? state.kdfSalt;
  const prk = hkdfExtractOnly(kdfSalt, concatBytes(oprfOutput, stretched));

  // 3. Unmask Server Identity & Recover Envelope
  const maskingKey = opaqueExpandLabel(
    prk,
    TAG_MASKING_KEY,
    new Uint8Array(0),
    Nh,
  );
  const { serverPubKey, envelope } = opaqueUnmask(
    maskingKey,
    maskingNonce,
    maskedResponse,
  );

  state.serverPubKey = serverPubKey;

  const { clientSk, clientPkBytes, exportKey } = opaqueRecoverEnvelope(
    prk,
    serverPubKey,
    clientIdentity,
    serverIdentity,
    envelope,
  );

  state.clientSk = clientSk;
  state.clientPk = clientPkBytes;
  state.exportKey = exportKey;

  // 4. Resolve Effective Identities & Compute 3DH Shared Secret
  const effClientId =
    clientIdentity && clientIdentity.length ? clientIdentity : clientPkBytes;
  const effServerId =
    serverIdentity && serverIdentity.length ? serverIdentity : serverPubKey;
  const effContext = context ?? state.context ?? new Uint8Array(0);

  const dh1 = ptBytes(
    ptFrom(serverKeysharePkBytes).multiply(state.clientKeyshareSk),
  );
  const dh2 = ptBytes(ptFrom(serverPubKey).multiply(state.clientKeyshareSk)); // serverStatic × clientEph
  const dh3 = ptBytes(ptFrom(serverKeysharePkBytes).multiply(clientSk)); // serverEph × clientStatic
  const ikm = concatBytes(dh1, dh2, dh3);

  // 5. Derive Preamble, Handshake Secret & MACs
  const innerKe2 = serverResponseMessage.slice(
    0,
    Npk + Nn + (Npk + Nn + Nh) + Nn + Npk,
  );
  const preamble = opaquePreamble(
    effContext,
    effClientId,
    state.ke1,
    effServerId,
    innerKe2,
  );
  const preambleHash = sha512(preamble);

  const prkSession = hkdfExtractOnly(new Uint8Array(Nh), ikm);
  const handshakeSecret = opaqueDeriveSecret(
    prkSession,
    TAG_HANDSHAKE,
    preamble,
  );
  const sessionKey = opaqueDeriveSecret(prkSession, TAG_SESSION_KEY, preamble);
  const serverMacKey = opaqueExpandLabel(
    handshakeSecret,
    TAG_SERVER_MAC,
    new Uint8Array(0),
    Nh,
  );
  const clientMacKey = opaqueExpandLabel(
    handshakeSecret,
    TAG_CLIENT_MAC,
    new Uint8Array(0),
    Nh,
  );

  const expectedServerMac = hmac(sha512, serverMacKey, preambleHash);
  const transcript3 = sha512(concatBytes(preamble, expectedServerMac));
  const clientMac = hmac(sha512, clientMacKey, transcript3);

  // 6. Verify Server MAC
  if (!ctEq(expectedServerMac, serverMac)) {
    throw new Error("server MAC mismatch");
  }

  state.sessionKey = sessionKey;

  return {
    finishLoginRequest: clientMac,
    sessionKey,
    exportKey,
  };
}

export async function _opaqueFinishLoginCore(params) {
  return await opaqueFinishLogin(params);
}

// --- Modular inverse ---------------------------------------------------------
// @noble/curves v2 removed `mod.invert`. ristretto255's scalar field order L
// is prime, so we can invert with Fermat's little theorem: a^(L-2) mod L.
function modPow(base, exp, m) {
  let r = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) r = mod(r * base, m);
    exp >>= 1n;
    base = mod(base * base, m);
  }
  return r;
}

function modInverse(a, m = L) {
  return modPow(mod(a, m), m - 2n, m);
}

// =============================================================================
// Public API surface
// =============================================================================

export default {
  createClientState,
  opaqueStartRegistration,
  opaqueFinishRegistration,
  opaqueStartLogin,
  _opaqueFinishLoginCore,
  opaqueFinishLogin,
  hkdfExtractOnly,
  hkdfExpand,
  opaqueExpand,
  opaqueExpandLabel,
  opaqueDeriveSecret,
  opaqueHashToGroup,
  opaqueDeriveKeyPair,
  opaqueDeriveDHKeyPair,
  opaqueBlind,
  opaqueBlindEvaluate,
  opaqueOPRFFinalize,
  opaqueStretch,
  opaqueDeriveAuthKey,
  opaqueCreateEnvelope,
  opaqueRecoverEnvelope,
  opaqueMask,
  opaqueUnmask,
  opaquePreamble,
};
