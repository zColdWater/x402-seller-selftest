#!/usr/bin/env node
// x402-seller-selftest — zero-dependency security self-test for x402 SELLERS (the server that charges).
//
// It answers one question: "can someone get my paid content without actually paying me?"
//
//   passive (default)  read your 402 challenge and lint it (payTo checksum, asset, atomic amount,
//                      EIP-712 domain, timeout, resource binding, CORS)
//   --active           send unpaid route variants (method / trailing slash / case / %-encoding / double slash)
//                      and forged payments: malformed header, invalid signature, a correctly signed
//                      authorization from a fresh zero-balance key, and the legacy v1 header.
//                      Nothing is ever paid: the throwaway key has no funds.
//   --funded           TESTNET ONLY. Uses X402_TEST_KEY (your own funded test wallet) to check
//                      underpayment, client-chosen requirements, self-pay, replay, concurrent replay
//                      and cross-resource binding. Spends a few cents of TEST USDC.
//
// Run it ONLY against endpoints you own or are explicitly authorized to test.
// Node >= 18. No npm install. MIT License.

import { createHmac, randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const VERSION = '0.1.0';
export const HOMEPAGE = 'https://github.com/zColdWater/x402-seller-selftest';

// ============================================================ bytes

const te = new TextEncoder();

export function hexToBytes(hex) {
  let h = String(hex);
  if (h.startsWith('0x') || h.startsWith('0X')) h = h.slice(2);
  if (h.length % 2) h = '0' + h;
  if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b) {
  let s = '0x';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

function concat(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

function bytesToBig(b) {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  return n;
}

function bigToBytes32(n) {
  if (n < 0n || n >= 1n << 256n) throw new Error('uint256 out of range');
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}

// ============================================================ keccak-256 (Ethereum, not SHA3-256)

const MASK64 = (1n << 64n) - 1n;
const RC = [
  '0x0000000000000001', '0x0000000000008082', '0x800000000000808A', '0x8000000080008000',
  '0x000000000000808B', '0x0000000080000001', '0x8000000080008081', '0x8000000000008009',
  '0x000000000000008A', '0x0000000000000088', '0x0000000080008009', '0x000000008000000A',
  '0x000000008000808B', '0x800000000000008B', '0x8000000000008089', '0x8000000000008003',
  '0x8000000000008002', '0x8000000000000080', '0x000000000000800A', '0x800000008000000A',
  '0x8000000080008081', '0x8000000000008080', '0x0000000080000001', '0x8000000080008008',
].map((h) => BigInt(h));
// rotation offsets, index x + 5*y
const ROTC = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14].map(BigInt);

function rotl(v, n) { return n === 0n ? v : ((v << n) | (v >> (64n - n))) & MASK64; }

function keccakF(A) {
  const C = new Array(5);
  const B = new Array(25);
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (let x = 0; x < 5; x++) {
      const D = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1n);
      for (let y = 0; y < 25; y += 5) A[y + x] ^= D;
    }
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], ROTC[x + 5 * y]);
    for (let y = 0; y < 25; y += 5) for (let x = 0; x < 5; x++) A[y + x] = B[y + x] ^ ((~B[y + ((x + 1) % 5)] & MASK64) & B[y + ((x + 2) % 5)]);
    A[0] ^= RC[round];
  }
}

export function keccak256(input) {
  const data = typeof input === 'string' ? te.encode(input) : input;
  const rate = 136;
  const padLen = rate - (data.length % rate);
  const msg = new Uint8Array(data.length + padLen);
  msg.set(data);
  msg[data.length] ^= 0x01;
  msg[msg.length - 1] ^= 0x80;
  const A = new Array(25).fill(0n);
  for (let off = 0; off < msg.length; off += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(msg[off + i * 8 + b]);
      A[i] ^= lane;
    }
    keccakF(A);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let lane = A[i];
    for (let b = 0; b < 8; b++) { out[i * 8 + b] = Number(lane & 0xffn); lane >>= 8n; }
  }
  return out;
}

// ============================================================ addresses (EIP-55)

export function toChecksumAddress(addr) {
  const a = String(addr).toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(a)) throw new Error('not a 20-byte hex address');
  const h = bytesToHex(keccak256(a)).slice(2);
  let out = '0x';
  for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}

/** @returns {{ valid: boolean, checksum: 'ok'|'bad'|'none', zero: boolean }} */
export function inspectAddress(addr) {
  if (typeof addr !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(addr)) return { valid: false, checksum: 'none', zero: false };
  const body = addr.slice(2);
  const zero = /^0{40}$/.test(body);
  if (body === body.toLowerCase() || body === body.toUpperCase()) return { valid: true, checksum: 'none', zero };
  return { valid: true, checksum: toChecksumAddress(addr) === addr ? 'ok' : 'bad', zero };
}

const sameAddr = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

// ============================================================ secp256k1 (sign with RFC 6979, recover)

const P = (1n << 256n) - (1n << 32n) - 977n;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G = [
  0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
  0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
];

const mod = (a, m) => { const r = a % m; return r >= 0n ? r : r + m; };

function inv(a, m) {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error('not invertible');
  return mod(s0, m);
}

function modPow(b, e, m) {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}

function pointAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  const [x1, y1] = p1;
  const [x2, y2] = p2;
  let l;
  if (x1 === x2) {
    if (mod(y1 + y2, P) === 0n) return null;
    l = mod(3n * x1 * x1 * inv(2n * y1, P), P);
  } else {
    l = mod((y2 - y1) * inv(x2 - x1, P), P);
  }
  const x3 = mod(l * l - x1 - x2, P);
  return [x3, mod(l * (x1 - x3) - y1, P)];
}

function pointMul(k, pt) {
  let r = null;
  let a = pt;
  while (k > 0n) { if (k & 1n) r = pointAdd(r, a); a = pointAdd(a, a); k >>= 1n; }
  return r;
}

function pubToAddress([x, y]) {
  return toChecksumAddress(bytesToHex(keccak256(concat(bigToBytes32(x), bigToBytes32(y))).slice(12)));
}

export function publicKeyOf(priv) { return pointMul(priv, G); }
export function privToAddress(priv) { return pubToAddress(publicKeyOf(priv)); }

export function parsePrivateKey(hex) {
  const d = bytesToBig(hexToBytes(hex));
  if (d <= 0n || d >= N) throw new Error('private key out of range');
  return d;
}

export function randomPrivateKey(rand = randomBytes) {
  for (;;) { const d = bytesToBig(rand(32)); if (d > 0n && d < N) return d; }
}

function hmac(key, ...parts) {
  const h = createHmac('sha256', key);
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

/** Deterministic ECDSA (RFC 6979, HMAC-SHA256), low-s, Ethereum v = 27 + recid. */
export function signDigest(digest, priv) {
  const z = bytesToBig(digest);
  const x = bigToBytes32(priv);
  const h1 = bigToBytes32(mod(z, N));
  let V = new Uint8Array(32).fill(1);
  let K = new Uint8Array(32).fill(0);
  K = hmac(K, V, Uint8Array.of(0), x, h1); V = hmac(K, V);
  K = hmac(K, V, Uint8Array.of(1), x, h1); V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);
    const k = bytesToBig(V);
    if (k >= 1n && k < N) {
      const R = pointMul(k, G);
      const r = mod(R[0], N);
      if (r !== 0n) {
        let s = mod(inv(k, N) * (z + r * priv), N);
        if (s !== 0n) {
          let recid = (R[1] & 1n ? 1 : 0) | (R[0] >= N ? 2 : 0);
          if (s > N / 2n) { s = N - s; recid ^= 1; }
          return { r, s, v: 27 + recid };
        }
      }
    }
    K = hmac(K, V, Uint8Array.of(0)); V = hmac(K, V);
  }
}

export function sigToHex({ r, s, v }) { return bytesToHex(concat(bigToBytes32(r), bigToBytes32(s), Uint8Array.of(v))); }

export function hexToSig(hex) {
  const b = hexToBytes(hex);
  if (b.length !== 65) throw new Error('signature must be 65 bytes');
  return { r: bytesToBig(b.slice(0, 32)), s: bytesToBig(b.slice(32, 64)), v: b[64] };
}

export function recoverAddress(digest, sig) {
  const { r, s, v } = typeof sig === 'string' ? hexToSig(sig) : sig;
  const recid = v >= 27 ? v - 27 : v;
  if (recid < 0 || recid > 3) throw new Error('bad v');
  if (r <= 0n || r >= N || s <= 0n || s >= N) throw new Error('bad r/s');
  const x = r + (recid & 2 ? N : 0n);
  if (x >= P) throw new Error('bad r');
  const y2 = mod(x * x * x + 7n, P);
  let y = modPow(y2, (P + 1n) / 4n, P);
  if (mod(y * y, P) !== y2) throw new Error('r is not on the curve');
  if (Number(y & 1n) !== (recid & 1)) y = P - y;
  const rinv = inv(r, N);
  const Q = pointAdd(pointMul(mod(s * rinv, N), [x, y]), pointMul(mod(-bytesToBig(digest) * rinv, N), G));
  if (Q === null) throw new Error('point at infinity');
  return pubToAddress(Q);
}

// ============================================================ EIP-712

function findDeps(t, types, found = new Set()) {
  const base = t.replace(/\[\d*\]$/, '');
  if (found.has(base) || !types[base]) return found;
  found.add(base);
  for (const f of types[base]) findDeps(f.type, types, found);
  return found;
}

export function encodeType(primary, types) {
  const deps = [...findDeps(primary, types)].filter((t) => t !== primary).sort();
  return [primary, ...deps].map((t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(',')})`).join('');
}

function encodeValue(type, value, types) {
  if (types[type]) return hashStruct(type, value, types);
  if (type === 'string') return keccak256(te.encode(String(value)));
  if (type === 'bytes') return keccak256(hexToBytes(value));
  if (type === 'address') return bigToBytes32(BigInt(value));
  if (type === 'bool') return bigToBytes32(value ? 1n : 0n);
  if (/^uint\d*$/.test(type)) return bigToBytes32(BigInt(value));
  if (/^int\d*$/.test(type)) return bigToBytes32(mod(BigInt(value), 1n << 256n));
  const m = /^bytes(\d+)$/.exec(type);
  if (m) { const b = hexToBytes(value); if (b.length !== Number(m[1])) throw new Error(`${type} length`); const out = new Uint8Array(32); out.set(b); return out; }
  throw new Error(`unsupported EIP-712 type ${type}`);
}

export function hashStruct(t, data, types) {
  return keccak256(concat(keccak256(encodeType(t, types)), ...types[t].map((f) => encodeValue(f.type, data[f.name], types))));
}

const DOMAIN_FIELDS = [['name', 'string'], ['version', 'string'], ['chainId', 'uint256'], ['verifyingContract', 'address'], ['salt', 'bytes32']];

export function eip712Digest({ domain, types, primaryType, message }) {
  const EIP712Domain = DOMAIN_FIELDS.filter(([k]) => domain[k] !== undefined).map(([name, type]) => ({ name, type }));
  const all = { ...types, EIP712Domain };
  return keccak256(concat(Uint8Array.of(0x19, 0x01), hashStruct('EIP712Domain', domain, all), hashStruct(primaryType, message, all)));
}

export const TWA_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
  ],
};

/** EIP-3009 transferWithAuthorization digest, as USDC (FiatTokenV2) computes it. */
export function twaDigest({ chainId, asset, name, version, auth }) {
  return eip712Digest({
    domain: { name, version, chainId, verifyingContract: asset },
    types: TWA_TYPES,
    primaryType: 'TransferWithAuthorization',
    message: auth,
  });
}

// ============================================================ x402 knowledge

const V1_NETWORKS = {
  base: 8453, 'base-sepolia': 84532, ethereum: 1, mainnet: 1, polygon: 137, 'polygon-amoy': 80002,
  arbitrum: 42161, 'arbitrum-sepolia': 421614, optimism: 10, avalanche: 43114, 'avalanche-fuji': 43113,
};
const V1_NAME_BY_CHAIN = { 8453: 'base', 84532: 'base-sepolia', 1: 'ethereum', 137: 'polygon', 80002: 'polygon-amoy', 42161: 'arbitrum', 421614: 'arbitrum-sepolia', 10: 'optimism', 43114: 'avalanche', 43113: 'avalanche-fuji' };
export const TESTNET_CHAINS = new Set([84532, 80002, 421614, 43113, 11155111, 11155420]);

// Canonical (native) USDC. The EIP-712 domain is only asserted where it is widely relied on by x402 SDKs.
export const KNOWN_USDC = {
  8453: { address: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', eip712: { name: 'USD Coin', version: '2' } },
  84532: { address: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', eip712: { name: 'USDC', version: '2' } },
  1: { address: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48' },
  137: { address: '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359' },
  42161: { address: '0xaf88d065e77c8cC2239327C5EDb3A432268e5831' },
  10: { address: '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85' },
  43114: { address: '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E' },
};

export function b64encodeJSON(obj) { return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64'); }
export function b64decodeJSON(str) {
  const s = String(str).trim();
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) throw new Error('not base64');
  return JSON.parse(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
}

export function parseChallenge(res) {
  const out = { version: null, source: null, raw: null, error: null };
  const hdr = res.headers.get('payment-required');
  if (hdr) {
    try { out.raw = b64decodeJSON(hdr); out.source = 'header'; } catch { out.error = 'PAYMENT-REQUIRED header is present but is not base64-encoded JSON'; }
  }
  if (!out.raw) {
    try {
      const j = JSON.parse(res.bodyText);
      if (j && typeof j === 'object' && Array.isArray(j.accepts)) { out.raw = j; out.source = 'body'; }
    } catch { /* not JSON */ }
  }
  if (out.raw) out.version = out.raw.x402Version;
  return out;
}

export function normalizeOption(o, pr, index) {
  const network = o && o.network;
  let chainId = null;
  if (typeof network === 'string') {
    const m = /^eip155:(\d+)$/.exec(network);
    if (m) chainId = Number(m[1]);
    else if (Object.prototype.hasOwnProperty.call(V1_NETWORKS, network)) chainId = V1_NETWORKS[network];
  }
  const amount = o && (o.amount !== undefined ? o.amount : o.maxAmountRequired);
  const resource = pr.x402Version === 2 ? pr.resource && pr.resource.url : o && o.resource;
  return {
    index, raw: o, scheme: o && o.scheme, network, chainId, amount, asset: o && o.asset, payTo: o && o.payTo,
    maxTimeoutSeconds: o && o.maxTimeoutSeconds, extra: (o && o.extra) || {}, resource,
  };
}

function eip712DomainFor(opt) {
  const known = KNOWN_USDC[opt.chainId];
  const name = opt.extra.name ?? (known && sameAddr(known.address, opt.asset) && known.eip712 ? known.eip712.name : undefined);
  const version = opt.extra.version ?? (known && sameAddr(known.address, opt.asset) && known.eip712 ? known.eip712.version : undefined);
  return name !== undefined && version !== undefined ? { name: String(name), version: String(version) } : null;
}

function formatAmount(opt) {
  const known = KNOWN_USDC[opt.chainId];
  if (!known || !sameAddr(known.address, opt.asset) || !/^\d+$/.test(String(opt.amount))) return `${opt.amount} atomic units`;
  const v = Number(opt.amount) / 1e6;
  return `${opt.amount} atomic USDC (= $${v})`;
}

// ============================================================ runner

const LEVELS = ['pass', 'info', 'warn', 'fail', 'skip'];

function makeCtx(opts) {
  return {
    url: opts.url,
    method: (opts.method || 'GET').toUpperCase(),
    headers: opts.headers || {},
    body: opts.body,
    marker: opts.marker || null,
    timeout: opts.timeout || 15000,
    fetch: opts.fetch || globalThis.fetch,
    now: opts.now || (() => Math.floor(Date.now() / 1000)),
    random: opts.random || randomBytes,
    requests: 0,
    spent: 0n,
  };
}

async function send(ctx, { url = ctx.url, method = ctx.method, headers = {}, body = ctx.body } = {}) {
  ctx.requests++;
  const init = { method, headers: { ...ctx.headers, ...headers }, redirect: 'manual' };
  if (body !== undefined && method !== 'GET' && method !== 'HEAD') init.body = body;
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ctx.timeout);
  init.signal = ac.signal;
  try {
    const res = await ctx.fetch(url, init);
    const bodyText = method === 'HEAD' ? '' : await res.text();
    return { status: res.status, headers: res.headers, bodyText };
  } catch (e) {
    return { status: 0, headers: new Headers(), bodyText: '', error: e && e.name === 'AbortError' ? 'timeout' : String((e && e.message) || e) };
  } finally {
    clearTimeout(timer);
  }
}

const is2xx = (res) => res.status >= 200 && res.status < 300;
const hasMarker = (ctx, res) => !!ctx.marker && res.bodyText.includes(ctx.marker);

/** Shared verdict for "this request must NOT get the paid content". */
function judgeRejected(ctx, add, res, id, title, why) {
  if (res.status === 0) return add(id, 'warn', title, `request failed (${res.error}); could not evaluate`);
  if (is2xx(res)) {
    if (ctx.marker && !hasMarker(ctx, res)) return add(id, 'warn', title, `HTTP ${res.status} but the marker is not in the body. Confirm by hand that no paid content was served.`);
    return add(id, 'fail', title, `HTTP ${res.status}: the paid response was served. ${why}${ctx.marker ? '' : ' (No --marker given: if this 2xx is not the paid content, re-run with --marker.)'}`);
  }
  if (hasMarker(ctx, res)) return add(id, 'fail', title, `HTTP ${res.status}, but the body contains the paid-content marker: content leaks through the error response.`);
  if (res.headers.get('payment-response') || res.headers.get('x-payment-response')) {
    return add(id, 'warn', title, `HTTP ${res.status} (not delivered), but a settlement response header was sent. Check whether money moved.`);
  }
  if (res.status === 402 || res.status === 400) return add(id, 'pass', title, `HTTP ${res.status}, not delivered`);
  if (res.status === 502 || res.status === 503 || res.status === 504) return add(id, 'info', title, `HTTP ${res.status}, not delivered. Fine if your facilitator was unreachable; otherwise a forged payment should get 402.`);
  if (res.status >= 500) return add(id, 'warn', title, `HTTP ${res.status}: not delivered, but the x402 HTTP transport uses 400 (malformed) / 402 (verification or settlement failed). A 500 often hides an unhandled exception on a crafted header.`);
  if (res.status >= 300 && res.status < 400) return add(id, 'info', title, `HTTP ${res.status} redirect to ${res.headers.get('location') || '?'} (not followed). Make sure the target is paywalled too.`);
  return add(id, 'pass', title, `HTTP ${res.status}, not delivered`);
}

export function urlVariants(u) {
  const url = new URL(u);
  const path = url.pathname;
  const out = [];
  if (path && path !== '/') {
    out.push(['trailing-slash', path.endsWith('/') ? path.slice(0, -1) : `${path}/`]);
    const upper = path.toUpperCase();
    if (upper !== path) out.push(['uppercase', upper]);
    const segs = path.split('/');
    let i = segs.length - 1;
    if (segs[i] === '' && i > 0) i--;
    const m = /[A-Za-z]/.exec(segs[i]);
    if (m) {
      segs[i] = `${segs[i].slice(0, m.index)}%${segs[i].charCodeAt(m.index).toString(16).toUpperCase()}${segs[i].slice(m.index + 1)}`;
      out.push(['percent-encoded', segs.join('/')]);
    }
    out.push(['double-slash', `/${path}`]);
  }
  return out.map(([name, p]) => { const v = new URL(url.toString()); v.pathname = p; return [name, v.toString()]; });
}

function pickOption(options) {
  const usable = options.filter((o) => o.scheme === 'exact' && o.chainId !== null && inspectAddress(o.payTo).valid
    && inspectAddress(o.asset).valid && /^\d+$/.test(String(o.amount)) && BigInt(o.amount) > 0n);
  return usable.find((o) => eip712DomainFor(o)) || usable[0] || null;
}

function paymentHeader(pr, opt, auth, signature, { acceptedOverride, forceV1 } = {}) {
  if (pr.x402Version === 2 && !forceV1) {
    const p = { x402Version: 2, accepted: acceptedOverride || opt.raw, payload: { signature, authorization: auth } };
    if (pr.resource) p.resource = pr.resource;
    return { 'PAYMENT-SIGNATURE': b64encodeJSON(p) };
  }
  const network = pr.x402Version === 2 ? V1_NAME_BY_CHAIN[opt.chainId] || opt.network : opt.network;
  return { 'X-PAYMENT': b64encodeJSON({ x402Version: 1, scheme: 'exact', network, payload: { signature, authorization: auth } }) };
}

function makeAuth(ctx, opt, from, overrides = {}) {
  const now = ctx.now();
  const window = Math.min(Math.max(Number(opt.maxTimeoutSeconds) || 300, 60), 3600);
  return {
    from, to: opt.payTo, value: String(opt.amount), validAfter: String(now - 600), validBefore: String(now + window),
    nonce: bytesToHex(ctx.random(32)), ...overrides,
  };
}

function signAuth(opt, domain, priv, auth) {
  return sigToHex(signDigest(twaDigest({ chainId: opt.chainId, asset: opt.asset, name: domain.name, version: domain.version, auth }), priv));
}

function lintChallenge(ctx, add, res, pr, ch) {
  const v = pr.x402Version;
  if (v === 2) add('lint.version', 'pass', 'x402 version', 'x402Version 2');
  else if (v === 1) add('lint.version', 'info', 'x402 version', 'x402Version 1 (legacy body format). v2 clients read the PAYMENT-REQUIRED header.');
  else add('lint.version', 'warn', 'x402 version', `unexpected x402Version ${JSON.stringify(v)}`);
  if (v === 2 && ch.source !== 'header') add('lint.header', 'warn', 'PAYMENT-REQUIRED header', 'v2 object found only in the body; v2 clients expect the base64 PAYMENT-REQUIRED header.');
  if (ch.source === 'header') {
    const expose = (res.headers.get('access-control-expose-headers') || '').toLowerCase();
    if (!expose.includes('payment-required') && !expose.includes('*')) add('lint.cors', 'info', 'CORS', 'Access-Control-Expose-Headers does not list PAYMENT-REQUIRED: browser-based clients cannot read the challenge (fine for server-to-server only).');
  }
  if (v === 2) {
    const ru = pr.resource && pr.resource.url;
    if (!ru) add('lint.resource', 'warn', 'resource binding', 'resource.url missing: the challenge does not say which resource the payment is for.');
    else checkResourceUrl(ctx, add, ru);
  }
  const options = (pr.accepts || []).map((o, i) => normalizeOption(o, pr, i));
  if (!options.length) { add('lint.accepts', 'fail', 'accepts[]', 'no payment options in accepts[]'); return options; }
  for (const o of options) {
    const tag = `option #${o.index} (${o.scheme} on ${o.network})`;
    if (o.scheme !== 'exact') { add(`lint.opt${o.index}`, 'info', tag, 'not the "exact" scheme; not checked'); continue; }
    if (o.chainId === null) { add(`lint.opt${o.index}`, 'info', tag, 'non-EVM or unknown network; not checked'); continue; }
    const problems = [];
    const notes = [];
    const pt = inspectAddress(o.payTo);
    if (!pt.valid) problems.push(['fail', `payTo ${JSON.stringify(o.payTo)} is not a 20-byte address`]);
    else if (pt.zero) problems.push(['fail', 'payTo is the zero address: payments would be burned']);
    else if (pt.checksum === 'bad') problems.push(['fail', `payTo ${o.payTo} has a wrong EIP-55 checksum (typo?). Expected ${toChecksumAddress(o.payTo)}`]);
    else if (pt.checksum === 'none') notes.push('payTo is not checksummed (all one case); a typo would go unnoticed');
    const known = KNOWN_USDC[o.chainId];
    if (!inspectAddress(o.asset).valid) problems.push(['fail', `asset ${JSON.stringify(o.asset)} is not a token address`]);
    else if (!known) notes.push(`no canonical-USDC reference for chain ${o.chainId}; asset not verified`);
    else if (!sameAddr(known.address, o.asset)) problems.push(['warn', `asset ${o.asset} is not canonical USDC on chain ${o.chainId} (${known.address}). Make sure this is the token you mean.`]);
    const amt = String(o.amount);
    if (o.amount === undefined) problems.push(['fail', 'amount / maxAmountRequired missing']);
    else if (!/^\d+$/.test(amt)) problems.push(['fail', `amount ${JSON.stringify(o.amount)} is not an integer string in atomic units (USDC has 6 decimals: $0.01 = "10000")`]);
    else if (BigInt(amt) === 0n) problems.push(['fail', 'amount is 0']);
    else if (known && sameAddr(known.address, o.asset) && BigInt(amt) > 1_000_000_000n) problems.push(['warn', `amount ${amt} = $${Number(amt) / 1e6}: is that intended?`]);
    if (known && known.eip712 && sameAddr(known.address, o.asset)) {
      const n = o.extra.name;
      const ver = o.extra.version;
      if (n === undefined || ver === undefined) problems.push(['warn', `extra.name / extra.version missing; clients must guess the EIP-712 domain (expected "${known.eip712.name}" / "${known.eip712.version}")`]);
      else if (n !== known.eip712.name || String(ver) !== known.eip712.version) problems.push(['fail', `extra.name/version = "${n}"/"${ver}" but this token's EIP-712 domain is "${known.eip712.name}"/"${known.eip712.version}": every client signature will be rejected`]);
    }
    const t = o.maxTimeoutSeconds;
    if (t === undefined) problems.push(['warn', 'maxTimeoutSeconds missing']);
    else if (!(Number(t) > 0)) problems.push(['warn', `maxTimeoutSeconds ${JSON.stringify(t)} is not a positive number`]);
    else if (Number(t) > 3600) notes.push(`maxTimeoutSeconds ${t}: signed authorizations stay valid for over an hour`);
    if (v === 1) {
      if (!o.resource) problems.push(['warn', 'resource missing in the requirement: payment is not bound to a resource']);
      else checkResourceUrl(ctx, add, o.resource, `lint.opt${o.index}.resource`);
    }
    const worst = problems.some((p) => p[0] === 'fail') ? 'fail' : problems.length ? 'warn' : 'pass';
    const detail = [...problems.map((p) => p[1]), ...notes].join('; ') || `pays ${formatAmount(o)} to ${o.payTo}`;
    add(`lint.opt${o.index}`, worst, tag, detail);
  }
  return options;
}

function checkResourceUrl(ctx, add, ru, id = 'lint.resource') {
  let a;
  let b;
  try { a = new URL(ru); b = new URL(ctx.url); } catch { return add(id, 'warn', 'resource binding', `resource ${JSON.stringify(ru)} is not an absolute URL`); }
  if (a.host !== b.host || a.pathname.replace(/\/+$/, '') !== b.pathname.replace(/\/+$/, '')) {
    return add(id, 'warn', 'resource binding', `challenge names resource ${ru}, but you requested ${ctx.url}. If the server does not check the resource on payment, a payment for one route may unlock another.`);
  }
  return add(id, 'pass', 'resource binding', `challenge is bound to ${ru}`);
}

export async function runSelfTest(opts) {
  const ctx = makeCtx(opts);
  const results = [];
  const add = (id, level, title, detail) => { results.push({ id, level, title, detail }); };
  const finish = (extra = {}) => {
    const summary = Object.fromEntries(LEVELS.map((l) => [l, results.filter((r) => r.level === l).length]));
    return { tool: 'x402-seller-selftest', version: VERSION, url: ctx.url, method: ctx.method, results, summary, requests: ctx.requests, testUsdcSpentAtomic: String(ctx.spent), ...extra };
  };

  // ---------------------------------------------------------- 1. baseline
  const base = await send(ctx);
  if (base.status === 0) { add('baseline', 'fail', 'Unpaid request', `request failed: ${base.error}`); return finish(); }
  if (is2xx(base)) {
    if (ctx.marker && !hasMarker(ctx, base)) add('baseline', 'warn', 'Unpaid request', `HTTP ${base.status} without payment, marker not present. Is this route actually paywalled?`);
    else add('baseline', 'fail', 'Unpaid request', `HTTP ${base.status} without any payment: the route is not paywalled.`);
    return finish();
  }
  if (base.status !== 402) {
    add('baseline', 'fail', 'Unpaid request', `expected HTTP 402, got ${base.status}. Check the URL/method (-X) or headers (-H).`);
    return finish();
  }
  if (hasMarker(ctx, base)) add('baseline.leak', 'fail', 'Unpaid request', 'the 402 body contains the paid-content marker');
  add('baseline', 'pass', 'Unpaid request', 'HTTP 402');

  const ch = parseChallenge(base);
  if (!ch.raw) { add('challenge', 'fail', 'Payment challenge', ch.error || 'HTTP 402 but no x402 PaymentRequired (no PAYMENT-REQUIRED header, no JSON body with accepts[])'); return finish(); }
  add('challenge', 'pass', 'Payment challenge', `x402 v${ch.version} challenge from ${ch.source === 'header' ? 'PAYMENT-REQUIRED header' : 'response body'}`);
  const pr = ch.raw;

  // ---------------------------------------------------------- 2. lint
  const options = lintChallenge(ctx, add, base, pr, ch);
  const opt = pickOption(options);

  if (!opts.active) {
    add('active', 'skip', 'Active checks', 'not run. Add --active --i-own-this to probe route variants and forged payments (no money moves).');
    return finish({ option: opt && opt.index });
  }

  // ---------------------------------------------------------- 3. unpaid route variants
  const altMethods = ctx.method === 'GET' ? ['POST', 'HEAD'] : ctx.method === 'POST' ? ['GET', 'HEAD'] : ['GET', 'POST'];
  for (const m of altMethods) {
    const r = await send(ctx, { method: m });
    if (m === 'HEAD') {
      if (is2xx(r)) add('variant.method.HEAD', 'info', 'Unpaid HEAD', `HTTP ${r.status}. No body is returned, but check that the paid handler does not run (cost, side effects) on HEAD.`);
      else add('variant.method.HEAD', 'pass', 'Unpaid HEAD', `HTTP ${r.status}`);
      continue;
    }
    if (r.status === 404 || r.status === 405) { add(`variant.method.${m}`, 'pass', `Unpaid ${m}`, `HTTP ${r.status}`); continue; }
    judgeRejected(ctx, add, r, `variant.method.${m}`, `Unpaid ${m}`, 'The paywall only covers one HTTP method but the handler answers others.');
  }
  for (const [name, vurl] of urlVariants(ctx.url)) {
    const r = await send(ctx, { url: vurl });
    if (r.status === 404 || r.status === 405) { add(`variant.path.${name}`, 'pass', `Unpaid ${name} path`, `HTTP ${r.status} for ${new URL(vurl).pathname}`); continue; }
    judgeRejected(ctx, add, r, `variant.path.${name}`, `Unpaid ${name} path`, `The paywall's route matcher and the router disagree on ${new URL(vurl).pathname}.`);
  }

  // ---------------------------------------------------------- 4. forged payments (no funds)
  if (!opt) {
    add('forge', 'skip', 'Forged payments', 'no usable EVM "exact" option in the challenge (needs a valid payTo, asset and integer amount)');
    return finish();
  }
  const hdrName = pr.x402Version === 2 ? 'PAYMENT-SIGNATURE' : 'X-PAYMENT';
  {
    const r = await send(ctx, { headers: { [hdrName]: '%%not-base64%%' } });
    judgeRejected(ctx, add, r, 'forge.malformed', `Malformed ${hdrName}`, 'Garbage in the payment header unlocked the content.');
  }
  {
    const r = await send(ctx, { headers: { [hdrName]: b64encodeJSON({ x402Version: pr.x402Version }) } });
    judgeRejected(ctx, add, r, 'forge.empty', 'Empty payment payload', 'A payload with no signature/authorization unlocked the content.');
  }
  const throwaway = randomPrivateKey(ctx.random);
  const throwawayAddr = privToAddress(throwaway);
  {
    const auth = makeAuth(ctx, opt, throwawayAddr);
    const sig = bytesToHex(ctx.random(65));
    const r = await send(ctx, { headers: paymentHeader(pr, opt, auth, sig) });
    judgeRejected(ctx, add, r, 'forge.bad-signature', 'Invalid signature', 'The server does not verify the signature (no facilitator /verify, or its result is ignored). Anyone can read for free.');
  }
  const domain = eip712DomainFor(opt);
  if (!domain) {
    add('forge.unfunded', 'skip', 'Unfunded signed payment', 'cannot build an EIP-3009 signature: extra.name/version missing and asset not recognized');
  } else {
    const auth = makeAuth(ctx, opt, throwawayAddr);
    const r = await send(ctx, { headers: paymentHeader(pr, opt, auth, signAuth(opt, domain, throwaway, auth)) });
    judgeRejected(ctx, add, r, 'forge.unfunded', 'Valid signature, zero balance', `A correctly signed authorization from a wallet with no funds (${throwawayAddr}) unlocked the content: the server delivers when verify/settle fails or errors (fail-open).`);
    if (pr.x402Version === 2) {
      const auth1 = makeAuth(ctx, opt, throwawayAddr);
      const r1 = await send(ctx, { headers: paymentHeader(pr, opt, auth1, signAuth(opt, domain, throwaway, auth1), { forceV1: true }) });
      judgeRejected(ctx, add, r1, 'forge.legacy-v1', 'Legacy X-PAYMENT (v1) path', 'The v1 (X-PAYMENT) path delivered for an authorization that cannot settle. Fix it, or stop accepting v1.');
    }
  }

  // ---------------------------------------------------------- 5. funded (testnet only)
  if (!opts.funded) {
    add('funded', 'skip', 'Funded checks', 'not run. On a TESTNET deployment, add --funded with X402_TEST_KEY to test underpayment, client-chosen payTo/amount, replay and binding.');
    return finish({ option: opt.index });
  }
  if (!TESTNET_CHAINS.has(opt.chainId)) {
    add('funded', 'skip', 'Funded checks', `refused: option #${opt.index} is on chain ${opt.chainId}, which is not a testnet. Funded checks never spend mainnet money.`);
    return finish({ option: opt.index });
  }
  if (!domain) { add('funded', 'skip', 'Funded checks', 'cannot sign: EIP-712 domain unknown'); return finish({ option: opt.index }); }
  let payer;
  try { payer = parsePrivateKey(opts.testKey || ''); } catch (e) { add('funded', 'skip', 'Funded checks', `X402_TEST_KEY missing or invalid (${e.message})`); return finish({ option: opt.index }); }
  const payerAddr = privToAddress(payer);
  const price = BigInt(opt.amount);
  const pay = async (auth, sendOpts = {}, extraHeaderOpts = {}) => {
    const r = await send(ctx, { ...sendOpts, headers: paymentHeader(pr, opt, auth, signAuth(opt, domain, payer, auth), extraHeaderOpts) });
    if (is2xx(r)) ctx.spent += BigInt(auth.value) * (sameAddr(auth.to, payerAddr) ? 0n : 1n);
    return r;
  };

  // F1: a correct payment must work (otherwise the deeper results mean nothing)
  const goodAuth = makeAuth(ctx, opt, payerAddr);
  const goodHeaders = paymentHeader(pr, opt, goodAuth, signAuth(opt, domain, payer, goodAuth));
  const good = await send(ctx, { headers: goodHeaders });
  if (!is2xx(good) || (ctx.marker && !hasMarker(ctx, good))) {
    add('funded.correct', 'warn', 'Correct payment', `a correct payment from ${payerAddr} got HTTP ${good.status}${is2xx(good) ? ' without the marker' : ''}. Is the test wallet funded with test USDC on chain ${opt.chainId}? Deeper checks skipped.`);
    return finish({ option: opt.index, payer: payerAddr });
  }
  ctx.spent += price;
  add('funded.correct', 'pass', 'Correct payment', `HTTP ${good.status}, paid ${formatAmount(opt)} from ${payerAddr}`);

  // F2: replay the exact same header
  {
    const r = await send(ctx, { headers: goodHeaders });
    judgeRejected(ctx, add, r, 'funded.replay', 'Replay of a settled payment', 'The same signed authorization was accepted twice: the server delivers without a successful settlement (or verify-only).');
  }
  // F3: underpayment, requirement left untouched
  if (price > 1n) {
    const r = await pay(makeAuth(ctx, opt, payerAddr, { value: String(price - 1n) }));
    judgeRejected(ctx, add, r, 'funded.underpay', 'Underpayment (price - 1)', 'authorization.value is not compared with the price.');
  }
  // F4: client-chosen requirements (v2 `accepted` rewritten to amount 1)
  if (pr.x402Version === 2) {
    const accepted = { ...opt.raw, amount: '1' };
    const r = await pay(makeAuth(ctx, opt, payerAddr, { value: '1' }), {}, { acceptedOverride: accepted });
    judgeRejected(ctx, add, r, 'funded.client-requirements', 'Client-chosen amount', 'The server verifies/settles against the requirements the CLIENT sent (accepted), not its own. Paying 1 atomic unit unlocked the content.');
  }
  // F5: self-pay (payTo rewritten to the payer)
  {
    const auth = makeAuth(ctx, opt, payerAddr, { to: payerAddr });
    const accepted = pr.x402Version === 2 ? { ...opt.raw, payTo: payerAddr } : undefined;
    const r = await pay(auth, {}, { acceptedOverride: accepted });
    judgeRejected(ctx, add, r, 'funded.self-pay', 'Payment to the payer itself', 'The server lets the client choose payTo: paying yourself unlocked the content.');
  }
  // F6: concurrent double use of one authorization
  {
    const auth = makeAuth(ctx, opt, payerAddr);
    const headers = paymentHeader(pr, opt, auth, signAuth(opt, domain, payer, auth));
    const [a, b] = await Promise.all([send(ctx, { headers }), send(ctx, { headers })]);
    const delivered = [a, b].filter((r) => is2xx(r) && (!ctx.marker || hasMarker(ctx, r))).length;
    if (delivered >= 1) ctx.spent += price;
    if (delivered > 1) add('funded.concurrent', 'fail', 'Concurrent double use', 'one authorization sent twice in parallel was delivered twice.');
    else if (delivered === 1) add('funded.concurrent', 'pass', 'Concurrent double use', `delivered once (HTTP ${a.status} / ${b.status})`);
    else add('funded.concurrent', 'warn', 'Concurrent double use', `neither request was delivered (HTTP ${a.status} / ${b.status}); could not evaluate`);
  }
  // F7: cross-resource binding
  if (opts.altUrl) {
    const altBase = await send(ctx, { url: opts.altUrl });
    const altCh = parseChallenge(altBase);
    const altOpt = altCh.raw ? pickOption((altCh.raw.accepts || []).map((o, i) => normalizeOption(o, altCh.raw, i))) : null;
    if (altBase.status !== 402 || !altOpt) {
      add('funded.binding', 'skip', 'Cross-resource binding', `--alt-url did not return a usable 402 challenge (HTTP ${altBase.status})`);
    } else {
      const r = await pay(makeAuth(ctx, opt, payerAddr), { url: opts.altUrl });
      const altPrice = BigInt(altOpt.amount);
      if (is2xx(r) && altPrice <= price && sameAddr(altOpt.payTo, opt.payTo)) {
        add('funded.binding', 'warn', 'Cross-resource binding', `a payment built for ${ctx.url} unlocked ${opts.altUrl} (same payTo, price ${altPrice} <= ${price}). Not a loss, but the payment is not bound to the resource.`);
      } else {
        judgeRejected(ctx, add, r, 'funded.binding', 'Cross-resource binding', `A payment of ${price} built for ${ctx.url} unlocked ${opts.altUrl} (price ${altPrice}).`);
      }
    }
  }
  return finish({ option: opt.index, payer: payerAddr });
}

// ============================================================ CLI

const USAGE = `x402-seller-selftest ${VERSION} — can someone get your paid content without paying you?

usage: node x402-seller-selftest.mjs <url> [options]

  -X, --method <M>      HTTP method of the paid route (default GET)
  -H, --header "K: V"   extra request header, repeatable (e.g. an API key your route needs)
  -d, --data <body>     request body for POST routes
  --marker <text>       a string that appears ONLY in the paid response (strongly recommended)
  --active              also probe unpaid route variants and forged payments (no money moves)
  --i-own-this          required with --active: you own, or are authorized to test, this endpoint
  --funded              TESTNET ONLY: real test-USDC payments signed with X402_TEST_KEY
                        (replay, underpayment, client-chosen amount/payTo, concurrency)
  --alt-url <url>       with --funded: a second paid route, for the cross-resource binding check
  --json                machine-readable output
  --timeout <ms>        per-request timeout (default 15000)

exit code: 0 = no FAIL, 2 = at least one FAIL, 64 = usage error
docs: ${HOMEPAGE}`;

export function parseArgs(argv) {
  const o = { headers: {}, active: false, funded: false, json: false, iOwnThis: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-X' || a === '--method') o.method = next();
    else if (a === '-H' || a === '--header') {
      const h = next();
      const k = h.indexOf(':');
      if (k < 1) throw new Error(`bad header ${JSON.stringify(h)}; use "Name: value"`);
      o.headers[h.slice(0, k).trim()] = h.slice(k + 1).trim();
    } else if (a === '-d' || a === '--data') o.body = next();
    else if (a === '--marker') o.marker = next();
    else if (a === '--active') o.active = true;
    else if (a === '--i-own-this') o.iOwnThis = true;
    else if (a === '--funded') o.funded = true;
    else if (a === '--alt-url') o.altUrl = next();
    else if (a === '--json') o.json = true;
    else if (a === '--timeout') o.timeout = Number(next());
    else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else if (!o.url) o.url = a;
    else throw new Error(`unexpected argument ${a}`);
  }
  return o;
}

const COLORS = { pass: '\x1b[32m', info: '\x1b[36m', warn: '\x1b[33m', fail: '\x1b[31m', skip: '\x1b[90m' };

export function formatReport(rep, color = false) {
  const lines = [`x402-seller-selftest ${rep.version}  ${rep.method} ${rep.url}`, ''];
  for (const r of rep.results) {
    const tag = r.level.toUpperCase().padEnd(4);
    const t = color ? `${COLORS[r.level]}${tag}\x1b[0m` : tag;
    lines.push(`${t}  ${r.title}: ${r.detail}`);
  }
  const s = rep.summary;
  lines.push('', `${s.fail} fail · ${s.warn} warn · ${s.pass} pass · ${s.info} info · ${s.skip} skipped   (${rep.requests} requests${rep.testUsdcSpentAtomic !== '0' ? `, ${rep.testUsdcSpentAtomic} atomic test-USDC spent` : ', no money moved'})`);
  if (s.fail) lines.push('Each FAIL is explained in the README checklist: ' + HOMEPAGE + '#checklist');
  return lines.join('\n');
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(`error: ${e.message}\n\n${USAGE}`); process.exit(64); }
  if (o.help || !o.url) { console.log(USAGE); process.exit(o.help ? 0 : 64); }
  try { const u = new URL(o.url); if (!/^https?:$/.test(u.protocol)) throw new Error(); } catch { console.error('error: <url> must be an absolute http(s) URL'); process.exit(64); }
  if ((o.active || o.funded) && !o.iOwnThis) {
    console.error('error: --active / --funded send forged or real payment attempts. Only test endpoints you own or are authorized to test, and confirm with --i-own-this.');
    process.exit(64);
  }
  if (o.funded) o.active = true;
  const rep = await runSelfTest({ ...o, testKey: process.env.X402_TEST_KEY });
  if (o.json) console.log(JSON.stringify(rep, null, 2));
  else console.log(formatReport(rep, process.stdout.isTTY));
  process.exit(rep.summary.fail ? 2 : 0);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
