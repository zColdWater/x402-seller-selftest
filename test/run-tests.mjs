// Zero-dependency tests: `node test/run-tests.mjs`
// 1) crypto vectors (keccak-256, EIP-55, EIP-712 reference example, secp256k1 vs node:crypto)
// 2) the self-test run against in-process mock sellers (no sockets, no network): one correct seller and
//    one seller per bug class. Every bug must be caught, and the correct seller must come out clean.

import { createECDH } from 'node:crypto';
import * as T from '../x402-seller-selftest.mjs';

let passed = 0;
let failed = 0;
function ok(cond, name, extra = '') {
  if (cond) { passed++; } else { failed++; console.log(`FAIL ${name} ${extra}`); }
}
const hx = T.bytesToHex;

// ------------------------------------------------------------------ 1. crypto vectors
ok(hx(T.keccak256('')) === '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', 'keccak("")');
ok(hx(T.keccak256('abc')) === '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45', 'keccak("abc")');
ok(hx(T.keccak256(new Uint8Array(135))).length === 66 && hx(T.keccak256(new Uint8Array(136))) !== hx(T.keccak256(new Uint8Array(135))), 'keccak block boundary');
ok(T.privToAddress(1n) === '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', 'address of private key 1');
ok(hx(T.keccak256(T.encodeType('TransferWithAuthorization', T.TWA_TYPES))) === '0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267', 'EIP-3009 typehash');
{
  const types = { Person: [{ name: 'name', type: 'string' }, { name: 'wallet', type: 'address' }], Mail: [{ name: 'from', type: 'Person' }, { name: 'to', type: 'Person' }, { name: 'contents', type: 'string' }] };
  const message = { from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' }, to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' }, contents: 'Hello, Bob!' };
  const d = T.eip712Digest({ domain: { name: 'Ether Mail', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' }, types, primaryType: 'Mail', message });
  ok(hx(d) === '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2', 'EIP-712 reference digest');
  const cow = BigInt(hx(T.keccak256('cow')));
  const sig = T.signDigest(d, cow);
  ok(sig.v === 28 && sig.r === 0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9dn && sig.s === 0x07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562n, 'EIP-712 reference signature (RFC 6979)');
  ok(T.recoverAddress(d, T.sigToHex(sig)) === '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826', 'recover reference signer');
  const e = createECDH('secp256k1');
  e.setPrivateKey(Buffer.from(hx(T.keccak256('cow')).slice(2), 'hex'));
  const [x, y] = T.publicKeyOf(cow);
  ok(e.getPublicKey('hex') === `04${x.toString(16).padStart(64, '0')}${y.toString(16).padStart(64, '0')}`, 'public key matches node:crypto');
}
for (let i = 0; i < 5; i++) {
  const k = T.randomPrivateKey();
  const d = T.keccak256(`msg${i}`);
  const s = T.signDigest(d, k);
  ok(T.recoverAddress(d, T.sigToHex(s)) === T.privToAddress(k), `sign/recover roundtrip ${i}`);
}
ok(T.inspectAddress('0x2d142B3e780c08a5bf5F3C912DbffD6bdE29Fd60').checksum === 'ok', 'EIP-55 ok');
ok(T.inspectAddress('0x2d142B3e780c08a5bf5F3C912DbffD6bdE29Fd61').checksum === 'bad', 'EIP-55 bad');
ok(T.inspectAddress('0x2d142b3e780c08a5bf5f3c912dbffd6bde29fd60').checksum === 'none', 'EIP-55 none');
for (const [chain, k] of Object.entries(T.KNOWN_USDC)) ok(T.inspectAddress(k.address).checksum === 'ok', `USDC address checksum chain ${chain}`);

// ------------------------------------------------------------------ 2. mock facilitator + sellers
const SEPOLIA = 84532;
const USDC = T.KNOWN_USDC[SEPOLIA];
const SELLER = '0x2d142B3e780c08a5bf5F3C912DbffD6bdE29Fd60';
const ORIGIN = 'https://seller.test';
const PATH = '/api/data';
const SECRET = 'PAID-CONTENT-7f3a';
const PRICE = '10000';
let NOW = 1_800_000_000;

function makeFacilitator() {
  const balances = new Map();
  const used = new Set();
  const check = (payload, req) => {
    const a = payload && payload.payload && payload.payload.authorization;
    const sig = payload && payload.payload && payload.payload.signature;
    if (!a || !sig) return 'invalid_payload';
    if (req.network !== `eip155:${SEPOLIA}` && req.network !== 'base-sepolia') return 'invalid_network';
    let signer;
    try {
      signer = T.recoverAddress(T.twaDigest({ chainId: SEPOLIA, asset: req.asset, name: req.extra.name, version: req.extra.version, auth: a }), sig);
    } catch { return 'invalid_signature'; }
    if (signer.toLowerCase() !== String(a.from).toLowerCase()) return 'invalid_signature';
    if (String(a.to).toLowerCase() !== String(req.payTo).toLowerCase()) return 'invalid_recipient';
    const need = BigInt(req.amount ?? req.maxAmountRequired);
    if (BigInt(a.value) < need) return 'insufficient_value';
    if (!(NOW > Number(a.validAfter) && NOW < Number(a.validBefore))) return 'expired';
    if (used.has(`${a.from.toLowerCase()}|${a.nonce}`)) return 'nonce_used';
    if ((balances.get(a.from.toLowerCase()) || 0n) < BigInt(a.value)) return 'insufficient_funds';
    return null;
  };
  return {
    balances,
    verify(payload, req) { const e = check(payload, req); return e ? { isValid: false, invalidReason: e } : { isValid: true, payer: payload.payload.authorization.from }; },
    settle(payload, req) {
      const e = check(payload, req);
      if (e) return { success: false, errorReason: e };
      const a = payload.payload.authorization;
      used.add(`${a.from.toLowerCase()}|${a.nonce}`);
      balances.set(a.from.toLowerCase(), balances.get(a.from.toLowerCase()) - BigInt(a.value));
      balances.set(a.to.toLowerCase(), (balances.get(a.to.toLowerCase()) || 0n) + BigInt(a.value));
      return { success: true, transaction: `0x${'ab'.repeat(32)}`, network: req.network, payer: a.from };
    },
  };
}

const requirement = (over = {}) => ({
  scheme: 'exact', network: `eip155:${SEPOLIA}`, amount: PRICE, asset: USDC.address, payTo: SELLER, maxTimeoutSeconds: 300,
  extra: { name: 'USDC', version: '2' }, ...over,
});

/**
 * kinds: good | noverify | failopen | trustclient | verifyonly | methodleak | caseleak | v1legacy | badlint | leak402 | free | v1good
 */
function makeSeller(kind, fac) {
  const req = kind === 'badlint'
    ? requirement({ amount: '0.01', extra: { name: 'USD Coin', version: '2' }, payTo: '0x2d142B3e780c08a5bf5F3C912DbffD6bdE29Fd61', maxTimeoutSeconds: undefined })
    : requirement();
  const v1req = { scheme: 'exact', network: 'base-sepolia', maxAmountRequired: PRICE, resource: ORIGIN + PATH, description: 'data', mimeType: 'application/json', payTo: SELLER, maxTimeoutSeconds: 300, asset: USDC.address, extra: { name: 'USDC', version: '2' } };
  const json = (status, obj, headers = {}) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', ...headers } });
  const challenge = () => {
    if (kind === 'v1good') return json(402, { x402Version: 1, error: 'payment required', accepts: [v1req] });
    const pr = { x402Version: 2, error: 'payment required', resource: { url: ORIGIN + PATH, description: 'data', mimeType: 'application/json' }, accepts: [req] };
    return json(402, kind === 'leak402' ? { preview: SECRET } : {}, { 'PAYMENT-REQUIRED': T.b64encodeJSON(pr), 'access-control-expose-headers': 'PAYMENT-REQUIRED, PAYMENT-RESPONSE' });
  };
  const deliver = (extra = {}) => json(200, { data: SECRET }, extra);
  const matchesOwn = (acc) => acc && acc.scheme === req.scheme && acc.network === req.network && acc.amount === req.amount
    && String(acc.asset).toLowerCase() === req.asset.toLowerCase() && String(acc.payTo).toLowerCase() === req.payTo.toLowerCase();

  return async function fetchImpl(url, init = {}) {
    const u = new URL(url);
    const method = (init.method || 'GET').toUpperCase();
    const headers = new Headers(init.headers || {});
    // ---- routing (where the method/case bugs live)
    const routerHit = kind === 'caseleak' ? u.pathname.toLowerCase() === PATH : u.pathname === PATH;
    if (!routerHit) return json(404, { error: 'not found' });
    const paywalled = kind === 'methodleak' ? method === 'GET' : kind === 'caseleak' ? u.pathname === PATH : true;
    if (kind !== 'methodleak' && method !== 'GET' && method !== 'HEAD') return json(405, { error: 'method not allowed' });
    if (kind === 'free' || !paywalled) return method === 'HEAD' ? new Response(null, { status: 200 }) : deliver();
    if (method === 'HEAD') return new Response(null, { status: 402 });

    // ---- payment
    const v2 = headers.get('payment-signature');
    const v1 = headers.get('x-payment');
    if (!v2 && !v1) return challenge();
    if (kind === 'v1good' && !v1) return challenge();
    if (kind !== 'v1good' && kind !== 'v1legacy' && !v2) return challenge();
    let payload;
    try { payload = T.b64decodeJSON(v2 || v1); } catch { return json(400, { error: 'malformed payment header' }); }
    if (!payload || typeof payload !== 'object') return json(400, { error: 'malformed payment payload' });

    if (kind === 'v1legacy' && v1 && !v2) {
      // legacy path only checks that the signature recovers to `from` — no balance, no settlement
      const a = payload.payload && payload.payload.authorization;
      try {
        const signer = T.recoverAddress(T.twaDigest({ chainId: SEPOLIA, asset: req.asset, name: 'USDC', version: '2', auth: a }), payload.payload.signature);
        if (signer.toLowerCase() === String(a.from).toLowerCase()) return deliver();
      } catch { /* fallthrough */ }
      return challenge();
    }
    if (kind === 'noverify') {
      if (payload.payload && payload.payload.authorization) return deliver();
      return challenge();
    }
    if (kind === 'failopen') {
      // the classic: settle "threw" (facilitator 500 / timeout) -> treat as unknown -> deliver anyway
      try {
        const s = fac.settle(payload, req);
        if (!s.success) throw new Error(s.errorReason);
      } catch { /* unknown outcome: deliver so we never "take money without delivering" */ }
      return deliver();
    }
    if (kind === 'v1good') {
      if (payload.x402Version !== 1 || payload.network !== 'base-sepolia') return challenge();
      const r = { ...v1req };
      const ver = fac.verify(payload, r);
      if (!ver.isValid) return challenge();
      const s = fac.settle(payload, r);
      return s.success ? deliver({ 'X-PAYMENT-RESPONSE': T.b64encodeJSON(s) }) : challenge();
    }
    if (payload.x402Version !== 2) return challenge();
    const reqUsed = kind === 'trustclient' ? payload.accepted : req;
    if (kind !== 'trustclient' && !matchesOwn(payload.accepted)) return challenge();
    const ver = fac.verify(payload, reqUsed);
    if (!ver.isValid) return challenge();
    if (kind === 'verifyonly') return deliver();
    const s = fac.settle(payload, reqUsed);
    if (!s.success) return challenge();
    return deliver({ 'PAYMENT-RESPONSE': T.b64encodeJSON(s) });
  };
}

function level(rep, id) { const r = rep.results.find((x) => x.id === id); return r ? r.level : 'missing'; }
const fails = (rep) => rep.results.filter((r) => r.level === 'fail').map((r) => r.id);

const PAYER_KEY = '0x' + '11'.repeat(32);
const PAYER = T.privToAddress(BigInt(PAYER_KEY));

async function run(kind, extra = {}) {
  const fac = makeFacilitator();
  fac.balances.set(PAYER.toLowerCase(), 1_000_000n);
  const rep = await T.runSelfTest({
    url: ORIGIN + PATH, fetch: makeSeller(kind, fac), now: () => NOW, marker: SECRET, active: true, ...extra,
  });
  return { rep, fac };
}

// correct seller, unfunded active run: zero FAIL, zero WARN
{
  const { rep } = await run('good');
  ok(fails(rep).length === 0 && rep.summary.warn === 0, 'good seller: clean active run', JSON.stringify(rep.results.filter((r) => r.level !== 'pass'), null, 1));
  ok(level(rep, 'forge.unfunded') === 'pass' && level(rep, 'forge.bad-signature') === 'pass' && level(rep, 'forge.legacy-v1') === 'pass', 'good seller: forged payments rejected');
  ok(level(rep, 'lint.opt0') === 'pass' && level(rep, 'lint.resource') === 'pass', 'good seller: lint passes');
  ok(rep.testUsdcSpentAtomic === '0', 'unfunded run spends nothing');
}
// correct seller, funded run
{
  const { rep, fac } = await run('good', { funded: true, testKey: PAYER_KEY });
  ok(fails(rep).length === 0, 'good seller: clean funded run', JSON.stringify(rep.results.filter((r) => r.level !== 'pass'), null, 1));
  ok(level(rep, 'funded.correct') === 'pass' && level(rep, 'funded.replay') === 'pass' && level(rep, 'funded.concurrent') === 'pass', 'good seller: funded checks pass');
  ok(fac.balances.get(SELLER.toLowerCase()) === 20000n, 'good seller: exactly two real payments settled', String(fac.balances.get(SELLER.toLowerCase())));
}
// passive mode only lints
{
  const { rep } = await run('good', { active: false });
  ok(level(rep, 'active') === 'skip' && rep.requests === 1, 'passive mode sends one request');
}
// each bug class is caught
const expectFail = [
  ['free', 'baseline', {}],
  ['noverify', 'forge.bad-signature', {}],
  ['failopen', 'forge.unfunded', {}],
  ['failopen', 'forge.bad-signature', {}],
  ['methodleak', 'variant.method.POST', {}],
  ['caseleak', 'variant.path.uppercase', {}],
  ['v1legacy', 'forge.legacy-v1', {}],
  ['badlint', 'lint.opt0', {}],
  ['leak402', 'baseline.leak', {}],
  ['verifyonly', 'funded.replay', { funded: true, testKey: PAYER_KEY }],
  ['verifyonly', 'funded.concurrent', { funded: true, testKey: PAYER_KEY }],
  ['trustclient', 'funded.client-requirements', { funded: true, testKey: PAYER_KEY }],
  ['trustclient', 'funded.self-pay', { funded: true, testKey: PAYER_KEY }],
];
for (const [kind, id, extra] of expectFail) {
  const { rep } = await run(kind, extra);
  ok(level(rep, id) === 'fail', `${kind}: ${id} is FAIL`, `got ${level(rep, id)} :: ${JSON.stringify(rep.results.find((r) => r.id === id))}`);
}
// bug sellers that look fine without funds must not be flagged unfunded (no false positives)
for (const kind of ['verifyonly', 'trustclient']) {
  const { rep } = await run(kind);
  ok(fails(rep).length === 0, `${kind}: no false positive in unfunded mode`, JSON.stringify(fails(rep)));
}
// badlint details
{
  const { rep } = await run('badlint');
  const d = rep.results.find((r) => r.id === 'lint.opt0').detail;
  ok(/atomic units/.test(d) && /EIP-55/.test(d) && /EIP-712 domain/.test(d) && /maxTimeoutSeconds/.test(d), 'badlint: all four problems reported', d);
}
// v1 seller works end to end (legacy format)
{
  const { rep } = await run('v1good', { funded: true, testKey: PAYER_KEY });
  ok(fails(rep).length === 0 && level(rep, 'funded.correct') === 'pass' && level(rep, 'lint.version') === 'info', 'v1 seller: clean funded run', JSON.stringify(rep.results.filter((r) => r.level !== 'pass' && r.level !== 'info'), null, 1));
}
// funded mode refuses mainnet
{
  const fac = makeFacilitator();
  const mainnetSeller = async (url, init = {}) => {
    const h = new Headers(init.headers || {});
    if (h.get('payment-signature')) return new Response('{}', { status: 402 });
    const pr = { x402Version: 2, resource: { url: ORIGIN + PATH }, accepts: [requirement({ network: 'eip155:8453', asset: T.KNOWN_USDC[8453].address, extra: { name: 'USD Coin', version: '2' } })] };
    return new Response('{}', { status: 402, headers: { 'PAYMENT-REQUIRED': T.b64encodeJSON(pr) } });
  };
  void fac;
  const rep = await T.runSelfTest({ url: ORIGIN + PATH, fetch: mainnetSeller, now: () => NOW, active: true, funded: true, testKey: PAYER_KEY });
  ok(level(rep, 'funded') === 'skip' && /not a testnet/.test(rep.results.find((r) => r.id === 'funded').detail), 'funded refuses mainnet');
}
// url variants and CLI parsing
{
  const v = Object.fromEntries(T.urlVariants('https://x.test/api/data?q=1'));
  ok(v['trailing-slash'] === 'https://x.test/api/data/?q=1' && v.uppercase === 'https://x.test/API/DATA?q=1' && v['percent-encoded'] === 'https://x.test/api/%64ata?q=1' && v['double-slash'] === 'https://x.test//api/data?q=1', 'url variants', JSON.stringify(v));
  const a = T.parseArgs(['https://x.test/a', '-X', 'post', '-H', 'Authorization: Bearer x', '--marker', 'M', '--active', '--i-own-this']);
  ok(a.url === 'https://x.test/a' && a.method === 'post' && a.headers.Authorization === 'Bearer x' && a.active && a.iOwnThis && a.marker === 'M', 'parseArgs');
  let threw = false;
  try { T.parseArgs(['--bogus']); } catch { threw = true; }
  ok(threw, 'parseArgs rejects unknown flags');
}
// report formatting
{
  const { rep } = await run('failopen');
  const txt = T.formatReport(rep);
  ok(/FAIL  Valid signature, zero balance/.test(txt) && /no money moved/.test(txt), 'text report');
}

console.log(`${failed ? 'FAIL' : 'PASS'}  ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
