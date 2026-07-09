#!/usr/bin/env tsx
/**
 * probes.ts — adaptation-middleware pilot: 4 WILD seeds → concrete probes on the custom-auth
 * surface, BEYOND the sub-mutation matrix. Headless, live, own project only.
 *
 *   Navajo (SG3)     — do SECONDARY claims (email_verified/groups/roles) get trusted? shared-email merge?
 *   Tardigrade (BIO4)— is `exp` actually ENFORCED (expired→reject)? nbf-future sleeper? far-future cap?
 *   Giraffe (GN2)    — is the ancillary validate-token a weaker route to the identity core? (conditional)
 *   Diogenes (NV14)  — can a wallet-LESS end-user reach a provisioning-gated op? (conditional on token)
 *
 * Guardrails: own project, self-minted JWTs, own throwaway end-users. No funds. Run: npm run probes
 */
import { SignJWT, importJWK } from 'jose';
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const p = (...s: string[]) => resolve(ROOT, ...s);
const BASE = process.env.CDP_BASE_PATH || 'https://api.cdp.coinbase.com/platform';

const { kid, privateJwk } = JSON.parse(readFileSync(p('keys', 'signing-key.json'), 'utf8'));
const cfg = JSON.parse(readFileSync(p('config.local.json'), 'utf8'));
const PROJECT = cfg.projectId as string;
const pk = await importJWK(privateJwk, 'ES256');
const now = () => Math.floor(Date.now() / 1000);

async function mint(claims: Record<string, unknown>, extra: { exp?: number; nbf?: number } = {}) {
  const t = now();
  const payload: Record<string, unknown> = { iss: cfg.iss, aud: cfg.aud, iat: t, exp: extra.exp ?? t + 300, jti: randomUUID(), ...claims };
  if (extra.nbf !== undefined) payload.nbf = extra.nbf;
  return new SignJWT(payload as never).setProtectedHeader({ alg: 'ES256', kid }).sign(pk);
}

async function authn(jwt: string) {
  const url = `${BASE}/v2/embedded-wallet-api/projects/${PROJECT}/auth/custom/authenticate`;
  const res = await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${jwt}`, 'Content-Type': 'application/json' } });
  const text = await res.text();
  let body: any = null;
  try { body = text ? JSON.parse(text) : null; } catch { body = { raw: text }; }
  return { status: res.status, body };
}

const uid = (b: any) => b?.endUser?.userId ?? null;
const errOf = (b: any) => (b?.errorType ? `${b.errorType}: ${b.errorMessage}` : '');
const results: Record<string, unknown> = {};

async function main() {
  console.log(`▶ adaptation-middleware pilot — project ${PROJECT}\n`);

  // ── SEED 1 (Navajo) — secondary-claim reflection + FULL-response recon ──────────────
  console.log('🧬 NAVAJO — secondary-claim trust + response recon');
  const rich = {
    sub: `navajo-${randomUUID()}`,
    email: 'victim@example.com', email_verified: true,
    phone_number: '+15550001111', phone_number_verified: true,
    name: 'Mallory', given_name: 'Mallory', groups: ['admin', 'kyc-tier-2'], roles: ['internal'],
    org: 'coinbase', tenant: 'coinbase-internal', is_admin: true,
  };
  const a = await authn(await mint(rich));
  results.navajo_reflection = a;
  console.log(`   HTTP ${a.status}  userId=${uid(a.body)}`);
  console.log('   FULL response body (recon — does it reflect our claims / return a token?):');
  console.log('   ' + JSON.stringify(a.body, null, 2).split('\n').join('\n   '));

  // ── SEED 1b (Navajo) — shared-email MERGE across two distinct subs ───────────────────
  console.log('\n🧬 NAVAJO — shared-email merge (two DIFFERENT subs, SAME email)');
  const email = `merge-${randomUUID()}@example.com`;
  const m1 = await authn(await mint({ sub: `m1-${randomUUID()}`, email, email_verified: true }));
  const m2 = await authn(await mint({ sub: `m2-${randomUUID()}`, email, email_verified: true }));
  results.navajo_merge = { m1, m2 };
  console.log(`   m1: HTTP ${m1.status} userId=${uid(m1.body)}`);
  console.log(`   m2: HTTP ${m2.status} userId=${uid(m2.body)}`);
  console.log(`   ⇒ ${uid(m1.body) && uid(m1.body) === uid(m2.body) ? '🔥 SAME userId — MERGE on shared email!' : '✅ distinct — no email-merge'}`);

  // ── SEED 3 (Tardigrade) — exp / nbf enforcement ─────────────────────────────────────
  console.log('\n🧬 TARDIGRADE — exp/nbf enforcement');
  const t = now();
  const cases: [string, string, number][] = []; // label, description, status
  const valid = await authn(await mint({ sub: `tv-${randomUUID()}` }, { exp: t + 300 }));
  const expired = await authn(await mint({ sub: `tx-${randomUUID()}` }, { exp: t - 3600 }));
  const farFuture = await authn(await mint({ sub: `tf-${randomUUID()}` }, { exp: t + 10 * 365 * 86400 }));
  const sleeper = await authn(await mint({ sub: `ts-${randomUUID()}` }, { nbf: t + 3600, exp: t + 7200 }));
  results.tardigrade = { valid, expired, farFuture, sleeper };
  console.log(`   valid   (exp +300s)      : HTTP ${valid.status}   ${valid.status === 200 ? '(baseline OK)' : errOf(valid.body)}`);
  console.log(`   EXPIRED (exp -1h)        : HTTP ${expired.status}   ${expired.status === 200 ? '🔥🔥 ACCEPTED — exp NOT enforced!' : '✅ rejected ' + errOf(expired.body)}`);
  console.log(`   far-future (exp +10y)    : HTTP ${farFuture.status}   ${farFuture.status === 200 ? '⚠️ accepted — no exp cap (minor)' : '✅ capped ' + errOf(farFuture.body)}`);
  console.log(`   sleeper (nbf +1h)        : HTTP ${sleeper.status}   ${sleeper.status === 200 ? '🔥 ACCEPTED early — nbf not enforced!' : '✅ rejected ' + errOf(sleeper.body)}`);

  // ── SEED 4 (Giraffe) — ancillary validate-token route (conditional) ─────────────────
  console.log('\n🧬 GIRAFFE — validate-token ancillary route');
  const tokenField = a.body && (a.body.accessToken || a.body.access_token || a.body.token || a.body.idToken);
  if (tokenField) {
    const vurl = `${BASE}/v2/end-users/auth/validate-token`;
    const vRes = await fetch(vurl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ accessToken: tokenField }) });
    const vBody = await vRes.text();
    results.giraffe = { status: vRes.status, body: vBody.slice(0, 500) };
    console.log(`   validate-token (no dev-auth): HTTP ${vRes.status}  ${vBody.slice(0, 200)}`);
  } else {
    results.giraffe = 'no access-token field in authenticate response — needs dev Secret-key path';
    console.log('   ⏭  authenticate returned no access-token field → validate-token is dev-authed (Secret key). Deferred.');
  }

  // ── SEED 2 (Diogenes) — wallet-less end-user reaching a provisioning-gated op ────────
  console.log('\n🧬 DIOGENES — empty (wallet-less) end-user; evmAccounts on fresh auth?');
  console.log(`   fresh end-user evmAccounts = ${JSON.stringify(a.body?.endUser?.evmAccounts ?? '(field absent)')}`);
  console.log('   (privileged wallet ops need the end-user access-token + Temporary Wallet Secret ceremony;');
  console.log('    if no token above, Diogenes-a real op = browser/enclave track — recon captured for next step.)');

  mkdirSync(p('out'), { recursive: true });
  writeFileSync(p('out', 'probes-results.json'), JSON.stringify(results, null, 2));
  console.log('\n  full JSON -> out/probes-results.json   [🔒 GITIGNORED]');
}

main().catch((e) => { console.error(e); process.exit(1); });
