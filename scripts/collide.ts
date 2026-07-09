#!/usr/bin/env tsx
/**
 * collide.ts — HEADLESS live runner for the C41 claim-collision test (no browser, no SDK).
 *
 * For each matrix row it signs a FRESH JWT and POSTs it to the CDP custom-auth endpoint:
 *   POST {basePath}/v2/embedded-wallet-api/projects/{projectId}/auth/custom/authenticate
 *   Authorization: Bearer <jwt>
 * CDP fetches our published JWKS, verifies the signature, and returns the server-side END USER
 * (`endUser.userId` — "unique across all end users in the project") + `isNewEndUser`.
 *
 * ORACLE (identity layer): userId is what a wallet binds to. Two DISTINCT `sub` values that resolve
 * to ONE userId => shared identity => shared wallet => C41. This is a cleaner, browser-free oracle
 * than the EVM address (which needs the secure-enclave key ceremony; that's the optional `npm run dev`).
 *
 * Also flags ISSUER/AUDIENCE CONFUSION: the xiss/xaud rows carry the same sub but a foreign iss/aud;
 * if CDP accepts them (200) the portal isn't enforcing iss/aud.
 *
 * Guardrails: hits ONLY the operator's own project with self-minted JWTs for own throwaway end-users.
 * No funds, no wallet creation, no foreign data. Run: npm run collide
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MATRIX, type Row } from '../src/matrix.ts';
import { loadSignCtx, signRow } from './sign.ts';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const p = (...s: string[]) => resolve(ROOT, ...s);

const BASE = process.env.CDP_BASE_PATH || 'https://api.cdp.coinbase.com/platform';

type Result = {
  label: string;
  subRepr: string;
  status: number;
  userId: string | null;
  isNewEndUser: boolean | null;
  evmAccounts: string[];
  error: string | null;
};

const subRepr = (row: Row) => (row.omitSub ? '<absent>' : JSON.stringify(row.sub));

async function authenticate(projectId: string, jwt: string) {
  const url = `${BASE}/v2/embedded-wallet-api/projects/${projectId}/auth/custom/authenticate`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${jwt}`, 'Content-Type': 'application/json' },
  });
  let body: any = null;
  const text = await res.text();
  try { body = text ? JSON.parse(text) : null; } catch { body = { raw: text }; }
  return { status: res.status, body };
}

async function main() {
  const ctx = await loadSignCtx();
  const projectId = ctx.cfg.projectId;
  if (!projectId || projectId.includes('<')) throw new Error('config.local.json `projectId` not set');

  console.log(`▶ C41 headless collision run — project ${projectId}`);
  console.log(`  endpoint ${BASE}/v2/embedded-wallet-api/projects/${projectId}/auth/custom/authenticate\n`);

  const results: Result[] = [];
  for (const row of MATRIX) {
    const jwt = await signRow(row, ctx);
    const r: Result = { label: row.label, subRepr: subRepr(row), status: 0, userId: null, isNewEndUser: null, evmAccounts: [], error: null };
    try {
      const { status, body } = await authenticate(projectId, jwt);
      r.status = status;
      if (status >= 200 && status < 300 && body?.endUser) {
        r.userId = body.endUser.userId ?? null;
        r.isNewEndUser = body.isNewEndUser ?? null;
        r.evmAccounts = body.endUser.evmAccounts ?? [];
      } else {
        r.error = body?.errorType ? `${body.errorType}: ${body.errorMessage}` : `HTTP ${status}`;
      }
    } catch (e) {
      r.error = e instanceof Error ? e.message : String(e);
    }
    results.push(r);
    const tag = r.userId ? `userId=${r.userId}${r.isNewEndUser === false ? ' (existing)' : ''}` : (r.error ?? '');
    console.log(`  ${String(r.status).padEnd(3)} ${row.label.padEnd(26)} sub=${r.subRepr.slice(0, 32).padEnd(32)} ${tag}`);
  }

  analyze(results);

  mkdirSync(p('out'), { recursive: true });
  writeFileSync(p('out', 'collide-results.json'), JSON.stringify(results, null, 2));
  console.log('\n  full JSON -> out/collide-results.json   [🔒 GITIGNORED]');
}

function userIdOf(results: Result[], label: string) {
  return results.find((r) => r.label === label)?.userId ?? null;
}

function analyze(results: Result[]) {
  // group successful auths by userId
  const byUser = new Map<string, Result[]>();
  for (const r of results) {
    if (r.status < 200 || r.status >= 300 || !r.userId) continue;
    (byUser.get(r.userId) ?? byUser.set(r.userId, []).get(r.userId)!).push(r);
  }

  // (1) C41 core: one userId reached by >=2 DISTINCT sub values
  const collisions = [...byUser.entries()]
    .map(([userId, rows]) => ({ userId, rows, distinctSubs: [...new Set(rows.map((x) => x.subRepr))] }))
    .filter((g) => g.rows.length >= 2 && g.distinctSubs.length >= 2);

  // (2) issuer/audience confusion: foreign iss/aud rows that still authenticated
  const xrows = results.filter((r) => r.label === 'xiss-same-sub-altiss' || r.label === 'xaud-same-sub-altaud');
  const cAUser = userIdOf(results, 'control-distinct-A');
  const issAudAccepted = xrows.filter((r) => r.status >= 200 && r.status < 300 && r.userId);

  // (3) control baseline invariants
  const cA = cAUser, cB = userIdOf(results, 'control-distinct-B'), cRep = userIdOf(results, 'control-repeat-A');
  const inv = {
    provisioned: !!cA && !!cB,
    distinct: !!cA && !!cB && cA !== cB,
    deterministic: !!cA && !!cRep && cA === cRep,
  };

  console.log('\n' + '='.repeat(72));
  console.log('CONTROL BASELINE');
  console.log(`  provisioned (A & B got a userId): ${inv.provisioned ? '✅' : '❌ NO — check portal/allowlist/claim'}`);
  console.log(`  distinct  (A ≠ B):                ${inv.distinct ? '✅ per-value identity' : '❌ A==B → NOT keyed per-sub → INCONCLUSIVE'}`);
  console.log(`  deterministic (repeat-A == A):    ${inv.deterministic ? '✅' : '❌ same sub → different userId → INCONCLUSIVE'}`);

  console.log('\nVERDICT');
  if (collisions.length > 0) {
    console.log(`  🔥🔥 C41 COLLISION — ${collisions.length} userId(s) shared across DISTINCT sub values`);
    for (const c of collisions) {
      console.log(`     userId ${c.userId}`);
      console.log(`        labels: ${c.rows.map((r) => r.label).join(', ')}`);
      console.log(`        distinct subs: ${c.distinctSubs.join('  |  ')}`);
    }
  } else if (!inv.distinct || !inv.deterministic) {
    console.log('  ⚠️ NO sub-collision, BUT baseline invariants failed → INCONCLUSIVE (not clean).');
  } else {
    console.log('  ✅ NO sub-collision — every distinct sub → distinct userId (baseline valid). C41 DEFENDED for this matrix.');
  }

  if (issAudAccepted.length > 0) {
    console.log('\n  ⚠️ ISSUER/AUDIENCE CONFUSION — foreign iss/aud token(s) ACCEPTED:');
    for (const r of issAudAccepted) {
      const shared = r.userId === cAUser ? '  → SAME userId as control-A (keys on sub alone!)' : '';
      console.log(`     ${r.label}: HTTP ${r.status} userId=${r.userId}${shared}`);
    }
  } else if (xrows.length > 0) {
    console.log(`\n  ✅ iss/aud enforced — foreign-issuer/audience rows rejected (${xrows.map((r) => r.status).join(', ')}).`);
  }
  console.log('='.repeat(72));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
