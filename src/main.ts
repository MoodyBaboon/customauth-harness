/**
 * main.ts — browser harness for the CDP C41 claim-collision test.
 *
 * Flow: initialize the CDP SDK once with a `customAuth.getJwt` callback that returns a
 * module-level "current JWT". Then, for each { label, jwt } in out/matrix.json:
 *   1. set currentJwt = jwt
 *   2. signOut()                     (clear prior end-user state)
 *   3. authenticateWithJWT()         (SDK pulls the JWT via getJwt, provisions a wallet)
 *   4. read user.evmAccountObjects[0].address + user.userId
 *
 * ORACLE: group results by wallet address. A group is a 🔥 C41 COLLISION iff it contains
 * ≥2 rows whose ACTUAL `sub` values differ (decoded from the JWT, not just the label — this
 * excludes the intentional same-value sanity rows like control-repeat-A / magic-admin).
 *
 * Guardrails: testnet / throwaway end-users only. The private signing key never reaches the
 * browser — only pre-signed JWTs (from mint.ts) do.
 */
import {
  initialize,
  authenticateWithJWT,
  signOut,
  type User,
} from '@coinbase/cdp-core';
import { MATRIX } from './matrix.ts';

// --- DOM handles ---
const runBtn = document.getElementById('run') as HTMLButtonElement;
const verdictEl = document.getElementById('verdict') as HTMLDivElement;
const resultsEl = document.getElementById('results') as HTMLDivElement;

// label -> note, for the results table (oracle hints)
const NOTE = new Map(MATRIX.map((r) => [r.label, r.note ?? '']));

// --- the JWT the SDK's getJwt callback will return on the next authenticate call ---
let currentJwt: string | undefined;

type Probe = { label: string; jwt: string };
type Result = {
  label: string;
  subRepr: string; // decoded actual `sub` (JSON) or "<absent>"
  address: string | null;
  userId: string | null;
  isNewUser: boolean | null;
  error: string | null;
};

/** Decode a JWT payload WITHOUT verifying (we just need the exact `sub` that was sent). */
function decodeSub(jwt: string): string {
  try {
    const part = jwt.split('.')[1];
    const json = atob(part.replace(/-/g, '+').replace(/_/g, '/'));
    // atob gives a latin1 string; re-decode as UTF-8 so multibyte subs survive
    const bytes = Uint8Array.from(json, (c) => c.charCodeAt(0));
    const payload = JSON.parse(new TextDecoder().decode(bytes));
    return 'sub' in payload ? JSON.stringify(payload.sub) : '<absent>';
  } catch {
    return '<undecodable>';
  }
}

function evmAddress(user: User): string | null {
  return user.evmAccountObjects?.[0]?.address ?? user.evmAccounts?.[0] ?? null;
}

async function runMatrix(projectId: string) {
  const matrix = (await import('../out/matrix.json')).default as Probe[];

  await initialize({
    projectId,
    ethereum: { createOnLogin: 'eoa' },
    customAuth: { getJwt: async () => currentJwt },
  });

  const results: Result[] = [];
  for (const probe of matrix) {
    currentJwt = probe.jwt;
    const subRepr = decodeSub(probe.jwt);
    const row: Result = { label: probe.label, subRepr, address: null, userId: null, isNewUser: null, error: null };
    try {
      await signOut().catch(() => {}); // best-effort clear; ignore "not signed in"
      const res = await authenticateWithJWT();
      row.address = evmAddress(res.user);
      row.userId = res.user.userId;
      row.isNewUser = res.isNewUser;
    } catch (e) {
      row.error = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
    }
    results.push(row);
    renderTable(results); // progressive render
  }
  await signOut().catch(() => {});
  return results;
}

// --- collision analysis ---
type Collision = { address: string; labels: string[]; subs: string[] };

function analyze(results: Result[]) {
  const byAddr = new Map<string, Result[]>();
  for (const r of results) {
    if (!r.address) continue;
    (byAddr.get(r.address) ?? byAddr.set(r.address, []).get(r.address)!).push(r);
  }

  const collisions: Collision[] = [];
  for (const [address, rows] of byAddr) {
    const distinctSubs = new Set(rows.map((r) => r.subRepr));
    if (rows.length >= 2 && distinctSubs.size >= 2) {
      collisions.push({ address, labels: rows.map((r) => r.label), subs: [...distinctSubs] });
    }
  }

  // control invariants (baseline sanity — a broken baseline makes the whole run inconclusive)
  const addrOf = (label: string) => results.find((r) => r.label === label)?.address ?? null;
  const cA = addrOf('control-distinct-A');
  const cB = addrOf('control-distinct-B');
  const cRepeat = addrOf('control-repeat-A');
  const invariants = {
    baselineProvisioned: cA != null && cB != null,
    baselineDistinct: cA != null && cB != null && cA !== cB, // A != B (per-value provisioning)
    deterministic: cA != null && cRepeat != null && cA === cRepeat, // same sub -> same wallet
  };

  return { collisions, invariants, hitLabels: new Set(collisions.flatMap((c) => c.labels)) };
}

// --- rendering ---
let lastHitLabels = new Set<string>();

function renderTable(results: Result[]) {
  const rows = results
    .map((r) => {
      const cls = r.error ? 'err' : lastHitLabels.has(r.label) ? 'hit' : '';
      return `<tr class="${cls}">
        <td>${esc(r.label)}</td>
        <td>${esc(r.subRepr)}</td>
        <td class="addr">${r.address ? esc(r.address) : '—'}</td>
        <td class="addr">${r.userId ? esc(r.userId) : '—'}</td>
        <td>${r.error ? esc(r.error) : r.isNewUser === false ? '↩ existing' : r.isNewUser ? 'new' : ''}</td>
        <td class="note">${esc(NOTE.get(r.label) ?? '')}</td>
      </tr>`;
    })
    .join('');
  resultsEl.innerHTML = `<table>
      <thead><tr><th>label</th><th>sub (sent)</th><th>wallet address</th><th>userId</th><th>state</th><th>oracle hint</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
}

function esc(s: string) {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
}

function renderVerdict(results: Result[]) {
  const { collisions, invariants, hitLabels } = analyze(results);
  lastHitLabels = hitLabels;
  renderTable(results);

  const lines: string[] = [];
  lines.push('CONTROL BASELINE');
  lines.push(`  provisioned (A & B got wallets): ${invariants.baselineProvisioned ? '✅' : '❌ NO — check config/allowlist'}`);
  lines.push(`  distinct  (A ≠ B):               ${invariants.baselineDistinct ? '✅ per-value provisioning' : '❌ A==B — provisioning NOT per-sub → run inconclusive'}`);
  lines.push(`  deterministic (repeat-A == A):   ${invariants.deterministic ? '✅' : '❌ same sub → different wallet → non-deterministic → inconclusive'}`);
  lines.push('');

  if (collisions.length > 0) {
    verdictEl.className = 'collision';
    lines.unshift(`🔥🔥 C41 COLLISION — ${collisions.length} wallet(s) shared across DISTINCT sub values 🔥🔥\n`);
    for (const c of collisions) {
      lines.push(`  address ${c.address}`);
      lines.push(`    ← labels: ${c.labels.join(', ')}`);
      lines.push(`    ← distinct subs: ${c.subs.join('  |  ')}`);
    }
  } else {
    verdictEl.className = invariants.baselineDistinct && invariants.deterministic ? 'clean' : 'pending';
    lines.unshift(
      invariants.baselineDistinct && invariants.deterministic
        ? '✅ NO COLLISION — every distinct sub → distinct wallet (baseline valid). C41 DEFENDED for this matrix.\n'
        : '⚠️ NO collision found, BUT baseline invariants failed — treat as INCONCLUSIVE, not clean.\n',
    );
  }
  verdictEl.textContent = lines.join('\n');

  // machine-readable dump for the repo write-up
  console.log('C41_RESULTS', JSON.stringify({ collisions, invariants, results }, null, 2));
}

// --- entry ---
runBtn.addEventListener('click', async () => {
  runBtn.disabled = true;
  verdictEl.className = 'pending';
  verdictEl.textContent = 'Loading config + minted JWTs…';
  try {
    const cfg = (await import('../config.local.json')).default as { projectId?: string };
    if (!cfg.projectId || cfg.projectId.includes('<')) {
      throw new Error('config.local.json `projectId` not set — the operator must paste the CDP Portal project id.');
    }
    verdictEl.textContent = 'Running matrix… (each row = signOut → authenticateWithJWT)';
    const results = await runMatrix(cfg.projectId);
    renderVerdict(results);
  } catch (e) {
    verdictEl.className = 'collision';
    verdictEl.textContent = `Harness error: ${e instanceof Error ? e.message : String(e)}\n\n` +
      'Prereqs: (1) npm run genkeys  (2) fill config.local.json  (3) npm run mint  (4) operator configured CDP portal + allowlisted this origin.';
    console.error(e);
  } finally {
    runBtn.disabled = false;
  }
});
