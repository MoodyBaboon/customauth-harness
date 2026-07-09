#!/usr/bin/env tsx
/**
 * mint.ts — mint a batch of end-user JWTs for the C41 claim-collision test.
 *
 * Signs one JWT per matrix row (via scripts/sign.ts) and writes out/matrix.json = [{ label, jwt }]
 * for the OPTIONAL browser harness (src/main.ts), which exercises the full wallet-address layer.
 *
 * For the primary IDENTITY-collision test, prefer the headless runner: `npm run collide`
 * (scripts/collide.ts) — it signs fresh + POSTs live, with no 300s-expiry race and no browser.
 *
 * The private key stays in Node — only signed JWTs travel to the browser. out/ is GITIGNORED.
 *
 * Run:  npm run mint
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MATRIX } from '../src/matrix.ts';
import { loadSignCtx, signRow } from './sign.ts';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const p = (...s: string[]) => resolve(ROOT, ...s);

async function main() {
  const ctx = await loadSignCtx();

  const out: { label: string; jwt: string }[] = [];
  for (const row of MATRIX) {
    out.push({ label: row.label, jwt: await signRow(row, ctx) });
  }

  mkdirSync(p('out'), { recursive: true });
  writeFileSync(p('out', 'matrix.json'), JSON.stringify(out, null, 2));
  console.log(`✅ minted ${out.length} JWTs -> out/matrix.json   [🔒 GITIGNORED]`);
  console.log('   headless live run: npm run collide   |   browser (wallet-addr layer): npm run dev');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
