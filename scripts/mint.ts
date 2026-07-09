#!/usr/bin/env tsx
/**
 * mint.ts — mint a batch of end-user JWTs for the C41 claim-collision test.
 *
 * Reads the private key (keys/signing-key.json) + config.local.json, signs one JWT per mutation
 * row below, writes out/matrix.json = [{ label, jwt }] for the browser harness (src/main.ts) to
 * run through the target's `authenticateWithJWT`.
 *
 * ORACLE: if two DISTINCT rows resolve to the SAME wallet address downstream => C41 wallet-takeover.
 * The private key stays in Node — only signed JWTs travel to the browser. out/ is GITIGNORED.
 *
 * Run:  npx tsx scripts/mint.ts
 */
import { SignJWT, importJWK } from 'jose';
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MATRIX } from '../src/matrix.ts';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const p = (...s: string[]) => resolve(ROOT, ...s);

async function main() {
  const keyFile = p('keys', 'signing-key.json');
  if (!existsSync(keyFile)) throw new Error('keys/signing-key.json missing — run: npx tsx scripts/genkeys.ts');
  const { kid, privateJwk } = JSON.parse(readFileSync(keyFile, 'utf8'));

  const cfgFile = p('config.local.json');
  if (!existsSync(cfgFile)) throw new Error('config.local.json missing — copy config.example.json and fill it in');
  const cfg = JSON.parse(readFileSync(cfgFile, 'utf8'));
  if (String(cfg.iss).includes('<'))
    console.warn('⚠️  config.local.json `iss` still has a placeholder — it MUST equal the portal `iss`');

  const privateKey = await importJWK(privateJwk, 'ES256');
  const now = Math.floor(Date.now() / 1000);
  const ttl = Number(cfg.ttlSeconds ?? 300);

  const out: { label: string; jwt: string }[] = [];
  for (const row of MATRIX) {
    const payload: Record<string, unknown> = {
      iss: row.iss ?? cfg.iss,
      aud: row.aud ?? cfg.aud,
      iat: now,
      exp: now + ttl,
      jti: randomUUID(),
    };
    if (!row.omitSub) payload.sub = row.sub; // NB: any type, on purpose (type-juggling rows)

    const jwt = await new SignJWT(payload as never)
      .setProtectedHeader({ alg: 'ES256', kid })
      .sign(privateKey);
    out.push({ label: row.label, jwt });
  }

  mkdirSync(p('out'), { recursive: true });
  writeFileSync(p('out', 'matrix.json'), JSON.stringify(out, null, 2));
  console.log(`✅ minted ${out.length} JWTs -> out/matrix.json   [🔒 GITIGNORED]`);
  console.log('   next: src/main.ts runs each through the target `authenticateWithJWT` and flags address collisions');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
