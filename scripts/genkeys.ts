#!/usr/bin/env tsx
/**
 * genkeys.ts — generate an ES256 (P-256) signing keypair for the Custom-Auth harness.
 *
 *   - private key  -> keys/signing-key.json   (🔒 GITIGNORED — never commit)
 *   - public JWKS  -> public/jwks.json         (the ONLY artifact that goes to GitHub Pages)
 *
 * The target's custom-auth config points its JWKS URL at the published public/jwks.json.
 * We mint end-user JWTs locally (mint.ts) signed by the private key; the target verifies them
 * against the public JWKS. Re-run ONLY to rotate keys (rare) — day-to-day sub-mutation is mint.ts.
 *
 * Run:  npx tsx scripts/genkeys.ts
 */
import { generateKeyPair, exportJWK } from 'jose';
import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const p = (...s: string[]) => resolve(ROOT, ...s);

async function main() {
  const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
  const kid = randomUUID();

  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'ES256', use: 'sig' };
  const privateJwk = { ...(await exportJWK(privateKey)), kid, alg: 'ES256', use: 'sig' };

  mkdirSync(p('keys'), { recursive: true });
  mkdirSync(p('public'), { recursive: true });

  writeFileSync(
    p('keys', 'signing-key.json'),
    JSON.stringify({ kid, alg: 'ES256', privateJwk, publicJwk }, null, 2),
  );
  writeFileSync(
    p('public', 'jwks.json'),
    JSON.stringify({ keys: [publicJwk] }, null, 2),
  );

  // seed config.local.json from the example if the operator hasn't made one yet
  if (!existsSync(p('config.local.json')) && existsSync(p('config.example.json'))) {
    copyFileSync(p('config.example.json'), p('config.local.json'));
  }

  console.log('✅ ES256 keypair generated');
  console.log('   kid              :', kid);
  console.log('   private (secret) : keys/signing-key.json     [🔒 GITIGNORED]');
  console.log('   public  JWKS     : public/jwks.json           [-> GitHub Pages]');
  console.log('');
  console.log('Portal custom-auth config — make config.local.json match these:');
  console.log('   JWKS URL : https://<user>.github.io/<repo>/jwks.json');
  console.log('   iss      : (any stable string; MUST equal the JWT `iss` in config.local.json)');
  console.log('   aud      : (any stable string; MUST equal the JWT `aud` in config.local.json)');
  console.log('   claim    : sub');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
