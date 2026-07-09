/**
 * sign.ts — single source of truth for turning a matrix Row into a signed end-user JWT.
 *
 * Used by BOTH mint.ts (writes out/matrix.json for the browser path) and collide.ts (the headless
 * live runner). Keeping signing here guarantees the two paths produce byte-identical claims —
 * critical for the type-juggling / null-byte / homograph rows where any re-encoding would change
 * the very thing under test.
 */
import { SignJWT, importJWK } from 'jose';
import { randomUUID } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Row } from '../src/matrix.ts';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const p = (...s: string[]) => resolve(ROOT, ...s);

export type SignConfig = { iss: string; aud: string; ttlSeconds?: number; projectId?: string };

export type SignCtx = {
  kid: string;
  privateKey: Awaited<ReturnType<typeof importJWK>>;
  cfg: SignConfig;
};

/** Load the private signing key + config.local.json once, ready to sign many rows. */
export async function loadSignCtx(): Promise<SignCtx> {
  const keyFile = p('keys', 'signing-key.json');
  if (!existsSync(keyFile)) throw new Error('keys/signing-key.json missing — run: npm run genkeys');
  const { kid, privateJwk } = JSON.parse(readFileSync(keyFile, 'utf8'));

  const cfgFile = p('config.local.json');
  if (!existsSync(cfgFile)) throw new Error('config.local.json missing — copy config.example.json and fill it in');
  const cfg = JSON.parse(readFileSync(cfgFile, 'utf8')) as SignConfig;
  if (String(cfg.iss).includes('<'))
    console.warn('⚠️  config.local.json `iss` still has a placeholder — it MUST equal the portal `iss`');

  const privateKey = await importJWK(privateJwk, 'ES256');
  return { kid, privateKey, cfg };
}

/** Sign one matrix Row into a fresh JWT (exp = now + ttl). */
export async function signRow(row: Row, ctx: SignCtx): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const ttl = Number(ctx.cfg.ttlSeconds ?? 300);
  const payload: Record<string, unknown> = {
    iss: row.iss ?? ctx.cfg.iss,
    aud: row.aud ?? ctx.cfg.aud,
    iat: now,
    exp: now + ttl,
    jti: randomUUID(),
  };
  if (!row.omitSub) payload.sub = row.sub; // NB: any type, on purpose (type-juggling rows)

  return new SignJWT(payload as never)
    .setProtectedHeader({ alg: 'ES256', kid: ctx.kid })
    .sign(ctx.privateKey);
}
