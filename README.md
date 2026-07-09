# customauth-harness

Reusable **custom-JWT auth harness** — a portable bug-bounty framework brick. It mints a matrix of
JWTs with mutated identity claims, feeds each to a target's custom-auth SDK, and flags when two
**distinct** subjects resolve to the **same** wallet/account (a claim-collision takeover).

**v1 target:** Coinbase CDP embedded wallets — hypothesis **C41 claim-collision wallet-takeover**
(`companies/coinbase/CAPABILITY_MAP.md`). Testnet / throwaway end-users only.

---

## How it works

```
scripts/genkeys.ts   ES256 keypair -> keys/signing-key.json (🔒) + public/jwks.json (public → Pages)
src/matrix.ts        the sub-mutation table (single source of truth)
scripts/mint.ts      signs one JWT per matrix row -> out/matrix.json = [{label, jwt}] (🔒)
src/main.ts (browser) initialize() → per row: signOut → authenticateWithJWT → read wallet address
                     → group by address → 🔥 flag if ≥2 DISTINCT subs share one address
```

The CDP SDK's `authenticateWithJWT()` takes **no JWT argument** — it pulls the token from the
`customAuth.getJwt` callback passed to `initialize()`. The harness sets a module-level "current JWT"
and swaps it per row, calling `signOut()` between each to force a fresh provisioning.

**Collision oracle:** each JWT's real `sub` is decoded in the browser, so the detector distinguishes
a true C41 finding (different `sub` values → one address) from the intentional same-value sanity rows
(`control-repeat-A`, `magic-admin`). It also checks the control baseline (A ≠ B, and repeat-A == A);
a broken baseline downgrades the run to **inconclusive**, never "clean".

## Security guardrails (hard)

- **Testnet / throwaway end-users only.** Goal is to prove address collision, not to move funds.
- Private signing key stays in `keys/` (gitignored) and only ever runs in Node. The browser receives
  **only pre-signed JWTs**. The **only** artifact published to Pages is `public/jwks.json` (public keys).
- Scope: authorized Coinbase program only (`BountyProject/companies/coinbase/scope.yaml`).

---

## Build & run order

```bash
npm install                     # deps: jose, @coinbase/cdp-core, vite, tsx, typescript
npm run genkeys                 # → keys/signing-key.json (🔒) + public/jwks.json ; seeds config.local.json
#   edit config.local.json: set iss / aud / projectId — MUST match the CDP portal exactly.
npm run collide                 # ★ PRIMARY: headless live run (no browser). Signs fresh + POSTs each
                                #   row to the custom-auth endpoint, groups by userId, prints verdict.
```

**`npm run collide` is the test.** It needs no browser, no SDK, no polyfills — it signs a fresh JWT per
row and POSTs to `POST /v2/embedded-wallet-api/projects/{projectId}/auth/custom/authenticate`
(`Authorization: Bearer <jwt>`), reading the server-side `endUser.userId`. Oracle: two distinct `sub`
values → one `userId` = shared identity = **C41**. It also checks the control baseline (A≠B, repeat-A==A;
a broken baseline ⇒ INCONCLUSIVE, never "clean") and flags iss/aud confusion.

Optional browser path (only if you want the full **wallet-address** layer, which needs the secure-enclave
key ceremony): `npm run mint` then `npm run dev` → localhost:5173 → "Run collision matrix". ⚠️ The CDP
browser SDK transitively needs `react` + a Node `Buffer` polyfill (`vite-plugin-node-polyfills`); the
headless runner avoids all of that. The identity oracle (userId) is authoritative for C41 on its own.

Pages hosts **only `public/jwks.json`** (via `.github/workflows/deploy.yml`) — the app runs locally,
so nothing else needs deploying. A full `npm run build` (`PAGES_BASE=/<repo>/ npm run build` → `dist/`)
is optional and for local inspection only; do **not** publish `dist/` (it would bundle the throwaway
minted JWTs from `out/`).

Console dumps a machine-readable `C41_RESULTS` JSON for the repo write-up.

---

## 📋 OPERATOR CHECKLIST (do these — the harness can't self-provision)

CDP custom-auth and built-in auth are **mutually exclusive**, so use a **fresh CDP project**.

1. **CDP Portal → new project → Embedded Wallets → Auth = Custom Auth (JWT).**
   Use a *fresh project* (the mutual-exclusivity is per-project, not per-account — a project that
   already has built-in auth or a server-wallet key won't let you switch to custom-auth). A second
   CDP account works as a clean slate but is not required; C41 needs only this one project.
2. **Publish this repo & enable Pages via the included workflow** (`.github/workflows/deploy.yml`):
   push to `main`, then repo **Settings → Pages → Source = "GitHub Actions"**. The workflow hosts
   **only `public/jwks.json`** (the app is NOT deployed — it runs locally). Confirm
   `https://<user>.github.io/<repo>/jwks.json` loads and returns the JWKS.
3. In the portal custom-auth config, set:
   - **JWKS URL** = `https://<user>.github.io/<repo>/jwks.json`
   - **iss** = the same string you put in `config.local.json`
   - **aud** = the same string you put in `config.local.json`
   - **claim** = `sub`
   - **domain allowlist** += `http://localhost:5173` (the origin the harness runs on). The Pages
     origin does NOT need allowlisting — CDP fetches the JWKS server-side, not via the browser.
4. Copy the **projectId** into `config.local.json` (`projectId` field). Save.
   *(A `clientApiKey` is not consumed by `@coinbase/cdp-core.initialize` — projectId + the domain
   allowlist are what gate the browser flow. Keep any client key out of git regardless.)*
5. `npm run mint` (if you changed iss/aud), then `npm run dev` → **Run collision matrix**.

### After the run
- Read the on-page verdict + `C41_RESULTS` console JSON.
- Record the verdict back in `BountyProject/companies/coinbase/` (repo = source of truth):
  `HYPOTHESES.md` "C41 CLAIM-COLLISION (LIVE)", `SECURITY_CONTRACT.md`, `status.yaml`.
  A valid control baseline is mandatory (candidate ≠ finding). Clean = Shadow-Architecture asset, not failure.

## Bonus vector (SS1 — separate test)
Custom-auth JWKS is configured by URL. Try a minted JWT carrying a `jku` / `x5u` header pointing at an
attacker-controlled JWKS: if CDP honors the header over the portal-pinned JWKS → SSRF / signature
bypass. Test this separately from the collision matrix; label it clearly as a bonus finding.
