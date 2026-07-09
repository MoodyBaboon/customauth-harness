/**
 * matrix.ts — the JWT `sub`-mutation matrix (single source of truth).
 *
 * This is the reusable "adaptation middleware" of the harness: a table of identity-claim
 * mutations that probe how the target keys an end-user wallet off the JWT subject.
 *
 * ORACLE (C41 claim-collision): if two DISTINCT rows resolve to the SAME wallet address
 * downstream => shared wallet => Critical wallet-takeover.
 *
 * Imported by:
 *   - scripts/mint.ts  (Node): signs one JWT per row -> out/matrix.json
 *   - src/main.ts      (browser): consumes labels/oracle metadata for the results table
 *
 * `crypto.randomUUID()` is available in both Node 20+ and browsers, so this module is
 * environment-agnostic. The control subjects A/B are randomized per process; that is fine —
 * only mint.ts evaluates them into signed JWTs, and it runs once.
 */
export type Row = {
  label: string;
  /** JWT subject. Intentionally `unknown` — type-juggling rows put non-strings here. */
  sub?: unknown;
  /** When true, omit `sub` from the payload entirely (distinct from sub:null / sub:""). */
  omitSub?: boolean;
  /** Override issuer for this row (cross-issuer test). Defaults to config.iss. */
  iss?: string;
  /** Override audience for this row (cross-audience test). Defaults to config.aud. */
  aud?: string;
  /** Free-text note surfaced in the results table / expected behaviour. */
  note?: string;
};

// two stable-per-run, clearly-distinct control subjects
const A = `alice-${crypto.randomUUID()}`;
const B = `bob-${crypto.randomUUID()}`;

/** The control subjects, exported so the browser can validate the baseline invariants. */
export const CONTROL = { A, B } as const;

export const MATRIX: Row[] = [
  // --- CONTROL: must yield DISTINCT wallets (proves provisioning is per-sub, so a collision means something) ---
  { label: 'control-distinct-A', sub: A, note: 'baseline A — must differ from B' },
  { label: 'control-distinct-B', sub: B, note: 'baseline B — must differ from A' },
  { label: 'control-repeat-A', sub: A, note: 'identical sub twice -> MUST be SAME wallet as control-distinct-A (sanity)' },

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
  { label: 'trunc-499A+B', sub: 'A'.repeat(499) + 'B', note: 'differs from 500A ONLY at index 499 -> collision => length cap' },
  { label: 'trunc-65x', sub: 'x'.repeat(65) },
  { label: 'trunc-129y', sub: 'y'.repeat(129) },
  { label: 'trunc-257z', sub: 'z'.repeat(257) },

  // --- unicode / homograph (dangerous normalization / lossy encoding) ---
  { label: 'homoglyph-latin-admin', sub: 'admin' },
  { label: 'homoglyph-cyrillic-admin', sub: 'аdmin', note: 'U+0430 CYRILLIC а + "dmin" — collision w/ latin admin => NFKC/skeleton fold' },
  { label: 'nfkc-ligature-file', sub: 'ﬁle', note: '"ﬁle" -> NFKC "file"' },
  { label: 'nfkc-plain-file', sub: 'file' },
  { label: 'fullwidth-USER', sub: 'ＵＳＥＲ', note: '"ＵＳＥＲ" -> NFKC "USER"' },

  // --- case sensitivity (citext / case-insensitive collations) ---
  { label: 'case-upper', sub: 'user_ID' },
  { label: 'case-lower', sub: 'user_id', note: 'collision w/ case-upper => case-insensitive keying' },

  // --- whitespace / control / null-byte truncation ---
  { label: 'ws-base', sub: 'user_1' },
  { label: 'ws-trailing-space', sub: 'user_1 ', note: 'collision w/ ws-base => trimming' },
  { label: 'ws-tab', sub: 'user_1\t' },
  { label: 'ws-newline', sub: 'user_1\n' },
  { label: 'ws-nullbyte', sub: 'user_1\x00', note: 'collision w/ ws-base => C-string null truncation' },
  { label: 'ws-nullbyte-evil', sub: 'user_1\x00evil', note: 'collision w/ ws-base => null-byte truncation' },

  // --- magic / bypass values (WK3 honeypot-reverse: hardcoded internal identifiers) ---
  { label: 'magic-internal-test', sub: 'internal-coinbase-testing' },
  { label: 'magic-zero-uuid', sub: '00000000-0000-0000-0000-000000000000' },
  { label: 'magic-admin', sub: 'admin', note: '== homoglyph-latin-admin (dupe = sanity: same value -> same wallet)' },
  { label: 'magic-system', sub: 'system' },
  { label: 'magic-zero', sub: '0' },
  { label: 'magic-neg1', sub: '-1' },

  // --- cross-issuer: same sub, different iss/aud (does the wallet key on sub ALONE, ignoring iss/aud?) ---
  { label: 'xiss-same-sub-altiss', sub: A, iss: 'https://evil.example/idp', note: 'collision w/ control-distinct-A => wallet ignores iss (tenant confusion)' },
  { label: 'xaud-same-sub-altaud', sub: A, aud: 'some-other-audience', note: 'collision w/ control-distinct-A => wallet ignores aud' },
];
