export const meta = {
  name: 'auth-sdk-completeness-audit',
  description: 'Audit libauth Go SDK real code status and identify gaps to be a complete authentication SDK',
  phases: [
    { title: 'Inventory', detail: 'deep-read each module + factual security-primitive sweep' },
    { title: 'Gap analysis', detail: '5 category evaluators vs complete-auth-SDK checklist' },
    { title: 'Critic', detail: 'adversarial completeness critic: missed categories + false positives' },
    { title: 'Synthesis', detail: 'final structured verdict + prioritized gap list' },
  ],
}

const REPO = '/home/jlugagne/Devel/Go/github.com/JLugagne/libauth'

const MODULE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['module','purpose','capabilities','publicAPI','completeness','intraModuleGaps','testCoverage','securityNotes'],
  properties: {
    module: { type: 'string' },
    purpose: { type: 'string' },
    capabilities: { type: 'array', items: { type: 'string' }, description: 'Concrete things this module actually does, grounded in code' },
    publicAPI: { type: 'array', items: { type: 'string' }, description: 'Key exported types/functions/interfaces' },
    completeness: { type: 'string', enum: ['complete','mostly-complete','partial','skeleton'] },
    intraModuleGaps: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['item','severity','detail'], properties: {
      item: { type: 'string' }, severity: { type: 'string', enum: ['critical','important','nice-to-have'] }, detail: { type: 'string' } } } },
    testCoverage: { type: 'string', description: 'Observed test depth' },
    securityNotes: { type: 'array', items: { type: 'string' } },
    stubsOrTodos: { type: 'array', items: { type: 'string' } },
  },
}

const SWEEP_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['findings'],
  properties: {
    findings: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['feature','present','evidence'], properties: {
      feature: { type: 'string' },
      present: { type: 'string', enum: ['yes','no','partial'] },
      evidence: { type: 'string', description: 'file:line or grep hit, or no matches' } } } },
  },
}

const GAP_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['category','assessment','items'],
  properties: {
    category: { type: 'string' },
    assessment: { type: 'string' },
    items: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['capability','status','severity','rationale','evidence'], properties: {
      capability: { type: 'string' },
      status: { type: 'string', enum: ['present','partial','stubbed','missing'] },
      severity: { type: 'string', enum: ['critical','important','nice-to-have'] },
      rationale: { type: 'string' },
      evidence: { type: 'string' } } } },
  },
}

const CRITIC_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['additionalGaps','falsePositives','blindspots'],
  properties: {
    additionalGaps: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['capability','status','severity','rationale'], properties: {
      capability: { type: 'string' }, status: { type: 'string', enum: ['present','partial','stubbed','missing'] }, severity: { type: 'string', enum: ['critical','important','nice-to-have'] }, rationale: { type: 'string' } } } },
    falsePositives: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['claim','correction'], properties: { claim: { type: 'string' }, correction: { type: 'string' } } } },
    blindspots: { type: 'array', items: { type: 'string' } },
  },
}

const SYNTHESIS_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict','completenessSummary','implemented','gaps'],
  properties: {
    verdict: { type: 'string', description: 'Direct answer: is this complete and what is the headline missing set' },
    completenessSummary: { type: 'string' },
    implemented: { type: 'array', items: { type: 'string' } },
    gaps: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['capability','category','status','severity','why','recommendation','evidence'], properties: {
      capability: { type: 'string' },
      category: { type: 'string' },
      status: { type: 'string', enum: ['missing','partial','stubbed'] },
      severity: { type: 'string', enum: ['critical','important','nice-to-have'] },
      why: { type: 'string' },
      recommendation: { type: 'string' },
      evidence: { type: 'string' } } } },
  },
}

const READ_GUIDANCE = [
  'You are auditing a Go authentication SDK (module github.com/JLugagne/libauth) at repo root ' + REPO + '.',
  'CRITICAL: assess the REAL code only. Do NOT trust PRD.md or README claims; open the .go source and verify what is actually implemented vs declared/stubbed.',
  'You may use Read, Grep, and optionally mcp__go-surgeon__overview (load via ToolSearch select:mcp__go-surgeon__overview) for a fast structural map.',
  'Read non-test .go files for capability; scan _test.go file names and assertions to judge real test coverage.',
].join('\n')

const MODULES = [
  { mod: 'identity', dir: 'identity/', hint: 'registration, credential auth, account lifecycle, email/account verification (verification.go), enumeration/timing defenses, store contract (memory+pgx).' },
  { mod: 'sessions', dir: 'sessions/', hint: 'stateful server-side sessions, middleware, lifecycle, store contract.' },
  { mod: 'tokens', dir: 'tokens/', hint: 'JWT issuance (jwt/), refresh+rotation, cookies, middleware + autorefresh, step-up, token hashing, store contract.' },
  { mod: 'passwords', dir: 'passwords/', hint: 'argon2 hashing, password policy + passphrase policy, breach check (verify if breach.go really calls HIBP or is a stub), hasher contract.' },
  { mod: 'mfa', dir: 'mfa/', hint: 'MFA enrollment/challenge, TOTP, recovery codes, store contract.' },
  { mod: 'otp', dir: 'otp/', hint: 'one-time codes, service, concurrency safety, store contract. Determine whether OTP delivery (email/SMS) is abstracted or absent. Check if magic-link lives here.' },
  { mod: 'oauth', dir: 'oauth/', hint: 'social login providers (google/github/discord), provider interface, OAuth state/CSRF, handlers. Verify PKCE, state validation, nonce/id_token.' },
  { mod: 'passkey', dir: 'passkey/', hint: 'WebAuthn/passkey registration+login via go-webauthn, handlers, store contract.' },
]

phase('Inventory')

const inventoryThunks = MODULES.map(m => () =>
  agent(READ_GUIDANCE + '\n\nAnalyze ONLY the ' + m.dir + ' directory. Intended role: ' + m.hint + '\n\nProduce a precise, code-grounded inventory: what flows are actually wired end-to-end, the public API, how complete it is, intra-module gaps, real test coverage, and security observations. Flag anything declared-but-stubbed.',
    { label: 'inv:' + m.mod, phase: 'Inventory', schema: MODULE_SCHEMA }))

const facadeThunk = () =>
  agent(READ_GUIDANCE + '\n\nAnalyze the TOP-LEVEL of the SDK: actor.go, README.md, SECURITY.md, go.mod, and how packages relate. Set module = "top-level".\nAnswer specifically: Is there a cohesive SDK facade/entrypoint wiring the modules together (a single constructor / Auth struct), or is it independent packages the consumer must assemble themselves? What does actor.go define and is it used across modules? Document the public API surface a consumer touches, and whether example/quickstart code exists.',
    { label: 'inv:top-level', phase: 'Inventory', schema: MODULE_SCHEMA })

const sweepFeatures = [
  '1. Rate limiting / request throttling (rate, throttle, RateLimit, limiter, token bucket)',
  '2. Brute-force account lockout / failed-attempt counting (lockout, attempts, MaxAttempts, locked)',
  '3. CSRF protection beyond OAuth state (csrf, SameSite, anti-forgery)',
  '4. Audit logging / security event emission / hooks / observers (audit, Event, Emit, Hook, Observer, Listener)',
  '5. Email/SMS delivery abstraction (Sender, Mailer, Email, SMS, Send, Deliver, Notifier) - how are verification codes / magic links / OTPs actually sent?',
  '6. Magic-link passwordless login (MagicLink, magic, login link)',
  '7. DB migrations / schema for pgx stores (CREATE TABLE, migration, schema.sql, .sql files)',
  '8. Background cleanup of expired records (DeleteExpired, cleanup, GC, sweep, purge, reaper)',
  '9. PKCE for OAuth (code_challenge, PKCE, S256)',
  '10. OAuth nonce / id_token validation (nonce, id_token, OIDC, openid)',
  '11. Session/token revocation and logout-everywhere (Revoke, RevokeAll, blacklist, denylist)',
  '12. Remember-me / persistent login (RememberMe, remember)',
  '13. Clock/time injection for testability (Clock, timeNow, nowFunc)',
  '14. Password strength estimator / zxcvbn / dictionary check',
  '15. CAPTCHA / bot mitigation hooks',
  '16. Webhooks / outbound integration',
  '17. Multi-tenancy (Tenant, tenantID, org)',
  '18. Authorization / RBAC / roles / permissions / scopes',
  '19. Structured logging / slog integration',
  '20. Metrics / tracing / OpenTelemetry used by libauths OWN code (not just transitive deps)',
  '21. Account deletion / GDPR data export',
  '22. Device management / trusted devices / per-user session listing',
].join('\n')

const sweepThunk = () =>
  agent(READ_GUIDANCE + '\n\nDo a FACTUAL keyword sweep across the whole repo Go code (exclude .git, .claude, .agents, PRD.md). Use ripgrep/grep. For each feature below report present yes/no/partial with concrete file:line evidence (or "no matches"). Be literal - base it on grep hits and a quick look, not assumptions.\n\nFeatures:\n' + sweepFeatures,
    { label: 'inv:sweep', phase: 'Inventory', schema: SWEEP_SCHEMA })

const invRaw = await parallel([...inventoryThunks, facadeThunk, sweepThunk])
const inventory = invRaw.filter(Boolean)
log('Inventory complete: ' + inventory.length + ' analyses gathered')

const moduleAnalyses = inventory.filter(x => x.module !== undefined)
const sweep = inventory.find(x => x.findings !== undefined) || { findings: [] }

const INVENTORY_JSON = JSON.stringify({ modules: moduleAnalyses, securitySweep: sweep.findings }, null, 1)

phase('Gap analysis')

const CATEGORIES = [
  { key: 'core-flows', title: 'Core authentication flows',
    checklist: 'End-to-end flows a complete auth SDK must support: sign-up, login, logout, password reset / forgot-password (request + token + reset), email and phone verification, account recovery, session lifecycle, token refresh + rotation + reuse-detection, passwordless / magic-link, social/OAuth login + account linking, MFA enrollment + challenge + fallback, passkey register + authenticate, remember-me, re-authentication / step-up, change-password / change-email while authenticated, account deletion. For each: is the full flow wired, or only pieces?' },
  { key: 'security-hardening', title: 'Security hardening',
    checklist: 'OWASP ASVS / NIST 800-63B controls: rate limiting and brute-force throttling, account lockout / progressive delays, breach-password check (HIBP), user-enumeration resistance, timing-attack resistance, secure cookie flags (HttpOnly/Secure/SameSite), CSRF protection, session fixation prevention (rotate id on login), token/session revocation and logout-everywhere, refresh-token reuse detection, OAuth state + PKCE + nonce/id_token validation, JWT key rotation and alg pinning, password policy strength, CAPTCHA/bot hooks, audit logging of security events, secret handling.' },
  { key: 'delivery-integration', title: 'Integration & delivery',
    checklist: 'How the SDK plugs into a real app: email/SMS sender abstraction + templating (verification codes, magic links, OTP, password-reset all need delivery), pluggable persistence (memory+pgx present - contract tests?), context propagation, HTTP framework-agnostic handlers/middleware, configurability and dependency injection, a cohesive top-level facade vs assemble-it-yourself packages, webhooks/event hooks, multi-tenancy, account-linking across auth methods.' },
  { key: 'operability', title: 'Operability & observability',
    checklist: 'Running it in production: structured logging (slog), metrics/tracing (otel) actually emitted by libauth, DB migrations/schema shipped for pgx stores, background cleanup of expired tokens/sessions/otp, clock injection for deterministic tests, error taxonomy consistency, graceful handling of store failures, health/readiness, config validation at startup.' },
  { key: 'api-docs-correctness', title: 'API ergonomics, docs & correctness',
    checklist: 'Public API consistency across modules, godoc coverage, README quickstart + runnable examples, semantic versioning / stability, consistent sentinel errors, idempotency of mutating ops, concurrency safety, context cancellation handling, the actor/principal model coherence (actor.go), whether a newcomer could assemble a working login quickly from docs.' },
]

const gapResults = await parallel(CATEGORIES.map(c => () =>
  agent('You are evaluating ONE category of completeness for the libauth Go authentication SDK: "' + c.title + '".\n\nHere is the full code-grounded inventory of every module plus a factual security-primitive grep sweep (JSON):\n\n' + INVENTORY_JSON + '\n\nChecklist for YOUR category:\n' + c.checklist + '\n\nUsing the inventory as primary evidence (you MAY grep/read the repo at ' + REPO + ' to confirm presence vs absence - do not assume), enumerate every capability in your category and classify each as present / partial / stubbed / missing, with a severity (critical = a real auth SDK is unsafe/unusable without it; important = expected by serious adopters; nice-to-have) and concrete evidence. Be skeptical: a test file named X is not proof the flow is wired; breach.go existing is not proof it calls HIBP. Only mark present when evidence supports it.',
    { label: 'gap:' + c.key, phase: 'Gap analysis', schema: GAP_SCHEMA })))

const gaps = gapResults.filter(Boolean)

phase('Critic')

const critic = await agent('You are an adversarial completeness critic for an audit of the libauth Go authentication SDK.\n\nINVENTORY (per-module + security sweep):\n' + INVENTORY_JSON + '\n\nGAP ANALYSIS (5 categories):\n' + JSON.stringify(gaps, null, 1) + '\n\nYour job:\n1. additionalGaps: capabilities a complete auth SDK needs that NEITHER the inventory NOR the gap analysis surfaced (entirely overlooked items - specific NIST/OWASP controls, flows, operational needs).\n2. falsePositives: anything marked present/complete that you doubt is genuinely wired end-to-end - spot-check the actual code at ' + REPO + ' (grep/read) to confirm your correction.\n3. blindspots: methodological gaps in how this audit was conducted.\n\nVerify before asserting. Prefer fewer, high-confidence findings.',
  { label: 'critic', phase: 'Critic', schema: CRITIC_SCHEMA })

phase('Synthesis')

const report = await agent('You are the lead author synthesizing a final completeness audit of the libauth Go authentication SDK. The reader is the SDK author, who asked: is anything missing for this to be a COMPLETE authentication SDK, based on REAL code not the PRD.\n\nINVENTORY:\n' + INVENTORY_JSON + '\n\nGAP ANALYSIS:\n' + JSON.stringify(gaps, null, 1) + '\n\nADVERSARIAL CRITIC:\n' + JSON.stringify(critic, null, 1) + '\n\nProduce the final synthesis:\n- verdict: a direct, honest one-paragraph answer to is this complete and what is the headline missing set.\n- completenessSummary: a few sentences on overall maturity and architecture quality.\n- implemented: capabilities that ARE present and solid. Reconcile against the critic false-positives - do NOT list as implemented anything the critic credibly debunked.\n- gaps: the consolidated, DEDUPLICATED list of what is missing/partial/stubbed. Merge duplicates across categories. Each gap: capability, category, status, severity, why it matters, a concrete recommendation, and evidence. Order by severity (critical first). Fold in the critic additionalGaps and remove anything the critic flagged as a false positive.\n\nBe precise and grounded. This is the definitive answer.',
  { label: 'synthesis', phase: 'Synthesis', schema: SYNTHESIS_SCHEMA })

return { report, gaps, critic, moduleCompleteness: moduleAnalyses.map(m => ({ module: m.module, completeness: m.completeness })) }
