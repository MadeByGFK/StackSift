# Retention extension + shareable links (issue #107)

What shipped, and the operational boundaries an operator must know.

## Pricing (founder-ruled 2026-11-01)

- Retention extension: **1 credit per +90 days** (`credits.COST_RETENTION_EXTENSION`,
  `RETENTION_EXTENSION_DAYS`), added to the report's *current* `expires_at`,
  stackable, lifetime ceiling `ready_at + 365 days` (`RETENTION_MAX_DAYS`).
  Full-unit purchases only: a unit that would pass the ceiling is rejected
  (409, no debit). Settlement is atomic: reserve → extend → action-receipt
  Result → complete, in one transaction under the `global:paid` lock (the
  same row `credit_maintenance.cleanup_results` locks), so extension and
  cleanup cannot race. Exactly −1 credit on success, 0 on any failure;
  402 with `purchase_url=/credits` on insufficient eligible credits.
- **Sharing is FREE.** Create, rotate and revoke never charge, never create
  a consent or a paid operation. There is no share price constant — do not
  add one without a new founder ruling.
- Share owner actions are rate-limited: **10 per hour per owner**
  (`credits.RATE_LIMIT_SHARE_ACTIONS`, policy `share:actions` via
  `credits._consume_rate`), covering create, rotate and revoke together.
  The check runs after the replay fence and the owner/source gates and
  before any mutation, so a same-key replay never consumes rate and still
  returns its stored outcome even at/over the limit. A rate-limited
  (429) attempt persists no `ReportAction` row and no token/generation
  change.
- Exports stay uniform 2 credits (issue #105). Extending a report does
  **not** extend its PDF or structured-export Results; each artifact keeps
  its own 7-day expiry.

## Share links

- 256-bit tokens (`auth.generate_token`), stored **hash-only**
  (`auth.hash_token`, SHA-256) in `report_sharing.token_hash`. The raw
  token is revealed exactly once, in the create/rotate response. A lost
  link is recovered by free rotation, never by re-display — the server
  cannot redisplay what it does not store.
- One active token per report; `generation` fences stale replays, and the
  permanent `report_actions` identity rows make create/rotate/revoke and
  retention replays safe forever (including after receipt payloads are
  cleaned up).
- Public route `GET /s/{token}` is a bearer capability, not a session: it
  sets no cookies, loads no owner identity, and mutates nothing. Unknown,
  malformed, tampered, revoked, rotated, expired, deleted or corrupt
  tokens all return the identical 404 body and headers. Revocation takes
  effect at commit for every new request; copies already delivered to
  recipients cannot be retracted.
- A PDF is reachable at `GET /s/{token}/pdf` **only** when a paid,
  unexpired PDF Result exists for that report. CSV/JSON are not shared
  in v1. Public sharing is single-file reports only; compare/batch are
  rejected with 422 before link creation.
- Abuse limiting: `PostgresRateLimiter` 30/min, 300/hr per trusted IP,
  isolated `s:` key namespace, no `request_id` replay bypass, fail-closed
  503 on limiter/database failure. Production sharing requires the shared
  database limiter — the in-memory fallback exists only for the
  no-database demo path.

## Token-path log redaction (launch requirement)

Raw tokens ride in `/s/{token}` request paths. The application installs
`report_access.SharePathRedactionFilter` on the `uvicorn.access`,
`uvicorn.error` and app loggers, rewriting `/s/<64 hex>` to
`/s/[redacted]` in rendered log messages.

**Not proven by application code:** edge/CDN/proxy access-log settings
(Railway/host dashboards) must be verified separately before launch —
the app filter cannot redact logs it never sees. Tokens must never be
put in analytics, outgoing links, page titles or client-side storage;
none are.

## Retention/cleanup semantics

Cleanup remains logical payload removal driven by `Result.expires_at`
(not verified physical erasure from storage/backups). Maintenance also
clears active share-token hashes for expired/deleted reports in the
same commit as hygiene; read-time expiry checks are the primary guard.
Extension cannot resurrect an expired or cleaned-up report (410/404,
no charge).
