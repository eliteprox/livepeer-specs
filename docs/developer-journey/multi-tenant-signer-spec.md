# Plan: Per-Identity Balance Tracking for Remote Signer

**TL;DR** — Add OIDC JWT authentication (external JWKS_URL) to all three remote signer HTTP endpoints, bind the JWT `sub` claim into the signed `RemotePaymentState` blob to prevent cross-identity session hijacking, add lightweight in-process per-identity accounting for rate limiting, and emit `caller_sub` into the existing Kafka `create_signed_ticket` event for billing attribution. When `JWKS_URL` is unset the signer behaves exactly as today.

---

## Locked-in decisions (from pymthouse research + user input)

| Question | Decision |
|---|---|
| `JWKS_URL` unset | Skip auth entirely — backward compatible |
| `sub` format | UUID (pymthouse `appUsers.id`) — treat as opaque string, no parsing |
| Middleware scope | All 3 endpoints (same middleware, least code) |
| Key rotation | Manual at pymthouse; JWKS endpoint returns up to 5 keys (active + 4 rotated). `lestrrat-go/jwx/v2` `jwk.Cache` handles multi-key window automatically |
| JWKS refresh interval | Configurable flag, default **15m** (matches pymthouse signer-DMZ default of 900s) |
| Rate limit thresholds | Configurable flags (not hardcoded) |
| `discover-orchestrators` auth | Covered by same middleware; no extra code |

---

## Phase 1 — OIDC middleware + flags (no auth logic changes elsewhere)

**New flags** (add to `cmd/livepeer/starter/flags.go` and `starter.go`):

| Flag | Default | Description |
|---|---|---|
| `-remoteSignerJwksUrl` | `""` | JWKS endpoint URL. Empty = auth disabled. |
| `-remoteSignerJwksRefreshInterval` | `15m` | How often to refresh the JWKS key cache |
| `-remoteSignerAudience` | `""` | Expected JWT `aud` claim. Empty = skip aud check |

**New file: `server/remote_signer_auth.go`**

- `JWKSMiddleware(jwksURL, audience string, refreshInterval time.Duration) func(http.Handler) http.Handler`
  When `jwksURL == ""` returns an identity wrapper (no-op). Otherwise:
  1. Initialize `jwk.NewCache(ctx)` (background refresh via `lestrrat-go/jwx/v2`). Cache fetches the key set on first request and re-fetches on `refreshInterval`. The library retains **all keys returned by the endpoint** — pymthouse returns up to 5 — so rotated keys within the window remain valid for up to one TTL (15m) after rotation.
  2. On each request: extract `Authorization: Bearer <token>`, parse and verify (RS256 against cached key set), check `exp`/`iat`, optionally check `aud`.
  3. Inject validated `sub` claim into `context.Context` via a typed key.
  4. On failure: `401` JSON error (same `respondJsonError` convention as rest of file).

- `identityFromContext(ctx context.Context) string` — returns `sub` or `""` if auth is disabled.

**Wire-up in `StartRemoteSignerServer`** (`server/remote_signer.go`):
Wrap `ls.HTTPMux` with the middleware once, before all three `Handle` calls. Single point of change.

**Dependency** — add `github.com/lestrrat-go/jwx/v2` to `go.mod`. `golang-jwt/jwt/v4` is already an indirect dep but has no JWKS caching; `lestrrat-go/jwx/v2` is the standard choice for JWKS-backed verification in Go.

---

## Phase 2 — Sub binding in `RemotePaymentState`

One field added to the existing struct in `server/remote_signer.go`:

```go
CallerSub string `json:"caller_sub,omitempty"`
```

Logic in `GenerateLivePayment`:

- **New session** (`!hasState`): set `state.CallerSub = callerSub`. If auth is disabled, `callerSub == ""` and the field is simply omitted — no behavior change.
- **Continuation** (`hasState`): after state signature is verified, check `state.CallerSub == callerSub`. Mismatch → `403 Forbidden`. When both are empty (auth disabled) the check passes trivially.

This closes the session-hijacking vector at zero cost on the happy path (string compare). It is enforced by the existing state-signature MAC — the `CallerSub` is part of the JSON blob that is signed by the signer's Ethereum key, so it cannot be forged by the caller.

---

## Phase 3 — In-process `IdentityAccounting`

**New flags**:

| Flag | Default | Description |
|---|---|---|
| `-remoteSignerMaxPixelsPerSubPerMin` | `0` (disabled) | Per-identity pixel rate limit per minute |
| `-remoteSignerMaxActiveSessionsPerSub` | `0` (disabled) | Max concurrent sessions per identity |
| `-remoteSignerIdentityTtl` | `30m` | Evict idle identity entries after this duration |

**Struct** (in `server/remote_signer_auth.go`):

- `IdentityAccounting` — `sync.RWMutex`-protected `map[string]*IdentityUsage`. Background goroutine evicts entries idle > TTL.
- `IdentityUsage` — `sub`, `atomic.Int64` for pixel counter and active session count, `sync.Mutex`-protected `*big.Int` for cumulative fee, `lastSeen time.Time`.
- `RecordUsage(sub string, pixels int64, fee *big.Rat)` — increments counters. Called **after** ticket generation succeeds (not blocking the ticket path).
- `CheckLimits(sub string) error` — called **before** expensive operations; returns non-nil if per-minute pixel budget or session count is exceeded → `429 Too Many Requests`.

Thresholds of `0` mean disabled — the `CheckLimits` call becomes a no-op when both flags are unset.

**Purpose boundary**: this is anomaly detection / soft rate limiting only. Authoritative billing lives in the Kafka consumer. No persistence, no cross-instance aggregation.

**Touch points in `GenerateLivePayment`**:
1. After `callerSub` extraction: call `ls.IdentityAccounting.CheckLimits(callerSub)` — fast path rejection before any protobuf decode.
2. After `completeBalanceUpdate`: call `ls.IdentityAccounting.RecordUsage(callerSub, pixels, fee)`.

---

## Phase 4 — Kafka instrumentation

**`GenerateLivePayment`** — add one field to the existing `create_signed_ticket` event map:
```
"caller_sub": callerSub,
```
No schema change, no new topic, no new event type. Downstream pipeline can immediately group by `caller_sub`.

**`SignOrchestratorInfo`** — add a new lightweight event (conditional on `monitor.Enabled`):
```go
monitor.SendQueueEventAsync("remote_signer_orch_info", map[string]interface{}{
    "caller_sub":        callerSub,
    "request_id":        requestID,
    "address":           address,
    "current_time_unix": now.UTC().UnixMilli(),
})
```
Useful for abuse detection (identity repeatedly cycling sessions).

---

## Phase 5 — Tests

**New file: `server/remote_signer_auth_test.go`**
- Valid JWT → `sub` in context
- Expired JWT → `401`
- Wrong `aud` → `401` (when audience flag is set)
- Missing `Authorization` header → `401`
- JWT signed by **second key** in JWKS (rotated key still in window) → accepted
- JWT signed by key **not in JWKS** → `401`
- `JWKS_URL` unset → all requests pass through (no-op middleware)

**Additions to `server/remote_signer_test.go`**
- Continuation request with different `sub` than bound in state → `403`
- Kafka event for `create_signed_ticket` includes `caller_sub`
- `IdentityAccounting.CheckLimits` blocks when pixel budget exceeded → `429`
- Rate limit disabled (threshold=0) → no blocking

---

## Relevant files

| File | Change |
|---|---|
| `server/remote_signer.go` | `RemotePaymentState.CallerSub`, `GenerateLivePayment` touches, `SignOrchestratorInfo` Kafka event, `StartRemoteSignerServer` middleware wiring |
| `server/remote_signer_auth.go` (new) | `JWKSMiddleware`, `IdentityAccounting`, `identityFromContext` |
| `server/remote_signer_test.go` | Extend with sub-binding and rate-limit tests |
| `server/remote_signer_auth_test.go` (new) | Auth middleware tests |
| `cmd/livepeer/starter/flags.go` | New flag definitions (6 flags) |
| `cmd/livepeer/starter/starter.go` | Wire flags → node; init `IdentityAccounting` + JWKS cache |
| `monitor/kafka.go` | No changes — called by `remote_signer.go` |
| `go.mod` | Add `github.com/lestrrat-go/jwx/v2` |

---

## Verification

1. `go test ./server/... -run TestRemoteSigner` — existing suite still passes (no-auth path unchanged)
2. `go test ./server/... -run TestJWKS` — new auth test suite passes
3. `go build ./...` — no import cycle (auth file in `server/` package only)
4. Manual: start signer with `-remoteSignerJwksUrl` pointing at a local JWKS server, send a valid `sign:job` JWT → `200`; send expired token → `401`; rotate key at pymthouse, send token from new key → `200` (old key still in 5-key window); send token from pre-window key → `401`
5. Kafka: verify `create_signed_ticket` events in topic include `caller_sub` field matching JWT `sub`

---

## Further Considerations

1. **pymthouse key TTL vs JWKS refresh alignment**: pymthouse token TTL is 15 minutes and the JWKS refresh default is also 15 minutes. If the SDK holds a token near expiry and the key set just refreshed but the old key is still in the 5-key window, requests will succeed. The 5-key window gives ~75 minutes of backward compatibility after a manual rotation — well beyond the 15-minute token TTL.

2. **`discover-orchestrators` data sensitivity**: The endpoint currently returns orchestrator URLs, capabilities, and scores. Since this endpoint is covered by the same OIDC middleware, unauthenticated SDK clients (no token yet) cannot discover orchestrators. Confirm with the pymthouse/SDK integration that the SDK always presents a token on discovery calls before shipping. If not, this endpoint should be re-split to a separate unauthenticated path — at the cost of a small amount of extra mux wiring.

3. **`LivepeerServer` field for `IdentityAccounting`**: Add `IdentityAccounting *IdentityAccounting` directly to `LivepeerServer` (wherever the struct is defined). This keeps it co-located with the other node-level singletons and makes it injectable in tests without global state.

4. **pymthouse `sub` sources**: The `sub` UUID may come from `appUsers.id`, `users.id`, or `endUsers.id` depending on token type. All are UUIDs and treated as opaque by the signer — no type-specific handling needed.
