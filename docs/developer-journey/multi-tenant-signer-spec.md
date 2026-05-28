# Spec: Per-Identity Balance Tracking for Remote Signer

**TL;DR** — Add OIDC JWT authentication to all three remote signer HTTP endpoints using any standards-compliant identity provider. Bind the JWT `sub` (user) and `client_id` (application) claims into the signed `RemotePaymentState` blob to prevent cross-identity session hijacking. Add lightweight in-process per-identity accounting for rate limiting. Emit `caller_sub` and `caller_client_id` into the existing Kafka `create_signed_ticket` event for full `(app, user)` billing attribution. When no issuer is configured the signer behaves exactly as today.

---

## Design principles

| Principle | Decision |
|---|---|
| Backward compatibility | No issuer configured → auth disabled entirely; all existing behaviour preserved |
| Issuer agnosticism | Any OIDC/OAuth2 issuer that publishes a discovery document (RFC 8414) or a JWKS endpoint is supported |
| Key rotation safety | `kid`-triggered on-demand JWKS refresh eliminates the polling race window — see [Phase 1](#phase-1--oidc-middleware--flags) |
| Claim contracts | `sub` (RFC 7519 §4.1.2) — opaque stable user identifier; `client_id` (RFC 9068 §2.2) — OAuth2 client/application identifier; both treated as opaque strings, no format enforced |
| Middleware scope | Same middleware wraps all three endpoints (least code) |
| Rate limit thresholds | Configurable flags; `0` means disabled |
| Accounting layer | In-process only — anomaly detection and soft rate limiting. Authoritative billing lives in the Kafka consumer |

---

## Phase 1 — OIDC middleware + flags

### Key rotation design

The previous approach — polling JWKS on a fixed interval — has an unavoidable rotation race window: tokens signed with a newly rotated key are rejected until the next poll fires. The correct solution is **`kid`-triggered on-demand refresh**:

1. On each request, look up the incoming token's `kid` header in the in-memory key set.
2. If the `kid` is present → verify immediately (pure CPU, ~1ms, no network).
3. If the `kid` is absent → the issuer has rotated keys. Trigger an immediate JWKS re-fetch (subject to a minimum debounce interval to prevent hammering the issuer on a burst of requests). Retry verification against the refreshed key set.
4. If verification still fails → `401`.

This means key rotation is **zero-latency transparent**: the very first request signed with the new key triggers a cache refresh; all subsequent requests within the same process hit the warm cache. No polling interval to tune. No coordination needed between the issuer's rotation schedule and the signer's refresh schedule.

`lestrrat-go/jwx/v2` implements this natively via `jwk.Cache` with `jwk.WithMinRefreshInterval`. The minimum refresh interval flag replaces the old polling interval flag — it is a debounce, not a schedule.

### Issuer discovery

Configure with an OIDC issuer URL. At startup, the middleware fetches `{issuer}/.well-known/openid-configuration` (RFC 8414 / OIDC Discovery 1.0) and extracts the `jwks_uri`. This avoids hardcoding the JWKS URL and works automatically when the issuer rotates its JWKS endpoint path.

For non-standard issuers without a discovery document, `-remoteSignerJwksUrl` provides a direct override that skips discovery.

### New flags

| Flag | Default | Description |
|---|---|---|
| `-remoteSignerOidcIssuer` | `""` | OIDC issuer base URL (e.g. `https://auth.example.com`). Fetches JWKS via discovery. Empty = auth disabled. |
| `-remoteSignerJwksUrl` | `""` | Direct JWKS endpoint override. Use when the issuer has no discovery document. Takes precedence over `-remoteSignerOidcIssuer` if both are set. |
| `-remoteSignerJwksMinRefreshInterval` | `30s` | Minimum time between JWKS re-fetches (debounce on unknown `kid`). Not a polling interval. |
| `-remoteSignerAudience` | `""` | Required JWT `aud` claim value. Empty = skip audience check. |
| `-remoteSignerRequiredScope` | `""` | Required scope in the `scope` or `scp` claim. Empty = skip scope check. |

Auth is disabled when both `-remoteSignerOidcIssuer` and `-remoteSignerJwksUrl` are empty.

### New file: `server/remote_signer_auth.go`

**`OIDCMiddleware(cfg OIDCConfig) func(http.Handler) http.Handler`**

`OIDCConfig` holds the resolved JWKS URL (from discovery or direct flag), audience, required scope, and minimum refresh interval.

When the JWKS URL is empty the function returns a no-op wrapper. Otherwise:

1. At construction time: if `-remoteSignerOidcIssuer` is set, fetch the discovery document and extract `jwks_uri`. Validate that the discovery document's `issuer` field matches the configured value (prevents open-redirect abuse). Register the resolved URL with `jwk.NewCache`.
2. **Per request**: extract `Authorization: Bearer <token>`, decode the JWT header to read `kid`. Look up `kid` in the cached key set.
   - Hit → verify signature, validate `exp`/`iat`/`nbf`, optionally validate `iss`, `aud`, scope.
   - Miss → call `cache.Refresh` (subject to debounce), retry lookup. Hit → verify as above. Miss → `401`.
3. Extract `sub` and `client_id` claims. Inject both into `context.Context` via package-private typed keys.
4. On any failure: respond with `401` JSON (matching the `respondJsonError` convention used throughout `remote_signer.go`).

**`identityFromContext(ctx context.Context) string`** — returns `sub` or `""`.

**`appFromContext(ctx context.Context) string`** — returns `client_id` or `""`. The `client_id` claim is defined as REQUIRED in RFC 9068 JWT access tokens; for other token profiles it may be absent. Absence is not a validation failure — the signer emits an empty `caller_client_id` in Kafka.

**Wire-up in `StartRemoteSignerServer`** (`server/remote_signer.go`):
Construct the middleware once from config, wrap `ls.HTTPMux` before all three `Handle` calls. Single point of change.

### Dependency

Add `github.com/lestrrat-go/jwx/v2` to `go.mod`. `golang-jwt/jwt/v4` (already an indirect dep) has no JWKS caching or `kid`-based refresh; `lestrrat-go/jwx/v2` is the standard Go library for this.

---

## Phase 2 — Identity binding in `RemotePaymentState`

Two fields added to the existing struct in `server/remote_signer.go`:

```go
CallerSub      string `json:"caller_sub,omitempty"`
CallerClientID string `json:"caller_client_id,omitempty"`
```

Logic in `GenerateLivePayment`:

- **New session** (`!hasState`): set `state.CallerSub = callerSub` and `state.CallerClientID = callerClientID`. When auth is disabled both are `""` and omitted — no behaviour change.
- **Continuation** (`hasState`): after the state signature is verified (existing check), assert `state.CallerSub == callerSub` and `state.CallerClientID == callerClientID`. Either mismatch → `403 Forbidden`. When both sides are `""` (auth disabled) the checks pass trivially.

Binding both claims closes the cross-identity session hijacking vector: a different user within the same app, or the same user presenting a token from a different app, cannot resume a session they did not create. The fields are inside the JSON blob signed by the signer's Ethereum key; they cannot be tampered with by the caller.

---

## Phase 3 — In-process `IdentityAccounting`

### New flags

| Flag | Default | Description |
|---|---|---|
| `-remoteSignerMaxPixelsPerSubPerMin` | `0` (disabled) | Per-user (`sub`) pixel rate limit per minute |
| `-remoteSignerMaxActiveSessionsPerSub` | `0` (disabled) | Max concurrent sessions per user (`sub`) |
| `-remoteSignerMaxPixelsPerAppPerMin` | `0` (disabled) | Per-app (`client_id`) aggregate pixel rate limit per minute |
| `-remoteSignerIdentityTtl` | `30m` | Evict idle identity entries after this duration |

### Struct (`server/remote_signer_auth.go`)

- `IdentityAccounting` — two `sync.RWMutex`-protected maps: `byUser map[string]*IdentityUsage` (keyed by `sub`) and `byApp map[string]*AppUsage` (keyed by `client_id`). Background goroutine evicts entries idle longer than TTL.
- `IdentityUsage` — `sub`, `atomic.Int64` for rolling pixel counter (reset each minute) and active session count, `sync.Mutex`-protected `*big.Rat` for cumulative fee, `lastSeen time.Time`.
- `AppUsage` — `clientID`, `atomic.Int64` for aggregate rolling pixel counter across all users of that app, `lastSeen time.Time`.
- `RecordUsage(sub, clientID string, pixels int64, fee *big.Rat)` — increments both maps. Called **after** ticket generation succeeds; not on the blocking request path.
- `CheckLimits(sub, clientID string) error` — checks both per-user and per-app thresholds. Called **before** protobuf decode; returns non-nil if any threshold is exceeded → `429 Too Many Requests`.

Thresholds of `0` are no-ops; `CheckLimits` short-circuits immediately when all thresholds are unset.

### Touch points in `GenerateLivePayment`

1. Immediately after extracting `callerSub`/`callerClientID`: `ls.IdentityAccounting.CheckLimits(callerSub, callerClientID)` — fast path rejection before any further work.
2. After `completeBalanceUpdate`: `ls.IdentityAccounting.RecordUsage(callerSub, callerClientID, pixels, fee)`.

---

## Phase 4 — Kafka instrumentation

**`GenerateLivePayment`** — add two fields to the existing `create_signed_ticket` event map:

```go
"caller_sub":       callerSub,
"caller_client_id": callerClientID,
```

No schema change, no new topic, no new event type. Downstream consumers can immediately group by:
- `caller_sub` — per-user pixels/fees
- `caller_client_id` — per-application aggregate (tenant billing)
- `(caller_client_id, caller_sub)` — per-user-per-app attribution
- `COUNT(DISTINCT caller_sub) WHERE caller_client_id = X` — active users per application

**`SignOrchestratorInfo`** — add a lightweight event (conditional on `monitor.Enabled`):

```go
monitor.SendQueueEventAsync("remote_signer_orch_info", map[string]interface{}{
    "caller_sub":        callerSub,
    "caller_client_id":  callerClientID,
    "request_id":        requestID,
    "address":           address,
    "current_time_unix": now.UTC().UnixMilli(),
})
```

Useful for per-app discovery-call attribution and session-cycling abuse detection.

Note: currently `SignOrchestratorInfo` creates the request ID inline inside `clog.AddVal`. To reference it in the Kafka event it must be stored as a local variable first:
```go
requestID := string(core.RandomManifestID())
ctx := clog.AddVal(r.Context(), "request_id", requestID)
now := time.Now()
```
This is a prerequisite one-liner refactor within the function.

---

## Phase 5 — Tests

**New file: `server/remote_signer_auth_test.go`**
- Valid JWT with `client_id` claim → both `sub` and `client_id` in context
- Valid JWT without `client_id` claim → `sub` present, `client_id` is `""`
- Expired JWT → `401`
- `nbf` in the future → `401`
- Wrong `aud` → `401` (when audience is configured)
- Missing required scope → `401` (when scope check is configured)
- Missing `Authorization` header → `401`
- JWT signed by a `kid` not currently in cache → middleware re-fetches JWKS, verifies successfully → `200`
- JWT signed by a key not present in JWKS at all → `401`
- Issuer and JWKS URL both empty → no-op middleware; all requests pass through
- `iss` claim mismatch → `401` (when issuer is configured)

**Additions to `server/remote_signer_test.go`**
- Continuation request with different `sub` than bound in state → `403`
- Continuation request with different `client_id` than bound in state → `403`
- Kafka `create_signed_ticket` event includes both `caller_sub` and `caller_client_id`
- `CheckLimits` returns `429` when per-user pixel budget is exceeded
- `CheckLimits` returns `429` when per-app pixel budget is exceeded
- All thresholds at `0` → `CheckLimits` is a no-op

---

## Relevant files

| File | Change |
|---|---|
| `server/remote_signer.go` | `RemotePaymentState.CallerSub`+`CallerClientID`, 4 touches to `GenerateLivePayment`, `SignOrchestratorInfo` minor refactor + Kafka event, `StartRemoteSignerServer` middleware wiring |
| `server/mediaserver.go` | Add `IdentityAccounting *IdentityAccounting` field to `LivepeerServer` |
| `server/remote_signer_auth.go` (new) | `OIDCMiddleware`, `OIDCConfig`, `IdentityAccounting`, `identityFromContext`, `appFromContext` |
| `server/remote_signer_test.go` | Extend with identity-binding and rate-limit tests |
| `server/remote_signer_auth_test.go` (new) | OIDC middleware tests |
| `cmd/livepeer/starter/flags.go` | New flag definitions (9 flags) |
| `cmd/livepeer/starter/starter.go` | Wire flags → `OIDCConfig`; init `IdentityAccounting`; pass to `StartRemoteSignerServer` |
| `monitor/kafka.go` | No changes |
| `go.mod` | Add `github.com/lestrrat-go/jwx/v2` |

---

## Verification

1. `go test ./server/... -run TestRemoteSigner` — existing suite passes (no-auth path unchanged)
2. `go test ./server/... -run TestOIDC` — new middleware test suite passes
3. `go build ./...` — no import cycle (`remote_signer_auth.go` is in the `server` package)
4. Manual — issuer configured:
   - Valid access token → `200`
   - Expired token → `401`
   - Rotate the signing key at the issuer; first subsequent request with the new `kid` triggers a JWKS re-fetch → `200` (no restart required)
   - Token signed by a completely unknown key → `401`
5. Kafka — `create_signed_ticket` events include `caller_sub` and `caller_client_id` matching the token claims

---

## Security considerations

1. **`kid`-refresh debounce under key-scanning attacks**: A malicious caller can craft tokens with random `kid` values to trigger repeated JWKS re-fetches. The `-remoteSignerJwksMinRefreshInterval` debounce (default `30s`) bounds this to at most one fetch per 30 seconds per process. If the signer is exposed to untrusted networks without a gateway, also consider TLS client certificate verification or an upstream API gateway for coarse admission control.

2. **`sub` and `client_id` are opaque**: The signer does no format validation, no UUID parsing, no splitting. Any stable string that an issuer puts in `sub` is accepted. This makes the middleware issuer-agnostic.

3. **`iss` claim validation**: When `-remoteSignerOidcIssuer` is set, the middleware validates the `iss` claim on every token against the configured value. This prevents tokens issued by a different OIDC provider from being accepted, even if they happen to be verifiable against the same key material.

4. **Scope validation**: When `-remoteSignerRequiredScope` is set, the middleware checks both `scope` (space-separated string, RFC 9068) and `scp` (array, common alternative) to accommodate different issuers. A token missing the required scope gets a `401`, not a `403`, to avoid leaking information about what scopes exist.

5. **`jti` replay prevention (future work)**: Short-lived access tokens can still be replayed within their validity window. A sliding-window `jti` cache on the signer would prevent this. Deferred because: (a) token TTLs are already short; (b) correct implementation across multiple signer instances requires a shared store. Revisit when the signer scales horizontally.

6. **`discover-orchestrators` sensitivity**: This endpoint returns orchestrator URLs, capabilities, and scores. With the OIDC middleware applied, unauthenticated SDK clients cannot call it. Ensure that any SDK integration always presents a valid access token before calling discovery. If an open discovery path is needed for bootstrapping, split it to a separate unauthenticated path prefix at the cost of extra mux wiring.

7. **`LivepeerServer.IdentityAccounting`**: Add the field directly to `LivepeerServer` (co-located with other node-level singletons). This keeps it injectable in tests without global state and nil-safe guarded at all call sites (`if ls.IdentityAccounting != nil`).
