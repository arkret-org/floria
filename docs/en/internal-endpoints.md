# Operator Endpoints

The operator routes use `http.internal_auth` bearer tokens or token hashes.
They are separate from the signed Arkret notify and registration handoff APIs.

| Route | Method | Purpose |
|-------|--------|---------|
| `/_floria/admin/push/status/{idempotency_key}` | GET | Dedup-cache status; 404 for an unknown request, 503 when the cache is disabled |
| `/_floria/admin/push/dead-letters?limit=N` | GET | Newest-first retry dead-letter snapshot, stripped of provider egress secrets; defaults to 100, maximum 1000; 503 when the queue is disabled |

No configured operator credential returns `503 service_unavailable`; missing
or invalid credentials return `401 unauthenticated`. Prefer hashed tokens and
rotate them independently of service HTTP-signature credentials. Network
isolation and service-mesh mTLS provide additional deployment protection.

The identity-bearing account-deactivation broadcast route and its DTOs are
retired. Even a valid operator bearer cannot reach that route. Account teardown
uses the existing signed, opaque registration revoke operation described in
[server integration](server-integration.md#account-deactivation).
