# Server Integration Guide

This guide covers soland or another trusted server calling floria's push
gateway APIs. Mobile clients do not call floria directly.

## Discovery

Use these unauthenticated discovery endpoints during rollout:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/integration/describe` | Lists supported integration surfaces and readiness checks |
| `GET /api/v1/push/bridge/describe` | Lists provider capability metadata for configured bridge clients |
| `GET /api/v1/push/describe` | Gateway profile and operational feature snapshot |
| `GET /ready` | Lightweight process readiness |
| `GET /readyz` | Strict readiness, including provider registry and reachable Redis-backed dependencies |

The OpenAPI artifact is committed at
[`docs/en/openapi.json`](./openapi.json).

## Authentication

Production deployments should enable `http.notify_auth.production_mode` and use
HTTP Message Signatures or mTLS-bound service principals. Bearer tokens are
supported for local or transitional deployments, but production mode rejects
gateway-wide bearer tokens.

The caller should set:

| Header | Required | Notes |
|--------|----------|-------|
| `Content-Type: application/json` | Yes | Request body must be JSON |
| `Idempotency-Key` | Recommended | Stable key for retry-safe `/notify` calls |
| `Authorization: Bearer ...` | Conditional | Only when bearer fallback is configured |
| HTTP Message Signature headers | Conditional | Required when the caller principal requires signatures |
| `X-Origin-Service-DID` | Recommended | Must match `origin_service_did` when present |
| `X-Destination-Service-DID` | Recommended | Must match the gateway DID when configured |

## Notify Request

`POST /api/v1/push/notify` accepts `cx.push.notify` envelopes:

```json
{
  "operation_id": "cx.push.notify",
  "idempotency_key": "notify-01J...",
  "origin_service_did": "did:web:sync.example.com",
  "destination_service_did": "did:web:push.example.com",
  "notification": {
    "event_id": "cx:event:01JS0EV000000000000000000",
    "message_id": "cx:message:01JS0MSG0000000000000000",
    "flow_id": "cx:flow:01JS0FLOW000000000000000",
    "realm_id": "cx:realm:01JS0SP000000000000000000",
    "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
    "wakeup_kind": "message",
    "push_hint": "new_message",
    "devices": [
      {
        "app_id": "com.example.mobile",
        "push_key": "provider-token-or-endpoint"
      }
    ]
  }
}
```

`push_hint` is only a body-free wakeup hint. Do not put message text, encrypted
payload bytes, SDP, ICE, TURN credentials, device names, actor DIDs, or stable
correlation identifiers into provider payload fields.

## Retry And Idempotency

Use a stable idempotency key for every logical notification. On success, floria
caches the response for `http.notify_dedup_ttl_seconds` when dedup is enabled.
Retries with the same body return the cached response. Reusing the same key with
a different body returns `duplicate_conflict`.

Temporary provider failures return a successful JSON envelope when at least one
device was accepted, with retry hints in `provider_retries`. Gateway-level
temporary failures use HTTP 503 and may include `Retry-After`.

## Response Shape

Successful responses are minimized and redact raw push tokens:

```json
{
  "request_id": "01J...",
  "accepted": 1,
  "rejected": [],
  "provider_retries": [],
  "delivery_receipts": [
    {
      "provider": "fcm",
      "status": "accepted",
      "push_key_hash": "..."
    }
  ]
}
```

Rejected devices contain app id and token hash metadata, never raw provider
tokens. Error responses use the standard `ok=false` envelope with
`error.code`, `error.message`, and a request id when available.

## Broadcast Endpoints

The internal endpoints `POST /api/v1/internal/account_deactivate_fanout` and
`POST /api/v1/internal/consent_revoke` are for soland's private broadcast path.
Keep them on a private listener, service mesh, or reverse-proxy route. They are
not mobile or third-party server APIs.
