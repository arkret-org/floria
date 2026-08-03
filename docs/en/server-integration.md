# Server Integration Guide

This guide covers soland or another trusted server calling floria's push
gateway APIs. Mobile clients do not call floria directly.

## Discovery

Use these unauthenticated discovery endpoints during rollout:

| Endpoint | Purpose |
|----------|---------|
| `GET /_floria/integration/describe` | Lists supported integration surfaces and readiness checks |
| `GET /_floria/push/bridge/describe` | Lists provider capability metadata for configured bridge clients |
| `GET /_arkret/describe` | Gateway profile and operational feature snapshot at the root meta position |
| `GET /ready` | Lightweight process readiness |
| `GET /readyz` | Strict readiness, including provider registry and reachable Redis-backed dependencies |

The OpenAPI artifact is committed at
[`docs/en/openapi.json`](./openapi.json).

## Authentication

Production deployments should enable `http.notify_auth.production_mode` and use
HTTP Message Signatures or mTLS-bound service principals. Bearer tokens are
supported for local or transitional deployments, but production mode rejects
gateway-wide bearer tokens and per-principal plaintext bearer tokens.

The caller should set:

| Header | Required | Notes |
|--------|----------|-------|
| `Content-Type: application/json` | Yes | Request body must be JSON |
| `Idempotency-Key` | Recommended | Stable key for retry-safe `/notify` calls |
| `Authorization: Bearer ...` | Conditional | Only when bearer fallback is configured |
| HTTP Message Signature headers | Conditional | Required when the caller principal requires signatures |
| `Source-Service-ID` | Required whenever notify auth is enabled | Must match the authenticated caller service; HTTP Message Signature callers also cover it in the signature transcript |
| `Destination-Service-ID` | Required when `gateway_service_id` is configured | Must match the gateway DID; HTTP Message Signature callers also cover it in the signature transcript |

## Notify Request

`POST /_arkret/edge/push/notify` accepts the body for
`ak.edge.push.command.notify`. The operation and transport identity are selected
by the URL and headers, not repeated in the body:

```json
{
  "notification": {
    "event_id": "ak:event:01JS0EV000000000000000000",
    "message_id": "ak:message:01JS0MSG0000000000000000",
    "strand_id": "ak:strand:019640f9-8000-7000-8000-000000000000",
    "realm_id": "ak:realm:01JS0SP000000000000000000",
    "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
    "wakeup_kind": "message",
    "timing_profile_hint": "default",
    "push_hint": "new_message",
    "devices": [
      {
        "device_id": "ak:device:0196419b-0000-7000-8000-000000000004",
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

`accepted` and `duplicate` both mean the gateway owns the route and the caller
must not resend it. A `rejected` route remains caller-owned; the caller may retry
only when that device outcome carries `retry_after_ms`. Provider retry and
terminal delivery state remain gateway-private and never change the original
gateway outcome.

## Response Shape

Successful responses conserve the requested device set and contain no provider
or token metadata:

```json
{
  "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
  "outcomes": [
    {
      "device_id": "ak:device:0196419b-0000-7000-8000-000000000004",
      "gateway_status": "accepted"
    }
  ]
}
```

Every requested `device_id` appears exactly once. A target-level failure is
expanded into one same-reason rejected outcome for every requested device.
Raw tokens, token hashes, app ids, provider ids, provider retries, delivery
receipts, and private provider errors never appear in this response. Transport
or malformed-request errors use the standard `ok=false` envelope with
`error.code`, `error.message`, and a request id when available.

## Broadcast Endpoints

The internal endpoint `POST /_floria/internal/account_deactivate_fanout` is for
soland's private broadcast path. Keep it on a private listener, service mesh,
or reverse-proxy route. It is not a mobile or third-party server API. Contact,
Direct Conversation, Agent participation, Sidecar and operation-control gates
are evaluated before the caller constructs the push-notify request.
