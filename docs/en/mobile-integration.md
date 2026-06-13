# Mobile Integration Guide

Mobile apps integrate through chime and the principal server. floria is a
server-side push gateway; mobile clients should not call floria directly.

## Ownership Split

| Component | Responsibility |
|-----------|----------------|
| Mobile app | Obtains and refreshes APNs, FCM, WebPush, or OEM provider tokens |
| chime | Owns client registration UX, platform permission prompts, and local token state |
| soland / principal server | Stores device routes, maps account state to `ck.edge.push.command.notify`, and calls floria |
| floria | Delivers minimized wakeups to configured provider adapters |

## Registration Flow

1. The app asks the platform for notification permission.
2. The app obtains the provider token or WebPush endpoint.
3. chime sends the token to the principal server over the authenticated app
   channel.
4. The principal server stores a push route containing app id, provider token,
   and opaque push target id.
5. The principal server calls floria only when it needs a wakeup.

Do not send provider tokens through floria discovery endpoints. Tokens appear
only inside authenticated `/_cokret/edge/push/notify` calls from the trusted server.

## Payload Contract

The mobile app should treat provider notifications as wakeup hints. The app
must fetch canonical event, unread, and message state from its normal encrypted
sync channel after receiving the push.

Expected blind-wakeup fields:

| Field | Meaning |
|-------|---------|
| `push_target_id` | Opaque server-issued target pseudonym |
| `wakeup_kind` | Closed wakeup type: `message`, `mention`, `reaction`, or `call_invite` |
| `push_hint` | Optional body-free hint for local routing |
| `badge` / `unread_count` | Optional platform count hints |

Forbidden mobile assumptions:

1. Do not require message body, sender DID, room name, flow id, realm id, or
   event id in provider payloads.
2. Do not use provider delivery as proof that the event exists or is readable.
3. Do not store raw provider tokens in logs, analytics, crash reports, or
   screenshots.

## Token Rotation

The app should report token refreshes immediately through chime. The principal
server should retire the old push route after the new route is confirmed. floria
returns rejected token hashes to the server so stale routes can be cleaned up
without exposing raw provider tokens.

## Local Development

For local testing, run floria with `examples/minimal.kdl` or the full
`floria.sample.kdl`, then have the server call
`POST /_cokret/edge/push/notify` with a test app id that matches one configured
provider. Mobile-side tests should assert that receiving a provider wakeup
causes the app to sync, not that the provider payload carries plaintext state.
