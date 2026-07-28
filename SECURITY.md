# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately to **chris@acroidea.com** (PGP available on request).

- **Acknowledgement SLA**: 3 business days
- **Triage**: within 7 business days
- **Fix target**: 30 business days for high-severity issues; 90 days for medium/low

Do **not** open a public GitHub issue for security bugs.

## Scope

In-scope:
- Authentication / authorization bypass
- Information leakage (PII, scope membership, secrets)
- Cryptographic weaknesses
- Denial-of-service amplification

Out-of-scope:
- Self-hosted dev defaults intended to be overridden in production
- Theoretical issues without practical exploitation

## AKP-0007 Circle Invariants

Per spec, Circle is an intra-Realm cryptographic sub-boundary:
- Circle member lists MUST NOT leak to directory services or push gateways in plaintext
- The security scope of an Event lives in its producer-signed `scope_ref`
  (`models/circle.md` §6.2 — the Event wire has exactly one scope field).
  Object read projections MAY materialize `effective_scope`, which must equal
  the creating Event's `scope_ref`; neither name may reach a push gateway.
- Raw Realm ids, Circle ids and `effective_scope` MUST NOT enter the
  `/_arkret/edge/push/notify` wire (`discovery/push-notifications.md` §5.1).
  Routing is expressed only through `route_tokens` and
  `devices[].target_route_token`.

Violations of these invariants are treated as security issues.

## TLS pinning policy

floria initiates outbound TLS to multiple push providers (APNS, FCM, the
Chinese OEM providers, WebPush endpoints, and custom URL pushkin
receivers). Provider certs are not equally trustworthy from a chain-of-
custody perspective; this section is the source of truth for what we pin
and how rotation works.

### Pinned providers

| Provider | What we pin | Rationale |
|---|---|---|
| **APNS** (`api.push.apple.com`) | Apple's root CA bundle, plus the public-key SPKI fingerprint of the leaf seen on first observation | Apple rotates leaf certs regularly but its root chain is stable. Pinning the SPKI of the leaf protects against an MITM scenario that compromises an intermediate CA. |
| **FCM** (`fcm.googleapis.com`) | Google Trust Services root + Google's leaf SPKI fingerprint | Google rotates leaf certs more aggressively than Apple; we accept the operational cost of SPKI rotation in exchange for the security gain. |
| **WebPush endpoints** | NOT pinned | The endpoints are subscriber-controlled URLs across the open web; pinning is operationally impossible. We rely on standard CA validation plus VAPID signature. |
| **Custom URL pushkin (HTTPS)** | Pinned per-deployment via `tls.ca_certfile` / `tls.spki_pin` config | The receiver's identity is known at config time; deployments SHOULD pin. |
| **Chinese OEM providers** (Huawei, Xiaomi, OPPO, vivo, JPush) | Per-provider root pin (configurable via `provider.tls.root_ca`) | The OEM API endpoints are stable; pinning is feasible and recommended. |

Pinning enforcement:

- floria refuses to start if a pinned SPKI cannot be matched against the
  leaf certificate seen during the TLS handshake. The relevant config keys
  are validated at startup, not at first-request.
- A failed pin produces structured log entry
  `tls_pin_mismatch{provider, observed_spki, expected_spki}` and the
  service exits 1.

### Rotation procedure

1. **Observe.** Capture the new leaf certificate from the provider:
   ```sh
   openssl s_client -showcerts -connect api.push.apple.com:443 < /dev/null \
       | openssl x509 -pubkey -noout \
       | openssl pkey -pubin -outform DER \
       | openssl dgst -sha256 -binary \
       | openssl base64
   ```
2. **Stage.** Update `provider.tls.spki_pin` config to a list containing
   both the old SPKI and the new one. Roll the deployment. Watch
   `floria_tls_pin_match_total{provider, spki}` — both SPKIs should now
   appear with non-zero counts as the provider rotates.
3. **Migrate.** Once the new SPKI count is steady and the old SPKI count
   is at zero for >24h, remove the old SPKI from config and roll again.

### Expiry monitoring

- `floria_tls_pin_observed_cert_not_after_seconds{provider}` — gauge of
  the `notAfter` field of the leaf cert each instance has most recently
  observed. Alert at <14d.
- `floria_client_cert_expiry{pushkin}` — gauge of any client cert
  configured for outbound mTLS (APNS p12 mode, custom URL mTLS). Alert at
  <30d.
- `floria_tls_pin_mismatch_total{provider}` — counter of pin mismatches.
  Any non-zero increment is an immediate page; this is either a provider
  rotation we missed or an MITM in flight.

### Threat model

Pinning protects against:

- A rogue or compromised intermediate CA issuing a valid cert chain for a
  provider hostname.
- A misconfigured cloud proxy terminating TLS to a pinned provider.

Pinning does NOT protect against:

- A compromise of the provider's own signing infrastructure (a stolen
  Apple/Google private key would sign new leaves we would, correctly, pin
  against).
- Compromised push-payload secrets (covered by the encryption-scope
  invariant under AKP-0007).

## Disclosure

Coordinated disclosure preferred; we will credit reporters in CHANGELOG unless anonymity is requested.
