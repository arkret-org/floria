# Reverse Proxy & TLS Trust Roots

floria is designed to sit behind a TLS-terminating reverse proxy. The
gateway never opens its own listener on `:443` and never validates
client certificate chains itself — it relies on the proxy to:

1. Terminate TLS for `push.example.com`.
2. Validate the caller's client certificate against a pinned **trust
   root chain** (the bundle of CAs that tenants are allowed to chain
   to).
3. Forward the parsed certificate fields as HTTP headers that
   `notify_auth` binds against.

This split keeps cert chain validation in a single, well-audited
component (nginx / Caddy / Envoy / cloud LB) and lets floria stay a
plain HTTP server. The cost is one shared invariant: the proxy and
the gateway must agree on header names, formatting, and the *source
of authority* for the trust pool.

## Headers floria binds against

| Header | Default config key | Required value |
|---|---|---|
| `X-Client-Certificate-Verified` | `notify_auth.mtls_verified_header` | one of `1`, `true`, `yes`, `success`, `verified` when the chain validated; floria fails closed otherwise |
| `X-Client-Certificate-SHA256` | `notify_auth.mtls_fingerprint_header` | lowercase hex SHA-256 fingerprint of the client cert (no `:` separators required) |
| `X-Client-Certificate-Subject` | `notify_auth.mtls_subject_dn_header` | the certificate subject DN (RFC 2253 / RFC 4514 form) |
| `X-Client-Certificate-SAN` | `notify_auth.mtls_subject_alt_names_header` | comma-separated SAN list (e.g. `DNS:sync.example.com,URI:did:web:sync.example.com`) |

Subject DN comparison is whitespace-collapsed and case-insensitive on
the gateway side; SAN matching is exact, comma-split, and
case-insensitive.

## Where the trust root lives

The reverse proxy holds the trust root chain. floria's per-principal
config (`mtls_cert_fingerprints`, `mtls_subject_dn`,
`mtls_subject_alt_names`) is the second-line check — it pins the
*specific* cert(s) a service principal is allowed to use, but cannot
recover from a compromised CA. Treat the proxy's trust pool as a
first-class secret: pin it in a known location, rotate it the same way
you rotate provider credentials (see
[credential-rotation.md](./credential-rotation.md)), and avoid
shipping the system CA bundle as the trust pool.

## Sample configurations

Reference samples are in
[examples/reverse-proxy/](../../examples/reverse-proxy/):

- [`nginx.conf.sample`](../../examples/reverse-proxy/nginx.conf.sample) —
  nginx with `ssl_client_certificate` + `ssl_verify_client
  optional_no_ca`, forwarding the four mTLS headers and stripping
  client-supplied copies.
- [`Caddyfile.sample`](../../examples/reverse-proxy/Caddyfile.sample) —
  Caddy with `client_auth.trust_pool` and `mode
  require_and_verify`, using the `{tls_client_*}` placeholders to
  populate the headers.

Both samples treat `/health`, `/ready`, and `/readyz` as unauthenticated probes
and strip any client-supplied copies of the mTLS headers so an
upstream caller cannot forge their own context.

## Operational notes

- **Health probes**: keep `/health`, `/ready`, and `/readyz` reachable without a
  client cert. floria does not consult `notify_auth` on these
  endpoints, so the proxy should accept them without forwarding the
  mTLS headers.
- **SAN extraction**: nginx exposes the parsed cert via
  `$ssl_client_s_dn` but does not natively expose SANs as a
  joined string. Use `njs`, `lua`, or an upstream filter to project
  the SAN list into a comma-joined string before forwarding.
- **Production-mode coupling**:
  `http.notify_auth.production_mode = true` requires every principal
  to authenticate via HTTP Message Signature *or* mTLS and rejects
  plaintext notify bearer tokens in config. Combined with this proxy,
  it means an unauthenticated request that bypasses the proxy still
  cannot forge a verified mTLS context — floria's per-principal
  allowlist won't match without a real fingerprint.
- **Header rename**: if your proxy uses non-standard header names,
  override them in floria's config under
  `http.notify_auth.mtls_verified_header`,
  `mtls_fingerprint_header`, `mtls_subject_dn_header`,
  `mtls_subject_alt_names_header`.
- **Direct TLS termination**: not supported. If you need floria to
  own TLS itself, deploy it behind a localhost-only proxy (e.g.
  `127.0.0.1` nginx) so the proxy semantics still hold.
