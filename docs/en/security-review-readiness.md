# Security Review Readiness

Local record for the v1.0.0 security review gate. This file is not an external
audit report; it records what must be ready before scheduling review.

## Scope

Review focus:

1. `/api/v1/push/notify` authentication, including HTTP Message Signatures,
   bearer fallback, mTLS header binding, and production-mode constraints.
2. Replay protection: nonce store, idempotency keys, Redis failure behavior,
   and dedup collision handling.
3. Multi-tenant isolation: provider app matching, plaintext metadata gates,
   blind payload sanitizer, and token redaction.
4. Internal broadcast paths for deactivation fanout and consent revocation.
5. Supply-chain controls: audit, deny, typos, Trivy, SBOM, and local provenance.

Out of scope for this local readiness record:

1. Publishing images, crates, GitHub releases, or tags.
2. Registry-attached signatures or public SLSA attestations.
3. Mobile app code review; mobile integration is covered separately through
   chime-facing contracts.

## Local Evidence

Run these before handing the repository to reviewers:

```powershell
cargo fmt --check
cargo check
cargo test --lib
cargo test --test provider_payload_strictness
cargo test --test sample_config_parse
cargo test --test sample_config_secret_scan
cargo test --test property_provider_payload
.\scripts\local-supply-chain.ps1 -Image floria:local-security-review -SkipCosign
```

Optional environment-backed tests:

```powershell
$env:FLORIA_REDIS_URL="redis://127.0.0.1:6379/0"
$env:FLORIA_REDIS_DEDUP_LOAD_RUN="1"
cargo test redis_dedup_ttl_load --lib -- --ignored

$env:FLORIA_SOAK_RUN="1"
cargo test soak_chaos_rate_limit_cleanup --lib -- --ignored
```

## Reviewer Packet

Include these files in the packet:

| File | Purpose |
|------|---------|
| `README.md` | Feature summary and operational notes |
| `docs/en/configuration.md` | Config, secrets, and restart-required semantics |
| `docs/en/server-integration.md` | Server-side notify contract |
| `docs/en/mobile-integration.md` | chime/mobile ownership contract |
| `docs/en/openapi.json` | Machine-readable public API artifact |
| `docs/en/grafana-dashboard.json` | Recommended dashboard |
| `docs/en/supply-chain.md` | Local SBOM/provenance/image-scan commands |
| `docs/en/sdk-sync.md` | SDK forbidden-key upgrade gate |

## Current Readiness Status

As of the local v1.0.0 milestone record, floria has local evidence for auth,
replay protection, sanitizer coverage, readiness probes, audit divert metrics,
and supply-chain artifact generation. External review is still a separate
approval step and should be recorded outside this repository when complete.
