# Review code

## 2026-08-01 — service binding constructor drifted from the typed registry

- Surface: `ServiceDescribe.supported_bindings` for the push gateway.
- Regression: the fixture passed the legacy string `"http"` to
  `SupportedBinding::new`; the SDK now requires the closed `BindingKind` enum, and the service
  failed to compile against the current protocol kernel.
- Correction: Floria now declares `BindingKind::HttpJson` explicitly.
- Prevention dimension: protocol registry members must be constructed through their generated
  closed types so renamed or retired literals fail at the owning service boundary.
