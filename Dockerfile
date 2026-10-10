# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Stage 1 — Cargo dependency cache.
#
# Root manifests and the local contracts crate move into this stage so Cargo
# can resolve every workspace member while warming the dependency cache.
# ---------------------------------------------------------------------------
FROM rust:1.98-trixie AS deps

WORKDIR /app

COPY --from=arkret-rust-sdk . /arkret-rust-sdk
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN mkdir -p src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked

# ---------------------------------------------------------------------------
# Stage 2 — Source build.
#
# Reuses the cargo registry cache from `deps` and recompiles only the project
# crate. The `target/` directory is mounted as a cache so dirty rebuilds stay
# incremental between Docker invocations.
# ---------------------------------------------------------------------------
FROM rust:1.98-trixie AS builder

WORKDIR /app

COPY --from=deps /usr/local/cargo /usr/local/cargo
COPY --from=arkret-rust-sdk . /arkret-rust-sdk
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
COPY tools/docker-healthcheck.rs ./tools/docker-healthcheck.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo clean --release --package floria \
    && cargo build --release --locked \
    && cp /app/target/release/floria /app/floria \
    && rustc --edition=2024 -D warnings -O tools/docker-healthcheck.rs -o /app/floria-healthcheck \
    && ldd /app/floria /app/floria-healthcheck

# ---------------------------------------------------------------------------
# Stage 3 — Runtime libraries and certificates, without shell/package tools.
# Both build and runtime stages use Debian 13 to keep the glibc ABI compatible.
# The std-only helper preserves the existing TCP liveness check.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

WORKDIR /app

COPY --from=builder /app/floria /usr/local/bin/floria
COPY --from=builder /app/floria-healthcheck /usr/local/bin/floria-healthcheck
COPY floria.sample.kdl /app/floria.kdl

ENV FLORIA_CONF=/app/floria.kdl

EXPOSE 5000 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/floria-healthcheck"]

USER 65532:65532

CMD ["/usr/local/bin/floria"]
