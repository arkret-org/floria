# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Stage 1 — Cargo dependency cache.
#
# Only `Cargo.toml` and `Cargo.lock` move into this stage so the dependency
# graph compiles into the cargo cache layers. Subsequent rebuilds reuse this
# layer until either manifest changes — typical incremental builds touch only
# the source-build stage.
# ---------------------------------------------------------------------------
FROM rust:1.92-bookworm AS deps

WORKDIR /app

COPY --from=contrix-rust-sdk . /contrix-rust-sdk
COPY Cargo.toml Cargo.lock ./

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
FROM rust:1.92-bookworm AS builder

WORKDIR /app

COPY --from=deps /usr/local/cargo /usr/local/cargo
COPY --from=contrix-rust-sdk . /contrix-rust-sdk
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    && cp /app/target/release/floria /app/floria

# ---------------------------------------------------------------------------
# Stage 3 — Minimal runtime.
#
# debian:bookworm-slim is the smallest tier-1-supported base that ships with
# `libssl3` so reqwest's native-tls features work out of the box. We keep only
# the libraries the binary actually links: ca-certificates, libssl3, and the
# nghttp2/zlib pair pulled in by reqwest's HTTP/2 support. `curl` is shipped
# only because the HEALTHCHECK relies on it; everything else (including
# `tini`, build tools, package indexes) is stripped.
#
# HEALTHCHECK strategy: the default probe is a TCP-level liveness check
# via `nc -z` so we do not have to pay a full TLS / HTTP roundtrip on
# every interval. The HTTP `/ready` probe via wget is left available as
# a fallback (commented out) for environments that need richer signal.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Retry apt-get up to 5x to absorb transient 5xx from upstream Debian
# mirrors / corporate proxies (C36.5 + C37.3 lesson — Docker Desktop
# proxy intermittently 502s on debian-security InRelease). The
# Acquire::Retries config covers per-package fetch retry; the
# enclosing for-loop covers full-resolve failures.
RUN echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries \
    && for i in 1 2 3 4 5; do \
        apt-get update \
        && apt-get install --yes --no-install-recommends \
            ca-certificates \
            libnghttp2-14 \
            libssl3 \
            netcat-openbsd \
            wget \
            zlib1g \
        && break || (echo "apt retry $i" && sleep 10); \
    done \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
    && groupadd --system --gid 65532 floria \
    && useradd --system --uid 65532 --gid floria --no-create-home --shell /usr/sbin/nologin floria

WORKDIR /app

COPY --from=builder /app/floria /usr/local/bin/floria
COPY floria.sample.kdl /app/floria.kdl

ENV FLORIA_CONF=/app/floria.kdl

EXPOSE 5000 8000

# TCP probe — fastest signal that the listener is up. To switch to the
# richer `/ready` HTTP probe, replace the CMD line with:
#   CMD wget --quiet --spider --tries=1 --timeout=4 http://127.0.0.1:5000/ready || exit 1
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nc -z 127.0.0.1 5000 || exit 1

USER floria:floria

CMD ["floria"]
