FROM rust:1.94-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        ca-certificates \
        libcurl4 \
        libnghttp2-14 \
        libssl3 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/floria /usr/local/bin/floria
COPY floria.kdl.sample /app/floria.kdl

ENV SOFLARE_CONF=/app/floria.kdl

EXPOSE 5000 8000

CMD ["floria"]
