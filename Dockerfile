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

COPY --from=builder /app/target/release/soflare /usr/local/bin/soflare
COPY soflare.kdl.sample /app/soflare.kdl

ENV SOFLARE_CONF=/app/soflare.kdl

EXPOSE 5000 8000

CMD ["soflare"]
