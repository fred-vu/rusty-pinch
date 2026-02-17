FROM rust:1.91-bookworm AS builder
WORKDIR /work

COPY rusty-pinch/Cargo.toml rusty-pinch/Cargo.lock ./rusty-pinch/
COPY rusty-pinch/src ./rusty-pinch/src
COPY rusty-pinch/assets ./rusty-pinch/assets
COPY rusty-pinch/docs ./rusty-pinch/docs

RUN cargo build --manifest-path rusty-pinch/Cargo.toml --release

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/rusty-pinch
COPY --from=builder /work/rusty-pinch/target/release/rusty-pinch /usr/local/bin/rusty-pinch
COPY rusty-pinch/.env.example ./.env.example
COPY rusty-pinch/docs ./docs
COPY rusty-pinch/assets ./assets

ENV RUSTY_PINCH_DATA_DIR=/var/lib/rusty-pinch/data
ENV RUSTY_PINCH_WORKSPACE=/var/lib/rusty-pinch/workspace
ENV RUSTY_PINCH_TELEMETRY_FILE=/var/lib/rusty-pinch/data/telemetry/latest.json

VOLUME ["/var/lib/rusty-pinch/data", "/var/lib/rusty-pinch/workspace"]
ENTRYPOINT ["rusty-pinch"]
CMD ["doctor"]
