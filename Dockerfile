# Multi-stage build for the MCP server. Everything the binary serves is
# compiled in via include_str!, so the runtime image carries only the binary.
FROM rust:1-slim-bookworm AS build
WORKDIR /app
# GIT_SHA / BUILD_TIME are baked into the binary (option_env! in main.rs) and
# surfaced at GET /version; pass with --build-arg GIT_SHA=$(git rev-parse HEAD)
# --build-arg BUILD_TIME=$(date +%s).
ARG GIT_SHA=unknown
ARG BUILD_TIME
ENV GIT_SHA=${GIT_SHA}
ENV BUILD_TIME=${BUILD_TIME}
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# The workspace member crates (imcp2-core carries the tool surface and its
# compiled-in candid/OQL references under crates/imcp2-core/static).
COPY crates ./crates
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
# ca-certificates: TLS to the IC boundary node (icp-api.io) via rustls' platform verifier.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/imcp2 /usr/local/bin/imcp2
# See deploy/native/imcp2.service: the per-request log line is debug-level, and
# is worth keeping on a deployed host.
ENV RUST_LOG=info,imcp2::metrics=debug
# PaaS injects $PORT; the server honours it (default 8000). PUBLIC_URL must be set
# to the deployment's public https URL so OAuth discovery + the /app link are correct.
CMD ["imcp2"]
