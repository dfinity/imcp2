# Multi-stage build for the MCP server. The WASM Candid codec under static/wasm
# is prebuilt and committed, so no wasm toolchain is needed here.
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
# static/ is needed at build time too: main.rs/auth.rs include_str! the HTML pages.
COPY static ./static
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
# ca-certificates: TLS to the IC boundary node (icp-api.io) via rustls' platform verifier.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/imcp2 /usr/local/bin/imcp2
# Static assets (signing frontend + WASM codec) are served relative to the workdir.
COPY static ./static
ENV RUST_LOG=info
# PaaS injects $PORT; the server honours it (default 8000). PUBLIC_URL must be set
# to the deployment's public https URL so OAuth discovery + the /app link are correct.
CMD ["imcp2"]
