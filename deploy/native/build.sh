#!/usr/bin/env bash
# Cross-build the imcp2 binary for linux/arm64 (AWS Graviton) without needing a
# local Rust cross-toolchain. Compiles inside a throwaway linux/arm64 container and
# exports just the binary to ./build-out/imcp2.
#
# We build against bullseye (glibc 2.31) on purpose: a binary linked against an
# older glibc runs on newer ones, so it works on Amazon Linux 2023 (glibc 2.34).
# Building against bookworm (2.36) would NOT run on AL2023.
#
# Usage:  deploy/native/build.sh
# Output: build-out/imcp2  (linux/arm64 ELF)
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# Commit + build time baked into the binary (surfaced at GET /version). Prefer an
# injected GIT_SHA (CI passes github.sha); fall back to the local checkout, then
# "unknown". BUILD_TIME is the build moment as Unix epoch seconds.
GIT_SHA="${GIT_SHA:-$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)}"
BUILD_TIME="${BUILD_TIME:-$(date +%s)}"

echo ">> building linux/arm64 binary (bullseye/glibc 2.31) -> build-out/imcp2 (commit ${GIT_SHA})"
docker buildx build --platform linux/arm64 --target bin \
  --build-arg GIT_SHA="$GIT_SHA" \
  --build-arg BUILD_TIME="$BUILD_TIME" \
  --output type=local,dest=./build-out -f - . <<'DOCKERFILE'
FROM --platform=linux/arm64 rust:1-slim-bullseye AS build
WORKDIR /app
# GIT_SHA / BUILD_TIME are read by option_env! in main.rs at compile time. Setting
# them as ENV (from the build-args) makes a changed commit bust the cargo layer.
ARG GIT_SHA=unknown
ARG BUILD_TIME
ENV GIT_SHA=${GIT_SHA}
ENV BUILD_TIME=${BUILD_TIME}
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake clang libclang-dev perl pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN cargo build --release
FROM scratch AS bin
COPY --from=build /app/target/release/imcp2 /imcp2
DOCKERFILE

file build-out/imcp2
echo ">> done"
