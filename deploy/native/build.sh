#!/usr/bin/env bash
# Cross-build the imcp2 binary for a Linux target without needing a local Rust
# cross-toolchain. Compiles inside a throwaway container of the target platform
# and exports just the binary to ./build-out/imcp2.
#
# We build against bullseye (glibc 2.31) on purpose: a binary linked against an
# older glibc runs on newer ones, so it works on Amazon Linux 2023 (glibc 2.34).
# Building against bookworm (2.36) would NOT run on AL2023.
#
# Target architecture is selected with $ARCH (arm64 or amd64). It must match the
# deploy target's `uname -m` — an arm64 binary on an x86_64 host (or vice versa)
# fails at exec with "Exec format error". deploy.sh re-checks this before
# installing, so a mismatch is caught rather than left as a crash-looping unit.
#
# Usage:  deploy/native/build.sh            # arm64 (Graviton) — the default
#         ARCH=amd64 deploy/native/build.sh # x86_64
# Output: build-out/imcp2
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

# Docker platform names, not `uname -m` names. Accept the uname spellings too,
# since that is what you get from inspecting the target host.
ARCH="${ARCH:-arm64}"
case "$ARCH" in
  arm64|aarch64) ARCH=arm64 ;;
  amd64|x86_64)  ARCH=amd64 ;;
  *) echo "unsupported ARCH=$ARCH (want arm64 or amd64)" >&2; exit 1 ;;
esac

# Commit + build time baked into the binary (surfaced at GET /version). Prefer an
# injected GIT_SHA (CI passes the resolved checkout SHA); fall back to the local
# checkout, then "unknown". BUILD_TIME is the build moment as Unix epoch seconds.
GIT_SHA="${GIT_SHA:-$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)}"
BUILD_TIME="${BUILD_TIME:-$(date +%s)}"

echo ">> building linux/$ARCH binary (bullseye/glibc 2.31) -> build-out/imcp2 (commit ${GIT_SHA})"
docker buildx build --platform "linux/$ARCH" --target bin \
  --build-arg GIT_SHA="$GIT_SHA" \
  --build-arg BUILD_TIME="$BUILD_TIME" \
  --build-arg ARCH="$ARCH" \
  --output type=local,dest=./build-out -f - . <<'DOCKERFILE'
ARG ARCH=arm64
FROM --platform=linux/${ARCH} rust:1-slim-bullseye AS build
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
COPY crates ./crates
RUN cargo build --release
FROM scratch AS bin
COPY --from=build /app/target/release/imcp2 /imcp2
DOCKERFILE

file build-out/imcp2
echo ">> done"
