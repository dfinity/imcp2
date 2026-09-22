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
# bullseye left LTS on 2026-08-31 and deb.debian.org has since pruned its
# -security pool: the suite's index still lists versions whose .deb files answer
# 404, so any apt-get that consults the live bullseye-security fails. Resolving
# from main alone does not work either: this image's preinstalled base packages
# are at the FINAL security versions (perl-base 5.32.1-4+deb11u5, libc6
# 2.31-13+deb11u14, ...), and main's perl / libc6-dev depend on exactly the
# older main versions of perl-base / libc6, which apt will not downgrade to.
# So install from snapshot.debian.org at the last moment both suites were
# complete (2026-08-30; the image was built 2026-08-25). Both suites are frozen,
# so that snapshot is the permanent final state of bullseye and the versions
# match what the image already has: nothing is downgraded and apt's inputs are
# fixed. (Only package resolution is reproducible: the rust:1-slim-bullseye tag
# is mutable and BUILD_TIME is stamped per build.) The snapshot's Release files
# have passed their Valid-Until,
# hence check-valid-until=no. With that check off, apt's only defence against a
# replayed older (still validly signed) index is the transport, so both lines
# use https; the rust image preinstalls ca-certificates, so that works before
# anything is installed. Acquire::Retries absorbs snapshot's occasional
# throttling. (The durable fix is a base image whose archive is alive and whose
# glibc still fits the host -- amazonlinux:2023 -- tracked separately.)
RUN printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260830T000000Z bullseye main\ndeb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20260830T000000Z bullseye-security main\n' > /etc/apt/sources.list \
    && rm -rf /etc/apt/sources.list.d/* \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
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
