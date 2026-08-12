#!/usr/bin/env bash
# Deploy imcp2 to an existing Amazon Linux 2023 (arm64) host WITHOUT Docker on the
# box: ships the prebuilt binary + static assets, then runs the app and Caddy as
# native systemd services. Re-runnable (idempotent) — also use it to push updates.
#
# Prereqs:
#   - deploy/native/build.sh has produced build-out/imcp2
#   - SSH access to the host as a sudo-capable user
#   - DNS A/AAAA for $DOMAIN points at the host's public address(es)
#   - Security group allows inbound 80 + 443 from the internet (ACME + HTTPS)
#
# Usage:
#   HOST=ec2-user@1.2.3.4 DOMAIN=mcp.example.com ACME_EMAIL=you@example.com \
#     deploy/native/deploy.sh
set -euo pipefail

: "${HOST:?set HOST=user@host}"
: "${DOMAIN:?set DOMAIN=fqdn}"
: "${ACME_EMAIL:?set ACME_EMAIL=email}"
REMOTE_DIR="${REMOTE_DIR:-/opt/imcp2}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=20 $HOST"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"

[ -x "$repo_root/build-out/imcp2" ] || { echo "build-out/imcp2 missing — run deploy/native/build.sh first"; exit 1; }

# Refuse to ship a binary built for the wrong architecture. Without this the unit
# installs cleanly and then crash-loops on "Exec format error", which reads like an
# app bug rather than a build-target mistake. Read the ELF header directly — no
# dependency on `file` or its output wording.
bin="$repo_root/build-out/imcp2"
# Match all four magic bytes (0x7F 'E' 'L' 'F'), not just the "ELF" that trails
# them: a file whose first byte is anything else is not an ELF object however its
# next three read. A file shorter than four bytes leaves the tail fields empty and
# fails here too.
read -r magic0 magic1 magic2 magic3 <<<"$(od -An -tu1 -j0 -N4 "$bin")"
[ "$magic0 $magic1 $magic2 $magic3" = "127 69 76 70" ] || {
  echo "ERROR: $bin is not an ELF binary — did build.sh write something else there?" >&2
  exit 1
}
# e_machine is a 2-byte field at offset 18, in the byte order named by EI_DATA
# (offset 5: 1 = little-endian, 2 = big-endian). Read the whole field rather than
# assuming it fits in the low byte: it does for our targets (x86-64 is 0x003E,
# aarch64 0x00B7) but not in general — LoongArch is 258, whose low byte is 2.
elf_data="$(od -An -tu1 -j5 -N1 "$bin" | tr -d '[:space:]')"
read -r m0 m1 <<<"$(od -An -tu1 -j18 -N2 "$bin")"
case "$elf_data" in
  1) elf_machine=$(( m0 | (m1 << 8) )) ;;
  2) elf_machine=$(( (m0 << 8) | m1 )) ;;
  *) elf_machine=-1 ;;
esac
case "$elf_machine" in
  62)  built_for=x86_64 ;;   # 0x003E EM_X86_64
  183) built_for=aarch64 ;;  # 0x00B7 EM_AARCH64
  *)   built_for="unknown(e_machine=$elf_machine)" ;;
esac
host_arch="$($SSH 'uname -m')"
if [ "$built_for" != "$host_arch" ]; then
  echo "ERROR: build-out/imcp2 is $built_for but $HOST is $host_arch." >&2
  case "$host_arch" in
    x86_64)  echo "       Rebuild with: ARCH=amd64 deploy/native/build.sh" >&2 ;;
    aarch64) echo "       Rebuild with: ARCH=arm64 deploy/native/build.sh" >&2 ;;
  esac
  exit 1
fi
echo ">> architecture ok ($built_for -> $HOST)"

echo ">> staging $REMOTE_DIR"
$SSH "sudo install -d -o \$(id -un) -g \$(id -gn) $REMOTE_DIR"

echo ">> shipping binary + static assets"
tar -C "$repo_root/build-out" -cf - imcp2 | $SSH "tar -C $REMOTE_DIR -xf - && chmod +x $REMOTE_DIR/imcp2"
tar -C "$repo_root" -cf - static | $SSH "tar -C $REMOTE_DIR -xf -"
# Status dashboard (Node tool): shipped as source — it has no build step.
tar -C "$repo_root" -cf - monitoring | $SSH "tar -C $REMOTE_DIR -xf -"

echo ">> rendering + installing units and Caddyfile, then (re)starting services"
# MCP_SERVE_BETA is set (to "1") only for the staging deployment, so /mcp-beta
# is exposed there and not in production; it defaults to empty (off) otherwise.
unit_mcp="$(sed -e "s#__PUBLIC_URL__#https://$DOMAIN#g" -e "s#__MCP_SERVE_BETA__#${MCP_SERVE_BETA:-}#g" -e "s#__OPENAI_APPS_CHALLENGE_TOKEN__#${OPENAI_APPS_CHALLENGE_TOKEN:-}#g" "$here/imcp2.service")"
caddyfile="$(sed -e "s#__DOMAIN__#$DOMAIN#g" -e "s#__ACME_EMAIL__#$ACME_EMAIL#g" "$here/Caddyfile")"
caddy_unit="$(cat "$here/caddy.service")"
# Pin the dashboard's SSRF allowlist to this deployment's own host. It used to be
# the PARENT domain (${DOMAIN#*.}) because the dashboard guessed the II origin by
# stripping the `mcp.` label — on mcp.internetcomputer.org that silently
# allowlisted all of internetcomputer.org. The II origins now come from the
# server's /version and are covered by the dashboard's built-in id.ai suffixes,
# so only the MCP host itself needs adding.
status_allowed="$DOMAIN"
unit_status="$(sed -e "s#__DOMAIN__#$DOMAIN#g" -e "s#__ALLOWED_HOSTS__#$status_allowed#g" "$here/imcp-status.service")"

$SSH "sudo bash -s" <<EOF
set -e
# ca-certificates: rustls platform verifier reads the system trust store
command -v update-ca-trust >/dev/null && dnf install -y -q ca-certificates >/dev/null 2>&1 || true

# --- app service ---
cat > /etc/systemd/system/imcp2.service <<'UNIT'
$unit_mcp
UNIT

# --- status dashboard service (Node) ---
# Install Node >= 20 if missing or too old (AL2023 provides the nodejs20 package).
node_major="\$(node -v 2>/dev/null | cut -c2- | cut -d. -f1)"
if [ -z "\$node_major" ] || [ "\$node_major" -lt 20 ] 2>/dev/null; then
  dnf install -y -q nodejs20 >/dev/null 2>&1 || dnf install -y -q nodejs >/dev/null 2>&1 || true
fi
cat > /etc/systemd/system/imcp-status.service <<'UNIT'
$unit_status
UNIT

# --- caddy: install static binary if missing, create user/dirs ---
if [ ! -x /usr/local/bin/caddy ]; then
  # Match the host, not the build host: this box may be Graviton or x86_64.
  case "\$(uname -m)" in
    aarch64) caddy_arch=arm64 ;;
    x86_64)  caddy_arch=amd64 ;;
    *) echo "unsupported architecture \$(uname -m) for caddy download" >&2; exit 1 ;;
  esac
  curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=\$caddy_arch" -o /usr/local/bin/caddy
  chmod +x /usr/local/bin/caddy
fi
id caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/caddy --shell /sbin/nologin caddy
mkdir -p /etc/caddy /var/lib/caddy && chown -R caddy:caddy /var/lib/caddy

cat > /etc/caddy/Caddyfile <<'CADDY'
$caddyfile
CADDY

cat > /etc/systemd/system/caddy.service <<'UNIT'
$caddy_unit
UNIT

# --- log retention: bound journald to the privacy policy's three months ---
# Everything this deployment logs (imcp2 tracing, Caddy, the dashboard) lands
# in journald, whose default retention is size-based with no time cap — logs
# could outlive the "retained for up to three months" the ICP MCP privacy
# policy states. MaxRetentionSec deletes an archived journal FILE once its
# newest entry passes the cap, so a file's oldest entries can overshoot by one
# rotation period; MaxFileSec=1week bounds that overshoot, making the worst
# case 12+1 weeks (~91 days). Size-based vacuuming may still delete entries
# sooner, which the policy's "up to" wording allows. A drop-in (not an edit to
# journald.conf) so the setting is owned by this deploy and idempotent.
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/90-imcp2-retention.conf <<'JOURNALD'
# Installed by imcp2 deploy/native/deploy.sh. Bounds log retention to match
# the ICP MCP privacy policy ("technical logs are retained for up to three
# months"): files rotate at most weekly and are deleted 12 weeks after their
# newest entry. Size pressure may delete them sooner.
[Journal]
MaxFileSec=1week
MaxRetentionSec=12week
JOURNALD
systemctl restart systemd-journald

# One-time migration off the pre-rename unit: imcp2.service replaces
# mcp-poc.service. Stop, disable, and remove the old unit (if present) so the
# two don't contend for :8000 on hosts first deployed before the rename.
if systemctl cat mcp-poc.service >/dev/null 2>&1; then
  systemctl disable --now mcp-poc.service || true
  rm -f /etc/systemd/system/mcp-poc.service
fi

systemctl daemon-reload
systemctl enable imcp2 caddy
systemctl restart imcp2
systemctl restart caddy
if command -v node >/dev/null 2>&1; then
  systemctl enable imcp-status
  systemctl restart imcp-status
else
  echo "WARNING: node not installed; imcp-status dashboard not started" >&2
fi
EOF

echo ">> deployed. Verifying..."
sleep 6
$SSH "systemctl is-active imcp2 caddy imcp-status; ss -tlnp 2>/dev/null | grep -E ':(80|443|8000|8137)\b' || true"
# The Prometheus exposition must be serving on the app's own port. It is gated on
# MCP_SERVE_METRICS (off by default, since a deployment with no proxy in front would
# publish it) and the unit hardcodes the opt-in, so a missing endpoint here is not an
# optional condition — it means the unit's environment did not take effect, or the
# app is not up. Fatal rather than a warning: the alternative is a scrape target that
# silently returns nothing, which looks exactly like a service with no traffic.
#
# What this proves and what it does not. Over loopback it proves the app serves the
# endpoint. It does NOT prove a scraper can reach it: that needs the private
# interface to accept TCP 8000 from the scraper's range, which is a security-group
# and VPN-routing question this script cannot answer — the deploy runs from a
# GitHub-hosted runner, which is not on the VPN and so cannot probe the host's
# private address at all. Do not read a green deploy as "the scrape path works". It
# remains the open question on the pull request that added this endpoint.
metrics_ok=""
for attempt in 1 2 3 4 5; do
  if $SSH "curl -fsS --max-time 5 http://127.0.0.1:8000/metrics | grep -q imcp2_build_info"; then
    metrics_ok=1
    echo "on-host loopback /metrics -> serving the exposition (attempt $attempt)"
    break
  fi
  sleep 3
done
if [ -z "$metrics_ok" ]; then
  echo "FATAL: on-host /metrics never served imcp2_build_info; MCP_SERVE_METRICS did not take effect, or the app is not up" >&2
  exit 1
fi

# The part of the scrape path that IS checkable from here: the host reaching itself
# on its private address, which proves the app bound 0.0.0.0 rather than loopback and
# that no host-local firewall drops the port. The remaining hop — the scraper's
# network reaching that address — cannot be tested from a GitHub-hosted runner.
#
# The address is never printed. This repository is public, so its Actions logs are
# too, and echoing a private address into them is the exact disclosure the
# repository was scrubbed to remove (see .github/scripts/scan-internal-identifiers.sh).
# curl's own errors would carry the URL, so its stderr is dropped and this reports
# only pass or fail.
#
# A warning, not fatal: users are served through Caddy over loopback either way, so
# this affects scraping alone — and the fix would be a security-group or firewall
# change, which failing a deploy does not bring any closer.
if $SSH 'addr="$(hostname -I 2>/dev/null | awk "{print \$1}")"; [ -n "$addr" ] && curl -fsS --max-time 5 "http://$addr:8000/metrics" 2>/dev/null | grep -q imcp2_build_info'; then
  echo "on-host private-address /metrics -> reachable off loopback (scraper ingress still unverified)"
else
  echo "WARNING: /metrics did not answer on the host's private address; a scraper cannot reach it (app bound to loopback, or a host firewall drops :8000)" >&2
fi

echo ">> external check:"
# --max-time on every external request. An origin that accepts the connection and
# then never finishes the response hangs curl indefinitely, and `|| true` does not
# help with that: it handles a non-zero exit, not the absence of one. A hung verify
# step wedges the deploy after the service has already been restarted, and (for the
# checks below) never reaches the retry loop or the failure it exists to report.
curl -sS --max-time 20 -o /dev/null -w "https://$DOMAIN/ -> HTTP %{http_code} (TLS verify %{ssl_verify_result})\n" "https://$DOMAIN/" || true
curl -sS --max-time 20 -o /dev/null -w "https://$DOMAIN/status/ -> HTTP %{http_code}\n" "https://$DOMAIN/status/" || true

# ...and it must NOT be reachable on the public origin. Caddy answers /metrics
# itself with a 404; drop that one block and the catch-all reverse-proxies it like
# any other path, publishing request volumes, session counts and process memory,
# and handing out a whole-registry gather per request. That is a config edit away
# at all times, so assert it on every deploy rather than trusting the file to
# still say what it said when it was written.
#
# The assertion is "exactly the configured 404", not "anything but 200". Absence of
# a 200 is not absence of exposure: if the catch-all is proxying this path and the
# app happens to answer 500, or if this curl never reached the origin at all
# (`000`), a not-200 check reports "not published" while having disproved nothing.
# So every other code fails too, retrying first because Caddy may still be
# reloading. A hard failure is right here — the deploy is idempotent and
# re-runnable, and a published exposition is worth stopping for.
#
# --max-time is load-bearing rather than hygiene: without it a stalled response
# hangs here forever, so this check never reaches its own retry or its own failure —
# the security assertion silently becomes a deadlock. A timeout yields `000`, which
# is not 404, so it retries and then fails, which is the honest verdict for an
# origin that would not answer.
hidden=""
for attempt in 1 2 3 4 5; do
  code="$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "https://$DOMAIN/metrics" || echo 000)"
  if [ "$code" = 200 ]; then
    echo "FATAL: https://$DOMAIN/metrics answered 200 — the Prometheus exposition is public" >&2
    exit 1
  fi
  if [ "$code" = 404 ]; then
    hidden=1
    echo "https://$DOMAIN/metrics -> HTTP 404 (not published, as intended)"
    break
  fi
  echo "https://$DOMAIN/metrics -> HTTP $code, expected 404 (attempt $attempt)" >&2
  sleep 3
done
if [ -z "$hidden" ]; then
  echo "FATAL: https://$DOMAIN/metrics never answered the configured 404, so its exposure is unproven" >&2
  exit 1
fi
