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
# Dedicated UID for the dashboard: it can carry a Statuspage API key in its
# environment, so it must not share a user with the internet-facing imcp2
# service (same-UID processes can read each other's /proc/<pid>/environ).
id imcp-status >/dev/null 2>&1 || useradd --system --no-create-home --shell /sbin/nologin imcp-status
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
# The unit hardcodes MCP_SERVE_METRICS=1, so a missing /metrics means the
# environment did not take effect or the app is not up — fatal, or the scrape
# target silently returns nothing. This proves the app serves the endpoint; it
# does NOT prove a scraper can reach it (security-group ingress on TCP 8000
# cannot be probed from a GitHub-hosted runner, which is not on the VPN).
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

# The host reaching itself on its private address proves the app bound 0.0.0.0
# and no host-local firewall drops :8000. The address is never printed — this
# repo's Actions logs are public, and curl's errors would carry the URL, so its
# stderr is dropped. A warning, not fatal: only scraping is affected, and the
# remedy is a firewall change a failed deploy would not bring closer.
if $SSH 'addr="$(hostname -I 2>/dev/null | awk "{print \$1}")"; [ -n "$addr" ] && curl -fsS --max-time 5 "http://$addr:8000/metrics" 2>/dev/null | grep -q imcp2_build_info'; then
  echo "on-host private-address /metrics -> reachable off loopback (scraper ingress still unverified)"
else
  echo "WARNING: /metrics did not answer on the host's private address; a scraper cannot reach it (app bound to loopback, or a host firewall drops :8000)" >&2
fi

echo ">> external check:"
# --max-time on every external request: an origin that accepts the connection but
# never finishes the response would otherwise hang the deploy (`|| true` handles a
# non-zero exit, not the absence of one).
curl -sS --max-time 20 -o /dev/null -w "https://$DOMAIN/ -> HTTP %{http_code} (TLS verify %{ssl_verify_result})\n" "https://$DOMAIN/" || true
curl -sS --max-time 20 -o /dev/null -w "https://$DOMAIN/status/ -> HTTP %{http_code}\n" "https://$DOMAIN/status/" || true

# ...and /metrics must NOT be reachable on the public origin. Caddy answers it
# with a 404; losing that one block would publish the exposition, so assert it on
# every deploy. The assertion is "exactly the configured 404": any other code —
# a proxied 500, a `000` from an unreachable or stalled origin — has not disproved
# exposure, so it retries (Caddy may be reloading) and then fails hard.
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
