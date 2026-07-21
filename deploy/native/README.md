# Native (Docker-free) deploy of imcp2

Run `imcp2` directly on an **existing** Amazon Linux 2023 (arm64) host as native
`systemd` services — no Docker on the box. Useful when the instance already exists
(e.g. in a managed VPC) and you just want to put the app on it. The repo's
[`Dockerfile`](../../Dockerfile) remains the container-based alternative.

```
   build.sh  ─────►  build-out/imcp2        (cross-built linux/arm64 binary)
   deploy.sh ─────►  /opt/imcp2/{imcp2,static}   + systemd: imcp2.service
                     /opt/imcp2/monitoring         + systemd: imcp-status.service (dashboard)
                     /usr/local/bin/caddy          + systemd: caddy.service (TLS)
```

`imcp2` listens on `127.0.0.1:8000`/`0.0.0.0:8000`; **Caddy** terminates HTTPS for
your domain and reverse-proxies to it, obtaining a Let's Encrypt cert automatically.

The **status dashboard** (`monitoring/mcp-status`) is also shipped and run as a
Node systemd service (`imcp-status.service`) bound to `127.0.0.1:8137`. Caddy
publishes it at **`https://$DOMAIN/status/`**, where it probes the deployment's
own public endpoints and the linked Internet Identity instance. Node ≥ 20 is
installed automatically on first deploy if absent; the dashboard has no build
step and no third-party dependencies.

## Quick start

```sh
# 1. Cross-build the arm64 binary (needs Docker locally; compiles in a container).
deploy/native/build.sh

# 2. Ship it and stand up the services.
HOST=ec2-user@<host> DOMAIN=mcp.example.com ACME_EMAIL=you@example.com \
  deploy/native/deploy.sh
```

`deploy.sh` is idempotent — re-run it to push a new build (it restarts `imcp2`).

## Why cross-build against bullseye

`build.sh` compiles in a `rust:1-slim-bullseye` container (glibc **2.31**). A binary
linked against an older glibc runs on newer ones, so it works on AL2023 (glibc 2.34).
Building against bookworm (glibc 2.36) would fail at runtime on AL2023. The build is
native arm64 (no QEMU) and handles the heavy deps (`aws-lc-sys`, `ring`, `rustls`).

## Host prerequisites

- **Inbound 80 + 443 from the internet** in the security group. Port 80 and 443 are
  both used for ACME (Caddy prefers TLS-ALPN-01 on 443, falls back to HTTP-01 on 80)
  and 443 serves traffic; 80 also does the HTTP→HTTPS redirect.
- **DNS**: an `A` (and/or `AAAA`) record for `$DOMAIN` pointing at the host's public
  address. Let's Encrypt validates over whichever the record resolves to.
- A sudo-capable SSH user (the units run the app as `ec2-user`).

### Networking note for private-subnet / managed VPCs

If the instance's primary interface is in a **private subnet** (default IPv4 route via
a NAT gateway), its IPv4 is outbound-only and **not reachable from the internet** — only
IPv6 (if the subnet routes `::/0` to an Internet Gateway) is publicly reachable. To get
public IPv4, attach a **second ENI in a public subnet** (route table `0.0.0.0/0 → IGW`)
and associate an Elastic IP; AL2023's `amazon-ec2-net-utils` auto-configures the
source-based policy routing for the secondary interface. Point `$DOMAIN` at that EIP.

## Handing this off (deploying via a Claude Code session)

If you want someone else to run the deploy in a Claude session, here's what they
need ready and what to prompt. **Note that SSH access ≠ public web reachability** —
being able to `ssh` in does not mean 80/443 are reachable from the internet.

**Have ready:**
1. An EC2 instance already launched — **Amazon Linux 2023, arm64** (Graviton).
2. SSH access as a sudo-capable user (`ec2-user`); confirm `ssh ec2-user@<host>` works.
3. This repo checked out locally (with `deploy/native/`).
4. **Docker running on their workstation** (for the cross-build in `build.sh`).
5. A domain (FQDN) + an ACME email for Let's Encrypt.
6. **DNS already set**: `A`/`AAAA` for the domain → the instance's public address.
7. **Inbound 80 + 443 open to the internet**, verified from an outside network.
8. *Only if the box isn't already publicly reachable* (e.g. private/managed subnet):
   AWS CLI creds with EC2 networking permissions — Claude must first build the public
   path (public subnet → IGW, secondary ENI, Elastic IP, SG for 80/443/22). See the
   networking note above.

**Prompt (box already publicly reachable):**

> Do a native (no-Docker) deploy of `imcp2` to my EC2 instance using `deploy/native`.
> - Repo: `/path/to/imcp2`
> - Host: `ec2-user@<ip-or-fqdn>` — I have SSH key trust, sudo works
> - Domain: `mcp.example.com`, with `A`/`AAAA` already pointing at the host
> - ACME email: `you@example.com`
> - Amazon Linux 2023, arm64; inbound 80/443 already open to the internet.
>
> Cross-build with `deploy/native/build.sh`, then run `deploy/native/deploy.sh`.
> Verify the cert issues and `https://mcp.example.com/` returns 200 from outside.

**If the instance is in a private subnet,** also tell Claude the instance id + region,
that there's no public IPv4 inbound, and that AWS creds are granted — ask it to make
the box publicly reachable and report the address to set DNS *before* the deploy.

## Automated redeploy on push to `main`

[`.github/workflows/deploy.yml`](../../.github/workflows/deploy.yml) runs this same
native deploy automatically on every push to `main` (and can be re-run by hand from the
Actions tab). It first runs the status dashboard's unit tests (a regression there stops
the rollout), cross-builds the arm64 binary with `build.sh`, then runs `deploy.sh`
over SSH — which ships and (re)starts both the app and the dashboard service. A
`concurrency` group serializes deploys so two never overlap.

Configure these repository secrets (**Settings → Secrets and variables → Actions**):

| Secret | Value |
|---|---|
| `DEPLOY_SSH_KEY` | Private SSH key for the sudo-capable host user (e.g. `ec2-user`) |
| `DEPLOY_HOST` | `user@host`, e.g. `ec2-user@1.2.3.4` (the `HOST` deploy.sh expects) |
| `DEPLOY_DOMAIN` | Public FQDN served over HTTPS, e.g. `mcp.example.com` |
| `DEPLOY_ACME_EMAIL` | Email for Let's Encrypt / ACME |
| `DEPLOY_KNOWN_HOSTS` | *(optional)* output of `ssh-keyscan <host>`; pin it to avoid trust-on-first-use. If omitted, the host key is fetched at run time. |

The host prerequisites above (DNS, inbound 80/443, sudo SSH user) still apply — the
workflow only automates the build-and-ship step, not provisioning the box.

### Approval gate

The deploy job runs in the GitHub **`production` environment**. To require a manual
approval before each deploy, go to **Settings → Environments → production** and add
yourself (or a team) as a **Required reviewer**. Until a reviewer is configured the
environment imposes no gate, so the deploy still runs automatically on push to `main`.
You can also scope the environment's secrets/branches there if you'd rather not keep
`DEPLOY_*` as repo-wide secrets.

## Operating

```sh
ssh <host>
sudo systemctl status imcp2 caddy imcp-status
sudo journalctl -u imcp2 -f      # app logs
sudo journalctl -u caddy -f        # TLS / cert logs
sudo journalctl -u imcp-status -f  # status dashboard logs
```

The dashboard is at `https://<domain>/status/`. To probe a different target or
extend its SSRF allowlist, edit `Environment=`/`ExecStart=` in
`/etc/systemd/system/imcp-status.service` and `systemctl restart imcp-status`.

## Files

| File | Purpose |
|---|---|
| `build.sh` | Cross-build `build-out/imcp2` (linux/arm64, bullseye glibc) |
| `deploy.sh` | Ship binary + `static/` + `monitoring/`, render & install units/Caddyfile, (re)start services |
| `imcp2.service` | systemd unit for the app (`__PUBLIC_URL__` substituted at deploy) |
| `imcp-status.service` | systemd unit for the status dashboard (`__DOMAIN__`, `__ALLOWED_HOSTS__` substituted at deploy) |
| `caddy.service` | systemd unit for Caddy |
| `Caddyfile` | Caddy config (`__DOMAIN__`, `__ACME_EMAIL__` substituted at deploy) |
