# Native (Docker-free) deploy of imcp2

Run `imcp2` directly on an **existing** Amazon Linux 2023 host as native `systemd`
services — no Docker on the box. Useful when the instance already exists (e.g. in a
managed VPC) and you just want to put the app on it. The repo's
[`Dockerfile`](../../Dockerfile) remains the container-based alternative.

```
   build.sh  ─────►  build-out/imcp2        (cross-built linux/arm64 or amd64 binary)
   deploy.sh ─────►  /opt/imcp2/imcp2            + systemd: imcp2.service
                     /opt/imcp2/monitoring         (staging copy of the dashboard source)
                     /opt/imcp-status              + systemd: imcp-status.service (dashboard;
                                                     root-owned executable copy, run as the
                                                     dedicated imcp-status user)
                     /usr/local/bin/caddy          + systemd: caddy.service (TLS)
```

Hosts are **arm64 (Graviton)**. Keep any additional host on the same architecture:
`aws-lc-sys` and `ring` carry per-arch assembly, so a host differing from the one
that changes are rehearsed on would leave the crypto paths the auth flow depends
on unexercised. `build.sh` can target `amd64` if you ever need it (`ARCH=amd64`), and `deploy.sh`
compares the built binary's ELF header against the host's `uname -m` and aborts on a
mismatch — otherwise the unit installs fine and then crash-loops on
`Exec format error`, which reads like an app bug rather than a build-target mistake.

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
#    Use ARCH=amd64 for an x86_64 target.
deploy/native/build.sh

# 2. Ship it and stand up the services.
HOST=ec2-user@<host> DOMAIN=mcp.example.com ACME_EMAIL=you@example.com \
  deploy/native/deploy.sh
```

`deploy.sh` is idempotent — re-run it to push a new build (it restarts `imcp2`).

## Why cross-build against bullseye

`build.sh` compiles in a `rust:1-slim-bullseye` container (glibc **2.31**). A binary
linked against an older glibc runs on newer ones, so it works on AL2023 (glibc 2.34).
Building against bookworm (glibc 2.36) would fail at runtime on AL2023. Pick a runner
matching `ARCH` so the build stays native (no QEMU) — it handles the heavy deps
(`aws-lc-sys`, `ring`, `rustls`), and emulating the other architecture is several
times slower.

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

**Do not settle for an AAAA-only deployment.** A host with a public IPv6 but only a
private IPv4 can obtain a Let's Encrypt cert (ACME validates over IPv6 happily) and
will look healthy from any v6-capable network — while being entirely unreachable from
IPv4-only clients. For a public MCP server that is a silent outage for a large share
of callers, and the `/status/` dashboard will not reveal it if the prober itself has
v6. This is not hypothetical: both hosts sat in exactly that state for a while,
unnoticed because every observer had v6.

**The two families are not symmetric, so "publish both" is the wrong rule.** What
matters is that **IPv4 works**. An `A`-only deployment is fine in practice, because
IPv4 reaches effectively everyone; the IPv6-only networks that do exist are mostly
mobile carriers, and those generally run NAT64/DNS64 so their clients can still reach
v4-only services. That translation is a property of the *client's* network, though, not
something this deployment provides — a v6-only client whose network lacks it cannot
reach an `A`-only host at all. So publish an `AAAA` too whenever the v6 path is
genuinely reachable; just never publish `AAAA` *instead* of `A`. Production is `A`-only
today because its IPv4 path was repaired and its `AAAA` record removed at the same time.

Verify **IPv4 specifically**, from a network that has no v6 of its own if you can. A
v6-capable client will happily mask a dead v4 path, and so will any check you run from
inside a VPN or a cloud shell.

### Verifying dual-stack reachability

Three things bite here, none of them visible from inside the box:

**An Elastic IP only works if the ENI's subnet routes to an IGW.** AWS lets you
associate an EIP with an instance in a NAT-routed private subnet, and nothing
complains — but inbound to it silently blackholes. The instance can't tell you
either: an EIP is 1:1 NAT at the gateway, so `ip addr` correctly shows only the
private address whether the EIP works or not. Check the egress path instead:

```sh
curl -4 -s -m5 ifconfig.me    # expect the Elastic IP itself
```

If that returns the EIP, the subnet has an IGW route and inbound will work. If it
returns anything else, egress is via a NAT gateway, the EIP is not on the path, and
no security-group change will make inbound reach it.

**IPv4 and IPv6 security-group rules are separate entries.** Opening 80/443 to
`0.0.0.0/0` does nothing for v6; `::/0` needs its own rules. Miss them and ACME may
still succeed over whichever family works, leaving a valid cert on a half-reachable
host.

**Check both families from outside** once DNS is published — a v6-capable network
will happily mask a broken v4 path:

```sh
curl -4 -sS -o /dev/null -w 'v4 -> %{http_code}\n' https://$DOMAIN/
curl -6 -sS -o /dev/null -w 'v6 -> %{http_code}\n' https://$DOMAIN/
```

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

## Automated deploys: staging on `main`, production on `release-*`

Two hosts, two triggers, one shared mechanism:

| Workflow | Trigger | Target | Environment |
|---|---|---|---|
| [`deploy.yml`](../../.github/workflows/deploy.yml) | push to `main` | staging | `staging` |
| [`deploy-release.yml`](../../.github/workflows/deploy-release.yml) | push tag `release-*` | production | `production` |

Staging tracks `main` continuously so changes get exercised on a real host; production
only ever moves when someone cuts a tag, so the live revision is always a named,
reproducible point in history.

The staging deploy additionally sets `MCP_SERVE_BETA=1` (via `deploy-native.yml`,
substituted into the unit by `deploy.sh`), so staging serves the beta Internet
Identity instance at `/mcp-beta` alongside the production `/mcp`. Production leaves
it unset, so it serves `/mcp` (production II) alone.

Both hosts set `MCP_SERVE_METRICS=1` (hardcoded in the unit), so the app serves
the Prometheus exposition at `/metrics` on its own port for a scraper to reach on
the host's private address. Caddy answers `/metrics` on the public origin with a
404, which is what keeps it off the internet.

The mechanics live in [`deploy-native.yml`](../../.github/workflows/deploy-native.yml),
a reusable workflow both call. It first runs the status dashboard's unit tests (a
regression there stops the rollout), cross-builds the binary with `build.sh`, then runs
`deploy.sh` over SSH — which ships and (re)starts the app and the dashboard service. A
`concurrency` group per environment serializes deploys so two never overlap.

### Cutting a release

```sh
git tag release-2026-07-27 <commit>   # any suffix; the `release-` prefix is the trigger
git push origin release-2026-07-27
```

**Rolling back:** re-run `deploy-release.yml` from the Actions tab with an earlier tag
as the `ref` input. That rebuilds and ships that exact commit — no revert commit, no
new tag.

### The build/ship split

`deploy-native.yml` runs as two jobs. **build** runs on a GitHub-hosted runner matching
`inputs.arch` — it needs Docker for `build.sh` and does the expensive Rust compile.
**ship** runs wherever the target host is reachable and needs only `ssh` + `tar`, no
Docker and no Rust.

That split is what lets the ship job run on a **self-hosted runner**, which is how both
environments deploy: the host is reached on its private address over the VPN rather than
over the public internet. The heavy build stays on hosted infrastructure and only the
binary crosses into the private network. The ship runner's own architecture is
irrelevant; it never executes the binary.

#### Narrowing inbound SSH

Inbound SSH from the public internet is **closed** on both hosts. Each one has two
network interfaces — a public-facing one carrying the HTTPS address, and a private one the
deploy reaches over the VPN — and security groups attach per-interface, so the public one
carries a group permitting `80`/`443` only. Verified from outside the VPN: `22` times out
where it previously reached `sshd`. See #91 for the before/after evidence.

That split only works if `DEPLOY_HOST` names the host's **private** address. Point it at
the public FQDN and the deploy leaves over the internet instead of the VPN and arrives on
the public interface, where `22` is no longer permitted — which is exactly how staging was
configured, unnoticed, until that change made it fail. The secret's description in
[`deploy-native.yml`](../../.github/workflows/deploy-native.yml) now says so.

What remains open is `22` on the private interface, so anything that can route to the
host's private address still reaches SSH: the VPN and the on-prem estate. That is accepted
as the current state.

To see what source the host actually sees, ask the host — the ship job's **Report source
address as seen by the host** step does this via `$SSH_CLIENT` on every run, or after the
fact:

```sh
sudo journalctl -u sshd --since '15 minutes ago' | grep 'Accepted publickey'
```

Do not substitute `curl ifconfig.me` on the runner: that reports public internet egress,
which the VPN path does not use, and the two are unrelated.

**The remaining step is to narrow the rule to the private range and delete the
world-facing one.** Deploys taking the VPN path have so far presented sources inside that
range, which the hosts already permit — but confirm it across both runner clusters before
acting, because Calico source-NATs each pod to whichever worker node it landed on, node
addresses are provisioned dynamically rather than declared, the two clusters are separate
sites with separate ranges, and that SNAT behaviour is an unpinned upstream default rather
than a contract. A prefix that looks right today can stop matching after routine cluster
maintenance, and it fails as a deploy timeout rather than as anything self-explanatory.
When adding the rule, add our own rather than relying on the existing one, which belongs
to another team and can change without reference to this deployment.

An earlier attempt at this removed the world-facing rule *before* any of the above was
understood, and broke the deploy. The cause was staging's public-FQDN misconfiguration
rather than the rule, but the lesson stands: measure the source first.

Considered and declined: reaching the hosts through **AWS Systems Manager Session
Manager**, which needs no inbound port at all and records each session in CloudTrail.
`ssh` keeps working over it via a `ProxyCommand`, so `deploy.sh` would need no changes —
only the workflow's SSH setup. It is the stronger end state, but it was judged
over-engineering for the residual risk once internet-facing SSH was closed. Revisit if
that judgement changes. Two alternatives that do not work at all: a job that opens a
short-lived rule for its own address cannot discover which address to open, and a bastion
still needs inbound SSH from the same sources.

The `::/0` half of the port-22 rule has been removed: the IPsec tunnels and BGP sessions
to this VPC are IPv4-only, so the deploy never arrives over IPv6 and that half permitted
nothing but internet-sourced attempts. The rule permitting `22` from the private range has
no IPv6 entry either, so nothing on the v6 side was relying on it.

`ship_runs_on` takes a JSON string, so a bare name is `'"dind-small"'` and a label set
is `'["self-hosted","linux"]'`. Both deploys use the bare-name form, because the org's
self-hosted capacity is **ARC runner scale sets** — a scale set is selected by its name
alone and carries none of the `self-hosted` / `linux` / `x64` labels that classic
runners get automatically. A label list therefore matches no scale set however the pool
is labelled, and a job requesting one simply queues forever rather than failing, which
reads like a stuck runner rather than a misconfigured selector.

After each deploy the ship job reads `GET /version` on the host and asserts the
reported `commit` matches what was just built, so a `systemctl restart` that silently
kept the old binary fails the run instead of passing quietly.

### Secrets

Staging and production take separate secrets so a production rollout can never be
pointed at the wrong box by a stale value. Both hosts are reached on their **private**
addresses, since the ship job runs inside the VPN.

| Staging | Production | Value |
|---|---|---|
| `DEPLOY_SSH_KEY` | `PROD_DEPLOY_SSH_KEY` | Private SSH key for the sudo-capable host user |
| `DEPLOY_HOST` | `PROD_DEPLOY_HOST` | `user@host`, the host's private address |
| `DEPLOY_DOMAIN` | `PROD_DEPLOY_DOMAIN` | Public FQDN served over HTTPS |
| `DEPLOY_ACME_EMAIL` | `PROD_DEPLOY_ACME_EMAIL` | Email for Let's Encrypt / ACME |
| `DEPLOY_KNOWN_HOSTS` | `PROD_DEPLOY_KNOWN_HOSTS` | *(optional)* output of `ssh-keyscan <host>`; pin it to avoid trust-on-first-use |
| `OPENAI_APPS_CHALLENGE_TOKEN` | *(same name)* | *(optional)* OpenAI Apps domain-verification token, served at `/.well-known/openai-apps-challenge` (404 while unset). Submission-specific rather than host-specific, so one repository-level secret feeds both environments |

One setting is a GitHub Environment **variable** rather than a secret (**Settings →
Environments → *staging* / *production* → Variables**); `deploy.sh` renders it into
the unit like the secrets above:

| Variable | Value |
|---|---|
| `OAUTH_CIMD_ENABLED` | `1` to advertise Client ID Metadata Documents — the registration mode Claude and ChatGPT prefer over DCR — on that environment; unset or empty is off. Off by default so a routine deploy never switches the directory clients over by itself: enable it on staging first, then production. The value is rendered into the unit at deploy time and read once at start-up, so to roll back, unset (or clear) the variable **and redeploy** — `workflow_dispatch` with the same ref is enough, no rebuild; changing the variable alone changes nothing on the host |

> **Set these as repository-level secrets** (**Settings → Secrets and variables →
> Actions**). The callers pass them into the reusable workflow, and a job that calls
> one with `uses:` cannot itself declare an `environment:` — so `${{ secrets.* }}` in
> the caller only resolves repository and organization secrets. An environment-scoped
> secret referenced there arrives empty.
>
> Environment secrets are *not* unusable, though. The `ship` job inside
> `deploy-native.yml` does set `environment:`, and a secret defined on that
> environment resolves there — and **takes precedence over the value passed in by the
> caller**. So defining, say, `DEPLOY_HOST` on both the `staging` environment and at
> repository level is not additive: the environment copy silently wins inside `ship`.
> Pick one place per secret. Repository level is what the table above assumes, and
> keeps the two callers symmetric.
>
> Environment **protection rules** are unaffected either way — see the approval gate
> below.

The host prerequisites above (DNS, inbound 80/443, sudo SSH user) still apply — the
workflow only automates the build-and-ship step, not provisioning the box.

### Approval gate

Each deploy job runs in its named GitHub Environment. To require manual approval
before production rollouts, go to **Settings → Environments → production** and add
yourself (or a team) as a **Required reviewer**. Until a reviewer is configured the
environment imposes no gate, so a `release-*` tag deploys straight through.

## Operating

```sh
ssh <host>
sudo systemctl status imcp2 caddy imcp-status
sudo journalctl -u imcp2 -f      # app logs
sudo journalctl -u caddy -f        # TLS / cert logs
sudo journalctl -u imcp-status -f  # status dashboard logs
```

The dashboard is at `https://<domain>/status/` and shows staging and production
side by side (the same two columns on every host). To change the monitored set,
its II pins or the SSRF allowlist, set `STATUS_TARGETS` / `STATUS_TARGET_II` for
`deploy.sh` or edit the `Environment=` lines in
`/etc/systemd/system/imcp-status.service` and `systemctl restart imcp-status`.
The optional Statuspage pusher (`/etc/imcp-status/statuspage.env`) drives its
component from the first configured instance unless `STATUSPAGE_TARGET` names
another — set it to `production` there, so the public page reflects production.

## Files

| File | Purpose |
|---|---|
| `build.sh` | Cross-build `build-out/imcp2` (linux/arm64, bullseye glibc) |
| `deploy.sh` | Ship binary + `monitoring/`, render & install units/Caddyfile, (re)start services |
| `imcp2.service` | systemd unit for the app (`__PUBLIC_URL__` substituted at deploy) |
| `imcp-status.service` | systemd unit for the status dashboard (`__TARGETS__`, `__TARGET_II__`, `__ALLOWED_HOSTS__` substituted at deploy) |
| `caddy.service` | systemd unit for Caddy |
| `Caddyfile` | Caddy config (`__DOMAIN__`, `__ACME_EMAIL__` substituted at deploy) |
