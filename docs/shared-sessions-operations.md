# Shared sessions: operations runbook

Status: **draft**, for release 0.7.0, uncommitted on `igor/session-sharing`.

This runbook is for the on-call engineer who runs imcp2 on the staging and production hosts and
operates the session canister. It assumes you know `dfx` and systemd, but not this design. The
design record is [scoping-shared-sessions.md](scoping-shared-sessions.md). The host deploy is
described in [deploy/native/README.md](../deploy/native/README.md), and the canister workflow in
the header of [deploy-session-canister.yml](../.github/workflows/deploy-session-canister.yml).

Everything this runbook describes exists in the code: the canister, its reproducible build, the
release assets, the `deploy-session-canister.yml` workflow, the staging host's systemd drop-in, and
in the binary its configuration, `imcp2 shared-config-check`, `imcp2 shared-key-check`,
`/ready/shared` and the `/version` block. It has been exercised locally (tests, and a smoke run
against a local PocketIC), not yet on staging. A `TODO(reconcile)` comment marks what only staging
or an owner can settle: a measurement, an ownership decision, a threshold.

## Contents

1. [How it works in 60 seconds](#1-how-it-works-in-60-seconds)
2. [Reference](#2-reference)
3. [Creating the canister](#3-creating-the-canister)
4. [Keys](#4-keys)
5. [Enabling, disabling and rolling back imcp2](#5-enabling-disabling-and-rolling-back-imcp2)
6. [Configuration changes](#6-configuration-changes)
7. [Canister upgrades and rollback](#7-canister-upgrades-and-rollback)
8. [Incidents](#8-incidents)
9. [Monitoring](#9-monitoring)
10. [Appendix A: a key check without the binary](#appendix-a-a-key-check-without-the-binary)
11. [Appendix B: Candid arguments](#appendix-b-candid-arguments)

## 1. How it works in 60 seconds

- **One canister per deployment.** Several imcp2 nodes sit behind a load balancer that is not
  sticky, and share their OAuth / Internet Identity sessions through **one session canister**.
  Staging and prod each have their own.
- **A sign-in makes two canister update calls,** about 2 s each:
  - `put_session` at `/oauth/connect/redeem` stores the session record;
  - `consume_code` at `/oauth/token` makes the authorization code single-use and moves the
    record into the canister's **change feed**.

  The rest of the sign-in makes no canister call. The connect cookie, the code, the access token
  and the client id are self-contained.
- **Every node mirrors the feed.** It polls by query every second and confirms with replicated
  reads (at most 30 s apart while anything changes, every 5 minutes otherwise). `/mcp` makes no
  canister call for a mirrored session; a miss reads through by query. Nothing is kept on disk: a
  restarted node rebuilds its mirror from the canister, and **a restart signs nobody out**.
- **Records are sealed** (XChaCha20-Poly1305) under a **keyring** that every node holds:
  `kid:base64` entries. The canister never sees inside a record. It publishes one **key check**
  per kid, and a node seals only under a kid whose check matches its own key (`Verified`).
- **Each node has its own identity** (a PEM), which must be on the canister's allow-list
  (`authorized`, at most 32 principals). Only controllers can call the `admin_*` methods. Nodes
  cannot delete anything.
- **Trouble answers 503, not 401.** An outage, replication lag, key drift or a newer format gets
  `503` with `Retry-After: 5`: at `/mcp` the body `{"error":"temporarily_unavailable"}` and no
  `WWW-Authenticate`, so MCP clients retry rather than sign in again. Only an authoritative fact
  gets 401, which makes the client sign in again: the session was purged, its grant expired, or
  its kid was retired.
- **The canister purges on a timer,** every 60 s by default:
  - sign-ins abandoned for 6 minutes;
  - sessions at grant expiry (II grants last at most 30 days);
  - idle sessions, but only if the idle timeout is lowered below its 30-day default.
- **Admin changes go through the workflow.** Every one runs in the `admin` mode of
  `deploy-session-canister.yml`, and that mode's run history is the **admin journal**.
- **A snapshot load is disaster recovery only.**
  - The canister detects it from its own history and bumps its `epoch`.
  - Every node then discards its mirror and resyncs.
  - Sessions created after the snapshot must sign in again.
  - Admin changes made since the snapshot are replayed from the journal.
- **With `IMCP2_SHARED_CANISTER_ID` unset, imcp2 behaves as before.** The one exception: it
  still accepts the `imcp2_dcr1.` client ids that shared mode issues.

## 2. Reference

### 2.1 Environment variables of the imcp2 binary

`imcp2 --help` lists them too. A blank value counts as unset.

| Variable | Meaning | Default |
|---|---|---|
| `IMCP2_SHARED_CANISTER_ID` | Turns shared mode on: the session canister's id. It must be a canister id; the anonymous, management (`aaaaa-aa`) and self-authenticating principals are refused. Unset, imcp2 behaves as before. | unset |
| `IMCP2_SHARED_IDENTITY_PEM_FILE` | This node's identity for the canister, one per node, on the allow-list ([3.2](#32-generate-one-identity-per-node)). An unencrypted secp256k1 key (`EC PRIVATE KEY` as `openssl ecparam` or dfx write it, or PKCS#8 `PRIVATE KEY`) or Ed25519 key (PKCS#8, as `openssl genpkey -algorithm ed25519` writes it). Encrypted keys, other curves (P-256 included) and algorithms, and files with more than one private key are refused. | required in shared mode |
| `IMCP2_SHARED_KEYS_FILE` (preferred) | A file holding the keyring ([4.1](#41-generate-a-key-and-the-keyring)). | exactly one of the two |
| `IMCP2_SHARED_KEYS` | The keyring inline, e.g. `2:<base64>,1:<base64>`. Prefer the file: processes running as the same user can read each other's environment. Setting both is an error. | |
| `IMCP2_SHARED_IC_URL` | The IC API endpoint the node calls the canister through: an `http://` or `https://` URL with a host. | `https://icp-api.io` |
| `IMCP2_SHARED_FETCH_ROOT_KEY` | Trust the root key the endpoint reports. Only for a local or test replica: refused with a mainnet endpoint (`icp-api.io`, `ic0.app`, `icp0.io` or a subdomain), and a loud warning with any other remote one. Exactly `1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`; anything else is an error. | off |
| `IMCP2_SHARED_MIRROR_CAP` | Records in this node's mirror, across all namespaces, about 300 B each. Over the cap, the soonest-expiring records are evicted, and an evicted record is read through on its next use. 1000 to 5 000 000. | 500 000 (about 150 MB) |
| `IMCP2_SHARED_ADOPTED_CAP` | Sessions one server (`/mcp`, `/mcp-beta`) keeps opened. At the cap a session idle for 15 minutes makes room; a cache full of active sessions answers 503 at `/oauth/token`, and on `/mcp` for sessions not yet adopted. 100 to 500 000. | 50 000 per server |
| `IMCP2_SHARED_POLL_MS` | Interval of the feed poll (a free query). 100 to 30 000. | 1000 |

**At startup:**

- **Bad configuration fails it.** Every setting is checked, and the keyring and the PEM are read,
  before the listener binds. The process exits with status 1 and one line, `Error: <message>`,
  naming the variable and never quoting a key. Under systemd (`Restart=always`, `RestartSec=3`)
  that is a restart every 3 s: read `journalctl -u imcp2`.
- **`imcp2 shared-config-check` runs the same checks without starting.** It reads the same
  variables and both files through the very code a start uses, then stops, with no network call.
  It prints the canister id, the node's principal (the one the allow-list must hold) and the
  keyring's kids and fingerprints, and exits 0; or it exits 1 with the `Error:` line a start
  would print. With `IMCP2_SHARED_CANISTER_ID` unset it says so and exits 0; any argument but
  `--help` (or `-h`) exits 2.
  The staging deploy runs it with the new binary before installing anything (5.2). On a host, as
  root, with the files the drop-in names (2.2):

  ```sh
  sudo env -i IMCP2_SHARED_CANISTER_ID=<CANISTER_ID> \
    IMCP2_SHARED_KEYS_FILE=/etc/imcp2/keys \
    IMCP2_SHARED_IDENTITY_PEM_FILE=/etc/imcp2/identity.pem \
    /opt/imcp2/imcp2 shared-config-check
  ```

  Run it after changing either file and before `sudo systemctl restart imcp2`: the files are read
  only at start, so a restart onto a bad one is the exit loop above. A setting from another
  drop-in is checked only if you add it to the command.
- **An unreachable canister does not.** The node starts, but is not ready
  ([8.3](#83-a-node-is-not-ready)).
- **With `IMCP2_SHARED_CANISTER_ID` unset,** any other `IMCP2_SHARED_*` variable that is set is
  named in one warning (never its value) and ignored.
- **It logs** (info) `shared sessions on: the canister's allow-list must hold node_principal`,
  with `canister_id`, `node_principal`, `node_key`, `ic_url`, `fetch_root_key`, `mirror_cap`,
  `adopted_cap`, `poll_interval`, then the keyring as `kid 2 (fingerprint …), kid 1 (fingerprint …)`.

On the staging host, `imcp2.service` caps memory at 2 GB (`MemoryMax=2G`), which leaves room for a
full default mirror.

### 2.2 On the staging host

The `staging` environment's `IMCP2_SHARED_CANISTER_ID` variable makes `deploy.sh` render
`/etc/systemd/system/imcp2.service.d/shared.conf`. When the variable is unset, `deploy.sh` removes
that file.

```ini
[Service]
Environment=IMCP2_SHARED_CANISTER_ID=<CANISTER_ID>
LoadCredential=keys:/etc/imcp2/keys
LoadCredential=identity.pem:/etc/imcp2/identity.pem
Environment=IMCP2_SHARED_KEYS_FILE=%d/keys IMCP2_SHARED_IDENTITY_PEM_FILE=%d/identity.pem
```

| File | Content | Owner, mode |
|---|---|---|
| `/etc/imcp2/` | | `root:root`, `700` (`deploy.sh` creates it on every host) |
| `/etc/imcp2/keys` | The keyring, the same on every node of the deployment | `root:root`, `600` |
| `/etc/imcp2/identity.pem` | This node's identity | `root:root`, `600` |

- **Before shipping anything,** `deploy.sh` checks that both files are regular files (not
  symlinks), owned by root, mode `600` and not empty. If they are not, it stops and leaves the host
  as it was.
- **Before installing anything,** it checks what is in them, which the check above cannot see: it
  ships the new binary beside the running one (`/opt/imcp2/imcp2.new`) and runs its
  `shared-config-check` (2.1) on both files, as root, with the drop-in's three variables. If that
  fails, it stops with the binary's `Error:` line: nothing is installed, and imcp2 keeps running,
  and would restart into, its old binary and drop-in (5.2).
- **After the restart,** it checks that systemd loaded the drop-in, or did not when sharing is off.
  It also reports, without failing, whether `/ready/shared` answers 200.
- **The credentials are read when the service starts.** After changing either file, check it with
  the command of 2.1, and restart only if that passes (a restart onto a bad file is an exit loop):

  ```sh
  sudo env -i IMCP2_SHARED_CANISTER_ID=<CANISTER_ID> \
    IMCP2_SHARED_KEYS_FILE=/etc/imcp2/keys \
    IMCP2_SHARED_IDENTITY_PEM_FILE=/etc/imcp2/identity.pem \
    /opt/imcp2/imcp2 shared-config-check && sudo systemctl restart imcp2
  ```

  Neither file ever goes in the repository or a GitHub secret.
- **The drop-in sets three variables only.** Everything else keeps its default: mainnet
  (`https://icp-api.io`, no root-key fetch) and the default caps and poll interval. To tune one,
  put its `Environment=` line in another drop-in of `imcp2.service.d/`; `deploy.sh` manages only
  `shared.conf`.

<!-- TODO(reconcile): staging verification. LoadCredential= and %d on the host's systemd (AL2023, systemd 252) are untested; the drop-in rendering was only checked with a stubbed ssh. -->

Production is not deployed from this repository; it embeds the imcp2 crate. Its nodes need the
same three things: a keyring, one identity per node, and that identity on the allow-list.
<!-- TODO(reconcile): not built yet. The production wiring is the ic-gateway follow-up (design record, 14); add its flags and file locations here when it lands. -->

### 2.3 The deploy-session-canister workflow

The workflow runs only on manual dispatch, from the Actions tab or with `gh workflow run`.

| Input | Values |
|---|---|
| `tag` | `rc-X.Y.Z-N` or `vX.Y.Z`. **deploy:** the release to install. **admin:** the release installed now. The run refuses if the canister runs any other module, and the release's `imcp2_session.did` types the call. |
| `target` | `staging` or `prod`. It selects the environment `session-canister-<target>`, and with it the canister and the controller key. |
| `mode` | `deploy` or `admin` |
| `method` | `none` for deploy. For admin: `admin_update_config`, `admin_set_key_check`, `admin_retire_kid` or `admin_purge_sessions`. |
| `argument` | Admin only: the method's whole Candid argument, e.g. `(record {})` ([Appendix B](#appendix-b-candid-arguments)). |

```sh
# Dispatch from main: the environments only admit main.
gh workflow run deploy-session-canister.yml --ref main \
  -f tag=<TAG> -f target=<staging|prod> -f mode=admin \
  -f method=admin_update_config -f argument='(record {})'
```

- **Approval.** The `apply` job holds the controller key, and runs only after someone other than
  the requester approves it in the environment.
- **The release job's summary** shows the digest it verified.
- **The apply job's summary** records the method, argument, target, canister, release, requester,
  approvers and result.
- **Finding the release installed now.** An `rc-X.Y.Z-N` and the `vX.Y.Z` promoted from it carry
  the same module, so either tag names it. To find it, read the title of the last successful
  deploy run, or compare the module hash with the releases' `.sha256` assets:

  ```sh
  dfx canister info <CANISTER_ID> --network ic   # "Module hash:"
  ```

**The admin journal.** Every `admin_*` call goes through this workflow, so that its run history
records it, and a snapshot load can be followed by a replay ([8.10](#810-disaster-recovery-snapshot-load)).

- The run name (`<target>: <method> <argument>`) is kept permanently.
- The summaries (result, approvers) are kept only as long as the repository's log retention. Copy
  each entry somewhere durable if it must outlive that.
  <!-- TODO(reconcile): ownership decision. Name the durable place for journal entries (design record, 13 item 12). -->
- If you ever call an `admin_*` method by hand, record it in the incident notes as a journal entry.

```sh
gh run list --workflow deploy-session-canister.yml --limit 200 \
  --json displayTitle,conclusion,createdAt,url
```

### 2.4 Conventions in this runbook

- **Placeholders.**
  - `<CANISTER_ID>` is the target's canister: the `SESSION_CANISTER_ID` variable of
    `session-canister-<target>`.
  - `<NODE_n_PRINCIPAL>` is a node identity's principal.
  - `<TAG>` is a release tag.
- **Who can run the `dfx` commands.** They run as a **controller** unless marked *anyone*. The CI
  controller key never leaves its GitHub environment, so commands you run by hand use the
  break-glass controller ([3.4](#34-set-the-freezing-threshold-and-the-controllers)).
- **dfx version.** The workflow pins dfx 0.32.0. The commands here were rehearsed on dfx 0.27.0
  against a local replica, so without `--network ic`. That rehearsal is how 3.5 gained its
  `dfx build`: as first written, without it, the install failed. Every flag they use was checked
  against the 0.32.0 sources: `canister create` (`--with-cycles`, `--subnet`, `--subnet-type`),
  `update-settings`, `install`, `call` (`--update`, `--output json`, `--candid`), `snapshot`
  (`create --replace`, `list`, `load`, `delete`), `logs`, `cycles` and `ledger top-up`, and
  `identity import --storage-mode`; `dfx build` is given no flag but `--network`. Use dfx 0.32.0
  for the manual commands too.
- **Two dfx 0.27 limits** met in the local rehearsal (not checked on 0.32.0):
  - it cannot import a PKCS#8 secp256k1 PEM ("missing data"); generate node keys as in 3.2, which
    writes the SEC1 form both dfx and imcp2 read;
  - its local replica (`dfx start`, with PocketIC 9) cannot serve imcp2's ic-agent 0.49, which
    needs the `/api/v4/…/call` and `/api/v3/…/query` endpoints. To rehearse with nodes locally,
    run a PocketIC 15 server and its HTTP gateway (or icp-cli), and point dfx and
    `IMCP2_SHARED_IC_URL` at that gateway, with `IMCP2_SHARED_FETCH_ROOT_KEY=1`.

## 3. Creating the canister

Do this once per target (staging, prod). The canister is useless until the key check is
published ([4.3](#43-publish-the-key-check)) and the nodes are enabled ([5.2](#52-enable)).

### 3.1 Choose the subnet

- **Cost.** Use an application subnet. The cycle estimate assumes a 13-node subnet; a 34-node
  subnet costs about 2.6 times more.
- **Trust.** The canister's state is visible to the node operators of its subnet. Without the
  keyring they still cannot open a record.
- **Record the choice.** Write down the subnet id: every later procedure assumes this one
  canister. `dfx ledger show-subnet-types --network ic` lists the subnet types; `--subnet` below
  pins a specific subnet instead.

<!-- TODO(reconcile): ownership decision. Which subnet staging and prod use (design record, 13 item 12). -->

### 3.2 Generate one identity per node

Each node gets its own identity, so that a compromised node can be removed, and its sessions
purged, on its own ([8.6](#86-stolen-node-identity)). For each node:

```sh
umask 077
openssl ecparam -name secp256k1 -genkey -noout -out node-<NAME>.pem
# Read its principal, then drop dfx's copy of the key.
dfx identity import --storage-mode plaintext imcp2-node-<NAME> node-<NAME>.pem
dfx identity get-principal --identity imcp2-node-<NAME>
dfx identity remove imcp2-node-<NAME>
```

Note each principal. The PEM goes to its node only ([4.2](#42-deploy-a-keyring-and-an-identity-to-a-node)).
Never make a node identity a controller: a controller can call every `admin_*` method and can
download the canister's state in a snapshot.

- **imcp2 reads this file as is.** It loads the SEC1 `EC PRIVATE KEY` that `openssl ecparam`
  writes (with or without an `EC PARAMETERS` block) to the same principal dfx reports.
- **imcp2 also tells you the principal.** A node started with the PEM logs it at startup
  (`node_principal=…`), and its `/version` shows it as `shared.node_principal`, so you can check a
  node's identity without dfx.
- **Ed25519 works too:** `openssl genpkey -algorithm ed25519 -out node-<NAME>.pem` (PKCS#8). Not
  P-256: imcp2 refuses an EC key on any curve but secp256k1.

### 3.3 Create and fund the canister

`dfx canister create` needs a project, so work in a throwaway directory that holds the release's
module:

```sh
mkdir session-canister-<TARGET> && cd session-canister-<TARGET>
gh release download <TAG> --repo dfinity/imcp2 \
  --pattern 'imcp2-session-canister.wasm.gz*' --pattern imcp2_session.did
sha256sum -c imcp2-session-canister.wasm.gz.sha256   # macOS: shasum -a 256 -c
cat > dfx.json <<'EOF'
{ "canisters": { "imcp2_session": { "type": "custom",
  "wasm": "imcp2-session-canister.wasm.gz", "candid": "imcp2_session.did" } } }
EOF
dfx cycles balance --network ic       # fund it with: dfx cycles convert --amount <ICP> --network ic
dfx canister create imcp2_session --network ic --with-cycles 20T --subnet <SUBNET_ID>
dfx canister id imcp2_session --network ic   # this is <CANISTER_ID>
```

- **The subnet.** Leave `--subnet` out for a random application subnet, or use
  `--subnet-type <TYPE>`.
- **The fee.** `--with-cycles` includes the creation fee, so the canister starts slightly below
  20 T.
- **Use a release's module.** Then the workflow's admin mode can name that release.
- **Check the digest yourself if you like.** A checkout of the tag rebuilds the module to the same
  digest:

  ```sh
  GIT_SHA=<commit> scripts/build-session-canister-docker.sh <out-dir>
  ```

  The build needs Docker.

### 3.4 Set the freezing threshold and the controllers

```sh
# 90 days, in seconds.
dfx canister update-settings <CANISTER_ID> --network ic --freezing-threshold 7776000
dfx canister update-settings <CANISTER_ID> --network ic --add-controller <CI_CONTROLLER_PRINCIPAL>
dfx canister status <CANISTER_ID> --network ic   # check controllers, freezing threshold, balance
```

The canister has two kinds of controller:

- **The CI controller.** Generate its PEM as in 3.2. It goes in the environment secret
  `SESSION_CANISTER_CONTROLLER_PEM` and nowhere else.
- **The identity that created the canister.** It stays a controller as the break-glass identity
  for the manual commands in this runbook. Keep it password-protected or in a hardware key, never
  in plaintext on a shared machine.

<!-- TODO(reconcile): ownership decision. Who holds the break-glass controller, and whether there is more than one (design record, 13 item 12). -->

### 3.5 Install with `Init`

The first install is manual. `deploy-session-canister.sh` refuses an empty canister, because it
only upgrades. Run it in the 3.3 directory:

```sh
dfx build imcp2_session --network ic
dfx canister install imcp2_session --network ic --mode install \
  --argument '(variant { Init = record { authorized = opt vec { principal "<NODE_1_PRINCIPAL>"; principal "<NODE_2_PRINCIPAL>" } } })'
dfx canister info <CANISTER_ID> --network ic   # Module hash: the release's .sha256
dfx canister call <CANISTER_ID> get_status '()' --network ic --update
```

- **Build first.** `dfx canister install` by canister name refuses until `dfx build` has run
  ("The canister must be built before install"). For a `custom` canister the build compiles
  nothing: it copies the release's `.wasm.gz` into `.dfx/` byte for byte, so the installed module
  hash still equals the release's `.sha256`, which the workflow's admin mode checks.
- **Typing.** Installing by the project's canister name types the argument against
  `imcp2_session.did`.
- **Never reinstall.** Do not run `dfx canister install --mode reinstall` on this canister, now
  or later; a wrong `Init` is fixed with `admin_update_config` (6). A reinstall wipes the store
  (records, key checks, retirements) and starts the epoch again at 0. The nodes rebuild their
  mirrors only when the epoch changes, which a reinstall does only if a snapshot load had moved
  it, so they keep the wiped sessions in their mirrors and serve them again once the key checks
  are back, until those grants expire. If a reinstall ever happens, restart every node, so that
  each starts from an empty mirror, or move the fleet to a new canister id.
- **Defaults.** Fields left out of the `Init` record keep their defaults:

  | Field | Default |
  |---|---|
  | `idle_timeout_secs` | 2 592 000 (30 d) |
  | `max_sessions` | 2 000 000 |
  | `max_sessions_per_namespace` | 1 000 000 |
  | `purge_interval_secs` | 60 |
  | `purge_batch` | 2 000 |

  An empty or missing `authorized` admits nobody.
- **Check.** `get_status` should show the list under `config.authorized`, and the release's
  `version` and `git_commit`.
- **After this.** From here on, every change goes through the workflow. The throwaway directory
  is no longer needed.

### 3.6 Configure the GitHub environment

In **Settings → Environments**, create `session-canister-<target>` with:

- **secret** `SESSION_CANISTER_CONTROLLER_PEM`: the CI controller's PEM;
- **variable** `SESSION_CANISTER_ID`: `<CANISTER_ID>`;
- **protection rules:** required reviewers with *Prevent self-review*, and deployment branches
  limited to `main`.

Create the environment, with its rules, before the first run of the workflow for that target. A run
that names an environment which does not exist yet creates it with no rules at all. That run fails
for want of the secret, but the unprotected environment stays behind.

Do not put the PEM in the `staging` environment. It has no reviewers, and every host-deploy job
can read its secrets. Leave `IMCP2_SHARED_CANISTER_ID` on `staging` unset until you enable sharing
([5.2](#52-enable)).

### 3.7 Cycles

- **Provisioning:** 20 T to start, a 90-day freezing threshold, and an alert below 3 T
  ([9.2](#92-alerts)).
- **The estimate:** about 6 to 7 T a month for 8 nodes and 2000 sign-ins a day on a 13-node
  subnet. It excludes the history probe, one management-canister call per timer run (about 43 000
  a month at the 60 s default).
- **The freeze line.** A canister freezes when its balance falls below what it would burn idle
  during the freezing threshold. `dfx canister status` shows *Idle cycles burned per day*;
  90 times that is the line.

<!-- TODO(reconcile): staging measurement. The cycles estimate predates any node running against a canister; re-measure it on the staging canister, the history probe included. -->

## 4. Keys

### 4.1 Generate a key and the keyring

```sh
umask 077
printf '%s:%s\n' <KID> "$(openssl rand -base64 32)" > keys.txt
```

**Keyring format.**

- `kid:base64` entries, separated by commas or line breaks. Whitespace around entries is ignored.
- A kid is a decimal number from 1 to 255, and appears once.
- A key is exactly 32 bytes, in standard or URL-safe base64, padded or not.
- **Order is the sealing preference:** a node seals under the first kid whose key check is
  `Verified`.

**Rules.**

- **Every node of a deployment holds the same keyring.** Each target has its own.
- **A kid number is used once.** A retired kid can never be published again, so a new key always
  takes a kid number that was never used.
- **Keep the master copy** in the team's secret store. Never put it in the repository, a GitHub
  secret, a log or a ticket.
  <!-- TODO(reconcile): ownership decision. Name the secret store (design record, 13 item 12). -->

### 4.2 Deploy a keyring and an identity to a node

"Deploy a keyring" in the procedures below means doing this on **every** node. On the staging
host:

```sh
scp keys.txt node-<NAME>.pem <HOST>:      # the SSH path the deploy uses
ssh <HOST>
sudo install -d -m 700 -o root -g root /etc/imcp2
sudo install -m 600 -o root -g root keys.txt /etc/imcp2/keys
sudo install -m 600 -o root -g root node-<NAME>.pem /etc/imcp2/identity.pem   # identity: once per node
shred -u keys.txt node-<NAME>.pem
sudo env -i IMCP2_SHARED_CANISTER_ID=<CANISTER_ID> \
  IMCP2_SHARED_KEYS_FILE=/etc/imcp2/keys \
  IMCP2_SHARED_IDENTITY_PEM_FILE=/etc/imcp2/identity.pem \
  /opt/imcp2/imcp2 shared-config-check \
  && sudo systemctl restart imcp2         # 2.1; the restart only when sharing is on
curl -s http://127.0.0.1:8000/metrics | grep '^imcp2_shared_key_info'
```

- **The check** prints the node's principal and the keyring's kids and fingerprints, or exits 1
  with the `Error:` line a start would print (2.1). Fix the file before restarting: the credentials
  are read at start, and a restart onto a bad one is an exit loop.
- **The last line** should list the kids of the new keyring ([4.4](#44-verify-on-every-node)).
- **Restarting a node** discards nothing durable. It answers some shared requests with 503 until
  its first sync completes; with several nodes, the load balancer skips it meanwhile. That sync is
  one `get_key_checks` and then the whole feed as update calls, one per 1000 live sessions (about
  2 s each), so the time to ready grows with the store: about 2 s per 1000 sessions, plus a few
  seconds.
  <!-- TODO(reconcile): staging measurement. Measure how long a restarted node takes to become ready, against a store of realistic size. -->

### 4.3 Publish the key check

The key check of a kid is `HKDF-SHA256(key, info = "imcp2/keycheck/v1")`, first 16 bytes. It is
public: it reveals nothing about the key. Print it on a host that holds the keyring:

```sh
sudo env IMCP2_SHARED_KEYS_FILE=/etc/imcp2/keys /opt/imcp2/imcp2 shared-key-check
```

It reads only the keyring, from `IMCP2_SHARED_KEYS_FILE` or `IMCP2_SHARED_KEYS` by the server's
rules, and makes no network call. It prints one line per kid, in keyring order: Candid for
`admin_set_key_check`'s first argument, with the kid's fingerprint in a Candid comment.

```text
record { kid = 2 : nat8; check = blob "\79\fb\95\75\ed\18\e1\c5\09\c1\bc\27\e1\a7\e2\77" } /* fingerprint 79fb9575ed18e1c5 */
record { kid = 1 : nat8; check = blob "\ea\f4\8e\9d\d7\cc\75\4f\02\7f\54\93\06\d8\6a\2f" } /* fingerprint eaf48e9dd7cc754f */
```

Every byte of the blob is escaped, so the whole line, comment included, pastes into the argument
below. A keyring it cannot read exits 1 with `Error: …` (naming the variable or the entry, never a
key); an argument after `shared-key-check` exits 2. Appendix A computes the same lines without the
binary.

Then publish it with the workflow:

| Input | Value |
|---|---|
| `tag` | the release installed now |
| `target` | the canister's target |
| `mode` | `admin` |
| `method` | `admin_set_key_check` |
| `argument` | `(<the printed line>, false)`, e.g. `(record { kid = 2 : nat8; check = blob "\79\fb\95\75\ed\18\e1\c5\09\c1\bc\27\e1\a7\e2\77" } /* fingerprint 79fb9575ed18e1c5 */, false)` |

By hand, as a controller: `dfx canister call <CANISTER_ID> admin_set_key_check '(<the printed
line>, false)' --network ic` (then record it in the journal, 2.3).

What the canister does with it:

- **The same check again changes nothing,** so a journal replay is harmless.
- **A different check for a kid that already has one is refused,** unless the second argument is
  `true`.
  - Pass `true` only to correct a wrongly published check.
  - Every node that holds the old key then turns `Mismatch` on that kid.
- **A retired kid is refused** for good.
- **Each change bumps the key-checks version,** which tells the nodes to fetch the checks again.

### 4.4 Verify on every node

The fingerprint of a kid is the first 8 bytes of its key check, in hex. Two nodes show the same
fingerprint exactly when they hold the same key under that kid. On each node:

```sh
curl -s http://127.0.0.1:8000/metrics | grep '^imcp2_shared_key_info'
# imcp2_shared_key_info{fingerprint="79fb9575ed18e1c5",kid="2",sealing="true",state="verified"} 1
```

Across the fleet, in PromQL:

- `count(imcp2_shared_key_info{kid="2",state="verified"})` equals the number of nodes;
- `count by (kid) (count by (kid, fingerprint) (imcp2_shared_key_info)) > 1` returns nothing (no
  kid with two different keys).

| `state` | Meaning | Action |
|---|---|---|
| `verified` | The canister's check equals this node's. | None. |
| `unpublished` | The canister has no check for this kid. | Publish it (4.3), if the kid is meant to be used. |
| `mismatch` | The canister holds a different check. | [8.4](#84-key-drift) |
| `retired` | The kid has been retired. | Remove it from the keyring. |
| `unknown` | This node has never fetched the checks. | [8.3](#83-a-node-is-not-ready) |

### 4.5 Planned rotation

The procedure below rotates from `K1` (kid 1) to `K2` (kid 2). Records keep their keys across a
rotation. A record sealed under kid 1 stays readable while every node still holds kid 1, and no
record lives longer than 31 days.

1. **Publish kid 2's check.** Run `imcp2 shared-key-check` for K2, then `admin_set_key_check` with
   kid 2's check and `false` (4.3). The nodes do not hold K2 yet, so compute the check from the
   new keyring file where you generated it (Appendix A, or `shared-key-check` with
   `IMCP2_SHARED_KEYS_FILE` pointing at that file).
2. **Deploy `1:K1,2:K2`** to every node (4.2). Every node should show
   `imcp2_shared_key_info{kid="2",state="verified"}` (4.4). Nodes still seal under kid 1.
   **Do not go on until every node is verified on kid 2:** a node without K2 answers 503 to
   anything sealed under kid 2.
3. **Deploy `2:K2,1:K1`.** Nodes now seal under kid 2. Check `sealing="true"` on kid 2 on every
   node.
4. **After 31 days,** nothing sealed under kid 1 can still be live:
   1. deploy `2:K2`;
   2. run `admin_retire_kid` with `(1 : nat8)`.

### 4.6 Emergency rotation

Use this when kid `k` has leaked. Pick a new, never-used kid `n` with a fresh key `Kn` (4.1).

1. **Publish kid n's check:** `admin_set_key_check` with kid n's check and `false`.
2. **Deploy `n:Kn,k:Kk`** to every node, and confirm `verified` on kid n everywhere (4.4).
3. **Retire kid k:** `admin_retire_kid` with `(k : nat8)`.
   - Within about 35 s, every node answers 401 to every value sealed under kid k (reason
     `retired_kid`). That is a poll (1 s) seeing the key-checks version move, the replicated
     fetch's debounce (at most 30 s after the previous one), then `get_key_checks` as an update.
   - Clients sign in again, under kid n.
   <!-- TODO(reconcile): staging measurement. The ~35 s is derived from the sync loop's timings; measure it on staging. -->
4. **Purge kid k's records:** `admin_purge_sessions` with `(record { kid = opt (k : nat8) })`.
   This tombstones every record sealed under kid k.
5. **Deploy `n:Kn`.**

**Residual risk:** a session key S already extracted with the leaked key stays valid at Internet
Identity until its grant expires (at most 30 days). imcp2 cannot revoke it.

If the key leaked with a host, the node's identity leaked too: also follow
[8.6](#86-stolen-node-identity).

## 5. Enabling, disabling and rolling back imcp2

### 5.1 Before enabling

1. **Ship 0.7.0 with sharing off first,** and run it for at least one release.
   - Every release you might roll back to must already decode `imcp2_dcr1.` client ids, which
     0.7.0 and later do even with sharing off.
   - An older binary does not know these ids, so the clients that registered while sharing was on
     would have to register again.
2. **Create the canister** (3), with every node's principal on the allow-list.
3. **Generate the keyring** (4.1), and **publish its key check** (4.3).
4. **Provision the credentials** on every node (4.2), and **check them there** with
   `imcp2 shared-config-check` (2.1). Sharing is still off, so nothing reads them yet: the check
   is the first thing that does. Compare the principal it prints with the allow-list, and the
   fingerprints with the ones you published.
5. **Merge `oauth-clients.json` across the nodes** (more than one node only). Legacy client ids
   (`client-…`, issued before sharing) live in each node's `/var/lib/imcp2/oauth-clients.json`,
   and work only on the node that issued them until the client registers again. Give every node
   the union. Each file is one JSON object keyed by client id:

   ```sh
   jq -s 'add' node-a.json node-b.json > oauth-clients.json
   # On every node. Stop imcp2 first: it rewrites this file from memory when a client registers.
   sudo systemctl stop imcp2
   sudo install -m 600 -o ec2-user -g ec2-user oauth-clients.json /var/lib/imcp2/oauth-clients.json
   sudo systemctl start imcp2
   ```

   - **The 10 000 cap.** The store keeps at most 10 000 clients. Past that, registering a new
     client evicts the least recently used ones.
   - **Staging has one host,** so there is nothing to merge there.
   - **New registrations need no file.** Once sharing is on, new clients get `imcp2_dcr1.` ids,
     which every node accepts.

### 5.2 Enable

On the staging host:

1. **Set the variable.** In **Settings → Environments → staging → Variables**, set
   `IMCP2_SHARED_CANISTER_ID` to `<CANISTER_ID>`. It is normally the same canister as
   `SESSION_CANISTER_ID` on `session-canister-staging`.
2. **Redeploy.** Run `deploy-candidate.yml` from the Actions tab, with the rc tag that staging runs
   now as its `ref` input. The variable takes effect only at a deploy. `deploy.sh` then:
   - checks the credentials' owner, mode and size;
   - ships the new binary beside the running one (`/opt/imcp2/imcp2.new`) and runs its
     `shared-config-check` on the credentials, as root, with the drop-in's variables (2.1);
   - if that fails, stops with the binary's `Error:` line: nothing is installed, and imcp2 keeps
     running, and would restart into, its old binary and drop-in. Fix the file, then redeploy;
   - otherwise installs the binary and the drop-in and restarts imcp2;
   - fails unless systemd loaded the drop-in;
   - reports whether `/ready/shared` answered 200.
3. **Verify:**
   - the deploy log says `shared sessions: /ready/shared -> 200`;
   - `imcp2_shared_up` and `imcp2_shared_ready` are 1;
   - kid states are as in 4.4;
   - `/version` has a `shared` block ([9.4](#94-version));
   - sign in with an MCP client (e.g. `claude mcp add --transport http <origin>/mcp`), call a tool,
     and check that `imcp2_shared_resolve_total{result="ready"}` grows while
     `imcp2_shared_unavailable_total` stays flat;
   - watch for unexpected 401s, and check how Claude, ChatGPT and Cursor handle a 503 from `/mcp`.

Users signed in before the restart sign in once more, as after any deploy: legacy sessions live
in process memory. From then on, restarts and deploys no longer sign anyone out: a restarted node
rebuilds its mirror from the canister.

With several nodes:

- Enable them all together, after the key check is published.
- Point the load balancer's upstream selection for the MCP routes at `/ready/shared`
  ([9.3](#93-readyshared)).

### 5.3 Disable

1. Delete (or empty) the `IMCP2_SHARED_CANISTER_ID` variable of `staging`.
2. Redeploy as in 5.2. `deploy.sh` runs no `shared-config-check` (there is nothing to check),
   removes the drop-in, and fails if systemd still loads it.
3. Expect every client to sign in once more. A node with sharing off never opens shared values:
   it answers an access token (`imcp2_at1.`) with today's 401, and a code (`imcp2_ac1.`) with
   `invalid_grant`, as any unknown one (the multi-instance test
   `a_server_without_sharing_behaves_as_today_beside_the_fleet`). `imcp2_dcr1.` client ids keep
   working.

The canister keeps its records until their grants expire, and nothing needs doing. To decommission
the node as well:

- remove its principal from the allow-list ([6.3](#63-allow-list));
- `sudo shred -u /etc/imcp2/keys /etc/imcp2/identity.pem` on the host.

### 5.4 Roll back an imcp2 release

- **Staging:** run `deploy-candidate.yml` with an earlier `rc-*` tag (or a full commit SHA) as its
  `ref` input. See [deploy/native/README.md](../deploy/native/README.md), "Rolling back staging".
- **One release back, sharing on:** safe. The codec's two-release rule ships readers one release
  before writers, so the earlier release reads every value the later one wrote.
  - A value in a format a node cannot read answers 503 (reason `newer_format`), never 401.
  - Records live at most 31 days.
- **Never roll back below 0.7.0 once sharing has been on.** Those binaries do not know
  `imcp2_dcr1.` client ids.
- **`imcp2_dcr1.` ids keep working** on any 0.7.0 or later binary, with sharing on or off.

## 6. Configuration changes

Every change is an `admin_update_config` run of the workflow (admin mode).

- **The patch.** Each field you set replaces the current value; fields you leave out stay. The
  whole resulting configuration is validated.
- **A refused patch changes nothing.** It answers `Err` with `InvalidArgument`, and the run fails.
- **The current configuration** is in `get_status` (`config`):

  ```sh
  dfx canister call <CANISTER_ID> get_status '()' --network ic --update
  ```

| Field | Default | Allowed |
|---|---|---|
| `authorized` | empty (nobody) | at most 32 principals, none anonymous, no duplicates. **Replaces the whole list.** |
| `idle_timeout_secs` | 2 592 000 (30 d) | 3 600 to 31 536 000 |
| `max_sessions` | 2 000 000 | at least 1 |
| `max_sessions_per_namespace` | 1 000 000 | 1 to `max_sessions` |
| `purge_interval_secs` | 60 | 10 to 3 600 |
| `purge_batch` | 2 000 | 100 to 20 000 |

### 6.1 Idle timeout

**At the 30-day default the idle purge never fires.** II grants last at most 30 days, so grant
expiry always comes first, and nodes send no activity reports ("touches") at all.

**Lowering it at time T,** e.g. with `(record { idle_timeout_secs = opt (604800 : nat64) })`
(7 days):

1. **The idle floor is set to T.** Nodes learn the new values within about 30 s.
2. **Touches start,** seeded by each session's next request. They run only while the timeout is
   below 2 570 040 s (about 29.7 days): above that, grant expiry always wins.
3. **No session is idle before T + idle + granularity + 300 s.** The granularity is
   `clamp(idle / 48, 5 min, 6 h)`. Activity after T is reported, and activity before T does not
   count, so lowering the timeout logs out no active user.
4. **At its deadline, an idle session gets a tombstone** (reason `idle`). Nodes apply it within
   about 30 s; the session's next request gets 401, and the client signs in again.

| New timeout | Granularity | First idle purges |
|---|---|---|
| 1 h (`3600`, the minimum) | 5 min | T + 1 h 10 min |
| 1 d (`86400`) | 30 min | T + 1 d 35 min |
| 7 d (`604800`) | 3.5 h | T + 7 d 3 h 35 min |
| 14 d (`1209600`) | 6 h | T + 14 d 6 h 5 min |

- **Touches cost update calls.** Each node flushes every 60 s, in batches of at most 2000, and
  reports a session only once its activity has advanced by at least the granularity.
  `imcp2_shared_touch_backlog` shows what is pending.
- **Raising the timeout** needs no floor: every deadline only moves later.
- **"Within about 30 s"** is the sync loop's timing: a node's 1 s poll sees the new values or the
  tombstone, and the replicated fetch that makes them authoritative runs at most 30 s after the
  previous one (its debounce). `/version` shows what a node holds as `shared.idle_timeout_secs`,
  `shared.idle_floor_at` and `shared.touches_effective`.

### 6.2 Capacity caps and the CapacityExceeded alert

- **Every put needs room under both caps.** Records still in sign-in count too.
- **Eviction.** At a cap, a put evicts at most one record, and only one whose idleness can be
  trusted:
  - it is consumed;
  - touches are in effect (6.1);
  - its grant outlives one more idle span: now + idle + granularity + 300 s + 60 s < grant expiry;
  - it has been idle, measured from the later of its last activity and the idle floor, for at
    least the granularity + 2 × 60 s + 1 h.
- **At the 30-day default nothing can be evicted.** A full store answers `CapacityExceeded`:
  - the node fails the sign-in at redeem with a 503, which the sign-in page shows as "We couldn't
    save your sign-in just now. Wait a moment, then restart from your client.", and logs
    `storing the session record failed` with `reason=capacity_exceeded`;
  - **nobody already signed in is logged out**, but new sign-ins fail until there is room.
- **The 65th namespace is refused** (`CapacityExceeded`). Each pair of II instance and MCP issuer
  is one namespace: staging's `/mcp` and `/mcp-beta` are two.
- **Memory.** A session takes about 450 B with its indexes, so 1 M sessions take about 450 MB. The
  default caps are memory tripwires, not operating points.

**Alert:**

- on growth towards the caps: `max by (ii_instance) (imcp2_shared_canister_sessions)` against
  `max_sessions_per_namespace`, and the sum against `max_sessions`;
- on `imcp2_shared_unavailable_total{endpoint="redeem",reason="capacity_exceeded"}`, which counts
  exactly the sign-ins refused for capacity;
- on `imcp2_shared_canister_calls_total{method="put_session",outcome="canister_error"}`, which
  counts every typed refusal of a put, `CapacityExceeded` included.

<!-- TODO(reconcile): threshold decision. Pick the warning level for growth towards the caps (a fraction of max_sessions_per_namespace and max_sessions). -->

**Response:**

- **Raise the caps,** if stable memory allows:
  `(record { max_sessions = opt (<TOTAL> : nat64); max_sessions_per_namespace = opt (<PER_NAMESPACE> : nat64) })`.
- **Purge what you can identify** with `admin_purge_sessions`, by namespace or by creation time
  ([Appendix B](#appendix-b-candid-arguments)).
- **Lower the idle timeout** (6.1). Eviction becomes possible once touches are in effect, and the
  idle floor delays it: no earlier than the granularity + 2 min + 1 h after the lowering.

### 6.3 Allow-list

`authorized` **replaces the whole list.** Always send the full list you want: read the current one
from `get_status` first.

- **Add a node:** generate its identity (3.2), then send the current list plus its principal:
  `(record { authorized = opt vec { principal "<NODE_1_PRINCIPAL>"; principal "<NODE_2_PRINCIPAL>"; principal "<NEW_NODE_PRINCIPAL>" } })`.
- **Remove a node:** send the list without it.
  - The removed node gets `Unauthorized` on its queries and rejects on its updates. It then stops
    being ready, and the load balancer skips it.
  - Removing a node does not remove its sessions; [8.6](#86-stolen-node-identity) does.
- **An empty list** locks out every node.

### 6.4 Purge timer

- **`purge_interval_secs`** sets how often the timer runs. It also bounds how long a snapshot
  load can go unnoticed when `admin_update_config(record {})` is not run after it.
- **`purge_batch`** bounds the removals per run, and so the instructions one run may spend. When a
  run uses its whole budget with work left, another follows at once. A removal costs about 0.4 M
  instructions (measured in PocketIC), so the default 2000 is about 0.8 B a run, and the maximum
  20 000 about 8 B, under the 40 B a message may use.
- **Raise the batch** if the purge backlog keeps growing ([8.9](#89-purge-backlog)).

## 7. Canister upgrades and rollback

### 7.1 Upgrade

Run the workflow with `tag` = the release to install, `target`, `mode` = `deploy`,
`method` = `none`, and an empty `argument`.

1. **The `release` job** (no environment, read-only token) rebuilds the module from the tag. It
   refuses unless the digest equals the release's `.sha256`.
2. **A reviewer approves** the `apply` job.
3. **The `apply` job,** as the controller:
   1. stop;
   2. snapshot, replacing the previous deploy snapshot (it keeps the sealed records of that
      moment, even after the canister purges them, until the next deploy replaces it);
   3. `install --mode upgrade --argument '(variant { Upgrade = null })'`;
   4. start;
   5. check the module hash, and that `get_status` reports the tag's commit.

**What the job refuses or skips:**

- **The module is already installed:** nothing is stopped, snapshotted or upgraded.
- **The canister has more than one snapshot:** delete the ones you no longer need with
  `dfx canister snapshot delete`.
- **The canister is empty:** the first install is 3.5.
- **A prod deploy of an `rc-*` tag** is allowed, with a warning.

**When something fails after the stop,** the job starts the canister again, on whatever module it
then runs. A failed upgrade keeps the previous module. If the summary says the canister could
**not** be started again:

```sh
dfx canister start <CANISTER_ID> --network ic
```

**While the canister is stopped:**

- register and authorize work;
- redeem asks the user to retry;
- `/oauth/token` answers 503 within about 8 s;
- `/mcp` works for mirrored sessions, and answers 503 for the others;
- nodes stay ready (`/ready/shared` 200), and `imcp2_shared_up` drops to 0 within 30 s.

<!-- TODO(reconcile): staging measurement. Measure the stop-to-start window of a deploy on staging. -->

**Staging the canister.** The staging host deploys itself on every `rc-*` tag push. The canister
moves only when someone runs the workflow.

- Deploy the candidate's module to staging while you test the candidate.
- Then deploy the promoted `vX.Y.Z` to prod. It is byte-identical to the candidate's module.

The interface only grows: methods are added, records gain only `opt` fields, and returned variants
never gain cases.

<!-- TODO(reconcile): process decision. No rule yet says whether a release may need the canister upgraded before its nodes; decide it with the first interface change. -->

### 7.2 Roll back canister code

**Deploy the previous release** with the workflow (deploy mode, the previous tag). It installs the
previous module with `--mode upgrade`, and stable layouts are append-only, so the older code reads
the newer state.

- **Exception: a release that migrated the stable schema.** The older module refuses memory of a
  schema it does not know. The upgrade fails, and the canister is started again on the newer
  module. Roll forward with a fix instead.
- **Never load a snapshot to roll back code.** A load rewinds the data too:
  - sessions created since the snapshot are lost;
  - admin changes made since the snapshot are undone.

  Snapshot loads are for [8.10](#810-disaster-recovery-snapshot-load) only.

## 8. Incidents

| Symptom | Section |
|---|---|
| `imcp2_shared_up` 0 on every node | [8.1](#81-canister-stopped-or-unreachable), [8.2](#82-canister-frozen-or-low-on-cycles) |
| `imcp2_shared_ready` 0 on one node, `/ready/shared` 503 | [8.3](#83-a-node-is-not-ready) |
| `key_info` not `verified`, `sealed_rejected_total{reason="kid_drift"}` | [8.4](#84-key-drift) |
| `abs(imcp2_shared_clock_skew_seconds) >= 60` | [8.5](#85-clock-skew) |
| A node identity or host is compromised | [8.6](#86-stolen-node-identity) |
| A key has leaked | [8.7](#87-leaked-key) |
| Sign-ins fail with "We couldn't save your sign-in just now" while the canister is up | [8.8](#88-capacity-exceeded) |
| `imcp2_shared_canister_purge_backlog_seconds` growing | [8.9](#89-purge-backlog) |
| Canister state lost or corrupted | [8.10](#810-disaster-recovery-snapshot-load) |

What clients see, per condition:

| Condition | register, authorize | redeem | token | `/mcp`, mirrored | `/mcp`, not mirrored |
|---|---|---|---|---|---|
| Canister stopped or down (upgrade windows too) | ok | "retry" | 503 (within 8 s) | ok | 503 |
| Canister frozen (queries still work) | ok | "retry" | 503 | ok | ok via query; `up` = 0 within 6 min |
| Node not allow-listed, or started while the canister was down | authorize redirects with `temporarily_unavailable` | 503 | 503 | 503 | 503; not ready, so the load balancer skips it |
| Wrong key on this node (`Mismatch`) | another verified kid, else authorize redirects with `temporarily_unavailable` | 503 | 503 | other nodes' values: 503, never 401 | 503 |
| Adopted-session cache full of active sessions | ok | ok | 503 | 503 if not adopted | 503 |
| Store at capacity, default idle timeout | ok | "couldn't save" (503) | ok | ok | ok |
| Snapshot load | ok | ok | ok | ok after the resync; a lost session gets 401 and signs in again | same |

Each row is a test in the code (`src/shared/failure_matrix.rs`, and the multi-instance suite
through the real routers); the stopped canister was also checked against the real canister in
PocketIC. "retry" and "couldn't save" are what the sign-in page shows: "Sign-in is briefly
unavailable…" before anything was spent, "We couldn't save your sign-in just now…" after.

### 8.1 Canister stopped or unreachable

**Symptoms:**

- `imcp2_shared_up` is 0 on every node;
- `imcp2_shared_canister_calls_total` shows outcomes `reject`, `timeout` or `transport`;
- `imcp2_shared_unavailable_total` climbs at redeem and token;
- mirrored sessions keep working.

**Check:**

```sh
dfx canister status <CANISTER_ID> --network ic   # Status: Running / Stopping / Stopped
dfx canister logs <CANISTER_ID> --network ic
```

Also check whether a deploy run is in progress: it stops the canister on purpose.

**Fix:**

- **Stopped outside a deploy:** `dfx canister start <CANISTER_ID> --network ic`.
- **Running but unreachable from every node:** suspect the subnet or the boundary nodes.
- **Down on one node only:** see 8.3.

Nodes need no action. They back off from 1 s to 60 s, keep all their state, and recover by
themselves. Their logs say `fetching the session feed failed` (warn) meanwhile; they stay ready.

### 8.2 Canister frozen or low on cycles

**Frozen:** the balance fell below the freezing threshold.

- Updates fail and queries still work.
- `imcp2_shared_up` drops to 0 within 6 minutes.
- Sign-ins fail at redeem and token; `/mcp` keeps working through queries.
- `dfx canister status` shows the balance and the threshold.

**Low cycles:** `max(imcp2_shared_canister_cycles)` is below 3 T.

**Fix either one** by topping up. Anyone can, no controller needed:

```sh
dfx cycles top-up <CANISTER_ID> 20T --network ic       # from your cycles ledger balance
dfx ledger top-up <CANISTER_ID> --amount <ICP> --network ic   # or mint from ICP
dfx canister status <CANISTER_ID> --network ic
```

A frozen canister unfreezes once its balance is back above the threshold. Nodes see `up` return
by themselves.

**After a long stop or freeze,** the canister log may show `[ic-cdk-timers] canister_global_timer:
too many concurrent timer calls (250), deferring timer to next round`: the timer library replays
the purge intervals it missed. Each replay only schedules a run, so this is harmless and stops by
itself. Any upgrade re-arms the timer and ends it at once.

### 8.3 A node is not ready

`ready` requires three things since the node started:

- its initial sync completed (the key checks, then a full replicated fetch of the feed);
- it holds a `Verified` sealing kid;
- the canister does not refuse its identity: its queries answered `Unauthorized` **and** its
  updates rejected, or an update answered `Unauthorized`. A reject alone (a stopped or frozen
  canister) does not count.

A node that is not ready answers 503 on the shared paths, and the load balancer skips it. `deploy.sh`
prints a warning pointing here when `/ready/shared` does not answer 200 within 30 s.

**Start with `/version`** on the node: `curl -s http://127.0.0.1:8000/version | jq .shared`
([9.4](#94-version)). `identity_refused`, `kids[].state`, `synced`, `epoch` and the
`last_*_ok_s_ago` fields tell the cases below apart.

**Not on the allow-list:** `shared.identity_refused` is `true`.

- `imcp2_shared_canister_calls_total{outcome="unauthorized"}` counts its queries;
- `outcome="reject"` counts its updates, which `inspect_message` refuses before the method runs.

Compare the node's principal (`shared.node_principal`, also logged at startup as
`node_principal=…`) with `config.authorized` in `get_status`, then fix the list (6.3). The node
becomes ready by itself once it is listed; no restart is needed.

**No verified kid:** `imcp2_shared_key_info` shows the reason (4.4).

- `unknown` means the node never fetched the checks: the canister is unreachable, or the node is
  refused. Its log repeats `cannot read the session canister's key checks; nothing is sealed until
  then` (warn), with the error.
- `unpublished`: publish the check (4.3). On every node at once right after a snapshot load, the
  load rewound the key checks: replay them from the journal (8.10, step 5).
- `mismatch`: see 8.4.
- `retired`: deploy a keyring without that kid.

When the node has fetched the checks but none of its kids is verified, it logs `no kid of this
node's keyring is verified by the session canister: nothing can be sealed`; once one is, `shared
sessions seal under kid` (info).

**Initial sync pending:** the canister was down when the node started (`shared.synced` is
`false`). The node becomes ready once a full replicated fetch completes; with a large store that
takes a while (4.2).

**Root key not fetched** (local and test networks only, `IMCP2_SHARED_FETCH_ROOT_KEY` on): the log
says `could not fetch the root key; retrying in the background`, and every call fails
verification until a retry succeeds.

### 8.4 Key drift

**Symptoms:**

- one node shows `imcp2_shared_key_info{state="mismatch"}`, or one kid shows two fingerprints
  across the nodes;
- `imcp2_shared_sealed_rejected_total{reason="kid_drift"}` grows.

**Effect:**

- The node seals under another verified kid if it has one, and otherwise answers 503.
- Values sealed elsewhere under the drifted kid answer 503 there, never 401.

**Find the odd node.** Compare the `fingerprint` labels across the nodes, and with the canister's
check: its first 8 bytes, in hex, are the fingerprint.

```sh
dfx canister call <CANISTER_ID> get_key_checks '()' --network ic --update
```

**Fix the node, not the canister.** Copy the keyring from the master copy, install it (4.2),
restart, and verify (4.4).

- Do not "fix" it with `admin_set_key_check(..., true)` to match one node. That would turn every
  other node to `Mismatch`.
- `sealed_rejected_total{reason="missing_key"}` means a value under a published kid that this node
  lacks: its keyring is behind. Deploy the full keyring.

### 8.5 Clock skew

`imcp2_shared_clock_skew_seconds` is the node's clock minus the canister's, at the last
replicated read. A positive value means the node is ahead. It includes the reply's latency, so a
small positive value is normal.

- **Why it matters.** Every expiry check tolerates 60 s (`CLOCK_SKEW`). Beyond that, cookies,
  codes and tokens are judged expired too early or too late.
- **When to page.** Page at 60 s. `src/shared/metrics.rs` advises alerting well before that.
  `/version` shows the same value as `shared.clock_skew_s`.
  <!-- TODO(reconcile): threshold decision. Choose the warning threshold below 60 s. -->
- **Fix** the host's time sync: `chronyc tracking` and `timedatectl status`, then restart
  `chronyd` or repair its sources.

### 8.6 Stolen node identity

**What a stolen identity can do:**

- flood `put_session` up to the caps;
- nothing worse. It cannot consume other users' codes (it lacks their code proof), and it cannot
  read any session key (it lacks the keyring).

**If the host itself was compromised,** the keyring leaked too: do [8.7](#87-leaked-key) as well.

**Scope it** from `get_status` `callers`: per principal, `opened`, `consumed`, `last_seen_at`.

1. **Remove it from the allow-list,** and add its replacement in the same call
   (`admin_update_config`, the full list without the stolen principal, plus the new one; 6.3).
2. **Purge the sessions it opened** with `admin_purge_sessions`:
   `(record { opened_by = opt principal "<STOLEN_PRINCIPAL>" })`.
   - This tombstones every session that node opened at redeem. Those users sign in again.
   - One purge job runs at a time. Starting another meanwhile is refused with code
     `purge_in_progress`. `get_status` shows `purge_job` and when it is `done`.
3. **Give the node a new identity** (3.2): install the PEM (4.2), restart, and check `ready`.

### 8.7 Leaked key

Run the emergency rotation, [4.6](#46-emergency-rotation).

### 8.8 Capacity exceeded

See [6.2](#62-capacity-caps-and-the-capacityexceeded-alert). Nobody signed in is logged out, but
new sign-ins fail until there is room.

### 8.9 Purge backlog

`imcp2_shared_canister_purge_backlog_seconds` is the age of the oldest record overdue for
removal. It includes how long a running admin purge job has been running, so it grows during a
large `admin_purge_sessions`.

**Check the canister log.** Each run that removed something logs
`purge: <n> processed, more due: <bool>, <instructions> instructions`. A failed history probe logs
`restore probe: canister_info failed: …` or `restore probe: unreadable canister_info reply: …`.

```sh
dfx canister logs <CANISTER_ID> --network ic
```

**A failing probe holds the idle purge back.** A run whose history probe fails cannot rule out a
snapshot load it would have detected, so it skips the idle purge (abandoned sign-ins, expired
sessions, tombstone collection and a running admin purge still proceed), and the next run probes
again. While the probe keeps failing, idle sessions due for removal stay, and
`imcp2_shared_canister_purge_backlog_seconds` grows with them. Nothing is lost: the first run whose
probe succeeds purges those still idle (after a snapshot load, that probe first raises the idle
floor to now, 8.10).

**Fix:**

- **The runs keep saying `more due: true`:** raise `purge_batch` (6.4).
- **The log shows `restore probe: …` lines run after run:** the idle purge waits for a probe that
  succeeds. `admin_update_config` with `(record {})` starts a run, and so a probe, at once.
- **No runs at all:** re-arm the timer with `admin_update_config` and `(record {})`, which also
  starts a run at once.

### 8.10 Disaster recovery: snapshot load

Use this only when the canister's state is lost or corrupted and cannot be fixed forward. Never
use it to roll back code (7.2).

**What a load costs:**

- **Sessions created after the snapshot are gone.** Their next request gets 401, and the client
  signs in again.
- **Sessions purged or evicted after the snapshot come back** until they are purged again. Their
  II grants were still valid, so this is hygiene only.
- **Admin changes made after the snapshot are undone** until you replay them (steps 5 and 8).
- **A key rotation finished after the snapshot drains every node** until its key checks and
  retirements are replayed (step 5). The load restores the snapshot's key list, in which a kid
  published since is `unpublished`. A node whose keyring holds only such kids has no sealing kid
  (4.1), so `imcp2_shared_ready` and `imcp2_shared_up` drop to 0 on it at its next replicated
  fetch; when every node is there, the load balancer marks every upstream down. The restored list
  also un-retires every kid retired since, a leaked one included.
- **An allow-list change made after the snapshot is undone** until step 5 restores the list: a
  node identity removed since (a stolen one, 8.6) is admitted again, and a node added since is
  refused.
- **No active user is idle-purged:** a timer run idle-purges only after its history probe
  succeeds, and the first probe after the load sees it and raises the idle floor to now. A run
  whose probe fails skips the idle purge, and the next run probes again. Eviction at a capacity
  cap (6.2) has no such guard: until that first probe, a put at a cap can evict a session whose
  recent activity the load rewound. Step 4 keeps that window short.

**Which snapshot.** The deploy job keeps exactly one snapshot, taken just before the last upgrade.

- Its id and time are in that deploy run's summary: *Snapshot (taken before the upgrade)*.
- It carries the module that was installed then: **loading it also rolls the code back** to the
  release before that deploy.

Steps:

1. **Note the snapshot's time** `T_snap`, and the release whose module it holds (the deploy run's
   *Module before*):

   ```sh
   dfx canister snapshot list <CANISTER_ID> --network ic
   ```

2. **Pick the journal entries to replay, before the load:** step 5 replays the key entries and
   restores the allow-list as soon as the canister is back, so have them at hand. List the admin
   journal (2.3), and keep this target's `admin` runs created after `T_snap`.
   - **Replay** every run whose last *Outcome* row is `Ok`.
   - **Inspect** a run whose last outcome is `call failed` or `unrecognized reply`, and a run that
     reached its *Admin call* step but has no final outcome (cancelled, timed out, failed, or its
     runner lost): its summary's last *Outcome* row says `submitted`, or it has no *Admin call*
     section at all. `gh run view <RUN_ID> --verbose` lists the steps a run reached. Once dfx has
     submitted a call, the IC executes it whatever becomes of the run, so such a call may or may
     not have taken effect: compare its intent with `get_status` and `get_key_checks` now, while
     they still show the state the run left (after the load they show the snapshot's), or simply
     replay it, since every admin method is idempotent or harmless to repeat.
   - **Skip** runs that stopped before their *Admin call* step, and runs whose outcome is `Err`
     (the canister refused the call). They changed nothing.
   - **Skip** the `admin_update_config(record {})` runs of this procedure (step 4).
   - **Add** any admin call made by hand since `T_snap`.
   - **Split them:** step 5 replays the `admin_set_key_check` and `admin_retire_kid` entries and
     restores the allow-list; step 8 replays everything else (the rest of the configuration,
     purges). `authorized` replaces the whole list (6.3), so restoring it takes one call with the
     list the latest entry that set `authorized` sent; replaying older lists, even for a moment,
     would admit again a node removed since. Note that list, and leave `authorized` out of the
     `admin_update_config` entries step 8 replays.
3. **Load it:**

   ```sh
   dfx canister stop <CANISTER_ID> --network ic
   dfx canister snapshot load <CANISTER_ID> <SNAPSHOT_ID> --network ic
   dfx canister start <CANISTER_ID> --network ic
   dfx canister info <CANISTER_ID> --network ic    # Module hash: the snapshot's release
   ```

4. **Run the workflow right away:** admin mode, `tag` = the snapshot's release, method
   `admin_update_config`, argument `(record {})`.
   - This re-arms the purge timer and schedules an immediate run.
   - That run's history probe sees the `load_snapshot` change. It sets
     `epoch = max(epoch + 1, change count)` and `idle_floor_at = now`, and adds 1 to
     `restores_detected`.
   - A run whose probe fails skips the idle purge (nothing is judged idle on the snapshot's
     stale activity times), and the next run, within `purge_interval_secs`, probes again.
   - Without this call, the next timer run does the same within `purge_interval_secs`, but only if
     the timer is armed.
5. **Replay the key checks and retirements, and restore the allow-list, right away,** before the
   checks below: the `admin_set_key_check` and `admin_retire_kid` entries of step 2, oldest first,
   with the same argument, and `tag` = the release now installed. They are idempotent. If an entry
   since `T_snap` set `authorized`, then run `admin_update_config` with
   `(record { authorized = opt vec { … } })` and the list step 2 noted (Appendix B).
   - **Until then, a key rotation finished since `T_snap` takes every node down.** The restored
     key list is the snapshot's, so a kid published since is `unpublished` in it. A node that
     holds no kid the snapshot verified has no sealing kid (4.1): at its next replicated fetch,
     which re-reads the key checks, `imcp2_shared_ready` and `imcp2_shared_up` drop to 0, on
     every node at once. The *Node not ready* and *Canister unreachable* alerts fire, and the load
     balancer marks every upstream down. Within about 35 s of the replay (as in 4.6 step 3) the
     nodes read the key checks again and come back, without a restart.
   - **Replaying first also closes a hole.** The restored list un-retires every kid retired since
     `T_snap`. A node that still holds such a kid (an emergency rotation before its step 5, 4.6)
     would accept values under it until the retirement is replayed, and seal under it too when no
     earlier kid of its keyring is verified, as kid n is not if its check was published since.
   - **So does restoring the allow-list.** The restored allow-list is the snapshot's. It admits
     again a node identity removed since `T_snap` (a stolen one, 8.6), which can flood
     `put_session` up to the caps meanwhile, and refuses a node added since, which is not ready
     until then.
6. **Check the canister:**
   - its log shows
     `restore check: the canister history shows a snapshot load; epoch <a> -> <b>, idle floor raised to now`;
   - `get_status` shows the new `epoch` and `counters.restores_detected`.
7. **Check every node** (within about 30 s, its next replicated fetch):
   - `imcp2_shared_epoch` (and `/version` `shared.epoch`) equals the new epoch;
   - `imcp2_shared_resyncs_total{reason="epoch"}` went up by 1, and the log says `the session
     canister's epoch changed (a snapshot load); rebuilding the mirror`. A node (re)started during
     the restore, whose first replicated page already carried the new epoch, had no epoch to
     change: it counts no `epoch` resync and logs no such line, but
     `imcp2_shared_resyncs_total{reason="first_page"}` if requests had mirrored anything before
     that page (9.1), and nothing otherwise. Its `imcp2_shared_epoch` is what shows it caught up;
   - `imcp2_shared_ready` is 1 (a node that dropped before step 5 is back within about 35 s of
     it), and `shared.synced` is `true` again once the rebuild is done. A node allow-listed
     after `T_snap` is ready again once step 5 restored the list, with no restart (8.3).
8. **Replay the rest** of step 2's entries (the rest of the configuration, purges), oldest first,
   with the same method and argument (an `admin_update_config` entry without its `authorized`
   field, which step 5 restored; one that set nothing else is done), and `tag` = the release now
   installed.
   - Purges run one at a time: wait for `purge_job.done` in `get_status` before the next.
9. **Redeploy when ready.** Once the cause is understood, deploy the release you want (7.1). That
   deploy replaces the loaded snapshot with one of the restored state.

**Snapshots taken by hand.** Take them only with the canister stopped
(`dfx canister snapshot create <CANISTER_ID> --network ic`). Delete them before the next deploy,
which refuses to run with more than one snapshot. Each snapshot is about the size of stable memory:
about 106 MiB for an empty canister.

## 9. Monitoring

### 9.1 Metrics

Each node serves these at `/metrics` on its own port. Caddy answers 404 on the public origin.

| Series | What it tells you |
|---|---|
| `imcp2_shared_up` | 1 while an update-path call succeeded within 360 s, a query within 30 s, and a verified sealing kid exists. Catches a frozen canister. (With a longer `replicated_interval` or poll interval than the defaults, the windows stretch to the interval + 60 s and two polls.) |
| `imcp2_shared_ready` | Node-local readiness (8.3). It stays 1 through canister-wide outages and resyncs, so the load balancer never drains every node at once. The exception is a snapshot load older than a key rotation: the restored key checks leave no verified sealing kid, and it drops to 0 on every node until they are replayed (8.10, step 5). |
| `imcp2_shared_canister_calls_total{method,mode,outcome}`, `…_call_duration_seconds{method,mode}` | Every canister call: `mode` is `query`, `replicated` or `update`; `outcome` is `ok`, `unauthorized`, `canister_error`, `timeout`, `transport`, `reject` or `decode`. |
| `imcp2_shared_cursor`, `imcp2_shared_head`, `imcp2_shared_epoch` | Feed position applied by replicated reads, the canister's latest position, its epoch. A lasting gap between `head` and `cursor` means the node is not applying replicated pages. |
| `imcp2_shared_mirrored_records`, `imcp2_shared_adopted_sessions` | Mirror size; sessions opened on this node. |
| `imcp2_shared_resolve_total{result}` | Token resolutions: `ready`, `invalid` (401: garbage, forged, or a retired kid), `gone` (401: purged or absent, authoritatively), `unavailable` (503). |
| `imcp2_shared_sealed_rejected_total{kind,reason}` | Values that did not open. `kind`: `record`, `connect`, `code`, `access_token`. 503 reasons: `kid_drift`, `missing_key`, `newer_format`, `newer_payload`. 401 reasons: `retired_kid`, `unknown_kid`, `bad_seal`, `malformed`, `malformed_payload`, `sid_mismatch`, `wrong_family`, `wrong_purpose`, `bad_base64`, `too_short`, `too_long`. |
| `imcp2_shared_unavailable_total{endpoint,reason}` | Requests answered 503 (or, at `authorize`, sent back with `temporarily_unavailable`) by shared mode. `endpoint`: `authorize`, `redeem`, `token`, `mcp`. `reason` names the cause, e.g. `no_sealing_kid`, `identity_refused`, `kid_drift`, `missing_key`, `capacity_exceeded`, `timeout`, `reject`, `transport`, `at_capacity`, `read_budget`, `resync`, and at `token` the exchange budget's `deadline`, `spacing`, `budget`. |
| `imcp2_shared_key_info{kid,fingerprint,state,sealing}` | Always 1, one series per kid of the keyring (4.4). |
| `imcp2_shared_clock_skew_seconds` | 8.5. |
| `imcp2_shared_touch_backlog` | Activity reports pending (only with a lowered idle timeout). |
| `imcp2_shared_resyncs_total{reason}` | Mirror rebuilds. `epoch`: the canister's epoch changed, after a snapshot load. `first_page`: at a node's first replicated page since its start, the mirror already held what requests had read through or exchanged before the node knew the epoch, and it was dropped and fetched again (logged at info). That happens on a start under traffic, not a restore, so no alert watches it. A node (re)started during a restore whose first page already carried the new epoch counts no `epoch` resync, at most this (8.10, step 7). |
| `imcp2_shared_canister_sessions{ii_instance}`, `…_canister_tombstones`, `…_canister_events_total{event}`, `…_canister_cycles`, `…_canister_stable_memory_bytes`, `…_canister_purge_backlog_seconds` | The canister's `get_status`, read by every node as an update. Every node reports the same values: **aggregate with `max()`**. `event` is one of `opened`, `consumed`, `abandoned`, `expired`, `idle_purged`, `evicted`, `admin_purged`, `tombstones_collected`, `restores_detected`. |

In shared mode, `imcp2_live_sessions` and `imcp2_active_sessions` count the sessions adopted **on
this node**: summed over nodes, a client served by several counts several times. For the
deployment-wide count, use `max by (ii_instance) (imcp2_shared_canister_sessions)`.

The canister gauges are read right after a node's first sync, then every 15 minutes (60 s after a
failed read), so they lag the canister by up to that much.

### 9.2 Alerts

| Alert | Condition | Action |
|---|---|---|
| Canister unreachable | `max(imcp2_shared_up) == 0` (every node) | 8.1, 8.2 |
| Node not ready | `imcp2_shared_ready == 0` on a node | 8.3 |
| 503s served | `sum by (endpoint, reason) (rate(imcp2_shared_unavailable_total[5m])) > 0` | by `reason` |
| Unexpected sign-outs | `rate(imcp2_shared_resolve_total{result="gone"}[5m])` well above its baseline, with no purge or retirement under way | check the journal and `canister_events_total` |
| Key drift | `imcp2_shared_key_info{state="mismatch"}` exists, or `count by (kid) (count by (kid, fingerprint) (imcp2_shared_key_info)) > 1` | 8.4 |
| Values not openable here | `rate(imcp2_shared_sealed_rejected_total{reason="kid_drift"}[5m]) > 0`, and the same for `missing_key` and `newer_format` | 8.4; `newer_format` means a rollback past the two-release rule |
| Clock skew | `abs(imcp2_shared_clock_skew_seconds) >= 60` | 8.5 |
| Low cycles | `max(imcp2_shared_canister_cycles) < 3e12` | 8.2 |
| Near capacity | `max by (ii_instance) (imcp2_shared_canister_sessions)` above your warning level for `max_sessions_per_namespace` | 6.2 |
| Puts refused | `rate(imcp2_shared_canister_calls_total{method="put_session",outcome="canister_error"}[5m]) > 0`, or `rate(imcp2_shared_unavailable_total{endpoint="redeem",reason="capacity_exceeded"}[5m]) > 0` | 6.2 |
| Purge falling behind | `max(imcp2_shared_canister_purge_backlog_seconds)` growing over a few purge intervals | 8.9 |
| Restore detected (informational) | `increase(imcp2_shared_resyncs_total{reason="epoch"}[15m]) > 0` | 8.10, steps 2 and 5 to 8 |

<!-- TODO(reconcile): staging tuning. Hold durations, the 503 and sign-out baselines and the capacity warning level are not specified by the design; tune them on staging. The 60 s skew and 3 T cycles thresholds are the design's. -->

### 9.3 `/ready/shared`

- **Answers:** `200` with the body `ready` when the node is ready, `503` with `not ready` when it
  is not (`text/plain`, `Cache-Control: no-store`), and `404` when sharing is off.
- **Use it only to select upstreams for the MCP routes,** e.g. Caddy's `health_uri /ready/shared`
  in front of several nodes.
- **Never feed it into a gateway's global health or a host's liveness check.** A node stays ready
  through canister outages on purpose, so that the MCP routes are never drained everywhere at
  once. The one exception: after a snapshot load older than a key rotation, the restored key
  checks leave no node a verified sealing kid, so every node is not ready (and `up` is 0) until
  the key checks are replayed ([8.10](#810-disaster-recovery-snapshot-load), step 5).
- **It is public.** Unauthenticated, like `/version`, and the staging Caddy proxies it with every
  other path; it reveals one bit. `robots.txt` disallows `/ready/`.
- **Staging** has one host behind Caddy, so nothing selects on it there. `deploy.sh` reports it
  after each deploy.

### 9.4 `/version`

With sharing on, `/version` gains a `shared` block with this node's status; with sharing off the
key is absent. Values not known yet are `null`. A node started against a canister it cannot reach:

```json
"shared": {
  "canister_id": "<CANISTER_ID>",
  "node_principal": "<NODE_PRINCIPAL>",
  "up": false, "ready": false, "synced": false, "identity_refused": false,
  "epoch": null, "cursor": 0, "hint": 0, "head": 0,
  "key_checks_version": null, "sealing_kid": null,
  "kids": [
    { "kid": 2, "fingerprint": "79fb9575ed18e1c5", "state": "unknown", "sealing": false },
    { "kid": 1, "fingerprint": "eaf48e9dd7cc754f", "state": "unknown", "sealing": false }
  ],
  "idle_timeout_secs": null, "idle_floor_at": null, "touches_effective": false,
  "clock_skew_s": null,
  "mirrored_records": 0, "final_tombstones": 0, "adopted_sessions": 0, "resyncs": 0,
  "last_update_ok_s_ago": null, "last_query_ok_s_ago": null, "last_replicated_fetch_s_ago": null,
  "instances": ["prod"], "loop_running": true
}
```

| Field | Meaning |
|---|---|
| `node_principal` | This node's identity: the principal the allow-list must hold. |
| `up`, `ready` | As the metrics (9.1). |
| `synced` | The mirror is complete for the current epoch: true once the first complete replicated fetch after a start or a resync is applied. |
| `identity_refused` | The canister refuses this node (8.3). |
| `epoch`, `cursor`, `hint`, `head` | The canister's epoch; the feed position applied from replicated reads, the one polls reached, and the canister's latest. |
| `key_checks_version`, `sealing_kid`, `kids` | The key checks held, the kid new values are sealed under, and each kid of the keyring in sealing order, with its state (4.4). |
| `idle_timeout_secs`, `idle_floor_at`, `touches_effective` | The canister's idle settings as last read, and whether this node reports activity under them (6.1). |
| `clock_skew_s` | 8.5. |
| `mirrored_records`, `final_tombstones`, `adopted_sessions`, `resyncs` | The mirror's size, the deletions held as final, the sessions opened on this node, and the epoch resyncs since start. |
| `last_update_ok_s_ago`, `last_query_ok_s_ago`, `last_replicated_fetch_s_ago` | Seconds since the canister last answered an update-path call, a query, and since the last complete replicated fetch. |
| `instances`, `loop_running` | The servers attached (`prod`, `beta`), and whether the sync loop runs. |

Use the block to check one node quickly, without Prometheus.

### 9.5 Node log lines

What a node logs about shared sessions (unit `imcp2`; never a key, a cookie, a code or a token):

| Level | Line | Meaning |
|---|---|---|
| info | `shared sessions on: the canister's allow-list must hold node_principal` | Startup, with the settings and the node's principal (2.1). |
| info | `shared-sessions keyring: new values are sealed under the first kid, …` | Startup: the kids and fingerprints, in sealing order. |
| warn | `IMCP2_SHARED_CANISTER_ID is unset, so shared sessions are off and these settings are ignored` | Sharing off, with other `IMCP2_SHARED_*` variables set (names only). |
| info | `shared-session sync loop started` / `stopped` | The loop's lifetime. |
| warn | `cannot read the session canister's key checks; nothing is sealed until then` | Startup, until the canister answers (8.3). |
| info | `shared sessions seal under kid` | A kid became the sealing kid. |
| warn | `no kid of this node's keyring is verified by the session canister: nothing can be sealed …` | 8.3, 8.4. |
| warn | `fetching the session feed failed` | A replicated fetch failed; it backs off and retries (8.1). |
| warn | `the session canister's epoch changed (a snapshot load); rebuilding the mirror` | 8.10. |
| info | `shared sessions: the first page of the feed; dropping what was mirrored before the epoch was known` | A start under traffic: `resyncs_total{reason="first_page"}` (9.1). |
| warn | `storing the session record failed` | A redeem's `put_session` failed, with its `reason` (6.2, 8.1). |
| warn | `the shared-session activity reports were not sent within 5s; dropped` | Shutdown: the flush timed out (it only keeps sessions from the idle purge). |

The `session opened` and `session closed` lines are `info` only on the nodes that ran the
sign-in's redeem and token steps (one node, or two when those steps landed on different nodes);
nodes that adopt the session later, to serve `/mcp`, log them at `debug`.

### 9.6 The canister itself

| Command | Who | Shows |
|---|---|---|
| `dfx canister info <CANISTER_ID> --network ic` | anyone | controllers, module hash |
| `dfx canister status <CANISTER_ID> --network ic` | controller | running status, balance, freezing threshold, idle burn, memory |
| `dfx canister call <CANISTER_ID> get_status '()' --network ic --update` | controller, or an allow-listed node | version, commit, config, sessions and tombstones per namespace, head, epoch, idle floor, key checks, per-caller statistics, purge job, counters, purge backlog, cycles, stable memory |
| `dfx canister call <CANISTER_ID> get_key_checks '()' --network ic --update` | controller, or an allow-listed node | published checks, retired kids, version |
| `dfx canister logs <CANISTER_ID> --network ic` | controller | install and upgrade lines, purge runs, restore probes and detections |

The canister has no HTTP interface and no public metrics. The nodes' `imcp2_shared_canister_*`
gauges are the way to watch it continuously.

Its log lines:

- `imcp2-session-canister <version> (<commit>) installed`, or `… upgraded`;
- `purge: <n> processed, more due: <bool>, <instructions> instructions`, one per purge step that
  did something;
- `restore check: the canister history shows a snapshot load; epoch <a> -> <b>, idle floor raised
  to now` (8.10);
- `restore probe: canister_info failed: …` or `restore probe: unreadable canister_info reply: …`
  (that run skips the idle purge, 8.9);
- `[ic-cdk-timers] … too many concurrent timer calls (250), deferring timer to next round`, after a
  long stop or freeze (8.2).

An update call refused by `inspect_message` (including a query method called with `--update`)
fails with the trap message `inspect_message: <caller> may not call <method>` (error code
`IC0503`): that is what dfx shows when, say, a non-controller calls an `admin_*` method. A plain
query from a caller not on the allow-list gets the typed `Err = variant { Unauthorized }`.

## Appendix A: a key check without the binary

This prints, for every entry of a keyring file, the same lines `imcp2 shared-key-check` prints
(byte for byte: checked against the binary with the test keyring below):

```sh
cat > keycheck.py <<'EOF'
import base64, hashlib, hmac, re, sys
text = open(sys.argv[1]).read()
for entry in filter(None, (e.strip() for e in re.split(r"[,\r\n]", text))):
    kid, b64 = (part.strip() for part in entry.split(":", 1))
    b64 = b64.replace("-", "+").replace("_", "/")
    key = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
    if len(key) != 32 or not 1 <= int(kid) <= 255:
        sys.exit(f"entry for kid {kid}: expected a kid in 1..=255 and a 32-byte key")
    prk = hmac.new(b"", key, hashlib.sha256).digest()          # HKDF-Extract, empty salt
    check = hmac.new(prk, b"imcp2/keycheck/v1\x01", hashlib.sha256).digest()[:16]
    blob = "".join(f"\\{b:02x}" for b in check)
    print(f'record {{ kid = {int(kid)} : nat8; check = blob "{blob}" }} /* fingerprint {check[:8].hex()} */')
EOF
python3 -I keycheck.py keys.txt
```

- **Where to run it:** on the machine where you generated the keyring.
- **What it reads:** only the file named on its command line. Nothing reaches the process list.
- **Why to trust it:** it reproduces the key-check vectors in `src/shared/keys.rs`'s tests. Kid 1
  with the key bytes `0x00..=0x1f` gives `eaf48e9dd7cc754f027f549306d86a2f`, and kid 2 with
  `0x20..=0x3f` gives `79fb9575ed18e1c509c1bc27e1a7e277`: the two lines shown in 4.3.
- **It is more lenient than the binary.** It does not refuse a repeated kid, nor every malformed
  entry the binary refuses. If the binary refuses a keyring, fix the keyring; do not publish the
  script's lines for it.

## Appendix B: Candid arguments

Every argument below was checked to decode into the API crate's types (`imcp2-session-api`), with
placeholders replaced by real values. Numbers carry their type, so an argument also encodes
correctly when nothing types it against the `.did`.

| Purpose | Method | Argument |
|---|---|---|
| First install | (install) | `(variant { Init = record { authorized = opt vec { principal "<NODE_1_PRINCIPAL>"; principal "<NODE_2_PRINCIPAL>" } } })` |
| Upgrade (the workflow) | (install) | `(variant { Upgrade = null })` |
| No change: re-arm the timer, detect a load | `admin_update_config` | `(record {})` |
| Idle timeout 7 days | `admin_update_config` | `(record { idle_timeout_secs = opt (604800 : nat64) })` |
| Allow-list | `admin_update_config` | `(record { authorized = opt vec { principal "<NODE_1_PRINCIPAL>"; principal "<NODE_2_PRINCIPAL>" } })` |
| Capacity caps | `admin_update_config` | `(record { max_sessions = opt (<TOTAL> : nat64); max_sessions_per_namespace = opt (<PER_NAMESPACE> : nat64) })` |
| Purge batch | `admin_update_config` | `(record { purge_batch = opt (<N> : nat32) })` |
| Publish a key check | `admin_set_key_check` | `(record { kid = <KID> : nat8; check = blob "<16 bytes as \hh escapes>" }, false)` |
| Retire a kid | `admin_retire_kid` | `(<KID> : nat8)` |
| Purge one kid's records | `admin_purge_sessions` | `(record { kid = opt (<KID> : nat8) })` |
| Purge one node's sessions | `admin_purge_sessions` | `(record { opened_by = opt principal "<PRINCIPAL>" })` |
| Purge one namespace, by creation time | `admin_purge_sessions` | `(record { namespace = opt blob "<16 bytes as \hh escapes>"; created_from = opt (<UNIX_SECONDS> : nat64); created_to = opt (<UNIX_SECONDS> : nat64) })` |

**Purge filters.**

- A purge removes the live records that match **every** field you set.
- `kid` is matched against byte 2 of the sealed envelope.
- Namespaces appear in `get_status` `per_namespace`.
- `created_from` must not be after `created_to`.
