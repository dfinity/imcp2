---
name: deploy-with-mcp
description: "Deploy an icp project to the Internet Computer through this MCP server's icp_deploy tool instead of running icp deploy yourself. Covers the three steps an agent performs: bundle the project with icp project bundle, call icp_deploy with the bundle and the environment's canister ids file, and write the canister ids the tool returns back to that file; and what to do when the deploy says the user's cycles do not cover it: where they can buy more, and to whom. Use when the user asks you to deploy, ship, publish, upgrade or redeploy an icp project, asks what icp_deploy needs, or needs cycles to deploy with. Do NOT use for projects targeting a local network (run icp deploy there) or for building the project (see the icp-cli skill)."
license: Apache-2.0
metadata:
  title: Deploy with this MCP server
  category: Infrastructure
---

# Deploy with this MCP server

## What This Is

This server has one tool that deploys: `icp_deploy`. It takes a
project bundle, an environment name and the environment's canister-id
mapping, runs every phase of `icp deploy` on the server's side (create,
wire ids, apply settings, install or upgrade, sync), and returns the status
and the resulting mapping. The project itself stays on your side: you build
it, bundle it, and keep its canister ids.

A deploy is three steps, in order:

1. Bundle the project with the icp CLI.
2. Call `icp_deploy` with the bundle, the environment, and the
   environment's current canister-id mapping. On a server that runs
   elsewhere than the project — one that lists `icp_deploy_upload` — the
   bundle is uploaded first, on a ticket that tool returns.
3. Write the mapping the tool returns back into the project.

Skipping step 3 is the mistake that costs the most: the next deploy would
not know the canisters already exist and would create a second set.

## Prerequisites

- The icp CLI (0.3.0 or later) on the machine that builds the project.
  Installation and project configuration are in the `icp-cli` skill.
- A signed-in session with the "Actions & questions" access level. If a
  tool answers that it needs an authenticated session, or that the session
  is over, how to sign in depends on the server. One that lists an
  `authenticate` tool (the local server) signs in through it: call it, have
  the user open the returned id.ai link, then retry; check with
  `auth_status`. One that does not (a hosted server) is signed in to by the
  MCP client as it connects: ask the user to reconnect the server in their
  client, then retry.
- Cycles. Each new canister is created from the user's cycles balance, 2T
  cycles unless `cycles` says otherwise. Before a deploy that will create canisters, tell the
  user how many and confirm; creation is not undone by a later failure.
  A canister on a cloud engine is the exception: it is not paid for from
  that balance, and a deploy to one needs no cycles bought.
  A deploy the balance does not cover fails and says how to fund it: see
  "When the cycles run short" below. `icp_deploy`'s description names where
  cycles are sold, so you can tell a user who asks; have them buy only what a
  deploy's `funding` says is missing.
- An environment on the `ic` network (mainnet), which every manifest has.
  The tool deploys to the Internet Computer only: an environment on any other
  network — the default `local`, a testnet — is refused. Deploy those with
  `icp deploy` in the project directory instead.

## Step 1: Bundle the project

From the project root (the directory holding `icp.yaml`):

```bash
icp project bundle --output /absolute/path/to/myapp.tar.gz
```

This builds every canister, then writes a gzipped tar archive holding the
built wasms, the plugins the sync steps need, and a rewritten `icp.yaml`
whose build steps reference the bundled wasms, pinned by sha256. The bundle
is self-contained: the server needs no toolchain to deploy it.

Rules that matter here:

- Use an absolute output path outside any directory a canister syncs (a
  frontend's `dist/`, for example), or the archive would include itself.
- Only `plugin` sync steps can be replayed from a bundle. A canister with a
  `script` sync step cannot be bundled; the CLI says so.
- A server that deploys for others runs only the sync plugins it knows: the
  released plugins that upload a frontend's assets, each known by the hash
  of its module. A bundle whose canister is synced by any other plugin — a
  build of your own, a release the server has not been told of — is refused
  on the upload (`422`) or by the deploy, and the refusal lists the hashes
  the server runs. That is not something to retry or work around: tell the
  user, who can switch the project to a listed plugin release and bundle
  again, or deploy with a server of their own (`imcp2-local`, or `icp
  deploy`), which runs whatever the project brings.
- The bundle is built for the environments the manifest declares. Pick the
  one you will deploy in step 2 now, and build with the matching settings.

If the build fails, fix the project and rebuild. Nothing has been sent yet.

## Step 2: Request the deployment

### Read the environment's canister ids file

The project keeps one file per environment, the record of which canisters
on the network are this app's:

```
.icp/data/mappings/<environment>.ids.json
```

Read it if it exists and pass its content on unchanged; there is nothing in
it to interpret or edit. If it does not exist, this is the first deploy of
that environment and every canister will be created.

### Upload the bundle, on a server that cannot read your files

A server takes the bundle one way, and `icp_deploy` lists the one
argument for it: `bundle_path` on a server running on the project's machine,
`bundle_upload` on one that is not. A server that lists `icp_deploy_upload`
is of the second kind: it cannot open a path of yours, and a tool call cannot
carry the archive itself. Upload it first:

1. Call `icp_deploy_upload`. It returns a one-time ticket, good for a few
   minutes, and the exact `curl` command to run.
2. Run that command with the archive's path in place of `<bundle.tar.gz>`.
   It `PUT`s the archive to the server and prints a JSON answer whose
   `upload_id` names the upload, held for five minutes: deploy it next. A
   refused upload exits non-zero and prints the server's reason instead
   (the limit it passed, why it is not a bundle, the plugin hash a server
   does not run): read it before trying again. The command needs curl 7.76
   or later for `--fail-with-body`; with an older one, drop the flag and
   read the outcome off the printed answer. One
   upload at a time: a new one replaces the one before it, so upload again
   only to replace. A server that answers that it is full is holding other
   users' bundles: ask for a new ticket and try again in a few minutes.

   The server extracts the archive as it arrives, and stops the upload if
   the archive, or what it extracts to, passes the limit the ticket's answer
   names (`max_bytes`, `max_extracted_bytes`). It answers `413` and says
   which, but `curl` is still sending and often reports only a failed
   transfer: `Broken pipe`, `Connection reset`, exit code 55 or 56. If
   `curl` printed the server's answer, go by that. If it printed only the
   failed transfer, take the bundle for too large before taking the network
   for faulty: check the archive's size, and what it extracts to
   (`tar -tzvf <bundle.tar.gz>`), against the two limits. Only a bundle
   within both was cut off for another reason (a ticket already spent, a
   server that is full or restarting, the network): ask for a new ticket
   and upload once more. What a bundle
   extracts to is counted as the space it occupies, so thousands of small
   files weigh more than their bytes: each takes at least 5 KiB. An answer
   of `422` means the server read the file and it is not a bundle; rebuild
   it with `icp project bundle`. A new ticket is needed after any of these.
3. Pass that id to `icp_deploy` as `bundle_upload`, in place of
   `bundle_path`.

A ticket is spent by one upload, successful or not; an upload is spent by
one deploy. If either lapses, ask for a new ticket and upload again. Each
kind of server refuses the other's argument: one that lists
`icp_deploy_upload` refuses `bundle_path`, one that does not refuses
`bundle_upload`.

### Call the tool

Pass the bundle, the environment name, and the file's content as
`canister_ids`:

```json
{
  "bundle_path": "/absolute/path/to/myapp.tar.gz",
  "environment": "ic",
  "canister_ids": { "backend": "rrkah-fqaaa-aaaaa-aaaaq-cai" }
}
```

- `bundle_path` must be absolute. On a server that cannot read your
  filesystem, pass `bundle_upload` from the upload above in its place.
- `environment` is the name as the manifest declares it, `ic` for a default
  project.
- `canister_ids` is the file's content. Omit it, or send `{}`, on a first
  deploy. Every canister named in it is upgraded in place; every canister the
  bundle names that is missing from it is created.

Canisters named in `canister_ids` are upgraded with the Candid compatibility
check; an incompatible interface change fails the deploy before any code is
replaced. Pass `skip_candid_check: true` only when the user has accepted the
break. `mode` (default `auto`; `install`, `reinstall`, `upgrade`),
`cycles`, `subnet` and `no_create` mirror the flags of `icp deploy`.

### Watch it run

The call lasts as long as the deploy: creating canisters, installing code
and syncing a frontend's assets take from seconds to minutes. The tool
reports each phase and canister step the moment it completes, as a progress
notification when your call carries a `progressToken` (most clients attach
one; it is also what keeps your client's per-call timeout from expiring
mid-deploy), else as a server log message. Keep the call open until it
returns. Cancelling it interrupts the deploy at its next step, see pitfall 9.

### Read the answer

The tool returns:

- `status`: `deployed`, `failed`, `interrupted`, or `nothing_to_deploy`.
- `canister_ids`: the mapping after this run, the ids you passed in plus
  every id created. Step 3 uses this.
- `created`: the canisters created by this run, in order.
- `error`: what failed, when the status is `failed` or `interrupted`.
- `funding`: how to fund the deploy, only when it failed because the user's
  cycles did not cover it. See "When the cycles run short".
- `log`: one line per phase and per canister task, with the cause of each
  failure.

A deploy that fails, or is interrupted, still returns every canister it
created before that, in both `canister_ids` and `created`. Do step 3 on that
answer too, then fix the cause the log names and run step 2 again with the
updated mapping: the retry upgrades what exists and creates only what is
still missing.

### When the cycles run short

A failed deploy whose answer carries `funding` ran out of the user's cycles
balance: the cycles ledger refused to create a canister. The canisters it
had created are in the answer, the rest are not paid for. Go by that field,
not by the error's wording: a failure that mentions cycles and has no
`funding` (a canister that ran out while its code was installed, say) is not
one a purchase for this account fixes. Disregard the icp CLI commands the
error itself suggests. `funding` holds:

- `principal`: the principal `icp_deploy` creates canisters as. Its Cycles
  Ledger account holds the balance, and is the account bought cycles must be
  delivered to. It is not the user's principal in any app, the provider's
  included.
- `needed`, and when the ledger answered, `balance` and `shortfall`, in
  cycles: what the canisters still to create take, what is there, and what
  is missing at the least.
- `providers`: where the user can buy cycles, each with a name, an `app_url`
  and how the user pays there.
- `steps`: what to do with a provider, the same for all of them.

What to do:

1. Do step 3 first, with the `canister_ids` of this answer.
2. Tell the user what is missing, show them the providers, and let them
   pick one and how much to buy. Do not pick for them, and do not round the
   amount up without saying so.
3. Call `open_app` with the provider's `app_url`, then
   `get_canister_api_doc` on the canister it marks `[declared]` for orders.
   That guide is the provider's own. It says how to quote a price (what the
   amount buys after the provider's fees, at the current rate) and how to
   make an order; this skill does not, because each provider differs and
   changes its terms without notice here.
4. Following the guide, make an order whose cycles go to the Cycles Ledger
   account of `principal`. Name that principal as the account to credit (a
   beneficiary or recipient argument): the order is made as the user's
   account at the provider, which is another principal, and an order that
   credits the caller sends the cycles where `icp_deploy` cannot spend them.
   The order call is a `canister_update_call` and needs an "Actions &
   questions" session. It takes no payment: it answers a payment URL.
5. Give the user the payment URL exactly as the provider returned it. They
   open it and confirm one payment on the provider's page. Never ask for
   card details and never enter any: they go to that page alone.
6. Read the order's status as the guide says until the cycles are delivered
   (the guide names the statuses on the way, and what a refund looks like).
7. Deploy again with the same environment and settings and the updated
   mapping. On a server that takes the bundle by upload, upload it again
   first and pass the new upload id: an upload is spent by one deploy.

If `open_app` marks none of a provider's canisters `[declared]`, the provider
is not reachable through this server and no order can be made here: offer
another, or tell the user they can buy on the provider's own site, entering
`principal` as the Cycles Ledger account to credit.

Nothing here moves money. The server names an account and a list; the order
records what the user is about to pay for; the payment is the user's own, on
a page of the provider's.

## Step 3: Update the project's mapping file

Write the returned `canister_ids` to the environment's file, unchanged, in
place of what was there (it holds every id you passed in, plus the new
ones):

```
.icp/data/mappings/<environment>.ids.json
```

Create the `.icp/data/mappings/` directory if it does not exist. The file is
the project's only record of which on-chain canisters belong to it; the
`icp-cli` skill lists committing `.icp/data/` to version control as the
rule, and losing the file as the pitfall. Tell the user which canisters were
created and their ids.

## Common Pitfalls

1. **Deploying twice without writing the mapping back.** The second deploy
   creates new canisters next to the first ones, spending cycles on
   duplicates. Always do step 3, including after a failure.
2. **Passing a relative `bundle_path`.** The tool refuses it; the server's
   working directory is not the project's.
3. **Deploying `local`.** Refused: this tool deploys to the `ic` network
   only. Use `icp deploy` in the project directory for local work and for
   other networks.
4. **Bundling a stale build.** `icp project bundle` builds first, so the
   bundle is current, but a bundle written earlier is not. Rebundle after
   every change.
5. **Mapping entries that are not canisters of the environment.** A name in
   `canister_ids` that the bundle's manifest does not declare for that
   environment is rejected before anything runs. Remove canisters from the
   file when they are removed from the project.
6. **Expecting the server to keep state.** It keeps nothing between calls:
   no bundle, no mapping. The project's mapping file is the record. The one
   exception is the working directory of a call that never returned, see 9.
7. **Deploying twice at once.** One deploy runs at a time per session; a
   second is refused, not queued. Wait for the answer, do step 3, then deploy
   again from the updated file. A server that answers that it is busy is
   deploying for others: try again in a few minutes.
8. **Sending bought cycles to the wrong account.** The balance
   `icp_deploy` spends is that of the `principal` in its `funding` answer.
   An order that credits its caller, or the principal the user has in the
   provider's app, delivers cycles the deploy cannot use. Name `principal`
   as the account to credit, every time.
9. **A call that never returned.** Cancelling the call, or losing the
   connection, interrupts the deploy at its next step; a canister call
   already in flight is waited for and what it did is recorded, so a
   canister it created is in the result. A server that restarts
   interrupts the deploy the same way and still answers: the result's
   `canister_ids` holds what is known to have been created, so do step 3
   with it and deploy again. One exception, which the result's error names:
   if it says a call **went unanswered** or **was given up on**, a canister
   that call was creating may exist without being listed. Do not deploy
   again yet, and do not go looking for it yourself: nothing here can list
   the canisters an identity controls (`icp canister list` shows the
   project's canister names, not what exists), and a cycles balance that
   dropped by one canister's funding more than the mapping accounts for
   says that one was created, not which. Tell the user what happened and
   that they must find out before retrying; a retry from the mapping as it
   stands may create, and fund, a second canister. If they establish the
   canister's id, add it to the mapping first. The same caution applies to
   the record below. If the server stopped mid-deploy, or you cancelled and never read
   the answer, the canisters it created are not lost: the deploy's working directory is kept — on the
   local server under the user's local data directory
   (`~/.local/share/imcp2-local/deploys/` on Linux,
   `~/Library/Application Support/imcp2-local/deploys/` on macOS,
   `%LOCALAPPDATA%\imcp2-local\deploys\` on Windows; on a hosted server
   under its state directory, where its operators can read it for the
   user), and its `.icp/data/mappings/<environment>.ids.json` records every
   canister the deploy had created. Do step 3 with that file's contents,
   delete the directory, and only then deploy again; otherwise the retry
   creates a second set.
