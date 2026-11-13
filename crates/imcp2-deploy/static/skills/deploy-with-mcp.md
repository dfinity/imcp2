---
name: deploy-with-mcp
description: "Deploy an icp project to the Internet Computer through this MCP server's icp_deploy_bundle tool instead of running icp deploy yourself. Covers the three steps an agent performs: bundle the project with icp project bundle, call icp_deploy_bundle with the bundle and the environment's canister ids file, and write the canister ids the tool returns back to that file. Use when the user asks you to deploy, ship, publish, upgrade or redeploy an icp project, or asks what icp_deploy_bundle needs. Do NOT use for projects targeting a local network (run icp deploy there) or for building the project (see the icp-cli skill)."
license: Apache-2.0
metadata:
  title: Deploy with this MCP server
  category: Infrastructure
---

# Deploy with this MCP server

## What This Is

This server has one tool that deploys: `icp_deploy_bundle`. It takes a
project bundle, an environment name and the environment's canister-id
mapping, runs every phase of `icp deploy` on the server's side (create,
wire ids, apply settings, install or upgrade, sync), and returns the status
and the resulting mapping. The project itself stays on your side: you build
it, bundle it, and keep its canister ids.

A deploy is three steps, in order:

1. Bundle the project with the icp CLI.
2. Call `icp_deploy_bundle` with the bundle, the environment, and the
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
  tool answers that it needs an authenticated session, call `authenticate`,
  have the user open the returned id.ai link, then retry. Check with
  `auth_status`.
- Cycles. Each new canister is created from the user's cycles balance, 2T
  cycles unless `cycles` says otherwise. `icp_cycles_balance` reports the
  balance and the principal that holds it, which is where the user sends
  cycles to top it up. Before a deploy that will create canisters, tell the
  user how many and confirm; creation is not undone by a later failure.
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

A server takes the bundle one way, and `icp_deploy_bundle` lists the one
argument for it: `bundle_path` on a server running on the project's machine,
`bundle_upload` on one that is not. A server that lists `icp_deploy_upload`
is of the second kind: it cannot open a path of yours, and a tool call cannot
carry the archive itself. Upload it first:

1. Call `icp_deploy_upload`. It returns a one-time ticket, good for a few
   minutes, and the exact `curl` command to run.
2. Run that command with the archive's path in place of `<bundle.tar.gz>`.
   It `PUT`s the archive to the server and prints a JSON answer whose
   `upload_id` names the upload, held for a quarter of an hour.
3. Pass that id to `icp_deploy_bundle` as `bundle_upload`, in place of
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
returns. Cancelling it interrupts the deploy at its next step, see pitfall 8.

### Read the answer

The tool returns:

- `status`: `deployed`, `failed`, `interrupted`, or `nothing_to_deploy`.
- `canister_ids`: the mapping after this run, the ids you passed in plus
  every id created. Step 3 uses this.
- `created`: the canisters created by this run, in order.
- `error`: what failed, when the status is `failed` or `interrupted`.
- `log`: one line per phase and per canister task, with the cause of each
  failure.

A deploy that fails, or is interrupted, still returns every canister it
created before that, in both `canister_ids` and `created`. Do step 3 on that
answer too, then fix the cause the log names and run step 2 again with the
updated mapping: the retry upgrades what exists and creates only what is
still missing.

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
   exception is the working directory of a call that never returned, see 8.
7. **Deploying twice at once.** One deploy runs at a time per session; a
   second is refused, not queued. Wait for the answer, do step 3, then deploy
   again from the updated file. A server that answers that it is busy is
   deploying for others: try again in a few minutes.
8. **A call that never returned.** Cancelling the call, or losing the
   connection, interrupts the deploy at its next step; a canister call
   already in flight completes on the network. If the server stopped
   mid-deploy, or you cancelled and never read the answer, the canisters it
   created are not lost: the deploy's working directory is kept — on the
   local server under the user's local data directory
   (`~/.local/share/imcp2-local/deploys/` on Linux,
   `~/Library/Application Support/imcp2-local/deploys/` on macOS,
   `%LOCALAPPDATA%\imcp2-local\deploys\` on Windows; on a hosted server
   under its state directory, where its operators can read it for the
   user), and its `.icp/data/mappings/<environment>.ids.json` records every
   canister the deploy had created. Do step 3 with that file's contents,
   delete the directory, and only then deploy again; otherwise the retry
   creates a second set.
