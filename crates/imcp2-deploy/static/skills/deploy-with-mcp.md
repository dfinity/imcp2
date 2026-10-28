---
name: deploy-with-mcp
description: "Deploy an icp project to the Internet Computer through this MCP server's icp_deploy_bundle tool instead of running icp deploy yourself. Covers the three steps an agent performs: bundle the project with icp project bundle, call icp_deploy_bundle with the bundle and the environment's canister-id mapping, and write the mapping the tool returns back into the project. Use when the user asks you to deploy, ship, publish, upgrade or redeploy an icp project, or asks what icp_deploy_bundle needs. Do NOT use for projects targeting a local network (run icp deploy there) or for building the project (see the icp-cli skill)."
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
   environment's current canister-id mapping.
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
- Cycles. Every canister the bundle names that does not exist yet is created
  from the user's cycles balance, 2T cycles each unless `cycles` says
  otherwise. `icp_cycles_balance` reports the balance and the principal
  it belongs to. Before a deploy that will create canisters, tell the user how
  many and confirm; creation is not undone by a later failure.
- An environment on a connected network. Every manifest has `ic` (mainnet).
  An environment on a managed network, such as the default `local`, is
  refused: there is no local replica on the server's side. Deploy those with
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

### Read the environment's canister-id mapping

The icp CLI keeps one mapping file per environment:

```
.icp/data/mappings/<environment>.ids.json
```

It is a JSON object from canister name to principal:

```json
{
  "backend": "rrkah-fqaaa-aaaaa-aaaaq-cai",
  "frontend": "ryjl3-tyaaa-aaaaa-aaaba-cai"
}
```

Read it if it exists. If it does not, this is the first deploy of that
environment and every canister will be created.

### Call the tool

Pass the bundle, the environment name, and the mapping as `canister_ids`:

```json
{
  "bundle_path": "/absolute/path/to/myapp.tar.gz",
  "environment": "ic",
  "canister_ids": {
    "backend": "rrkah-fqaaa-aaaaa-aaaaq-cai",
    "frontend": "ryjl3-tyaaa-aaaaa-aaaba-cai"
  }
}
```

- `bundle_path` must be absolute. When the server cannot read your
  filesystem, send the archive inline as `bundle_base64` instead; exactly one
  of the two is accepted.
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

### Read the answer

The tool returns:

- `status`: `deployed`, `failed`, or `nothing_to_deploy`.
- `canister_ids`: the mapping after this run, the ids you passed in plus
  every id created. Step 3 uses this.
- `created`: the canisters created by this run, in order.
- `error`: what failed, when the status is `failed`.
- `log`: one line per phase and per canister task, with the cause of each
  failure.

A deploy that fails still returns every canister it created before failing,
in both `canister_ids` and `created`. Do step 3 on that answer too, then
fix the cause the log names and run step 2 again with the updated mapping:
the retry upgrades what exists and creates only what is still missing.

## Step 3: Update the project's mapping file

Write the returned `canister_ids` into the environment's mapping file,
replacing the entries it names and keeping any others:

```
.icp/data/mappings/<environment>.ids.json
```

Create the `.icp/data/mappings/` directory if it does not exist. The file is
the project's only record of which on-chain canisters belong to it; the
`icp-cli` skill lists committing `.icp/data/` to version control as the
rule, and losing the file as the pitfall. Tell the user which canisters were
created and their ids.

After this step, `icp deploy -e <environment>` from the CLI and
`icp_deploy_bundle` from here see the same canisters and can be used
interchangeably for that environment.

## Common Pitfalls

1. **Deploying twice without writing the mapping back.** The second deploy
   creates new canisters next to the first ones, spending cycles on
   duplicates. Always do step 3, including after a failure.
2. **Passing a relative `bundle_path`.** The tool refuses it; the server's
   working directory is not the project's.
3. **Deploying `local`.** Refused as a managed network. Use `icp deploy` in
   the project directory for local work; use this tool for `ic` and other
   connected networks.
4. **Bundling a stale build.** `icp project bundle` builds first, so the
   bundle is current, but a bundle written earlier is not. Rebundle after
   every change.
5. **Mapping entries that are not canisters of the environment.** A name in
   `canister_ids` that the bundle's manifest does not declare for that
   environment is rejected before anything runs. Remove canisters from the
   file when they are removed from the project.
6. **Expecting the server to keep state.** It keeps nothing between calls:
   no bundle, no mapping. The project's mapping file is the record.
