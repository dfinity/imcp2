# Bundled IC skills

Reviewed, versioned copies of the official Internet Computer skills, served
as `skill://<name>` MCP resources. The served endpoint retrieves NOTHING
dynamically: these files are compiled into the binary with `include_str!`
(see `BUNDLED_SKILLS` in `src/skills.rs`), so what a client reads is exactly
what was reviewed at this commit.

- Source: <https://skills.internetcomputer.org> (DFINITY's skill registry),
  each file fetched verbatim from
  `/.well-known/skills/<name>/SKILL.md`.
- Bundled: 2026-08-28, from the registry manifest of the same date.
- To refresh: re-fetch the files, review the diff, re-apply the two local
  edits listed below, and update `BUNDLED_SKILLS` /
  `BUNDLED_SKILL_REFERENCES` for any added or removed documents — the update
  ships like any other code change, through review and a release.

## Companion documents

Several skills keep their detail in sibling files rather than inline. Those
are bundled too, under `references/<skill>/<file>`, and served as
`skill://<skill>/references/<file>` — fetched from
`/.well-known/skills/<skill>/references/<file>` on the same date. Every link
inside a served document resolves to another served resource, so following
one never sends the agent back to the network.

## Local edits to the mirrored text

The files are otherwise verbatim. Two mechanical edits are applied, and must
be re-applied on every refresh:

1. **Relative links become bundle URIs.** `](references/<file>)` becomes
   `](skill://<skill>/references/<file>)`, so a link resolves to the bundled
   companion rather than to a path the client cannot open.
2. **`caffeine-app` no longer instructs a live load.** Three lines told the
   agent to load `writing-motoko`'s `SKILL.md` from the registry over HTTP;
   they now point at the `skill://writing-motoko` resource. A bundled
   instruction to fetch instructions would defeat the bundle.

Content itself is not edited here: this is a mirror, and corrections belong
upstream in the registry, from where the next refresh picks them up.

## Deliberately not bundled

From that manifest: the token/wallet integration guides (`ckbtc`,
`icrc-ledger`, `wallet-integration` — this server is not a financial tool),
`sns-launch` (staking/governance launches), and `autosync-ic-skills` (it
instructs live re-syncing, the opposite of this bundle's point).

Also `canhelp`: it is a slash-command skill (`allowed-tools:` frontmatter)
whose steps run `./scripts/*.sh` from a local checkout, which no MCP client
has. Its job — reading a canister's interface from an id or a name — is what
`get_canister_candid` and `icp_lookup_canister_info_by_id` already do here.
