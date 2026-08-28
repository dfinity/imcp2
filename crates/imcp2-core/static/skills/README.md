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
- To refresh: re-fetch the files, review the diff, and update
  `BUNDLED_SKILLS` for any added or removed names — the update ships like any
  other code change, through review and a release.

Deliberately not bundled from that manifest: the token/wallet integration
guides (`ckbtc`, `icrc-ledger`, `wallet-integration` — this server is not a
financial tool), `sns-launch` (staking/governance launches), and
`autosync-ic-skills` (it instructs live re-syncing, the opposite of this
bundle's point).
