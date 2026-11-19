# ICP MCP for Grok Build

Connect Grok Build to the [Internet Computer](https://internetcomputer.org) through
DFINITY's official hosted MCP server. Fetch a canister's Candid interface and API
guide, discover the canisters behind an ICP app from its name or URL, read app data
with typed Candid queries or OQL, and, with your consent, act as your Internet
Identity account at a specific app.

Source and full documentation: <https://github.com/dfinity/imcp2> ·
Landing page: <https://internetcomputer.org/icp-mcp/>

## What this plugin installs

This plugin installs one remote, Streamable HTTP MCP server:

- Name: `icp`
- Endpoint: `https://mcp.internetcomputer.org/mcp`
- Operator: DFINITY Foundation

The plugin contains no executable scripts, hooks, skills, downloaded binaries, or
embedded credentials. It only adds the MCP server configuration in `.mcp.json`.

## Tools

The server provides 10 tools. Nine are annotated read-only; `canister_update_call`
is the only state-changing tool.

| Tool | What it does |
| --- | --- |
| `open_app` | Resolve an ICP app (name or URL) to its Internet Identity derivation origin and discover the canisters it declares |
| `get_canister_candid` | Return a canister's Candid (`.did`) interface, or a selected subset of its methods |
| `get_canister_api_doc` | Return the canister's own prose API guide, when it publishes one |
| `get_canister_oql_schema` | Return the OQL schema (entities, fields, edges) of a canister with an OQL query surface |
| `canister_query` | Read a canister via a Candid query method or an OQL query |
| `canister_update_call` | Make a state-changing call, anonymously or as your account at an app (see limits below) |
| `get_app_principal` | Return the principal you act as at an app |
| `list_app_accounts` | List your Internet Identity accounts at an app |
| `candid_syntax_guide` | Reference for the textual Candid value syntax |
| `icp_oql_guide` | Reference for the OQL query dialect |

See the [Tools section of the imcp2 README](https://github.com/dfinity/imcp2#tools)
for the full argument and result reference.

## Authentication

No API key or environment variable is required. On first connection Grok Build runs
the server's OAuth 2.1 authorization-code flow with PKCE (S256); dynamic client
registration and client ID metadata documents are both supported. You sign in with
[Internet Identity](https://id.ai) (passkey-based) and choose on the consent screen:

- a session duration (10 minutes to 30 days), and
- an access level: **Questions only** (read-only; the Internet Computer rejects
  state-changing calls signed for that session) or **Actions & questions**.

You can revoke a connection at any time at <https://id.ai/manage/settings>.

## Network endpoints and data

- Grok Build talks only to `https://mcp.internetcomputer.org` (MCP + OAuth).
- The server, operated by DFINITY, reaches the Internet Computer through public
  network infrastructure (API boundary nodes at `icp-api.io`, Internet Identity at
  `id.ai`) and forwards user-directed calls to the application canisters you name.
  App discovery fetches `/.well-known/ic-architecture` and related metadata from
  the app origins you supply.
- Privacy policy: <https://internetcomputer.org/icp-mcp/privacy-policy/>

## Safety limits

- **Opt-in canisters only.** Tools that touch a canister work only on canisters
  the owning app declares in its
  [service-discoverability](https://docs.internetcomputer.org/guides/frontends/service-discoverability/)
  manifest.
- **No financial operations.** Token transfers, approvals, and other ledger
  value-moving methods are refused, as is every update call to a canister whose
  interface declares ICRC-1/ICRC-2 methods. There are no canister creation,
  funding, or management tools; use the [`icp` CLI](https://github.com/dfinity/icp-cli)
  for those.

## Getting connected

Once you have installed the plugin, open `/mcps` in interactive `grok`, select `icp`,
and authenticate. Your browser opens Internet Identity. Sign in, choose the
session duration and access level, and return to Grok.

Example prompts:

- "What interface does canister gftcp-myaaa-aaaar-qcaaa-cai expose, and what can it do?"
- "What canisters are behind https://opencloud.org, and which one holds the app's data?"
- "Open opencloud.org and list my accounts there."

## Support

- Email: <mcp@dfinity.org>
- Issues: <https://github.com/dfinity/imcp2/issues>
- Security reports: see [SECURITY.md](https://github.com/dfinity/imcp2/blob/main/SECURITY.md)
- Service status: <https://status.internetcomputer.org/>

## License

Apache-2.0. Copyright © DFINITY Stiftung.
