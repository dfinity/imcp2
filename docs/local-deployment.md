# IMCP2 local deployment — overview

Status: **draft**. This is the concise, high-level doc; the full design with code-level
detail and evidence lives in [`scoping-local-deployment.md`](scoping-local-deployment.md).

## Summary

We will ship **`imcp2-local`**: a small binary users run on their own machine and register
with their AI tool (Claude, Codex, Cursor, …) as a local MCP server. It speaks MCP over
**stdio**, talks to **mainnet** and **production Internet Identity**, and keeps the full II
experience — the user logs in with their real anchor via a browser handshake, and the server
mints per-app account delegations on demand. What it drops is the entire **OAuth 2.1
authorization server**: a single-user process reached over a pipe needs no bearer tokens.
The existing `imcp2` crate remains the shared library and the hosted server.

## Problem

Today IMCP2 exists only as a hosted, multi-tenant server: a public streamable-HTTP endpoint
gated by OAuth 2.1. For someone working from a desktop or IDE AI tool this has two costs:

- **Trust.** Their Internet Identity login — and every delegation minted from it — runs
  through a third-party server, even though they are acting on their own mainnet accounts.
- **Weight.** OAuth exists so *remote* clients can authenticate to a *public* endpoint. A
  local single-user server inherits all of that machinery (tokens, PKCE, client
  registration, discovery documents, a state directory) without needing any of it.

At the same time, every major desktop AI tool can spawn **local stdio MCP servers** — and
there is no IMCP2 artifact that fits that slot.

## Non-goals

- **Not a local-replica product surface** — the shipped binary targets mainnet and
  production II. A **test configuration** that talks to a local replica (as spawned by the
  ICP CLI) is deliberately easy to compile and is how integration tests run — but it is not
  a v1 user-facing mode.
- **No change to the hosted server** — its name, behavior, and deployments stay as they are.
- **No session persistence in v1** — sessions are in-memory; users re-login per run.
- **Not for cloud-only AI surfaces** — claude.ai web/mobile, Perplexity web, and Codex Cloud
  cannot reach a local process; they continue to use the hosted server.

## Approach

Hosted-vs-local is a **deployment axis, not a network one**: both talk to the same mainnet
and the same production II. What changes is who can reach the server, and therefore what
machinery is needed.

- **stdio transport.** The server has no listening socket; it is reachable only by the AI
  tool that spawned it. The OS process boundary replaces the OAuth bearer gate.
- **Internet Identity stays.** On first authenticated use the binary opens the user's
  browser to II, receives the delegation on a transient localhost callback, redeems it, and
  holds the session in memory — the same handshake the hosted server runs, minus the OAuth
  wrapper around it.
- **Login is an in-band tool.** No AI client shows a stdio server's logs in chat, so the
  login URL is returned as the result of an `authenticate` tool (with best-effort browser
  auto-open), lazily on first use and without blocking on the callback.
- **One library, two binaries.** `imcp2` stays the shared core (and the hosted binary,
  behind a default-on `hosted` feature); `imcp2-local` is a new, small crate that compiles
  none of the OAuth/HTTP machinery.

## Design components

1. **Crate layout** — `imcp2` (library + hosted binary; hosted-only surfaces behind the
   `hosted` feature) and `imcp2-local` (new minimal binary).
2. **Dependency profile** — the local closure is the MCP stack (stdio), `ic-agent`/Candid,
   and the discovery/management essentials; no axum, no CORS layer, no metrics stack, no
   OAuth persistence.
3. **IC + II wiring** — a mainnet agent and production II, env-overridable for staging.
4. **Auth partition** — keep the II connect-handshake primitives (link builder, callback
   page, delegation parser, the II callback allow-list, a slim redeem); drop the whole
   OAuth authorization server.
5. **Browser login** — three transient loopback routes during the handshake; the grant then
   lives in memory only.
6. **AI tool clients** — Claude Desktop, Claude Code, Codex, Cursor, Antigravity, and the
   Perplexity macOS app run `imcp2-local` directly; cloud surfaces keep using hosted.
7. **Session seam** — the hosted bearer-token lookup collapses to a singleton session id;
   a small, verified change with no impact on tool behavior.
8. **Security model** — whoever drives the binary acts as the user's real II accounts on
   mainnet: treat the binary and its client config like a wallet.

## Implementation Stages

1. **Carve out the core.** Move the hosted-only surfaces behind the `hosted` feature and
   introduce the session seam — no behavior change to the hosted server.
2. **Ship `imcp2-local`.** The stdio server, the browser-login driver, and the loopback
   callback listener. Exit: a user logs in against II and uses the tools as their accounts.
3. **Polish.** Per-client setup docs and the wallet-grade trust note; integration tests that
   run `imcp2-local` in its local-replica test configuration (against an ICP CLI-spawned
   replica or PocketIC, with an II canister deployed there), extending the existing PocketIC
   end-to-end harness to the local login flow; optional keychain-backed session persistence.

Open decisions (details in the full doc): hand-rolled vs axum-based loopback listener; how
to open the browser; v1 session persistence; two-crate vs three-crate layout.
