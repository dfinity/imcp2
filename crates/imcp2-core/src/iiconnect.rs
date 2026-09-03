//! Internet Identity **connect-handshake primitives**, shared by every binary
//! that logs a user in with II's registration-delegation flow: building the II
//! `/mcp` connect link, rendering the pinned fragment-reading callback page,
//! parsing the fragment's delegation chain, and the `#4091` auth-callback
//! allow-list path. Everything here is parameterised on plain values (URLs,
//! strings) and returns plain values — the embedding server wraps them in its
//! own HTTP handlers and supplies its own state (an OAuth authorization server
//! in the hosted `imcp2` binary; a transient loopback listener in a local one).

use base64::Engine;
use candid::Principal;
use ic_agent::identity::{Delegation, SignedDelegation};
use serde::Deserialize;

/// Build Internet Identity's `/mcp` connect link for one connection. Everything
/// is in the URL **fragment** (never sent to II's servers): `callback` (the
/// pinned callback URL on the caller's origin), the single-use `state`, the
/// requested grant `ttl` in SECONDS, and `registration_key` — this connect's
/// registration public key `pub(X)` (DER, base64url), toward which II builds
/// the registration chain `P_reg -> Y -> X` (param name per
/// dfinity/internet-identity#4093; its presence selects the connect flow). II
/// navigates the tab back to `callback` — validated against the origin's
/// [`AUTH_CALLBACKS_WELL_KNOWN`] allow-list (#4091) — with the delegation in
/// the fragment; the callback page rendered by [`pinned_callback_page`] is the
/// sole fragment reader. No `priv(X)` is ever put in the link — only its
/// public half.
pub fn ii_mcp_url(
    ii_url: &str,
    callback_url: &str,
    state: &str,
    ttl_secs: u64,
    reg_pubkey_b64: &str,
) -> String {
    format!(
        "{ii_url}/mcp#callback={cb}&state={st}&ttl={ttl_secs}&registration_key={rk}",
        cb = urlencoding::encode(callback_url),
        st = urlencoding::encode(state),
        rk = urlencoding::encode(reg_pubkey_b64),
    )
}

// ---- Callback allow-list (II #4091) ---------------------------------------

/// The well-known path Internet Identity fetches a server's **auth-callback
/// allow-list** from (dfinity/internet-identity#4091): before contacting the
/// connect callback named in the (attacker-craftable) link fragment, II fetches
/// `<callback origin>` + this path — `redirect: "error"`, no credentials,
/// `no-store`, 8 KB cap, `application/json` required — and rejects the connect
/// unless the callback URL is EXACTLY (string-equal) one of the declared
/// entries. **Fail-closed**: a missing/unfetchable file fails every connect for
/// this origin, so serving this document is mandatory once #4091 ships.
pub const AUTH_CALLBACKS_WELL_KNOWN: &str = "/.well-known/ii-auth-callbacks";

/// A fresh CSP nonce: 128 bits from the OS CSPRNG, **standard** base64. CSP3's
/// `base64-value` grammar also admits base64url, but CSP2's does not (`-`/`_`
/// absent), so use the standard alphabet for maximum parser compatibility — a
/// strict-CSP2 parser that rejected the nonce source would block the inline
/// script and break the callback page. `+`/`/`/`=` are all safe where the nonce
/// rides (a quoted HTML attribute and a header value).
pub fn csp_nonce() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom");
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Styling for the pinned callback page, following the DFINITY brand guidelines
/// (Parchment/Ink/Rust palette, an editorial serif display over a UI sans, a
/// grid-paper surface, and the official gradient-infinity logo). A full-bleed
/// screen: the status stage (a spinner on a soft elevated tile plus an accessible
/// serif headline) fills and centres the viewport, with a foot-of-page "Hosted
/// by" mark; the spinner is CSS-only (disabled under `prefers-reduced-motion`).
/// Light/dark theming via `prefers-color-scheme` with a `data-theme` override,
/// using the brand's Bark/Bone/Ember dark palette. Fully self-contained (no
/// external fonts, images, or stylesheets; the logo is inlined into the served
/// HTML), so it renders identically under the pinned page's strict
/// `default-src 'none'` CSP. The stylesheet lives in `assets/connect.css` and is
/// compiled into the binary via `include_str!` (no runtime file I/O), so it is
/// authored as a real `.css` file rather than a Rust string literal. The pinned
/// page serves it in a `<style nonce>` block (with `style-src 'nonce-...'` added
/// to its CSP so the block is allowed WITHOUT `'unsafe-inline'`). The `.error`
/// modifier (added to `.screen` client-side) hides the spinner tile once a
/// terminal message is shown. Public so the embedding server's other
/// browser-facing pages (e.g. `imcp2`'s error screens) reuse the one shell.
pub const CONNECT_PAGE_CSS: &str = include_str!("assets/connect.css");

/// The official DFINITY logo (gradient-infinity mark + wordmark), taken from
/// dfinity.org. It lives in `assets/dfinity-logo.svg` and is compiled into the
/// binary via `include_str!`, then inlined into the served HTML so it needs no
/// external fetch under the pinned page's strict CSP. The infinity keeps the
/// brand gradients; the wordmark is set to `currentColor` so it follows the
/// page's Ink/Bone text color across light and dark themes. Public for the
/// same reason as [`CONNECT_PAGE_CSS`].
pub const CONNECT_LOGO_SVG: &str = include_str!("assets/dfinity-logo.svg");

/// HTML template for the pinned callback page, kept as a real `.html` asset file
/// (compiled in via `include_str!`, no runtime file I/O) rather than an inline
/// Rust string literal, so the markup reads and diffs as HTML. It is a self-
/// contained document with `__TOKEN__` placeholders spliced in at render time
/// (the stylesheet `__CSS__`, the logo `__LOGO__`, and the per-response
/// `__NONCE__`/`__SCRIPT__`). No user-influenced value is ever interpolated.
const PINNED_PAGE_HTML: &str = include_str!("assets/connect-callback.html");

/// The pinned page's inline script, kept as a PLAIN string, not a `format!`
/// template, so it reads naturally (no doubled braces, room for comments). The
/// one dynamic value, the redeem URL, is spliced in by replacing
/// `__REDEEM_URL__`, which sits inside a quoted JS string literal below.
const PINNED_PAGE_JS: &str = r#"(function () {
  // Swap the status line to `message` and move the screen into a terminal
  // state: 'error' drops the spinner and reveals the contact line, 'done'
  // just drops the spinner (see connect.css).
  function show(message, stateClass) {
    document.getElementById('m').textContent = message;
    if (stateClass) {
      var screenElement = document.querySelector('.screen');
      if (screenElement) { screenElement.classList.add(stateClass); }
    }
  }
  // II delivers #delegation=<chain JSON>&state=<state>: the two-hop chain plus
  // the connect state, percent-encoded by URLSearchParams and decoded again by
  // it here. Consent (permissions, max_ttl) is NOT in the fragment: the user
  // chose it earlier at II's prepare step, which stored it keyed by P_reg, and
  // mcp_register_v2 recovers it server-side. So the page forwards only the chain
  // and the state; the backend redeems with mcp_register_v2(session_key).
  var params = new URLSearchParams(location.hash.slice(1));
  var body = JSON.stringify({
    state: params.get('state') || '',
    delegation: params.get('delegation') || ''
  });
  // Scrub the delegation from the address bar, keeping the path and any query
  // string the declared callback carries. Best-effort: the POST below works
  // even if a browser refuses the history call.
  try { history.replaceState(null, '', location.pathname + location.search); } catch (ignored) {}
  fetch("__REDEEM_URL__", {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'same-origin',
    body: body
  })
    .then(function (response) { return response.json().catch(function () { return {}; }); })
    .then(function (data) {
      // Two success shapes, per deployment: the hosted redeem answers with the
      // `redirect` that continues its OAuth flow; a local redeem has nothing to
      // navigate to, so it answers `done` and this page IS the terminal state.
      if (data && data.redirect) {
        location.replace(data.redirect);
      } else if (data && data.done) {
        show("Signed in — you can close this tab.", 'done');
      } else {
        show((data && data.error) || "We couldn't finish the connection. Restart from your client.", 'error');
      }
    })
    .catch(function () {
      show("We couldn't reach the server. Restart from your client.", 'error');
    });
})();"#;

/// A rendered pinned callback page: the final HTML plus the
/// `Content-Security-Policy` header value its nonce is bound into. The
/// embedding server turns this into an HTTP response, adding its own
/// non-CSP hardening headers (`Referrer-Policy: no-referrer`,
/// `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`).
pub struct PinnedPage {
    /// The complete, self-contained HTML document.
    pub html: String,
    /// The `Content-Security-Policy` value matching the nonce spliced into
    /// `html`'s inline `<script>`/`<style>` blocks.
    pub csp: String,
}

/// Render the strict-CSP, non-reflecting **pinned callback page** — the sole
/// reader of the delegation fragment II delivers. A fresh per-response nonce is
/// bound into the CSP and BOTH the inline `<script>` and `<style>`, so no
/// `'unsafe-inline'` is needed; `connect-src 'self'` limits the page's only
/// network reach to the same-origin redeem endpoint, and `default-src 'none'`
/// forbids loading anything else (all styling is inline and self-contained; see
/// [`CONNECT_PAGE_CSS`]). No attacker-supplied value (fragment, query) is ever
/// interpolated into the HTML; the fragment is read client-side and sent via
/// `fetch`, never written to the DOM.
///
/// The fragment shape matches II's frontend (merged contract): the delegation
/// chain plus the connect state only:
/// `#delegation=<JSON.stringify(DelegationChain.toJSON())>&state=<state>`,
/// percent-encoded by `URLSearchParams`. The script reads both fields and
/// POSTs them as a [`RedeemBody`] to `redeem_url` (same-origin). `contact` is
/// the address shown by the page's error state so a failed handshake carries a
/// "report it" line.
pub fn pinned_callback_page(redeem_url: &str, contact: &str) -> PinnedPage {
    let nonce = csp_nonce();
    let redeem = js_escape(redeem_url);
    let script = PINNED_PAGE_JS.replace("__REDEEM_URL__", &redeem);
    // The markup lives in `assets/connect-callback.html` (include_str!). The
    // status line is a `role=status` / `aria-live=polite` region so screen
    // readers announce both "Connecting agent to Internet Identity…" and any
    // terminal error the script swaps in. Below it sits a `.contact-hint` line
    // (hidden during a normal connect; revealed by the stylesheet once the
    // script adds `.error` to `.screen`) so every handshake/redeem failure the
    // user lands on carries the "contact us to report it" line. The DFINITY logo
    // carries its own `aria-label`; the spinner is decorative (`aria-hidden`).
    // `__NONCE__` (both the `<style>` and `<script>` tags), the self-contained
    // stylesheet, logo, the contact address, and redeem script are spliced in;
    // none of those values contains a placeholder token, so the order is immaterial.
    let html = PINNED_PAGE_HTML
        .replace("__NONCE__", &nonce)
        .replace("__CSS__", CONNECT_PAGE_CSS)
        .replace("__LOGO__", CONNECT_LOGO_SVG)
        .replace("__CONTACT__", contact)
        .replace("__SCRIPT__", &script);
    // `style-src 'nonce-{nonce}'` admits ONLY the nonce'd `<style>` block above
    // (no `'unsafe-inline'`, so an injected `style=` attribute or stray `<style>`
    // still can't apply). Without it the block falls back to `default-src
    // 'none'` and the page renders unstyled.
    // `img-src 'self'`: CSP governs the `<link rel=icon>` fetch as an image, so
    // without it the favicon is dropped.
    // `frame-ancestors 'none'`: II reaches this page only by top-level
    // navigation, so framing is never legitimate: deny it outright so the
    // delegation-bearing page can't be embedded for UI redress. X-Frame-Options
    // covers legacy browsers that predate CSP2 (modern ones ignore it when
    // frame-ancestors is present).
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
         img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; \
         frame-ancestors 'none'"
    );
    PinnedPage { html, csp }
}

/// Escape a string for embedding inside a double-quoted JS string literal.
pub fn js_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('<', "\\x3c")
}

// ---- The redeem body + delegation-chain parsing ---------------------------

/// The redeem POST body — what the pinned callback page sends after parsing
/// the fragment: the `state` echo and the delegation chain's JSON text exactly
/// as II's frontend put it in the fragment
/// (`JSON.stringify(DelegationChain.toJSON())`, dfinity/internet-identity#4093).
/// **No consent values and no anchor are carried**: the user's chosen
/// permissions/TTL were captured earlier at `prepare_mcp_registration_delegation`
/// (keyed by `P_reg`), and II recovers them, and the user's identity number,
/// from `caller() == P_reg`, so the server never sees any of them.
#[derive(Deserialize)]
pub struct RedeemBody {
    /// The single-use connect state (= session id), echoed by II.
    pub state: String,
    /// The two-hop `P_reg -> Y -> X` chain as agent-js `DelegationChain` JSON
    /// ([`JsonDelegationChain`]); `der(P_reg)` rides inside as `publicKey`.
    #[serde(default)]
    pub delegation: String,
}

/// Size cap for the redeem body's `delegation` JSON text, checked BEFORE
/// parsing so oversized attacker-controlled input is rejected without large
/// allocations (same posture as the discovery-buffering bound, CWE-770). A
/// legitimate chain — one delegation plus a canister signature with its
/// certificate — is a few KB of hex/JSON, so this is generous while staying
/// far under a server's request-body limits.
pub const MAX_REG_DELEGATION_JSON: usize = 64 * 1024;

/// agent-js `DelegationChain.toJSON()`, the wire shape II's frontend delivers
/// in the callback fragment (dfinity/internet-identity#4093): byte fields are
/// HEX strings, `expiration` is a HEX string of ns since the epoch
/// (`BigInt.toString(16)`), `targets` are principal texts, and `publicKey` is
/// the chain root `der(P_reg)`. `delegations` carries TWO hops — the
/// canister-signed `P_reg -> Y` toward II's ephemeral browser-held `Y`, and
/// the `Y`-signed `Y -> X` toward our registration key (the split keeps the
/// canister-signed piece, which transits the IC, inert on its own).
///
/// `deny_unknown_fields` on purpose: every field of a delegation is covered by
/// its canister signature, so a field this parser does not carry (e.g. a future
/// `permissions`) could never re-hash to what II signed — dropping it silently
/// would resurface the opaque "sig not found in the signature tree" replica
/// error (the #40 read-only outage). Failing fast names the real problem.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonDelegationChain {
    delegations: Vec<JsonSignedDelegation>,
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonSignedDelegation {
    delegation: JsonDelegation,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonDelegation {
    pubkey: String,
    /// Hex string of ns since the Unix epoch (agent-js `BigInt.toString(16)`).
    expiration: String,
    #[serde(default)]
    targets: Option<Vec<String>>,
}

/// Decode a hex string field of the chain JSON.
fn hex_decode(field: &str, s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s.trim()).map_err(|e| format!("{field} is not valid hex: {e}"))
}

/// Parse the fragment's `DelegationChain` JSON into `(der(P_reg), chain)` as
/// `ic-agent` types — hop count is preserved verbatim (two hops per rev3 of the
/// guide; the redeem path only requires that the FINAL hop targets our `X`, and
/// the replica verifies every hop authoritatively). The chain carries no
/// `permissions` field: the access level isn't stored in the delegation at all.
/// The user chose it at consent, II stored it under `P_reg` at
/// `prepare_mcp_registration_delegation`, and it never touches the server. So a
/// `permissions` field appearing here would be unexpected, and
/// [`JsonDelegationChain`] fails fast if one ever does.
pub fn parse_registration_delegation(
    delegation_json: &str,
) -> Result<(Vec<u8>, Vec<SignedDelegation>), String> {
    // Bound the size BEFORE parsing (see MAX_REG_DELEGATION_JSON): reject
    // oversized input without allocating for it. This also inherently bounds
    // every field inside the JSON (pubkeys, signatures, targets).
    if delegation_json.len() > MAX_REG_DELEGATION_JSON {
        return Err(format!("delegation exceeds {MAX_REG_DELEGATION_JSON} bytes"));
    }
    let chain: JsonDelegationChain =
        serde_json::from_str(delegation_json).map_err(|e| format!("delegation JSON: {e}"))?;
    let user_key = hex_decode("publicKey", &chain.public_key)?;
    let delegations = chain
        .delegations
        .iter()
        .map(|d| {
            let targets = match &d.delegation.targets {
                None => None,
                Some(ts) => Some(
                    ts.iter()
                        .map(|t| {
                            Principal::from_text(t.trim())
                                .map_err(|e| format!("delegation target principal: {e}"))
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            };
            Ok(SignedDelegation {
                delegation: Delegation {
                    pubkey: hex_decode("delegation pubkey", &d.delegation.pubkey)?,
                    expiration: u64::from_str_radix(d.delegation.expiration.trim(), 16)
                        .map_err(|_| "delegation expiration is not a hex u64".to_string())?,
                    targets,
                    permissions: None,
                },
                signature: hex_decode("delegation signature", &d.signature)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((user_key, delegations))
}

#[cfg(test)]
mod tests {
    // A REAL agent-js `DelegationChain.toJSON()` payload round-trips: built
    // exactly as II's #4093 frontend emits it (hex byte fields, HEX-string
    // expiration, principal-text targets, top-level `publicKey` = der(P_reg)),
    // carrying rev3's TWO hops (`P_reg -> Y` canister-signed, `Y -> X`
    // browser-signed) — decodes into `(der(P_reg), [both hops in order])`.
    #[test]
    fn parse_registration_delegation_round_trips_two_hops() {
        let der_preg = vec![1u8, 2, 3];
        let der_y = vec![7u8, 7, 7]; // II's ephemeral browser-held key
        let der_x = vec![9u8, 8, 7, 6]; // our registration key
        let sig_canister = vec![4u8, 5, 6];
        let sig_y = vec![1u8, 9, 9];
        let chain_json = serde_json::json!({
            "delegations": [
                {
                    "delegation": {
                        "pubkey": hex::encode(&der_y),
                        "expiration": format!("{:x}", 66_u64), // BigInt.toString(16)
                        "targets": ["aaaaa-aa"],
                    },
                    "signature": hex::encode(&sig_canister),
                },
                {
                    "delegation": {
                        "pubkey": hex::encode(&der_x),
                        "expiration": format!("{:x}", 66_u64),
                    },
                    "signature": hex::encode(&sig_y),
                },
            ],
            "publicKey": hex::encode(&der_preg),
        })
        .to_string();
        let (uk, chain) = super::parse_registration_delegation(&chain_json).expect("parse");
        assert_eq!(uk, der_preg);
        assert_eq!(chain.len(), 2, "both hops preserved, in order");
        // Hop 1: canister-signed P_reg -> Y. Its `targets` round-trips from
        // principal text (`aaaaa-aa` here as a stand-in; live chains carry the
        // II canister id).
        assert_eq!(chain[0].delegation.pubkey, der_y);
        assert_eq!(chain[0].delegation.expiration, 66);
        assert_eq!(chain[0].signature, sig_canister);
        assert_eq!(
            chain[0].delegation.targets.as_ref().unwrap()[0],
            candid::Principal::management_canister()
        );
        // Hop 2: browser-signed Y -> X.
        assert_eq!(chain[1].delegation.pubkey, der_x);
        assert_eq!(chain[1].signature, sig_y);
        assert_eq!(chain[1].delegation.targets, None);
        // Neither hop carries a permissions field; the access level was chosen
        // at consent and stored by II under P_reg (recovered from caller()), so
        // it never rides the delegation or the fragment.
        assert!(chain.iter().all(|d| d.delegation.permissions.is_none()));
    }

    // Malformed input fails with a clear error: non-JSON, bad hex, a
    // non-hex expiration — and, critically, an UNKNOWN field inside the
    // delegation (deny_unknown_fields): every delegation field is covered by
    // the canister signature, so silently dropping one could never re-hash to
    // what II signed (the #40 outage class) — fail fast instead.
    #[test]
    fn parse_registration_delegation_rejects_bad_input() {
        assert!(super::parse_registration_delegation("not json").is_err());

        let bad_hex = serde_json::json!({
            "delegations": [{
                "delegation": { "pubkey": "zz", "expiration": "1" },
                "signature": "0102",
            }],
            "publicKey": "010203",
        })
        .to_string();
        let err = super::parse_registration_delegation(&bad_hex).expect_err("bad hex must fail");
        assert!(err.contains("not valid hex"), "got: {err}");

        let bad_exp = serde_json::json!({
            "delegations": [{
                "delegation": { "pubkey": "0102", "expiration": "not-hex" },
                "signature": "0102",
            }],
            "publicKey": "010203",
        })
        .to_string();
        let err =
            super::parse_registration_delegation(&bad_exp).expect_err("bad expiration must fail");
        assert!(err.contains("expiration"), "got: {err}");

        // A field this parser does not carry (e.g. a future `permissions`)
        // must fail fast rather than be silently dropped.
        let unknown_field = serde_json::json!({
            "delegations": [{
                "delegation": { "pubkey": "0102", "expiration": "1", "permissions": "queries" },
                "signature": "0102",
            }],
            "publicKey": "010203",
        })
        .to_string();
        let err = super::parse_registration_delegation(&unknown_field)
            .expect_err("an unknown delegation field must fail fast, not silently drop");
        assert!(err.contains("permissions"), "got: {err}");
    }

    // CWE-770 guard: an oversized delegation payload is rejected BEFORE any
    // JSON parse, so an attacker-sized payload can't force large allocations.
    // A legit chain is a few KB, far below the cap.
    #[test]
    fn parse_registration_delegation_bounds_input_size() {
        let huge = "A".repeat(super::MAX_REG_DELEGATION_JSON + 1);
        let err =
            super::parse_registration_delegation(&huge).expect_err("oversized delegation rejected");
        assert!(err.contains("exceeds"), "got: {err}");

        // At-cap input proceeds past the size check (and fails on content,
        // not on size) — the bound doesn't clip legitimate-shaped requests.
        let at_cap = "A".repeat(super::MAX_REG_DELEGATION_JSON);
        let err =
            super::parse_registration_delegation(&at_cap).expect_err("fails on content, not size");
        assert!(!err.contains("exceeds"), "at-cap input must pass the size check: {err}");
    }

    // The CSP nonce must use the STANDARD base64 alphabet: CSP2's base64-value
    // grammar has no `-`/`_`, so a base64url nonce risks a strict parser dropping
    // the source and blocking the inline script (breaking the callback page).
    #[test]
    fn csp_nonce_is_standard_base64() {
        for _ in 0..16 {
            let n = super::csp_nonce();
            assert!(
                !n.contains('-') && !n.contains('_'),
                "CSP nonce must not use base64url characters: {n}"
            );
            assert!(n.len() >= 22, "128-bit nonce floor: {n}");
        }
    }

    // The connect link carries everything in the FRAGMENT, percent-encoded, in
    // the #4093 parameter order; the pinned page's CSP binds the same nonce
    // into both inline blocks.
    #[test]
    fn ii_mcp_url_encodes_fragment_params() {
        let url = super::ii_mcp_url(
            "https://id.ai",
            "http://127.0.0.1:4361/callback",
            "sess-1",
            3600,
            "AQID",
        );
        assert!(url.starts_with("https://id.ai/mcp#callback="));
        assert!(url.contains("callback=http%3A%2F%2F127.0.0.1%3A4361%2Fcallback"), "{url}");
        assert!(url.contains("&state=sess-1&ttl=3600&registration_key=AQID"), "{url}");
    }

    // The page's script resolves the redeem answer three ways: `redirect`
    // (hosted — navigate into the OAuth continuation), `done` (local — render
    // the terminal "Signed in" state in place; there is nothing to navigate
    // to), and everything else as the error screen. The `done` state drops the
    // spinner without revealing the contact line (see connect.css). Guards the
    // contract the local redeem answers with `{"done": true}` against.
    #[test]
    fn pinned_page_script_handles_redirect_done_and_error() {
        let page = super::pinned_callback_page("/redeem", "mcp@dfinity.org");
        assert!(page.html.contains("data.redirect"), "hosted success arm");
        assert!(page.html.contains("data.done"), "local success arm");
        assert!(
            page.html.contains("Signed in \u{2014} you can close this tab."),
            "the done arm renders the terminal signed-in state"
        );
        assert!(page.html.contains("'done'") && page.html.contains("'error'"));
        assert!(
            super::CONNECT_PAGE_CSS.contains(".screen.done .spinner-tile"),
            "the done state must drop the spinner (connect.css)"
        );
    }

    #[test]
    fn pinned_page_binds_one_nonce_into_html_and_csp() {
        let page = super::pinned_callback_page("/oauth/connect/redeem", "mcp@dfinity.org");
        // The CSP names a nonce; that same nonce appears in the HTML (script +
        // style), and the redeem URL is spliced into the script.
        let nonce = page
            .csp
            .split("script-src 'nonce-")
            .nth(1)
            .and_then(|s| s.split('\'').next())
            .expect("CSP carries a script nonce");
        assert!(page.html.contains(nonce), "nonce must be spliced into the HTML");
        assert!(page.html.contains("/oauth/connect/redeem"), "redeem URL spliced into the script");
        assert!(page.html.contains("mcp@dfinity.org"), "contact line spliced in");
        assert!(!page.html.contains("__NONCE__") && !page.html.contains("__SCRIPT__"));
    }
}
