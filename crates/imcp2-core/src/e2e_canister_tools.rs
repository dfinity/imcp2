//! End-to-end tests for the **canister tools** — every tool that reaches a
//! canister — driven over a real MCP session against real canisters running in
//! PocketIC.
//!
//! ## What is real here
//! Everything between the tool call and the canister:
//!
//!   * a genuine **MCP session**: [`IcTools`] is served over a JSON-RPC
//!     connection; the suite reads the surface with `tools/list` the way a
//!     client does before calling anything, and each case is an ordinary
//!     `tools/call` — so tool names, the schemas advertised over the wire, the
//!     JSON argument objects those schemas describe, and the
//!     content/structured-content shape of every reply are exercised as a
//!     client sees them, not as Rust function arguments;
//!   * a genuine **replica**: PocketIC executes the calls, so argument
//!     encoding, ingress, query vs. update semantics, `candid:service`
//!     metadata reads, and reply decoding all happen for real, and an update
//!     call's state change is observable by the next read;
//!   * the whole tool composition: the compliance gate, the discoverability
//!     gate, identity binding, Candid encode/decode, and the provenance the
//!     replies carry.
//!
//! Two things are stood in for, each because a test cannot have the real one:
//!
//!   * the **app's web server** (its manifest and pinned derivation origin) —
//!     see [`crate::discover::webfixture`] for why a local server cannot serve
//!     it and what stays real;
//!   * **Internet Identity**, via [`Identities::seed_app_identity`], which
//!     signs a real delegation chain rooted in a plain key rather than a
//!     canister signature. The II handshake that normally produces one has its
//!     own end-to-end test against a live II canister (`imcp2`'s
//!     `e2e_handshake`).
//!
//! ## Gating (the default `cargo test` is untouched and offline)
//! Behind the `e2e` cargo feature — so `pocket-ic` is neither compiled nor its
//! server started by the default build — AND a runtime guard that skips unless
//! the PocketIC server binary, which cargo does not fetch, is provided:
//!
//! ```text
//! POCKET_IC_BIN=/abs/pocket-ic \        # pocket-ic v15 server
//!   cargo test -p imcp2-core --features e2e -- --nocapture
//! ```
//!
//! The binary is a release asset of the PocketIC repository
//! (`pocket-ic-x86_64-linux.gz` for a Linux x86-64 host); ungzip it and mark it
//! executable.
//!
//! ## The canisters under test
//! Built here, from WebAssembly text, rather than checked in as binaries or
//! compiled with a wasm toolchain: a handful of tiny methods
//! ([`Behavior`]) is all these tools need to be driven over, and assembling
//! them in-process keeps what each canister does readable next to the
//! assertions about it.

use candid::{Encode, Principal};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult},
    service::{RunningService, ServiceExt},
    RoleClient, RoleServer,
};
use std::sync::Arc;
use std::time::SystemTime;

use crate::{
    discover::webfixture,
    identities::{Identities, IiInstance},
    tools::IcTools,
    Agent,
};

// ===========================================================================
// The canisters under test
// ===========================================================================

/// What one exported method of a test canister does when called.
enum Behavior {
    /// Reply with these exact bytes — a Candid reply encoded here, in the test,
    /// so the canister needs no encoder of its own.
    Const(Vec<u8>),
    /// Reply with the call's own argument bytes. Candid encodes arguments and
    /// replies identically, so this is a valid `(text) -> (text)` echo.
    Echo,
    /// Store the argument bytes, then reply with them — the state change the
    /// update-call test observes.
    Store,
    /// Reply with the bytes the last [`Behavior::Store`] saved (the empty text
    /// until one has run).
    Load,
    /// Reply with the CALLER's principal, as a Candid `(principal)` — which is
    /// how a test sees whose identity a call was actually signed with.
    Caller,
}

/// One exported canister method: its Candid mode, its name, and what it does.
struct Method {
    /// Exported as `canister_query` when true, `canister_update` when false.
    /// The replica enforces this, which is what makes the read/write split in
    /// `canister_query` / `canister_update_call` testable for real.
    query: bool,
    name: &'static str,
    behavior: Behavior,
}

impl Method {
    fn query(name: &'static str, behavior: Behavior) -> Self {
        Self { query: true, name, behavior }
    }
    fn update(name: &'static str, behavior: Behavior) -> Self {
        Self { query: false, name, behavior }
    }
}

/// Bytes of one buffer in the canister's memory: big enough for any argument
/// or reply these tests send, small enough to keep the module tiny.
const BUFFER: u32 = 4096;
/// Where the caller's principal length is written, as the one byte that is also
/// the Candid value's own length prefix.
const CALLER_LEN: u32 = 4;
/// The 8-byte prefix of a Candid `(principal)` reply: the `DIDL` magic, an
/// empty type table, one argument of type `principal` (`0x68`), and the `0x01`
/// tag introducing a concrete id. The id's length byte and bytes follow it.
const CALLER_HEADER: u32 = 8;
/// Where the stored blob lives. Its length is an `i32` at address 0.
const STORE: u32 = 16;
/// Where an echoed argument is copied to.
const SCRATCH: u32 = STORE + BUFFER;
/// Where the constant replies start.
const CONSTS: u32 = SCRATCH + BUFFER;

/// Assemble a canister exporting `methods`, with `did` as its public
/// `candid:service` metadata (`None` for a canister that publishes no
/// interface — what an unreadable canister looks like to these tools).
fn canister_wasm(did: Option<&str>, methods: &[Method]) -> Vec<u8> {
    // (address, bytes) pairs emitted as data segments.
    let mut data: Vec<(u32, Vec<u8>)> = Vec::new();
    // The stored blob starts out as the Candid encoding of the empty text, so a
    // read before any write still decodes as `(text)` rather than as an empty
    // reply the decoder would have to guess at.
    let empty = Encode!(&"").expect("encode the empty text");
    data.push((0, (empty.len() as u32).to_le_bytes().to_vec()));
    data.push((STORE, empty));
    data.push((CALLER_HEADER, vec![b'D', b'I', b'D', b'L', 0x00, 0x01, 0x68, 0x01]));

    let mut next_const = CONSTS;
    let (mut funcs, mut exports) = (String::new(), String::new());
    for (i, m) in methods.iter().enumerate() {
        let body = match &m.behavior {
            Behavior::Const(bytes) => {
                let at = next_const;
                next_const += bytes.len() as u32;
                let len = bytes.len();
                data.push((at, bytes.clone()));
                format!(
                    "(call $reply_append (i32.const {at}) (i32.const {len}))\n    (call $reply)"
                )
            }
            Behavior::Echo => copy_arg_and_reply(SCRATCH, false),
            Behavior::Store => copy_arg_and_reply(STORE, true),
            Behavior::Load => format!(
                "(call $reply_append (i32.const {STORE}) (i32.load (i32.const 0)))\n    \
                 (call $reply)"
            ),
            // Assembled in three appends — the constant header, the id's length
            // byte, then the id — so the canister needs no Candid encoder of
            // its own to answer "who is calling?".
            Behavior::Caller => format!(
                "(call $reply_append (i32.const {CALLER_HEADER}) (i32.const 8))\n    \
                 (local.set $n (call $caller_size))\n    \
                 (i32.store8 (i32.const {CALLER_LEN}) (local.get $n))\n    \
                 (call $reply_append (i32.const {CALLER_LEN}) (i32.const 1))\n    \
                 (call $caller_copy (i32.const {SCRATCH}) (i32.const 0) (local.get $n))\n    \
                 (call $reply_append (i32.const {SCRATCH}) (local.get $n))\n    \
                 (call $reply)"
            ),
        };
        funcs.push_str(&format!("  (func $m{i} (local $n i32)\n    {body})\n"));
        let mode = if m.query { "query" } else { "update" };
        exports.push_str(&format!(
            "  (export \"canister_{mode} {}\" (func $m{i}))\n",
            m.name
        ));
    }

    let segments: String = data
        .iter()
        .map(|(at, bytes)| format!("  (data (i32.const {at}) \"{}\")\n", wat_bytes(bytes)))
        .collect();
    // One page past the highest address written, so a data segment can never
    // land outside the declared memory.
    let pages = next_const / 65536 + 2;
    let module = format!(
        "(module\n\
         \x20 (import \"ic0\" \"msg_arg_data_size\" (func $arg_size (result i32)))\n\
         \x20 (import \"ic0\" \"msg_arg_data_copy\" (func $arg_copy (param i32 i32 i32)))\n\
         \x20 (import \"ic0\" \"msg_caller_size\" (func $caller_size (result i32)))\n\
         \x20 (import \"ic0\" \"msg_caller_copy\" (func $caller_copy (param i32 i32 i32)))\n\
         \x20 (import \"ic0\" \"msg_reply_data_append\" (func $reply_append (param i32 i32)))\n\
         \x20 (import \"ic0\" \"msg_reply\" (func $reply))\n\
         \x20 (import \"ic0\" \"trap\" (func $trap (param i32 i32)))\n\
         \x20 (memory {pages})\n\
         {segments}{funcs}{exports})\n"
    );
    let wasm = wat::parse_str(&module).expect("assemble the test canister");
    match did {
        Some(did) => with_custom_section(wasm, "icp:public candid:service", did.as_bytes()),
        None => wasm,
    }
}

/// The body of a method that copies its argument to `dst` and replies with it,
/// recording the length at address 0 when `remember` (so a later
/// [`Behavior::Load`] can find it). An argument past [`BUFFER`] traps rather
/// than writing past the buffer — no test sends one, and a silent overwrite
/// would be a confusing way to find that out.
fn copy_arg_and_reply(dst: u32, remember: bool) -> String {
    let record = if remember { "(i32.store (i32.const 0) (local.get $n))\n    " } else { "" };
    format!(
        "(local.set $n (call $arg_size))\n    \
         (if (i32.gt_u (local.get $n) (i32.const {BUFFER}))\n      \
           (then (call $trap (i32.const 0) (i32.const 0))))\n    \
         (call $arg_copy (i32.const {dst}) (i32.const 0) (local.get $n))\n    \
         {record}(call $reply_append (i32.const {dst}) (local.get $n))\n    \
         (call $reply)"
    )
}

/// Escape bytes for a WebAssembly text string literal (every byte in hex, so
/// nothing has to be reasoned about being printable).
fn wat_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

/// Append a WebAssembly **custom section** carrying canister metadata, the way
/// a canister's build embeds `icp:public candid:service`. Hand-encoded (section
/// id 0, then the length-prefixed name followed by the payload) so the metadata
/// the tools read is not at the mercy of a text-format extension.
fn with_custom_section(mut wasm: Vec<u8>, name: &str, payload: &[u8]) -> Vec<u8> {
    let mut section = Vec::new();
    leb128(&mut section, name.len() as u64);
    section.extend_from_slice(name.as_bytes());
    section.extend_from_slice(payload);
    wasm.push(0);
    leb128(&mut wasm, section.len() as u64);
    wasm.extend_from_slice(&section);
    wasm
}

fn leb128(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            return;
        }
    }
}

/// The interface of the plain (non-OQL) canister: a query to read, an update to
/// write, and an API-doc method for `get_canister_api_doc` to find.
const APP_DID: &str = "service : {\n  \
    greet : (text) -> (text) query;\n  \
    whoami : () -> (principal) query;\n  \
    get_message : () -> (text) query;\n  \
    set_message : (text) -> (text);\n  \
    icrc1_transfer : (text) -> (text);\n  \
    get_api_doc : () -> (text) query;\n\
}";

/// What the app canister's `get_api_doc` returns.
const API_DOC: &str = "Messages are plain text, last write wins, and there is no history.";

/// The interface of the OQL canister: the `schema` / `execute` pair the OQL
/// detection keys on, with `execute`'s real reply type.
const OQL_DID: &str = "service : {\n  \
    schema : () -> (text) query;\n  \
    execute : (text) -> (variant { \
        ok : record { \
            hasMore : bool; \
            rows : vec vec record { name : text; value : variant { text : text; num : int } } \
        }; \
        err : text \
    }) query;\n\
}";

/// What the OQL canister's `schema` returns: the `{"entities":[…]}` document the
/// schema tool reads entity names out of (and builds ready-to-run examples from).
const OQL_SCHEMA: &str = r#"{"entities":[{"name":"booking","key":"id","fields":[{"name":"id","type":"text"},{"name":"seats","type":"int"}]}]}"#;

/// The `execute` reply every OQL query in these tests gets: two rows, two
/// columns, no further page.
const OQL_ROWS: &str = "(variant { ok = record { \
    hasMore = false; \
    rows = vec { \
        vec { \
            record { name = \"id\"; value = variant { text = \"b-1\" } }; \
            record { name = \"seats\"; value = variant { num = 2 : int } } \
        }; \
        vec { \
            record { name = \"id\"; value = variant { text = \"b-2\" } }; \
            record { name = \"seats\"; value = variant { num = 4 : int } } \
        } \
    } \
} })";

/// Encode a textual Candid value against the declared return types of `method`
/// in `did`, so a constant reply carries the field NAMES the decoder on the
/// other side matches on — the wire hashes them, and a reply encoded without
/// its types would be unrecognizable as an OQL table.
fn encode_typed_reply(did: &str, method: &str, textual: &str) -> Vec<u8> {
    let (env, actor) = candid_parser::utils::CandidSource::Text(did)
        .load()
        .expect("parse the test interface");
    let actor = actor.expect("a service");
    let func = env.get_method(&actor, method).expect("the method is declared");
    candid_parser::parse_idl_args(textual)
        .expect("parse the reply value")
        .to_bytes_with_types(&env, &func.rets)
        .expect("encode the reply value")
}

// ===========================================================================
// The harness
// ===========================================================================

/// The session id every tool call in these tests acts as. A single-user
/// deployment resolves one exactly like this.
const SESSION: &str = "e2e-canister-tools";

/// Every tool that reaches a canister — the surface these tests are about, and
/// the one the discoverability gate decides for.
const CANISTER_TOOLS: [&str; 5] = [
    "get_canister_candid",
    "get_canister_api_doc",
    "get_canister_oql_schema",
    "canister_query",
    "canister_update_call",
];

/// A live replica, the canisters under test, and an MCP client connected to the
/// real tool surface.
struct Harness {
    /// The replica. Held for the lifetime of the test (dropping it stops the
    /// replica), and called directly where a test needs to reach a canister
    /// from OUTSIDE the connector.
    pic: pocket_ic::nonblocking::PocketIc,
    /// The served tool surface, on the other end of [`Self::client`]. Held so
    /// the connection outlives the calls made over it.
    _server: RunningService<RoleServer, IcTools>,
    /// The MCP client every case calls through.
    client: RunningService<RoleClient, ()>,
    /// The canister with a Candid interface, an update method and an API doc.
    app: Principal,
    /// The canister exposing an OQL query surface.
    oql: Principal,
    /// A canister publishing no `candid:service` metadata at all.
    opaque: Principal,
    /// The principal the seeded session signs as at [`Self::origin`].
    principal: Principal,
    /// The session store, so a test that needs the user to hold an identity at
    /// a SECOND app can seed one ([`Identities::seed_app_identity`]).
    identities: Identities,
    /// The app origin whose manifest declares [`Self::app`] and [`Self::oql`].
    origin: String,
}

impl Harness {
    /// Boot a replica, install the canisters, register the app origin's
    /// manifest, and connect a client to the tool surface. `origin` must be
    /// unique to the calling test — the manifest fixtures are process-global.
    ///
    /// `None` when the PocketIC server binary was not provided, so a caller can
    /// skip cleanly rather than fail.
    async fn start(origin: &str) -> Option<Self> {
        if std::env::var("POCKET_IC_BIN").is_err() {
            eprintln!(
                "skipping the canister-tool end-to-end tests: set POCKET_IC_BIN to a pocket-ic \
                 v15 server binary to run them"
            );
            return None;
        }
        let mut pic = pocket_ic::PocketIcBuilder::new()
            .with_application_subnet()
            .build_async()
            .await;
        // A fresh instance boots at a mock clock years in the past, which would
        // put every ingress expiry and every delegation this test signs out of
        // range. Align it with the wall clock the server signs against.
        pic.set_time(SystemTime::now().into()).await;
        pic.tick().await;

        let app = install(
            &pic,
            canister_wasm(
                Some(APP_DID),
                &[
                    Method::query("greet", Behavior::Echo),
                    Method::query("whoami", Behavior::Caller),
                    Method::query("get_message", Behavior::Load),
                    Method::update("set_message", Behavior::Store),
                    // A value-moving method name, declared and exported, that
                    // writes to the SAME store `get_message` reads. The
                    // financial-transactions gate is the only thing standing
                    // between a tool call and that write, so a test that gets
                    // the refusal AND an unchanged store has shown the gate
                    // ran — an undeclared method would give both for free.
                    Method::update("icrc1_transfer", Behavior::Store),
                    Method::query("get_api_doc", Behavior::Const(text_reply(API_DOC))),
                ],
            ),
        )
        .await;
        let oql = install(
            &pic,
            canister_wasm(
                Some(OQL_DID),
                &[
                    Method::query("schema", Behavior::Const(text_reply(OQL_SCHEMA))),
                    Method::query(
                        "execute",
                        Behavior::Const(encode_typed_reply(OQL_DID, "execute", OQL_ROWS)),
                    ),
                ],
            ),
        )
        .await;
        // The same code with no interface metadata: a canister the tools cannot
        // read anything about.
        let plain = canister_wasm(None, &[Method::query("greet", Behavior::Echo)]);
        let opaque = install(&pic, plain).await;

        // The app's published manifest declares the two canisters under test —
        // and, deliberately, not `opaque`, which several cases rely on.
        webfixture::serve(origin, webfixture::Site::declaring(&[app, oql]));

        // The server's own agent, pointed at this replica's gateway.
        let gateway = pic.make_live(None).await;
        let agent = Agent::builder()
            .with_url(gateway.as_str())
            .build()
            .expect("build the agent");
        agent.fetch_root_key().await.expect("fetch the replica's root key");

        let identities = Identities::new(
            // No Internet Identity is reachable in these tests, and none is
            // contacted: the session below already holds its app delegation.
            IiInstance {
                name: "e2e",
                ii_url: "https://internet-identity.invalid".into(),
                ii_canister: Principal::anonymous(),
            },
            "https://mcp.invalid".into(),
            agent.clone(),
        );
        let principal = identities
            .seed_app_identity(SESSION, origin)
            .await
            .expect("seed the session's app identity");

        let tools = IcTools::new(
            agent,
            identities.clone(),
            // The authentication seam: every call in these tests arrives on the
            // one authenticated session, the way a single-user deployment
            // resolves it.
            Arc::new(|_ctx| Some(SESSION.to_string())),
        );
        // A real MCP connection over an in-memory pipe — the same byte-stream
        // shape stdio serves. Both ends are awaited together: each side's
        // `serve` completes only once the other has initialized.
        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        let (server, client) = tokio::join!(tools.serve(server_io), ().serve(client_io));
        let server = server.expect("serve the tool surface");
        let client = client.expect("connect an MCP client");

        Some(Self {
            pic,
            _server: server,
            client,
            app,
            oql,
            opaque,
            principal,
            identities,
            origin: origin.to_string(),
        })
    }

    /// Call a tool the way a client does: by name, with JSON arguments.
    async fn call(&self, tool: &'static str, args: serde_json::Value) -> CallToolResult {
        let arguments = match args {
            serde_json::Value::Object(map) => map,
            other => panic!("tool arguments must be a JSON object, got {other}"),
        };
        self.client
            .call_tool(CallToolRequestParams::new(tool).with_arguments(arguments))
            .await
            .unwrap_or_else(|e| panic!("{tool} call failed at the protocol level: {e}"))
    }
}

/// A Candid `(text)` reply — what the two methods that just hand back a
/// document return.
fn text_reply(text: &str) -> Vec<u8> {
    Encode!(&text).expect("encode a text reply")
}

/// Create and install one canister, returning its id.
async fn install(pic: &pocket_ic::nonblocking::PocketIc, wasm: Vec<u8>) -> Principal {
    let id = pic.create_canister().await;
    pic.add_cycles(id, 2_000_000_000_000).await;
    pic.install_canister(id, wasm, Vec::new(), None).await;
    id
}

// ---- reading a reply ------------------------------------------------------

/// The text content blocks of a result, in order.
fn blocks(result: &CallToolResult) -> Vec<String> {
    result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect()
}

/// Every text block joined — for asserting that a reply says something
/// somewhere, without pinning which block it lands in.
fn all_text(result: &CallToolResult) -> String {
    blocks(result).join("\n")
}

/// A successful result's primary (first) text block. Panics on a tool error, so
/// a failing case reports what the tool actually said.
fn ok_text(result: &CallToolResult) -> String {
    assert_ne!(
        result.is_error,
        Some(true),
        "expected success, got a tool error: {}",
        all_text(result)
    );
    blocks(result).first().cloned().unwrap_or_default()
}

/// A successful result's structured content.
fn ok_structured(result: &CallToolResult) -> serde_json::Value {
    assert_ne!(
        result.is_error,
        Some(true),
        "expected success, got a tool error: {}",
        all_text(result)
    );
    result
        .structured_content
        .clone()
        .expect("every canister tool declares an output schema and attaches structured content")
}

/// A tool error's message. Panics when the call SUCCEEDED — a gate that was
/// meant to refuse and did not is the failure worth reporting.
fn refusal(result: &CallToolResult) -> String {
    assert_eq!(
        result.is_error,
        Some(true),
        "expected a refusal, got success: {}",
        all_text(result)
    );
    all_text(result)
}

// ===========================================================================
// The tests
// ===========================================================================

/// Every READ tool, end to end against a declared canister: the interface, the
/// API doc, a Candid query, and both OQL reads — each returning real canister
/// data and naming the manifest that authorized it.
#[tokio::test]
async fn reads_reach_a_declared_canister_end_to_end() {
    let Some(h) = Harness::start("https://reads.e2e.test").await else { return };
    let app = h.app.to_text();
    let oql = h.oql.to_text();

    // --- what a client sees before it calls anything ---
    // The calls below are written against these advertised schemas, so read
    // them over the connection first: a tool whose schema never reached the
    // client is one no client could call, however well it answers in-process.
    let listed = h.client.list_all_tools().await.expect("tools/list");
    for tool in CANISTER_TOOLS {
        let advertised = listed
            .iter()
            .find(|t| &*t.name == tool)
            .unwrap_or_else(|| panic!("{tool} is not on the advertised surface"));
        let input = serde_json::to_value(&advertised.input_schema).expect("input schema");
        for arg in ["canister_id", "app_url"] {
            assert!(
                input["properties"][arg].is_object(),
                "{tool} must advertise `{arg}`, which every call below passes: {input}"
            );
        }
        let output = advertised
            .output_schema
            .as_ref()
            .unwrap_or_else(|| panic!("{tool} must advertise an output schema"));
        assert_eq!(
            serde_json::to_value(output).expect("output schema")["type"],
            "object",
            "{tool}'s output schema must be object-rooted, as its structured content is"
        );
    }

    // --- get_canister_candid: the canister's own published interface ---
    let result = h
        .call("get_canister_candid", serde_json::json!({ "canister_id": app, "app_url": h.origin }))
        .await;
    let did = ok_text(&result);
    assert!(did.contains("set_message"), "the canister's own .did comes back: {did}");
    let structured = ok_structured(&result);
    assert_eq!(structured["oql"], serde_json::json!(false), "no OQL surface on this one");
    assert_eq!(
        structured["api_doc_available"],
        serde_json::json!(true),
        "get_api_doc is declared, so the flag must say so: {structured}"
    );
    assert_eq!(
        structured["declared_by"],
        serde_json::json!(h.origin),
        "the reply names the app whose manifest authorized the read: {structured}"
    );
    assert_eq!(structured["declared_at"], serde_json::json!("/.well-known/ic-architecture"));

    // The OQL canister's interface is detected as an OQL surface, and the reply
    // says to read it through the OQL tools.
    let result = h
        .call("get_canister_candid", serde_json::json!({ "canister_id": oql, "app_url": h.origin }))
        .await;
    assert_eq!(ok_structured(&result)["oql"], serde_json::json!(true));
    assert!(
        all_text(&result).contains("get_canister_oql_schema"),
        "an OQL canister's interface must point at the OQL tools: {}",
        all_text(&result)
    );

    // A canister publishing no interface metadata is an unreadable canister,
    // not a broken tool.
    let result = h
        .call(
            "get_canister_candid",
            serde_json::json!({ "canister_id": h.opaque.to_text(), "app_url": h.origin }),
        )
        .await;
    // `opaque` is not declared, so the gate refuses before the metadata read is
    // even attempted — which is the point of the gate running first.
    assert!(
        refusal(&result).contains("/.well-known/ic-architecture"),
        "an undeclared canister is refused by the gate, naming the manifest"
    );

    // --- get_canister_api_doc: the prose the canister publishes ---
    let result = h
        .call("get_canister_api_doc", serde_json::json!({ "canister_id": app, "app_url": h.origin }))
        .await;
    assert_eq!(ok_text(&result), API_DOC, "the doc comes back verbatim");
    let structured = ok_structured(&result);
    assert_eq!(structured["available"], serde_json::json!(true));
    assert_eq!(structured["method"], serde_json::json!("get_api_doc"));
    assert_eq!(structured["declared_by"], serde_json::json!(h.origin));

    // A declared canister that publishes no API-doc method reports an EXPECTED
    // absence — nothing to retry.
    let result = h
        .call("get_canister_api_doc", serde_json::json!({ "canister_id": oql, "app_url": h.origin }))
        .await;
    let structured = ok_structured(&result);
    assert_eq!(structured["available"], serde_json::json!(false));
    assert_eq!(structured["expected"], serde_json::json!(true), "absence is expected here");
    assert_eq!(structured["retry"], serde_json::json!(false), "and retrying cannot help");

    // --- canister_query, Candid path: an anonymous read, encoded and decoded
    // against the canister's own interface ---
    let result = h
        .call(
            "canister_query",
            serde_json::json!({
                "canister_id": app,
                "method": "greet",
                "args": "(\"world\")",
                "app_url": h.origin,
            }),
        )
        .await;
    assert_eq!(ok_text(&result), "(\"world\")", "the reply decodes as textual Candid");
    let structured = ok_structured(&result);
    assert_eq!(structured["mode"], serde_json::json!("candid"));
    assert_eq!(structured["is_anonymous"], serde_json::json!(true), "no origin was passed");
    assert_eq!(structured["declared_by"], serde_json::json!(h.origin));

    // --- whose identity a call is signed with, as the canister sees it ---
    // Without a derivation origin the call is made anonymously, and the replica
    // reports the anonymous principal.
    let whoami = serde_json::json!({
        "canister_id": app, "method": "whoami", "args": "()", "app_url": h.origin,
    });
    let result = h.call("canister_query", whoami.clone()).await;
    assert_eq!(
        ok_text(&result),
        "(principal \"2vxsx-fae\")",
        "an origin-less read reaches the canister as nobody"
    );

    // With one, the call is signed by the per-app delegation the session holds,
    // and the canister sees THAT principal — the whole identity path, end to
    // end, as the replica verifies it at ingress.
    let mut as_the_user = whoami.clone();
    as_the_user
        .as_object_mut()
        .expect("object")
        .insert("derivation_origin".into(), serde_json::json!(h.origin));
    let result = h.call("canister_query", as_the_user).await;
    assert_eq!(
        ok_text(&result),
        format!("(principal \"{}\")", h.principal),
        "an authenticated read reaches the canister as the user's principal at this app"
    );
    let structured = ok_structured(&result);
    assert_eq!(structured["is_anonymous"], serde_json::json!(false));
    assert_eq!(structured["derived_for_origin"], serde_json::json!(h.origin));

    // --- get_canister_oql_schema: read as the app identity ---
    let result = h
        .call(
            "get_canister_oql_schema",
            serde_json::json!({ "canister_id": oql, "derivation_origin": h.origin, "app_url": h.origin }),
        )
        .await;
    let schema = ok_text(&result);
    assert!(schema.contains("\"booking\""), "the canister's schema comes back: {schema}");
    let structured = ok_structured(&result);
    assert_eq!(structured["is_anonymous"], serde_json::json!(false), "read as the app identity");
    let examples = structured["example_queries"]
        .as_array()
        .expect("a ready-to-run query per entity")
        .clone();
    assert_eq!(examples.len(), 1, "one entity, one example: {examples:?}");
    let example = examples[0].as_str().unwrap_or_default();
    // The example has to carry the origin that authorized this read, or copying
    // it would fail the very gate the schema read just passed.
    assert!(example.contains("app_url"), "the example carries app_url: {example}");
    assert!(example.contains("booking"), "and starts at the entity: {example}");

    // --- canister_query, OQL path: the query runs and comes back as a table ---
    let result = h
        .call(
            "canister_query",
            serde_json::json!({
                "canister_id": oql,
                "oql": "{\"start\":\"booking\",\"limit\":10}",
                "derivation_origin": h.origin,
                "app_url": h.origin,
            }),
        )
        .await;
    let table = ok_text(&result);
    assert!(table.contains("b-1") && table.contains("b-2"), "both rows render: {table}");
    let structured = ok_structured(&result);
    assert_eq!(structured["mode"], serde_json::json!("oql"));
    assert_eq!(
        structured["columns"],
        serde_json::json!(["id", "seats"]),
        "the reply's field names are recovered, not hashed: {structured}"
    );
    assert_eq!(structured["rows"].as_array().map(Vec::len), Some(2));
    assert_eq!(structured["has_more"], serde_json::json!(false));
    assert_eq!(structured["declared_by"], serde_json::json!(h.origin));

    // A Candid `method` query on an OQL canister is redirected to the OQL path
    // rather than run.
    let result = h
        .call(
            "canister_query",
            serde_json::json!({
                "canister_id": oql,
                "method": "schema",
                "args": "()",
                "app_url": h.origin,
            }),
        )
        .await;
    let msg = refusal(&result);
    assert!(msg.contains("OQL"), "the redirect names OQL: {msg}");
    assert!(msg.contains("get_canister_oql_schema"), "and the path to take: {msg}");
}

/// The write path, end to end: an update call changes canister state, the next
/// read sees it, and each of the guards that stands between a tool call and a
/// write refuses without touching the canister.
#[tokio::test]
async fn an_update_call_writes_state_a_query_reads_back() {
    let Some(h) = Harness::start("https://writes.e2e.test").await else { return };
    let app = h.app.to_text();

    let read_back = || async {
        let result = h
            .call(
                "canister_query",
                serde_json::json!({
                    "canister_id": app,
                    "method": "get_message",
                    "args": "()",
                    "app_url": h.origin,
                }),
            )
            .await;
        ok_text(&result)
    };

    // Nothing has been written yet.
    assert_eq!(read_back().await, "(\"\")", "the canister starts empty");

    // --- canister_update_call: the write itself ---
    let result = h
        .call(
            "canister_update_call",
            serde_json::json!({
                "canister_id": app,
                "method": "set_message",
                "args": "(\"booked seat 14\")",
                "app_url": h.origin,
                "derivation_origin": h.origin,
            }),
        )
        .await;
    assert_eq!(ok_text(&result), "(\"booked seat 14\")", "the update's own reply");
    let structured = ok_structured(&result);
    assert_eq!(structured["is_anonymous"], serde_json::json!(false), "signed as the app identity");
    assert_eq!(structured["derived_for_origin"], serde_json::json!(h.origin));
    assert_eq!(structured["declared_by"], serde_json::json!(h.origin));
    assert_eq!(structured["declared_at"], serde_json::json!("/.well-known/ic-architecture"));
    // The write's provenance is a text block too, so a client that reads no
    // structured content still shows the user which app authorized it.
    assert!(
        all_text(&result).contains(&format!("[declared by {} in /.well-known/ic-architecture]", h.origin)),
        "the reply carries the provenance block: {}",
        all_text(&result)
    );

    // The state really changed: a separate query call sees the new value.
    assert_eq!(read_back().await, "(\"booked seat 14\")", "the update is visible to the next read");

    // --- the read/write split, both ways ---
    // A query call to an UPDATE method is refused up front, with the tool to
    // use instead, rather than failing at the replica.
    let result = h
        .call(
            "canister_query",
            serde_json::json!({
                "canister_id": app,
                "method": "set_message",
                "args": "(\"via a query\")",
                "app_url": h.origin,
            }),
        )
        .await;
    let msg = refusal(&result);
    assert!(msg.contains("canister_update_call"), "the refusal names the write tool: {msg}");
    assert_eq!(read_back().await, "(\"booked seat 14\")", "and nothing was written");

    // The reverse is legitimate on the Internet Computer: a query method called
    // as an update call runs.
    let result = h
        .call(
            "canister_update_call",
            serde_json::json!({
                "canister_id": app,
                "method": "greet",
                "args": "(\"as an update\")",
                "app_url": h.origin,
            }),
        )
        .await;
    assert_eq!(ok_text(&result), "(\"as an update\")");

    // --- the financial-transactions gate: refused before the network ---
    // A value-moving method name is refused on EVERY canister. This canister
    // really declares and exports `icrc1_transfer`, and it writes to the same
    // store `get_message` reads — so the assertions below distinguish "the
    // gate stopped this" from "the canister would have rejected it anyway".
    let transfer = serde_json::json!({
        "canister_id": app,
        "method": "icrc1_transfer",
        "args": "(\"moved through the connector\")",
        "app_url": h.origin,
        "derivation_origin": h.origin,
    });
    let msg = refusal(&h.call("canister_update_call", transfer).await);
    assert!(
        msg.contains("icrc1_transfer"),
        "the refusal names the method it refused: {msg}"
    );
    // Wording only this gate produces: a replica rejection could never say it.
    assert!(
        msg.contains("not supported by this server, to protect the user"),
        "the refusal must be the connector's policy, not the replica's: {msg}"
    );
    assert_eq!(read_back().await, "(\"booked seat 14\")", "and the canister was never called");

    // The positive control for that last assertion: the method is live and
    // does mutate. Called from OUTSIDE the connector it writes, which is what
    // makes "unchanged" above a statement about the gate rather than about a
    // canister that could not have done anything anyway.
    h.pic
        .update_call(
            h.app,
            Principal::anonymous(),
            "icrc1_transfer",
            Encode!(&"moved on the replica").expect("encode the transfer argument"),
        )
        .await
        .expect("the fixture's icrc1_transfer is callable on the replica");
    assert_eq!(
        read_back().await,
        "(\"moved on the replica\")",
        "the method the gate refused really does change state when it is reached"
    );

    // --- the update path signs as the app identity too ---
    // `is_anonymous` above says only that an origin was passed. This is the
    // canister's own view of who called, on the WRITE path: a signer
    // regression there would not show up in the query-path check.
    let result = h
        .call(
            "canister_update_call",
            serde_json::json!({
                "canister_id": app,
                "method": "whoami",
                "args": "()",
                "app_url": h.origin,
                "derivation_origin": h.origin,
            }),
        )
        .await;
    assert_eq!(
        ok_text(&result),
        format!("(principal \"{}\")", h.principal),
        "an update call reaches the canister as the user's principal at this app"
    );

    // --- an argument that does not match the interface ---
    let result = h
        .call(
            "canister_update_call",
            serde_json::json!({
                "canister_id": app,
                "method": "set_message",
                "args": "(42 : nat)",
                "app_url": h.origin,
            }),
        )
        .await;
    refusal(&result);
    assert_eq!(
        read_back().await,
        "(\"moved on the replica\")",
        "a rejected argument writes nothing — the store still holds the last write"
    );
}

/// The discoverability gate, over the whole canister-reaching surface: a
/// canister no app declares is out of reach for every one of these tools, each
/// refusal names the operation it refused, and the same tools work on the
/// canister the app does declare.
#[tokio::test]
async fn the_gate_holds_for_every_canister_reaching_tool() {
    let Some(h) = Harness::start("https://gate.e2e.test").await else { return };
    let undeclared = h.opaque.to_text();
    let declared = h.app.to_text();

    // Every call shape that reaches a canister, each paired with the DECLARED
    // canister it would work against — the app canister for the Candid and
    // doc shapes, the OQL canister for the two OQL ones. Each shape is run
    // three ways below: against an undeclared canister (must be refused),
    // with no origin at all (must be refused), and against its own declared
    // canister, where it must SUCCEED. That last one is the control that says
    // the refusals above came from the gate rejecting the target rather than
    // from a call that could never have worked.
    let calls: Vec<(&'static str, &Principal, serde_json::Value)> = vec![
        ("get_canister_candid", &h.app, serde_json::json!({ "app_url": h.origin })),
        ("get_canister_api_doc", &h.app, serde_json::json!({ "app_url": h.origin })),
        (
            "get_canister_oql_schema",
            &h.oql,
            serde_json::json!({ "app_url": h.origin, "derivation_origin": h.origin }),
        ),
        (
            "canister_query",
            &h.app,
            serde_json::json!({ "method": "greet", "args": "(\"x\")", "app_url": h.origin }),
        ),
        (
            "canister_query",
            &h.oql,
            serde_json::json!({
                "oql": "{\"start\":\"booking\"}",
                "app_url": h.origin,
                "derivation_origin": h.origin,
            }),
        ),
        (
            "canister_update_call",
            &h.app,
            serde_json::json!({ "method": "greet", "args": "(\"x\")", "app_url": h.origin }),
        ),
    ];
    /// The call's arguments aimed at `canister`.
    fn at(args: &serde_json::Value, canister: &str) -> serde_json::Value {
        let mut args = args.clone();
        args.as_object_mut()
            .expect("object")
            .insert("canister_id".into(), serde_json::json!(canister));
        args
    }

    for (tool, _, args) in &calls {
        let is_write = *tool == "canister_update_call";
        let msg = refusal(&h.call(tool, at(args, &undeclared)).await);
        assert!(
            msg.contains(&undeclared),
            "{tool}'s refusal must name the canister it would not reach: {msg}"
        );
        assert!(
            msg.contains("/.well-known/ic-architecture"),
            "{tool}'s refusal must name the document that would authorize it: {msg}"
        );
        assert!(
            msg.contains(&declared),
            "{tool}'s refusal must list what the app DOES declare, so a wrong id can be \
             corrected in one step: {msg}"
        );
        // Each refusal names the operation actually attempted — a read reported
        // as a state-changing call relays something false to the user, and a
        // write reported as a read hides what was just tried.
        let write = "will not make a state-changing call to it";
        let read = "will not read it";
        let (named, not_named) = if is_write { (write, read) } else { (read, write) };
        assert!(msg.contains(named), "{tool}'s refusal must say \"{named}\": {msg}");
        assert!(!msg.contains(not_named), "{tool}'s refusal must not say \"{not_named}\": {msg}");
    }

    // With NO origin at all there is no manifest to consult, so every one of
    // them refuses — even aimed at a canister that IS declared, since without
    // an app named there is nothing to read a declaration from.
    for (tool, target, args) in &calls {
        let mut args = at(args, &target.to_text());
        let map = args.as_object_mut().expect("object");
        map.remove("app_url");
        map.remove("derivation_origin");
        let msg = refusal(&h.call(tool, args).await);
        assert!(
            msg.contains("app_url") || msg.contains("derivation_origin"),
            "{tool} with no origin must say which argument is missing: {msg}"
        );
    }

    // An app that publishes nothing at the protocol path cannot authorize a
    // read, and the refusal has to tell its operator what to publish.
    webfixture::serve("https://unadopted.e2e.test", webfixture::Site::serving_a_catch_all());
    let msg = refusal(
        &h.call(
            "get_canister_candid",
            serde_json::json!({ "canister_id": declared, "app_url": "https://unadopted.e2e.test" }),
        )
        .await,
    );
    assert!(
        msg.contains("text/html"),
        "answering the protocol path with a page is the classic misconfiguration, and the \
         refusal must name it: {msg}"
    );

    // --- the derivation origin has to belong to the app named by `app_url` ---
    // A second app that declares the same canister and pins ITS OWN origin as
    // the identity to derive against. Naming it as `app_url` while signing as
    // the user's identity at the first app is the case the binding exists for:
    // one app's manifest must not authorize a canister for a principal the
    // user holds somewhere else.
    const OTHER_APP: &str = "https://other.e2e.test";
    webfixture::serve(OTHER_APP, webfixture::Site::declaring(&[h.app, h.oql]).deriving_at(OTHER_APP));
    // On the write path and on the reads that sign as someone — the binding
    // runs wherever a call carries both an app and an identity, so a refusal
    // that only held for writes would leave the reads open.
    for (tool, args) in [
        (
            "canister_update_call",
            serde_json::json!({
                "canister_id": declared,
                "method": "set_message",
                "args": "(\"from the wrong app\")",
                "app_url": OTHER_APP,
                "derivation_origin": h.origin,
            }),
        ),
        (
            "canister_query",
            serde_json::json!({
                "canister_id": declared,
                "method": "greet",
                "args": "(\"from the wrong app\")",
                "app_url": OTHER_APP,
                "derivation_origin": h.origin,
            }),
        ),
        (
            "get_canister_oql_schema",
            serde_json::json!({
                "canister_id": h.oql.to_text(),
                "app_url": OTHER_APP,
                "derivation_origin": h.origin,
            }),
        ),
    ] {
        let msg = refusal(&h.call(tool, args).await);
        assert!(
            msg.contains("other.e2e.test") && msg.contains(&h.origin),
            "{tool}'s mismatch refusal must name BOTH apps: {msg}"
        );
    }

    // The other side of the same check: an app whose identity origin is NOT its
    // own URL — the common shape, since an app that pins a custom derivation
    // origin serves its manifest at the origin the user visits. Passing the
    // origin that app really pins is accepted, and the reply shows the two
    // apart: one app authorized the read, a different origin derived the
    // identity that made it.
    // The direction of trust is what makes this safe: the pinned origin is the
    // one that publishes who may derive against it, so it is registered here
    // listing the app back. Without that the claim is refused (the case below).
    const PINNING_APP: &str = "https://pinning.e2e.test";
    const PINNED_IDENTITY: &str = "https://identity.e2e.test";
    webfixture::serve(
        PINNING_APP,
        webfixture::Site::declaring(&[h.app]).deriving_at(PINNED_IDENTITY),
    );
    webfixture::serve(
        PINNED_IDENTITY,
        webfixture::Site::default().authorizing(&[PINNING_APP]),
    );
    h.identities
        .seed_app_identity(SESSION, PINNED_IDENTITY)
        .await
        .expect("the user also holds an identity at the pinned origin");
    let result = h
        .call(
            "canister_query",
            serde_json::json!({
                "canister_id": declared,
                "method": "greet",
                "args": "(\"from the app that pins an origin\")",
                "app_url": PINNING_APP,
                "derivation_origin": PINNED_IDENTITY,
            }),
        )
        .await;
    assert_eq!(ok_text(&result), "(\"from the app that pins an origin\")");
    let structured = ok_structured(&result);
    assert_eq!(
        structured["derived_for_origin"],
        serde_json::json!(PINNED_IDENTITY),
        "the identity came from the origin the app pins: {structured}"
    );
    assert_eq!(
        structured["declared_by"],
        serde_json::json!(PINNING_APP),
        "while the manifest that authorized it is the app's own: {structured}"
    );

    // And the claim the direction of trust exists to stop: an app pinning an
    // origin that does NOT list it back. Nothing about the claiming site
    // changes — only the answer from the origin it names — and the call is
    // refused rather than deriving against an identity that app has no right
    // to. (Unregistered here means an origin that authorizes nobody, which is
    // what an absent or unreadable list amounts to.)
    const SPOOFING_APP: &str = "https://spoofing.e2e.test";
    const UNWILLING_IDENTITY: &str = "https://unwilling.e2e.test";
    webfixture::serve(
        SPOOFING_APP,
        webfixture::Site::declaring(&[h.app]).deriving_at(UNWILLING_IDENTITY),
    );
    webfixture::serve(UNWILLING_IDENTITY, webfixture::Site::default().authorizing(&[]));
    h.identities
        .seed_app_identity(SESSION, UNWILLING_IDENTITY)
        .await
        .expect("the user holds an identity there too — the claim is still refused");
    let msg = refusal(
        &h.call(
            "canister_query",
            serde_json::json!({
                "canister_id": declared,
                "method": "greet",
                "args": "(\"x\")",
                "app_url": SPOOFING_APP,
                "derivation_origin": UNWILLING_IDENTITY,
            }),
        )
        .await,
    );
    assert!(
        msg.contains(SPOOFING_APP) && msg.contains(UNWILLING_IDENTITY),
        "the refusal must name the app and the origin it claimed: {msg}"
    );
    assert!(
        msg.contains("does not authorize it back"),
        "and say which way the authorization is missing — the claimed origin never listed \
         this app, not the other way round: {msg}"
    );
    assert!(
        msg.contains("Retrying will not change it"),
        "a misconfiguration is not a transient failure, and an agent told otherwise loops: {msg}"
    );

    // A derivation origin that is not an origin at all is refused before any
    // network work, naming the argument to fix.
    for bad in ["", "not a url", "ftp://app.example", "https://"] {
        let msg = refusal(
            &h.call(
                "canister_query",
                serde_json::json!({
                    "canister_id": declared,
                    "method": "greet",
                    "args": "(\"x\")",
                    "app_url": h.origin,
                    "derivation_origin": bad,
                }),
            )
            .await,
        );
        assert!(
            msg.contains("derivation_origin"),
            "a `derivation_origin` of {bad:?} must be refused by name: {msg}"
        );
    }

    // The control: the same six shapes, unchanged, against the canister each
    // one's app DOES declare. Every one must SUCCEED — not merely avoid one
    // wording of one refusal, which would still pass if the gate turned a
    // declared canister away down some other branch (no manifest, an
    // unreachable origin, an identity mismatch). A success is the only
    // outcome that proves the gate admitted the call.
    for (tool, target, args) in &calls {
        let result = h.call(tool, at(args, &target.to_text())).await;
        assert_ne!(
            result.is_error,
            Some(true),
            "{tool} must succeed against the canister its app declares, or the refusals \
             above prove nothing about the gate: {}",
            all_text(&result)
        );
    }
}

/// A read that cannot run comes back as a tool error saying what to fix — never
/// as a silent empty result, and never as a protocol-level failure the client
/// has to interpret. Each case here is one the tools decide for themselves,
/// checked against a live replica so a decision that only LOOKS right on paper
/// (an unreadable interface, a query the replica would reject) is exercised
/// where the canister can contradict it.
#[tokio::test]
async fn a_read_that_cannot_run_says_what_to_fix() {
    let Some(h) = Harness::start("https://errors.e2e.test").await else { return };
    let app = h.app.to_text();
    let oql = h.oql.to_text();

    // An app that declares all three canisters, including the one that
    // publishes no interface — so the gate lets these calls through and what
    // they hit is the canister itself.
    let declares_all = "https://errors-everything.e2e.test";
    webfixture::serve(declares_all, webfixture::Site::declaring(&[h.app, h.oql, h.opaque]));
    let opaque = h.opaque.to_text();

    // --- a declared canister that publishes no Candid interface ---
    let msg = refusal(
        &h.call(
            "get_canister_candid",
            serde_json::json!({ "canister_id": opaque, "app_url": declares_all }),
        )
        .await,
    );
    assert!(
        msg.contains("candid:service"),
        "the failure must name the metadata that is missing: {msg}"
    );

    // The API-doc tool cannot tell whether such a canister has a doc method, so
    // it reports the absence as UNEXPECTED and retryable — the opposite of the
    // canister that simply declares no doc method.
    let structured = ok_structured(
        &h.call(
            "get_canister_api_doc",
            serde_json::json!({ "canister_id": opaque, "app_url": declares_all }),
        )
        .await,
    );
    assert_eq!(structured["available"], serde_json::json!(false));
    assert_eq!(
        structured["expected"],
        serde_json::json!(false),
        "an unreadable interface is not a canister known to have no doc: {structured}"
    );
    assert_eq!(structured["retry"], serde_json::json!(true), "and it may be transient");

    // A method no interface declares still reaches the replica, which rejects
    // it — the tools fail open rather than second-guessing an unreadable
    // canister.
    let msg = refusal(
        &h.call(
            "canister_query",
            serde_json::json!({
                "canister_id": opaque,
                "method": "no_such_method",
                "args": "()",
                "app_url": declares_all,
            }),
        )
        .await,
    );
    assert!(msg.contains("query failed"), "the replica's rejection is surfaced: {msg}");

    // --- canister_query needs exactly one of `method` and `oql` ---
    let msg = refusal(
        &h.call("canister_query", serde_json::json!({ "canister_id": app, "app_url": h.origin }))
            .await,
    );
    assert!(msg.contains("method") && msg.contains("oql"), "both ways in are named: {msg}");
    let msg = refusal(
        &h.call(
            "canister_query",
            serde_json::json!({
                "canister_id": oql,
                "method": "schema",
                "args": "()",
                "oql": "{\"start\":\"booking\"}",
                "app_url": h.origin,
            }),
        )
        .await,
    );
    assert!(msg.contains("not both"), "asking for both at once is refused: {msg}");

    // --- the OQL reads refuse to run anonymously ---
    for args in [
        serde_json::json!({ "canister_id": oql, "app_url": h.origin }),
        serde_json::json!({ "canister_id": oql, "app_url": h.origin, "oql": "{\"start\":\"booking\"}" }),
    ] {
        let tool = if args.get("oql").is_some() { "canister_query" } else { "get_canister_oql_schema" };
        let msg = refusal(&h.call(tool, args).await);
        assert!(
            msg.contains("derivation_origin") && msg.contains("open_app"),
            "{tool} must say which argument is missing and where to get it: {msg}"
        );
    }

    // --- an argument that is not a canister id at all ---
    let msg = refusal(
        &h.call(
            "get_canister_candid",
            serde_json::json!({ "canister_id": "not-a-principal", "app_url": h.origin }),
        )
        .await,
    );
    assert!(msg.contains("invalid canister id"), "and it is named as such: {msg}");

    // --- the two reference guides these calls are written against ---
    // They reach no canister and take no arguments, but they are part of the
    // same surface: a client that cannot fetch them cannot write the `args` or
    // the `oql` the calls above take.
    let candid = ok_text(&h.call("candid_syntax_guide", serde_json::json!({})).await);
    assert!(candid.contains("Candid"), "the textual-Candid guide comes back: {candid:.80}");
    let oql_guide = ok_text(&h.call("icp_oql_guide", serde_json::json!({})).await);
    assert!(oql_guide.contains("OQL"), "the OQL guide comes back: {oql_guide:.80}");
}
