//! Golden encodings, the evolution rules, and reply-size limits.

use std::fmt::Debug;

use candid::{CandidType, Decode, Encode};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use super::*;

/// Compares `bytes` with the `pinned` hex. Mismatches are collected so that one
/// run prints every value to re-pin.
fn compare(name: &str, bytes: &[u8], pinned: &str, mismatches: &mut Vec<String>) {
    let actual = hex::encode(bytes);
    if actual != pinned {
        mismatches.push(format!("{name}:\n{actual}"));
    }
}

/// Encodes `value`, compares the bytes with `pinned`, and decodes them back.
fn golden<T>(name: &str, value: &T, pinned: &str, mismatches: &mut Vec<String>)
where
    T: CandidType + DeserializeOwned + PartialEq + Debug,
{
    let bytes = Encode!(value).expect("encodes");
    compare(name, &bytes, pinned, mismatches);
    let back = Decode!(&bytes, T).expect("decodes its own encoding");
    assert_eq!(&back, value, "{name}: round trip");
}

/// The exact bytes of every request and reply. A change here changes what goes
/// over the wire: confirm it is compatible (see the crate's evolution rules)
/// before re-pinning.
#[test]
fn golden_wire_bytes() {
    let mut m = Vec::new();

    // Install argument.
    golden(
        "InstallArg::Init",
        &InstallArg::Init(config_patch()),
        "4449444c076b02fcb88b840301b0ced18403026e026c06e6d6f9bd04039bbdbff90504e8f7fd940703d2d087850b0698998bf60c06abd9a9ed0f066e796e056d686e7801000101e80300000102011d0101010101010101010101010101010101010101010101010101010101011d0202020202020202020202020202020202020202020202020202020202011e0000000190d00300000000000120a107000000000001803a090000000000",
        &mut m,
    );
    golden(
        "InstallArg::Upgrade(None)",
        &InstallArg::Upgrade(None),
        "4449444c076b02fcb88b840301b0ced18403026e026c06e6d6f9bd04039bbdbff90504e8f7fd940703d2d087850b0698998bf60c06abd9a9ed0f066e796e056d686e7801000000",
        &mut m,
    );
    golden(
        "InstallArg::Upgrade(Some)",
        &InstallArg::Upgrade(Some(config_patch())),
        "4449444c076b02fcb88b840301b0ced18403026e026c06e6d6f9bd04039bbdbff90504e8f7fd940703d2d087850b0698998bf60c06abd9a9ed0f066e796e056d686e780100000101e80300000102011d0101010101010101010101010101010101010101010101010101010101011d0202020202020202020202020202020202020202020202020202020202011e0000000190d00300000000000120a107000000000001803a090000000000",
        &mut m,
    );

    // put_session
    let put = PutSessionArg {
        key: key(1),
        op_id: id(0x11),
        grant_expires_at: 1_702_592_000,
        sealed: record().sealed,
        code_lock: id(0x22),
    };
    golden(
        "PutSessionArg",
        &put,
        "4449444c026c059f93c60201f9f6aa9e03019ca7cc970601e181d68b0b78fdc6c6db0f016d7b010020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a001010101010101010101010101010101101111111111111111111111111111111106010002c0ffee007e7b65000000001022222222222222222222222222222222",
        &mut m,
    );
    golden(
        "PutSessionResult::Ok",
        &PutSessionResult::Ok(record()),
        "4449444c076b02bc8a0101c5fed201046c089f93c602029fb7de0278f9f6aa9e03029ca7cc970602aaacd9d00678ea9187de0803e181d68b0b78a3ade4df0e786d7b6e786c038a8ac1f7090587afebf709789797e0fb0d716e066b06cdd4d4aa037fd4b4c59a097ff4f6d8a2097ff4b895a40b7fb99b82810e7f89e3b3e50f7f01000020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00101010101010101010101010101010100f22f60ff9c9717101111111111111111111111111111111106010002c0ffee00f15365000000000105f1536500000000007e7b65000000002cf2536500000000",
        &mut m,
    );
    golden(
        "PutSessionResult::Err",
        &PutSessionResult::Err(PutSessionError::of(PutSessionErrorCase::CapacityExceeded)),
        "4449444c076b02bc8a0101c5fed201046c089f93c602029fb7de0278f9f6aa9e03029ca7cc970602aaacd9d00678ea9187de0803e181d68b0b78a3ade4df0e786d7b6e786c038a8ac1f7090587afebf709789797e0fb0d716e066b06cdd4d4aa037fd4b4c59a097ff4f6d8a2097ff4b895a40b7fb99b82810e7f89e3b3e50f7f01000101000d00000000000000207468652073657373696f6e2073746f7265206973206174206361706163697479",
        &mut m,
    );

    // consume_code
    let consume = ConsumeCodeArg { key: key(1), exchange_id: id(0x33), code_proof: id(0x44) };
    golden(
        "ConsumeCodeArg",
        &consume,
        "4449444c026c039f93c60201b7cfdbc50101b2fdf1bc05016d7b010020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00101010101010101010101010101010110333333333333333333333333333333331044444444444444444444444444444444",
        &mut m,
    );
    golden(
        "ConsumeCodeResult::Ok",
        &ConsumeCodeResult::Ok(record()),
        "4449444c076b02bc8a0101c5fed201046c089f93c602029fb7de0278f9f6aa9e03029ca7cc970602aaacd9d00678ea9187de0803e181d68b0b78a3ade4df0e786d7b6e786c038a8ac1f7090587afebf709789797e0fb0d716e066b07d8bbbe237fc0fdead5017fcfa0def2067fd4b4c59a097ff4b895a40b7f9fadc3c00d7fb99b82810e7f01000020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00101010101010101010101010101010100f22f60ff9c9717101111111111111111111111111111111106010002c0ffee00f15365000000000105f1536500000000007e7b65000000002cf2536500000000",
        &mut m,
    );
    golden(
        "ConsumeCodeResult::Err",
        &ConsumeCodeResult::Err(ConsumeCodeError::of(ConsumeCodeErrorCase::BadProof)),
        "4449444c076b02bc8a0101c5fed201046c089f93c602029fb7de0278f9f6aa9e03029ca7cc970602aaacd9d00678ea9187de0803e181d68b0b78a3ade4df0e786d7b6e786c038a8ac1f7090587afebf709789797e0fb0d716e066b07d8bbbe237fc0fdead5017fcfa0def2067fd4b4c59a097ff4b895a40b7f9fadc3c00d7fb99b82810e7f010001010515000000000000002b74686520617574686f72697a6174696f6e20636f64652070726f6f6620646f6573206e6f74206d61746368",
        &mut m,
    );

    // touch_sessions
    let touches = TouchSessionsArg {
        touches: vec![
            Touch { key: key(1), last_active_at: 1_700_000_300 },
            Touch { key: key(3), last_active_at: 1_700_000_600 },
        ],
    };
    golden(
        "touch_sessions argument",
        &touches,
        "4449444c046c01edbbe0c70d016d026c029f93c60203a3ade4df0e786d7b01000220a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0010101010101010101010101010101012cf253650000000020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00303030303030303030303030303030358f3536500000000",
        &mut m,
    );
    golden(
        "TouchResult::Ok",
        &TouchResult::Ok(TouchOk { updated: 1, unknown: vec![key(3)] }),
        "4449444c076b02bc8a0101c5fed201046c02bb84bfee09798ac7ec8b0e026d036d7b6c038a8ac1f7090587afebf709789797e0fb0d716e066b03d4b4c59a097ff4b895a40b7f9dada9e10b7f010000010000000120a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a003030303030303030303030303030303",
        &mut m,
    );
    golden(
        "TouchResult::Err",
        &TouchResult::Err(CommonError::of(CommonErrorCase::Unauthorized)),
        "4449444c076b02bc8a0101c5fed201046c02bb84bfee09798ac7ec8b0e026d036d7b6c038a8ac1f7090587afebf709789797e0fb0d716e066b03d4b4c59a097ff4b895a40b7f9dada9e10b7f01000101000100000000000000307468652063616c6c6572206973206e6f7420617574686f72697a656420746f2063616c6c2074686973206d6574686f64",
        &mut m,
    );

    // get_sessions
    golden(
        "get_sessions argument",
        &GetSessionsArg { keys: vec![key(1), key(2), key(3)] },
        "4449444c036c01f4c39bb804016d026d7b01000320a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00101010101010101010101010101010120a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00202020202020202020202020202020220a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a003030303030303030303030303030303",
        &mut m,
    );
    golden(
        "GetSessionsResult::Ok",
        &GetSessionsResult::Ok(GetSessionsOk {
            items: vec![Lookup::Live(record()), Lookup::Deleted(tombstone()), Lookup::Absent],
            epoch: 2,
            now_ns: 1_700_000_900_000_000_000,
        }),
        "4449444c0b6b02bc8a0101c5fed201086c038edeb39d0378c99ad48e077880d8b2900c026d036b038c96b1940304d9b59fb60b7fb99b82810e076c089f93c602059fb7de0278f9f6aa9e03059ca7cc970605aaacd9d00678ea9187de0806e181d68b0b78a3ade4df0e786d7b6e786c059f93c602059fb7de0278d9e5d5d60a78e181d68b0b78c49ff4e40f716c038a8ac1f7090987afebf709789797e0fb0d716e0a6b03d4b4c59a097ff4b895a40b7f9dada9e10b7f010000002858c2cf9d97170200000000000000030020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00101010101010101010101010101010100f22f60ff9c9717101111111111111111111111111111111106010002c0ffee00f15365000000000105f1536500000000007e7b65000000002cf25365000000000220a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a002020202020202020202020202020202002858c2cf9d971784f4536500000000007e7b65000000000469646c6501",
        &mut m,
    );
    golden(
        "GetSessionsResult::Err",
        &GetSessionsResult::Err(CommonError::invalid_argument("too many keys")),
        "4449444c0b6b02bc8a0101c5fed201086c038edeb39d0378c99ad48e077880d8b2900c026d036b038c96b1940304d9b59fb60b7fb99b82810e076c089f93c602059fb7de0278f9f6aa9e03059ca7cc970605aaacd9d00678ea9187de0806e181d68b0b78a3ade4df0e786d7b6e786c059f93c602059fb7de0278d9e5d5d60a78e181d68b0b78c49ff4e40f716c038a8ac1f7090987afebf709789797e0fb0d716e0a6b03d4b4c59a097ff4b895a40b7f9dada9e10b7f010001010102000000000000001f696e76616c696420617267756d656e743a20746f6f206d616e79206b657973",
        &mut m,
    );

    // list_changes
    golden(
        "ListChangesArg",
        &ListChangesArg { after: 42, limit: Some(MAX_PAGE_LIMIT) },
        "4449444c026c029ccc89ed0178bbbe84a807016e7901002a0000000000000001e8030000",
        &mut m,
    );
    golden(
        "ListChangesResult::Ok",
        &ListChangesResult::Ok(ChangesPage {
            changes: vec![Change::Live(record()), Change::Deleted(tombstone())],
            complete: true,
            next_after: 1_700_000_900_000_000_000,
            head: 1_700_000_900_000_000_000,
            epoch: 2,
            now_ns: 1_700_000_950_000_000_000,
            idle_timeout_secs: 604_800,
            idle_floor_at: 1_699_000_000,
            key_checks_version: 3,
        }),
        "4449444c0b6b02bc8a0101c5fed201086c09a4c8eb38788edeb39d0378a0d2aca80478c99ad48e0778b981a0fe077e90d59bd10978919da2cb0b7883e2b2e60c02abd9a9ed0f786d036b028c96b1940304b99b82810e076c089f93c602059fb7de0278f9f6aa9e03059ca7cc970605aaacd9d00678ea9187de0806e181d68b0b78a3ade4df0e786d7b6e786c059f93c602059fb7de0278d9e5d5d60a78e181d68b0b78c49ff4e40f716c038a8ac1f7090987afebf709789797e0fb0d716e0a6b03d4b4c59a097ff4b895a40b7f9dada9e10b7f0100000300000000000000009c9366db9d9717002858c2cf9d9717020000000000000001002858c2cf9d9717c0ae446500000000020020a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00101010101010101010101010101010100f22f60ff9c9717101111111111111111111111111111111106010002c0ffee00f15365000000000105f1536500000000007e7b65000000002cf25365000000000120a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a002020202020202020202020202020202002858c2cf9d971784f4536500000000007e7b65000000000469646c65803a090000000000",
        &mut m,
    );
    golden(
        "ListChangesResult::Err",
        &ListChangesResult::Err(CommonError::invalid_argument("after")),
        "4449444c0b6b02bc8a0101c5fed201086c09a4c8eb38788edeb39d0378a0d2aca80478c99ad48e0778b981a0fe077e90d59bd10978919da2cb0b7883e2b2e60c02abd9a9ed0f786d036b028c96b1940304b99b82810e076c089f93c602059fb7de0278f9f6aa9e03059ca7cc970605aaacd9d00678ea9187de0806e181d68b0b78a3ade4df0e786d7b6e786c059f93c602059fb7de0278d9e5d5d60a78e181d68b0b78c49ff4e40f716c038a8ac1f7090987afebf709789797e0fb0d716e0a6b03d4b4c59a097ff4b895a40b7f9dada9e10b7f0100010101020000000000000017696e76616c696420617267756d656e743a206166746572",
        &mut m,
    );

    // get_key_checks, admin_set_key_check, admin_retire_kid
    golden(
        "KeyChecksResult::Ok",
        &KeyChecksResult::Ok(key_checks()),
        "4449444c086b02bc8a0101c5fed201056c048edeb39d037898cec7e70778abadbcd00b02e9bccfb60f046d036c02869ac6027bc8b1daad04046d7b6c038a8ac1f7090687afebf709789797e0fb0d716e076b03d4b4c59a097ff4b895a40b7f9dada9e10b7f01000000002a36fe9c97170300000000000000020110313131313131313131313131313131310210323232323232323232323232323232320101",
        &mut m,
    );
    golden(
        "KeyChecksResult::Err",
        &KeyChecksResult::Err(CommonError::of(CommonErrorCase::Unauthorized)),
        "4449444c086b02bc8a0101c5fed201056c048edeb39d037898cec7e70778abadbcd00b02e9bccfb60f046d036c02869ac6027bc8b1daad04046d7b6c038a8ac1f7090687afebf709789797e0fb0d716e076b03d4b4c59a097ff4b895a40b7f9dada9e10b7f01000101000100000000000000307468652063616c6c6572206973206e6f7420617574686f72697a656420746f2063616c6c2074686973206d6574686f64",
        &mut m,
    );
    golden(
        "admin_retire_kid argument",
        &RetireKidArg { kid: 1 },
        "4449444c016c01869ac6027b010001",
        &mut m,
    );

    // get_status
    golden(
        "StatusResult::Ok",
        &StatusResult::Ok(status()),
        "4449444c176b02bc8a0101c5fed201146c12c487ee1b71b1a9c55178989f8fc90178f9a2e5da01028edeb39d0378a0d2aca8047888cb86a30505c99ad48e077898cec7e70771a9a1c7bc0807f7dbfd88090edda8f18b0978c392f7c6097d919da2cb0b78c2adc9be0c0f8bc1f2cd0c119080f48a0d78fedbd4ea0e786d036c03dda8f18b09789bd5b7bf0e04fedbd4ea0e786d7b6d066c05a9c5d18c0278cedcfb9104789bbdbff9057ea896c0b20a788ba9a1b70b686e086c0582e1b793047ef0bd82b30678d9b78c8c0778b8bfd4a90809f1808f960f786c05869ac6020aedb1c9ce040bb2cdd9d0060ce1c492820e0c9bd5b7bf0e0d6b028a80017bcce5c6017f6b028a800168cce5c6017f6b028a800178cce5c6017f6b028a800104cce5c6017f6c09c981abc60178a9c5d18c0278a5bfa9ab0278a8a8bfe70478e4a1a9b80678d4d5c2eb0678dc85e4d70978c89fd6ee0978a896c0b20a786c06e6d6f9bd04799bbdbff90510e8f7fd940779d2d087850b7898998bf60c78abd9a9ed0f786d686c048edeb39d037898cec7e70778abadbcd00b12e9bccfb60f046d136c02869ac6027bc8b1daad04046c038a8ac1f7091587afebf709789797e0fb0d716e166b03d4b4c59a097ff4b895a40b7f9dada9e10b7f010000076630663039386300000020000000000f0000000000000001d20400000000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a03800000000000000002858c2cf9d9717002858c2cf9d971701200300000000000052f4536500000000011603000000000000011d0101010101010101010101010101010101010101010101010101010101020000000000000005302e372e300100a00f0000000000000c00000000000000000100011d03030303030303030303030303030303030303030303030303030303030000f153650000000000805abb64000000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000f1536500000000070000000000000001000000000000000400000000000000060000000000000005000000000000000300000000000000090000000000000008000000000000000200000000000000d204000000000000f2dfb89ea7e702c0ae446500000000e803000002011d0101010101010101010101010101010101010101010101010101010101011d02020202020202020202020202020202020202020202020202020202021e00000090d003000000000020a1070000000000803a09000000000000002a36fe9c9717030000000000000002011031313131313131313131313131313131021032323232323232323232323232323232010170f45365000000003800000000000000",
        &mut m,
    );
    golden(
        "StatusResult::Err",
        &StatusResult::Err(CommonError::of(CommonErrorCase::Unauthorized)),
        "4449444c176b02bc8a0101c5fed201146c12c487ee1b71b1a9c55178989f8fc90178f9a2e5da01028edeb39d0378a0d2aca8047888cb86a30505c99ad48e077898cec7e70771a9a1c7bc0807f7dbfd88090edda8f18b0978c392f7c6097d919da2cb0b78c2adc9be0c0f8bc1f2cd0c119080f48a0d78fedbd4ea0e786d036c03dda8f18b09789bd5b7bf0e04fedbd4ea0e786d7b6d066c05a9c5d18c0278cedcfb9104789bbdbff9057ea896c0b20a788ba9a1b70b686e086c0582e1b793047ef0bd82b30678d9b78c8c0778b8bfd4a90809f1808f960f786c05869ac6020aedb1c9ce040bb2cdd9d0060ce1c492820e0c9bd5b7bf0e0d6b028a80017bcce5c6017f6b028a800168cce5c6017f6b028a800178cce5c6017f6b028a800104cce5c6017f6c09c981abc60178a9c5d18c0278a5bfa9ab0278a8a8bfe70478e4a1a9b80678d4d5c2eb0678dc85e4d70978c89fd6ee0978a896c0b20a786c06e6d6f9bd04799bbdbff90510e8f7fd940779d2d087850b7898998bf60c78abd9a9ed0f786d686c048edeb39d037898cec7e70778abadbcd00b12e9bccfb60f046d136c02869ac6027bc8b1daad04046c038a8ac1f7091587afebf709789797e0fb0d716e166b03d4b4c59a097ff4b895a40b7f9dada9e10b7f01000101000100000000000000307468652063616c6c6572206973206e6f7420617574686f72697a656420746f2063616c6c2074686973206d6574686f64",
        &mut m,
    );

    // admin_update_config
    golden(
        "ConfigPatch",
        &config_patch(),
        "4449444c056c06e6d6f9bd04019bbdbff90502e8f7fd940701d2d087850b0498998bf60c04abd9a9ed0f046e796e036d686e78010001e80300000102011d0101010101010101010101010101010101010101010101010101010101011d0202020202020202020202020202020202020202020202020202020202011e0000000190d00300000000000120a107000000000001803a090000000000",
        &mut m,
    );
    golden(
        "ConfigPatch (empty)",
        &ConfigPatch::default(),
        "4449444c056c06e6d6f9bd04019bbdbff90502e8f7fd940701d2d087850b0498998bf60c04abd9a9ed0f046e796e036d686e780100000000000000",
        &mut m,
    );
    golden(
        "ConfigResult::Ok",
        &ConfigResult::Ok(config()),
        "4449444c066b02bc8a0101c5fed201036c06e6d6f9bd04799bbdbff90502e8f7fd940779d2d087850b7898998bf60c78abd9a9ed0f786d686c038a8ac1f7090487afebf709789797e0fb0d716e056b03d4b4c59a097ff4b895a40b7f9dada9e10b7f010000e803000002011d0101010101010101010101010101010101010101010101010101010101011d02020202020202020202020202020202020202020202020202020202021e00000090d003000000000020a1070000000000803a090000000000",
        &mut m,
    );
    golden(
        "ConfigResult::Err",
        &ConfigResult::Err(CommonError::invalid_argument("purge_batch")),
        "4449444c066b02bc8a0101c5fed201036c06e6d6f9bd04799bbdbff90502e8f7fd940779d2d087850b7898998bf60c78abd9a9ed0f786d686c038a8ac1f7090487afebf709789797e0fb0d716e056b03d4b4c59a097ff4b895a40b7f9dada9e10b7f010001010102000000000000001d696e76616c696420617267756d656e743a2070757267655f6261746368",
        &mut m,
    );

    // admin_purge_sessions
    golden(
        "PurgeFilter",
        &purge_filter(),
        "4449444c066c05869ac60201edb1c9ce0402b2cdd9d00603e1c492820e039bd5b7bf0e046b028a80017bcce5c6017f6b028a800168cce5c6017f6b028a800178cce5c6017f6b028a800105cce5c6017f6d7b0100000100011d03030303030303030303030303030303030303030303030303030303030000f153650000000000805abb64000000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
        &mut m,
    );
    golden(
        "PurgeFilter (empty)",
        &PurgeFilter::default(),
        "4449444c066c05869ac60201edb1c9ce0402b2cdd9d00603e1c492820e039bd5b7bf0e046b028a80017bcce5c6017f6b028a800168cce5c6017f6b028a800178cce5c6017f6b028a800105cce5c6017f6d7b01000101010101",
        &mut m,
    );
    golden(
        "PurgeJobResult::Ok",
        &PurgeJobResult::Ok(purge_job()),
        "4449444c0b6b02bc8a0101c5fed201086c0582e1b793047ef0bd82b30678d9b78c8c0778b8bfd4a90802f1808f960f786c05869ac60203edb1c9ce0404b2cdd9d00605e1c492820e059bd5b7bf0e066b028a80017bcce5c6017f6b028a800168cce5c6017f6b028a800178cce5c6017f6b028a800107cce5c6017f6d7b6c038a8ac1f7090987afebf709789797e0fb0d716e0a6b03d4b4c59a097ff4b895a40b7f9dada9e10b7f01000000a00f0000000000000c00000000000000000100011d03030303030303030303030303030303030303030303030303030303030000f153650000000000805abb64000000000010a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a000f1536500000000",
        &mut m,
    );
    golden(
        "PurgeJobResult::Err",
        &PurgeJobResult::Err(CommonError::of(CommonErrorCase::Unauthorized)),
        "4449444c0b6b02bc8a0101c5fed201086c0582e1b793047ef0bd82b30678d9b78c8c0778b8bfd4a90802f1808f960f786c05869ac60203edb1c9ce0404b2cdd9d00605e1c492820e059bd5b7bf0e066b028a80017bcce5c6017f6b028a800168cce5c6017f6b028a800178cce5c6017f6b028a800107cce5c6017f6d7b6c038a8ac1f7090987afebf709789797e0fb0d716e0a6b03d4b4c59a097ff4b895a40b7f9dada9e10b7f01000101000100000000000000307468652063616c6c6572206973206e6f7420617574686f72697a656420746f2063616c6c2074686973206d6574686f64",
        &mut m,
    );

    // The empty argument records, and admin_set_key_check's.
    golden("get_key_checks argument", &GetKeyChecksArg {}, "4449444c016c000100", &mut m);
    golden("get_status argument", &GetStatusArg {}, "4449444c016c000100", &mut m);
    golden(
        "admin_set_key_check argument",
        &SetKeyCheckArg { kid: 2, check: vec![0x32; KEY_CHECK_LEN], replace: Some(true) },
        "4449444c036c03869ac6027bc8b1daad0401b490a1d90a026d7b6e7e01000210323232323232323232323232323232320101",
        &mut m,
    );

    assert!(m.is_empty(), "wire bytes changed; re-pin only if compatible:\n\n{}", m.join("\n\n"));
}

// --- Evolution rules ------------------------------------------------------------

/// `SessionRecord` as an older canister knew it: without `consumed_at`.
#[derive(CandidType, Deserialize)]
struct SessionRecordV0 {
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
    seq: u64,
    #[serde(with = "serde_bytes")]
    op_id: Vec<u8>,
    created_at: u64,
    grant_expires_at: u64,
    last_active_at: u64,
    #[serde(with = "serde_bytes")]
    sealed: Vec<u8>,
}

/// `ListChangesArg` as an older backend sends it: without `limit`.
#[derive(CandidType, Deserialize)]
struct ListChangesArgV0 {
    after: u64,
}

/// `ConfigPatch` as an older admin tool sends it.
#[derive(CandidType, Deserialize)]
struct ConfigPatchV0 {
    idle_timeout_secs: Option<u64>,
}

/// `SessionRecord` as a newer canister may send it: with `opt` fields this
/// version does not know.
#[derive(CandidType, Deserialize)]
struct SessionRecordV2 {
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
    seq: u64,
    #[serde(with = "serde_bytes")]
    op_id: Vec<u8>,
    created_at: u64,
    grant_expires_at: u64,
    last_active_at: u64,
    consumed_at: Option<u64>,
    #[serde(with = "serde_bytes")]
    sealed: Vec<u8>,
    revoked_at: Option<u64>,
    labels: Option<Vec<String>>,
}

#[test]
fn payloads_without_later_opt_fields_still_decode() {
    let r = record();
    let v0 = SessionRecordV0 {
        key: r.key.clone(),
        seq: r.seq,
        op_id: r.op_id.clone(),
        created_at: r.created_at,
        grant_expires_at: r.grant_expires_at,
        last_active_at: r.last_active_at,
        sealed: r.sealed.clone(),
    };
    let bytes = Encode!(&Result::<SessionRecordV0, PutSessionError>::Ok(v0)).expect("encodes");
    let decoded = Decode!(&bytes, PutSessionResult).expect("an older reply decodes");
    assert_eq!(decoded, Ok(SessionRecord { consumed_at: None, ..r }));

    let bytes = Encode!(&ListChangesArgV0 { after: 7 }).expect("encodes");
    let decoded = Decode!(&bytes, ListChangesArg).expect("an older request decodes");
    assert_eq!(decoded, ListChangesArg { after: 7, limit: None });

    let bytes = Encode!(&ConfigPatchV0 { idle_timeout_secs: Some(3_600) }).expect("encodes");
    let decoded = Decode!(&bytes, ConfigPatch).expect("an older patch decodes");
    assert_eq!(decoded, ConfigPatch { idle_timeout_secs: Some(3_600), ..ConfigPatch::default() });
}

#[test]
fn unknown_record_fields_are_ignored() {
    let r = record();
    let v2 = SessionRecordV2 {
        key: r.key.clone(),
        seq: r.seq,
        op_id: r.op_id.clone(),
        created_at: r.created_at,
        grant_expires_at: r.grant_expires_at,
        last_active_at: r.last_active_at,
        consumed_at: r.consumed_at,
        sealed: r.sealed.clone(),
        revoked_at: Some(1_700_001_000),
        labels: Some(vec!["new".to_string()]),
    };
    let bytes = Encode!(&Result::<SessionRecordV2, ConsumeCodeError>::Ok(v2)).expect("encodes");
    let decoded = Decode!(&bytes, ConsumeCodeResult).expect("a newer reply decodes");
    assert_eq!(decoded, Ok(r));
}

/// `PutSessionErrorCase` as a newer canister might know it, with a case this
/// crate's readers do not.
#[derive(CandidType, Deserialize)]
enum PutSessionErrorCaseV2 {
    Unauthorized,
    InvalidArgument,
    AlreadyExists,
    Deleted,
    GrantExpired,
    CapacityExceeded,
    RateLimited,
}

/// `PutSessionError` as that newer canister would send it.
#[derive(CandidType, Deserialize)]
struct PutSessionErrorV2 {
    err_code: u64,
    err_case: Option<PutSessionErrorCaseV2>,
    err_str: String,
}

/// `Lookup` with a case added in breach of the evolution rules.
#[derive(CandidType, Deserialize)]
enum LookupV2 {
    Live(SessionRecord),
    Deleted(Tombstone),
    Absent,
    Expired(u64),
}

/// Why errors are records with an `opt` case: a newer canister can add a case,
/// and an older reader decodes it as `err_case = None`, keeping the code and the
/// message, instead of rejecting the whole reply.
#[test]
fn an_unknown_error_case_decodes_as_none() {
    let newer = PutSessionErrorV2 {
        err_code: 99,
        err_case: Some(PutSessionErrorCaseV2::RateLimited),
        err_str: "slow down".to_string(),
    };
    let bytes = Encode!(&Result::<SessionRecord, PutSessionErrorV2>::Err(newer)).expect("encodes");
    assert_eq!(
        Decode!(&bytes, PutSessionResult).expect("decodes"),
        Err(PutSessionError { err_code: 99, err_case: None, err_str: "slow down".to_string() })
    );
    // A case this reader knows still arrives as itself.
    let known = PutSessionErrorV2 {
        err_code: error_code::CAPACITY_EXCEEDED,
        err_case: Some(PutSessionErrorCaseV2::CapacityExceeded),
        err_str: "full".to_string(),
    };
    let bytes = Encode!(&Result::<SessionRecord, PutSessionErrorV2>::Err(known)).expect("encodes");
    let decoded = Decode!(&bytes, PutSessionResult).expect("decodes").unwrap_err();
    assert!(decoded.is(PutSessionErrorCase::CapacityExceeded));
}

/// Why every other returned variant never gains cases: an older reader rejects
/// the whole reply when the new case is sent.
#[test]
fn unknown_variant_cases_are_rejected() {
    let bytes = Encode!(&vec![LookupV2::Absent, LookupV2::Expired(1)]).expect("encodes");
    assert!(Decode!(&bytes, Vec<Lookup>).is_err(), "an unknown lookup case must not decode");
}

// --- Size limits ----------------------------------------------------------------

/// The IC's limit on an ingress message and on a reply.
const MESSAGE_LIMIT: usize = 2 * 1024 * 1024;

fn largest_record() -> SessionRecord {
    SessionRecord {
        key: vec![0xFF; KEY_LEN],
        seq: u64::MAX,
        op_id: vec![0xFF; ID_LEN],
        created_at: u64::MAX,
        grant_expires_at: u64::MAX,
        last_active_at: u64::MAX,
        consumed_at: Some(u64::MAX),
        sealed: vec![0xFF; MAX_SEALED_LEN],
    }
}

fn largest_tombstone() -> Tombstone {
    let reason = [REASON_IDLE, REASON_EVICTED, REASON_ADMIN_PURGE]
        .into_iter()
        .max_by_key(|r| r.len())
        .expect("non-empty");
    Tombstone {
        key: vec![0xFF; KEY_LEN],
        seq: u64::MAX,
        deleted_at: u64::MAX,
        grant_expires_at: u64::MAX,
        reason: reason.to_string(),
    }
}

/// The encoded size of one value, header and type table included, so a
/// multiple of it over-estimates a vector of it.
fn encoded_len<T: CandidType>(value: &T) -> usize {
    Encode!(value).expect("encodes").len()
}

#[test]
fn a_full_change_page_fits_in_a_reply() {
    let per_change = encoded_len(&Change::Live(largest_record()))
        .max(encoded_len(&Change::Deleted(largest_tombstone())));
    let bound = MAX_PAGE_LIMIT as usize * per_change;
    assert!(bound < MESSAGE_LIMIT, "{MAX_PAGE_LIMIT} x {per_change} B = {bound} B");

    let page = ListChangesResult::Ok(ChangesPage {
        changes: vec![Change::Live(largest_record()); MAX_PAGE_LIMIT as usize],
        complete: false,
        next_after: u64::MAX,
        head: u64::MAX,
        epoch: u64::MAX,
        now_ns: u64::MAX,
        idle_timeout_secs: u64::MAX,
        idle_floor_at: u64::MAX,
        key_checks_version: u64::MAX,
    });
    let len = encoded_len(&page);
    assert!(len < MESSAGE_LIMIT, "a full page is {len} B");
}

#[test]
fn a_full_touch_batch_fits_in_a_message() {
    let touch = Touch { key: vec![0xFF; KEY_LEN], last_active_at: u64::MAX };
    let per_touch = encoded_len(&touch);
    let bound = MAX_TOUCH_BATCH * per_touch;
    assert!(bound < MESSAGE_LIMIT, "{MAX_TOUCH_BATCH} x {per_touch} B = {bound} B");
    let len = encoded_len(&TouchSessionsArg { touches: vec![touch; MAX_TOUCH_BATCH] });
    assert!(len < MESSAGE_LIMIT, "a full batch is {len} B");
}

#[test]
fn a_full_lookup_fits_in_a_reply() {
    let per_lookup = encoded_len(&Lookup::Live(largest_record()))
        .max(encoded_len(&Lookup::Deleted(largest_tombstone())));
    let bound = MAX_GET_KEYS * per_lookup;
    assert!(bound < MESSAGE_LIMIT, "{MAX_GET_KEYS} x {per_lookup} B = {bound} B");
    let reply = GetSessionsResult::Ok(GetSessionsOk {
        items: vec![Lookup::Live(largest_record()); MAX_GET_KEYS],
        epoch: u64::MAX,
        now_ns: u64::MAX,
    });
    let len = encoded_len(&reply);
    assert!(len < MESSAGE_LIMIT, "a full reply is {len} B");
}
