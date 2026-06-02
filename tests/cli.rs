//! Black-box CLI tests over synthetic Image4 DER vectors.
//!
//! These run the compiled `img4-dump` binary against hand-built fixtures and
//! assert on its `--json` summary and the files it writes. They lock in
//! spec-verified parsing behavior end-to-end.

mod common;
use common::*;

/// Standalone IM4P with type/version/data is detected and reported.
#[test]
fn im4p_standalone_basic() {
    let dir = tmpdir("im4p-basic");
    let im4p = Im4pBuilder::new("ibot", "iBoot-1234", &[0xAA; 48]).build();
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");

    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert_eq!(v["container"], "Im4pStandalone");
    assert_eq!(v["im4p"]["type"], "ibot");
    assert_eq!(v["im4p"]["version"], "iBoot-1234");
    assert_eq!(v["im4p"]["data_len"], 48);
    assert!(v["im4p"]["kbag"].is_null());
    // payload bytes are written out verbatim
    assert_eq!(std::fs::read(out.join("im4p.bin")).unwrap(), vec![0xAA; 48]);
}

/// KBAG with prod + dev entries parses to two entries — and the JSON summary
/// exposes only class + lengths, never the raw IV or AES key bytes.
#[test]
fn im4p_keybag_two_entries_redacted() {
    let dir = tmpdir("im4p-kbag");
    let kb = kbag(&[
        (1, vec![0x11; 16], vec![0x22; 32]),
        (2, vec![0x33; 16], vec![0x44; 32]),
    ]);
    let im4p = Im4pBuilder::new("sepi", "SEP", &[0xBB; 32]).keybag_raw(kb).build();
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");

    let raw = run(&["--json", "-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    let stdout = String::from_utf8(raw.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let kbags = v["im4p"]["kbag"].as_array().expect("kbag array");
    assert_eq!(kbags.len(), 2);
    assert_eq!(kbags[0]["kclass"], 1);
    assert_eq!(kbags[0]["iv_len"], 16);
    assert_eq!(kbags[0]["key_len"], 32);
    assert_eq!(kbags[1]["kclass"], 2);
    // Redaction: no raw `iv`/`key` arrays, and the key/iv byte patterns must not leak.
    assert!(kbags[0].get("iv").is_none(), "raw iv must not be serialized");
    assert!(kbags[0].get("key").is_none(), "raw key must not be serialized");
    assert!(!stdout.contains("34,34,34"), "key bytes (0x22) must not appear in JSON");
    assert!(out.join("im4p.kbag.der").exists());
}

/// A compressed-but-NOT-encrypted payload: KBAG absent, compression present.
/// The compression SEQUENCE physically sits at index 4, so positional parsing
/// would miss it. Tag-driven parsing must still detect it.
#[test]
fn im4p_compression_without_keybag() {
    let dir = tmpdir("im4p-comp-nokbag");
    // algorithm 1 = LZFSE, uncompressed size 4096
    let im4p = Im4pBuilder::new("krnl", "Kernel-x", &[0xDE; 64]).compression(1, 4096).build();
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");

    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert!(v["im4p"]["kbag"].is_null());
    assert_eq!(v["im4p"]["compression"]["algorithm"], "lzfse");
    assert_eq!(v["im4p"]["compression"]["method_id"], 1);
    assert_eq!(v["im4p"]["compression"]["uncompressed_size"], 4096);
}

/// Both KBAG and compression present (encrypted + compressed).
#[test]
fn im4p_keybag_and_compression() {
    let dir = tmpdir("im4p-kbag-comp");
    let kb = kbag(&[(1, vec![0x11; 16], vec![0x22; 16])]);
    let im4p = Im4pBuilder::new("ibot", "iBoot", &[0xAA; 48])
        .keybag_raw(kb)
        .compression(0, 9999)
        .build();
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");

    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert_eq!(v["im4p"]["kbag"].as_array().unwrap().len(), 1);
    assert_eq!(v["im4p"]["compression"]["algorithm"], "lzss");
    assert_eq!(v["im4p"]["compression"]["uncompressed_size"], 9999);
}

/// PAYP with-properties variant: payload-scoped properties are extracted and
/// written to im4p.payp.json, and surfaced in the JSON summary.
#[test]
fn im4p_payp_properties() {
    let dir = tmpdir("im4p-payp");
    let im4p = Im4pBuilder::new("sepi", "SEP-2", &[0xBB; 16])
        .payp(&[
            property("DGST", octet(&[0x99; 48])),
            property("EKEY", boolean(true)),
        ])
        .build();
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");

    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    let props = v["im4p"]["payload_properties"].as_array().expect("payload_properties");
    assert_eq!(props.len(), 2);
    let keys: Vec<&str> = props.iter().map(|p| p["key"].as_str().unwrap()).collect();
    assert!(keys.contains(&"DGST"));
    assert!(keys.contains(&"EKEY"));
    // side file written
    let payp = std::fs::read_to_string(out.join("im4p.payp.json")).expect("payp json");
    assert!(payp.contains("DGST"));
}

/// Full IMG4 container with IM4M + IM4R is fully detected.
#[test]
fn img4_full_container() {
    let dir = tmpdir("img4-full");
    let im4p = Im4pBuilder::new("krnl", "Kernel-1", &[0xCC; 32]).build();
    let manp = property(
        "MANP",
        // MANP's value is a SET of properties
        set(&[
            property("CHIP", integer(0x8030)),
            property("ECID", integer(0x1122334455)),
            property("CPRO", boolean(true)),
        ]),
    );
    let krnl_obj = property("krnl", set(&[property("DGST", octet(&[0x01; 48]))]));
    let manb = property("MANB", set(&[manp, krnl_obj]));
    let im4m = seq(&[
        ia5("IM4M"),
        integer(0),
        set(&[manb]),
        octet(&[0x55; 256]),
        seq(&[seq(&[ia5("c")])]), // bogus 1-cert chain
    ]);
    let im4r = seq(&[ia5("IM4R"), set(&[property("BNCN", octet(&[0xab; 8]))])]);
    let img4 = seq(&[ia5("IMG4"), im4p, ctx_explicit(0, &im4m), ctx_explicit(1, &im4r)]);
    let input = write_fixture(&dir, "in.img4", &img4);
    let out = dir.join("out");

    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert_eq!(v["container"], "Img4");
    assert_eq!(v["im4p"]["type"], "krnl");
    assert_eq!(v["im4m"]["version"], 0);
    assert_eq!(v["im4m"]["cert_chain_len"], 1);
    assert_eq!(v["im4m"]["signature_len"], 256);
    assert_eq!(v["im4r_len"].as_u64().unwrap() > 0, true);
}

/// IM4R BNCN nonce is extracted to a file.
#[test]
fn im4r_bncn_extracted() {
    let dir = tmpdir("im4r-bncn");
    let im4p = Im4pBuilder::new("krnl", "K", &[0; 8]).build();
    let im4r = seq(&[ia5("IM4R"), set(&[property("BNCN", octet(&[0xab; 8]))])]);
    let img4 = seq(&[ia5("IMG4"), im4p, ctx_explicit(1, &im4r)]);
    let input = write_fixture(&dir, "in.img4", &img4);
    let out = dir.join("out");

    let _ = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    let nonce = std::fs::read(out.join("im4r.bncn.bin")).expect("bncn file");
    assert_eq!(nonce, vec![0xab; 8]);
}

/// Standalone IM4M reports version / cert chain / signature.
#[test]
fn im4m_standalone() {
    let dir = tmpdir("im4m-standalone");
    let manb = property("MANB", set(&[property("MANP", set(&[property("CHIP", integer(1))]))]));
    let im4m = seq(&[
        ia5("IM4M"),
        integer(0),
        set(&[manb]),
        octet(&[0x55; 128]),
        seq(&[seq(&[ia5("c")]), seq(&[ia5("d")])]), // 2-cert chain
    ]);
    let input = write_fixture(&dir, "in.im4m", &im4m);
    let out = dir.join("out");

    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert_eq!(v["container"], "Im4mStandalone");
    assert_eq!(v["im4m"]["cert_chain_len"], 2);
    assert_eq!(v["im4m"]["signature_len"], 128);
}

/// Garbage input is rejected with a non-zero exit (no panic).
#[test]
fn rejects_garbage() {
    let dir = tmpdir("garbage");
    let input = write_fixture(&dir, "in.bin", &[0x00, 0x01, 0x02, 0x03, 0x04]);
    let out = dir.join("out");
    let res = run(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert!(!res.status.success(), "garbage should be rejected");
}
