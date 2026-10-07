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
    assert_eq!(v["im4p"]["compression"]["algorithm"], "unknown(0)");
    assert_eq!(v["im4p"]["compression"]["uncompressed_size"], 9999);
}

/// A stray/empty SEQUENCE among the IM4P optionals must be tolerated (warned and
/// skipped), not abort the whole parse.
#[test]
fn im4p_stray_sequence_tolerated() {
    let dir = tmpdir("im4p-stray");
    let im4p = seq(&[ia5("IM4P"), ia5("krnl"), ia5("v"), octet(&[0xAA; 16]), seq(&[])]);
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");
    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert_eq!(v["im4p"]["type"], "krnl");
    assert!(v["im4p"]["compression"].is_null());
}

/// A compression block whose declared uncompressed size exceeds u64 must not
/// sink the whole parse: the algorithm is still reported, the size as unknown.
#[test]
fn im4p_compression_oversized_size_degrades() {
    let dir = tmpdir("im4p-comp-big");
    // compression = SEQUENCE { INTEGER 1 (lzfse), INTEGER <9 bytes> }
    let comp = seq(&[integer(1), integer_raw(&[0x01, 2, 3, 4, 5, 6, 7, 8, 9])]);
    let im4p = seq(&[ia5("IM4P"), ia5("krnl"), ia5("v"), octet(&[0u8; 16]), comp]);
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");
    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert_eq!(v["im4p"]["compression"]["algorithm"], "lzfse");
    assert_eq!(v["im4p"]["compression"]["method_id"], 1);
    assert!(v["im4p"]["compression"]["uncompressed_size"].is_null());
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

/// Apple's [0] PAYP arm is independent of the optional KBAG and compression.
#[test]
fn im4p_payp_optional_fields() {
    for with_kbag in [false, true] {
        for with_compression in [false, true] {
            let dir = tmpdir("payp-optional");
            let mut builder = Im4pBuilder::new("krnl", "v", &[0xBB; 16]);
            if with_kbag {
                builder = builder.keybag_raw(kbag(&[(1, vec![0x11; 16], vec![0x22; 32])]));
            }
            if with_compression {
                builder = builder.compression(1, 4096);
            }
            let input = write_fixture(&dir, "in.im4p", &builder.payp(&[
                property("DGST", octet(&[0x99; 48])),
            ]).build());
            let out = dir.join("out");
            let v = run_json(&["-o", out.to_str().unwrap(), input.to_str().unwrap()]);
            assert_eq!(v["im4p"]["payload_properties"][0]["key"], "DGST");
            assert_eq!(v["im4p"]["kbag"].is_array(), with_kbag);
            assert_eq!(v["im4p"]["compression"].is_object(), with_compression);
        }
    }
}

/// Keep accepting the bare PAYP variant accepted by earlier img4-dump releases.
#[test]
fn im4p_bare_payp_compatibility() {
    let dir = tmpdir("payp-bare");
    let im4p = seq(&[
        ia5("IM4P"), ia5("krnl"), ia5("v"), octet(&[0xAA; 16]),
        seq(&[ia5("PAYP"), set(&[property("DGST", octet(&[0x99; 48]))])]),
    ]);
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");
    let v = run_json(&["-o", out.to_str().unwrap(), input.to_str().unwrap()]);
    assert_eq!(v["im4p"]["payload_properties"][0]["key"], "DGST");
}

/// Invalid optional wrappers must not fabricate properties or lose payload data.
#[test]
fn im4p_malformed_payp_wrapper() {
    let payp = seq(&[ia5("PAYP"), set(&[property("DGST", octet(&[0x99; 48]))])]);
    let mut trailing = payp.clone();
    trailing.extend(integer(1));
    for wrapper in [
        tlv(0x80, &payp),
        ctx_explicit(0, &trailing),
        ctx_explicit(0, &seq(&[ia5("IM4R"), set(&[])])),
    ] {
        let dir = tmpdir("payp-malformed");
        let input = write_fixture(&dir, "in.im4p", &seq(&[
            ia5("IM4P"), ia5("krnl"), ia5("v"), octet(&[0xAA; 16]), wrapper,
        ]));
        let out = dir.join("out");
        let v = run_json(&["-o", out.to_str().unwrap(), input.to_str().unwrap()]);
        assert!(v["im4p"]["payload_properties"].is_null());
        assert_eq!(std::fs::read(out.join("im4p.bin")).unwrap(), [0xAA; 16]);
    }
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

/// Build an IM4M wrapping the given MANP property set and image objects.
fn build_im4m(manp_props: &[Vec<u8>], images: &[(&str, Vec<Vec<u8>>)], version: u64) -> Vec<u8> {
    let mut manb_children = vec![property("MANP", set(manp_props))];
    for (fourcc, props) in images {
        manb_children.push(property(fourcc, set(props)));
    }
    let manb = property("MANB", set(&manb_children));
    seq(&[
        ia5("IM4M"),
        integer(version),
        set(&[manb]),
        octet(&[0x55; 64]),
        seq(&[seq(&[ia5("c")])]),
    ])
}

/// The structured manifest dump separates global (MANP) properties from per-image
/// property groups, with image->property association preserved and no structural noise.
#[test]
fn im4m_structured_manifest_props() {
    let dir = tmpdir("im4m-structured");
    let im4m = build_im4m(
        &[property("CHIP", integer(0x8030)), property("ECID", integer(0x1122334455))],
        &[
            ("krnl", vec![property("DGST", octet(&[0x01; 48]))]),
            ("sepi", vec![property("DGST", octet(&[0x02; 48]))]),
        ],
        0,
    );
    let input = write_fixture(&dir, "in.im4m", &im4m);
    let out = dir.join("out");
    let _ = run_json(&["--dump-im4m-props", "-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);

    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("im4m.props.json")).unwrap()).unwrap();
    let mp: Vec<&str> = v["manifest_properties"].as_array().unwrap().iter().map(|p| p["key"].as_str().unwrap()).collect();
    assert!(mp.contains(&"CHIP") && mp.contains(&"ECID"));
    // No structural noise: MANB / MANP / IM4M never appear as properties.
    assert!(!mp.contains(&"MANB") && !mp.contains(&"MANP") && !mp.contains(&"IM4M"));

    let images = v["images"].as_array().unwrap();
    assert_eq!(images.len(), 2);
    // Each image keeps its own DGST (association preserved).
    for img in images {
        let keys: Vec<&str> = img["properties"].as_array().unwrap().iter().map(|p| p["key"].as_str().unwrap()).collect();
        assert_eq!(keys, vec!["DGST"]);
        assert!(matches!(img["fourcc"].as_str().unwrap(), "krnl" | "sepi"));
    }
}

/// images_present in the summary is derived structurally from MANB children.
#[test]
fn im4m_images_present_structural() {
    let dir = tmpdir("im4m-images");
    let im4m = build_im4m(
        &[property("CHIP", integer(1))],
        &[("krnl", vec![]), ("ibot", vec![]), ("sepi", vec![])],
        0,
    );
    let input = write_fixture(&dir, "in.im4m", &im4m);
    let out = dir.join("out");
    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    let imgs: Vec<&str> = v["im4m"]["images_present"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    assert_eq!(imgs, vec!["ibot", "krnl", "sepi"]); // sorted, exact, no MANP/MANB
}

/// An INTEGER property wider than 64 bits is rendered as a hex magnitude, never
/// silently truncated to zero or mislabeled.
#[test]
fn im4m_big_integer_property() {
    let dir = tmpdir("im4m-bigint");
    // 9 significant content bytes => exceeds u64.
    let big = integer_raw(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x11]);
    let im4m = build_im4m(&[property("CHIP", big)], &[], 0);
    let input = write_fixture(&dir, "in.im4m", &im4m);
    let out = dir.join("out");
    let _ = run_json(&["--dump-im4m-props", "-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("im4m.props.json")).unwrap()).unwrap();
    let chip = v["manifest_properties"].as_array().unwrap().iter().find(|p| p["key"] == "CHIP").unwrap();
    assert_eq!(chip["value"]["type"], "Unknown");
    assert_eq!(chip["value"]["der_type"], "INTEGER");
    assert_eq!(chip["value"]["hex_value"], "0123456789abcdef11");
    // not mislabeled as an anomaly
    assert!(chip.get("anomaly").is_none());
}

/// A manifest with an out-of-spec version (>2) is still parseable (warn, not reject).
#[test]
fn im4m_version_out_of_range_tolerated() {
    let dir = tmpdir("im4m-ver");
    let im4m = build_im4m(&[property("CHIP", integer(1))], &[], 7);
    let input = write_fixture(&dir, "in.im4m", &im4m);
    let out = dir.join("out");
    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert_eq!(v["im4m"]["version"], 7);
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

/// Standalone IM4R is recognized and uses the same property extraction as an
/// embedded restore-info component.
#[test]
fn im4r_standalone() {
    let dir = tmpdir("im4r-standalone");
    let nonce = vec![0xAB; 8];
    let im4r = seq(&[ia5("IM4R"), set(&[property("BNCN", octet(&nonce))])]);
    let input = write_fixture(&dir, "in.im4r", &im4r);
    let out = dir.join("out");

    let v = run_json(&["--dump-im4r", "-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert_eq!(v["container"], "Im4rStandalone");
    assert_eq!(v["im4r_len"], im4r.len());
    assert!(v["im4r_properties"].as_array().unwrap().iter().any(|p| p["key"] == "BNCN"));
    assert_eq!(std::fs::read(out.join("im4r.der")).unwrap(), im4r);
    assert_eq!(std::fs::read(out.join("im4r.bncn.bin")).unwrap(), nonce);
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

/// Requesting a KBAG class that is absent must fail loudly, never silently fall
/// back to the other class's key (which would decrypt to garbage).
#[test]
fn kbag_class_selection_enforced() {
    let dir = tmpdir("kbag-class");
    // KBAG with ONLY a development (class 2) entry.
    let kb = kbag(&[(2, vec![0x33; 16], vec![0x44; 16])]);
    let im4p = Im4pBuilder::new("ibot", "iBoot", &[0xAA; 32]).keybag_raw(kb).build();
    let input = write_fixture(&dir, "in.im4p", &im4p);

    // Requesting prod (class 1) on a dev-only KBAG must error.
    let prod = run(&[
        "--decrypt", "--kbag-class", "prod",
        "-o", dir.join("prod").to_str().unwrap(), "-f", input.to_str().unwrap(),
    ]);
    assert!(!prod.status.success(), "prod request on dev-only KBAG must fail");
    let stderr = String::from_utf8_lossy(&prod.stderr);
    assert!(
        stderr.contains("production") || stderr.contains("class 1"),
        "error should explain the missing class: {stderr}"
    );

    // Requesting dev (class 2) succeeds and writes a decrypted payload.
    let outdev = dir.join("dev");
    let dev = run(&[
        "--decrypt", "--kbag-class", "dev",
        "-o", outdev.to_str().unwrap(), "-f", input.to_str().unwrap(),
    ]);
    assert!(dev.status.success(), "dev request should succeed: {}", String::from_utf8_lossy(&dev.stderr));
    assert!(outdev.join("im4p.decrypted").exists());
}

/// Apple Image4 decoders require exact DER consumption. A valid component or
/// container followed by unrelated bytes must not be accepted as a valid file.
#[test]
fn rejects_trailing_bytes_after_top_level_der() {
    let im4p = Im4pBuilder::new("krnl", "K", &[0xCC; 16]).build();
    let img4 = seq(&[ia5("IMG4"), im4p.clone()]);
    let im4m = build_im4m(&[], &[], 0);
    let im4r = seq(&[ia5("IM4R"), set(&[property("BNCN", octet(&[0xAB; 8]))])]);

    for (label, mut bytes) in [
        ("IM4P", im4p),
        ("IMG4", img4),
        ("IM4M", im4m),
        ("IM4R", im4r),
    ] {
        bytes.push(0x00);
        let dir = tmpdir("trailing-der");
        let input = write_fixture(&dir, "in.der", &bytes);
        let out_dir = dir.join("out");
        let result = run(&[
            "--json",
            "-o",
            out_dir.to_str().unwrap(),
            "-f",
            input.to_str().unwrap(),
        ]);
        assert!(
            !result.status.success(),
            "{label} with trailing bytes must be rejected"
        );
        let value: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("failure output must remain valid JSON");
        assert!(
            value["error"]
                .as_str()
                .unwrap_or_default()
                .contains("trailing byte"),
            "{label} error should identify trailing DER bytes: {value}"
        );
    }
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

/// In --json mode, a failure still produces valid JSON (an {"error": ...} object)
/// on stdout, so machine consumers never see a broken stream.
#[test]
fn json_error_boundary() {
    let dir = tmpdir("json-err");
    let input = write_fixture(&dir, "in.bin", b"not der at all");
    let out = dir.join("out");
    let res = run(&["--json", "-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    assert!(!res.status.success());
    let v: serde_json::Value = serde_json::from_slice(&res.stdout)
        .expect("stdout must be valid JSON even on error");
    assert!(v["error"].is_string(), "error object expected, got {v}");
}

/// The JSON summary is a superset of the human output: it lists the files written.
#[test]
fn json_lists_output_files() {
    let dir = tmpdir("json-files");
    let im4p = Im4pBuilder::new("krnl", "K", &[0xCC; 16]).build();
    let input = write_fixture(&dir, "in.im4p", &im4p);
    let out = dir.join("out");
    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    let files = v["output_files"].as_array().expect("output_files array");
    assert!(files.iter().any(|f| f["label"] == "Payload" && f["path"].as_str().unwrap().ends_with("im4p.bin")));
}

/// IM4R properties are surfaced in the JSON summary (superset of the file dump).
#[test]
fn json_includes_im4r_properties() {
    let dir = tmpdir("json-im4r");
    let im4p = Im4pBuilder::new("krnl", "K", &[0; 8]).build();
    let im4r = seq(&[ia5("IM4R"), set(&[property("BNCN", octet(&[0xab; 8]))])]);
    let img4 = seq(&[ia5("IMG4"), im4p, ctx_explicit(1, &im4r)]);
    let input = write_fixture(&dir, "in.img4", &img4);
    let out = dir.join("out");
    let v = run_json(&["-o", out.to_str().unwrap(), "-f", input.to_str().unwrap()]);
    let props = v["im4r_properties"].as_array().expect("im4r_properties");
    assert!(props.iter().any(|p| p["key"] == "BNCN"));
}

/// Native Cryptex1 fields use INTEGER/BOOLEAN; version values are OCTET STRING.
/// Wrong tags retain their bytes and expose an anomaly rather than a false digest.
#[test]
fn native_property_types_and_anomalies() {
    let dir = tmpdir("native-props");
    let im4m = build_im4m(&[
        property("type", integer(0xFFFF_FFFF)),
        property("data", boolean(true)),
        property("ndom", integer(0x1234)),
        property("pqvf", integer(3)),
        property("stng", integer(u64::MAX)),
        property("cnch", octet(&[0xAA; 48])),
        property("love", octet(b"26.1.0,123")),
        property("vnum", octet(b"26.1.0,123")),
        property("boid", octet(&[0xBB; 16])),
    ], &[("gdmg", vec![property("DGST", octet(&[0xCC; 48]))])], 2);
    let input = write_fixture(&dir, "in.im4m", &im4m);
    let out = dir.join("out");
    run_json(&["--dump-im4m-props", "-o", out.to_str().unwrap(), input.to_str().unwrap()]);
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(out.join("im4m.props.json")).unwrap()).unwrap();
    let props = v["manifest_properties"].as_array().unwrap();
    let find = |key: &str| props.iter().find(|p| p["key"] == key).unwrap();
    assert_eq!(find("type")["value"]["value"], 0xFFFF_FFFFu64);
    assert_eq!(find("data")["value"]["value"], true);
    assert_eq!(find("stng")["value"]["value"], u64::MAX);
    assert_eq!(find("cnch")["value"]["type"], "Digest");
    for key in ["love", "vnum", "boid"] {
        assert_eq!(find(key)["value"]["type"], "OctetString");
    }
    assert_eq!(find("love")["value"]["value"], hex::encode(b"26.1.0,123"));
    assert!(props.iter().all(|p| p.get("anomaly").is_none()));
    assert_eq!(v["images"][0]["fourcc"], "gdmg");

    let wrong = build_im4m(&[
        property("type", ia5("gdmg")),
        property("data", integer(1)),
        property("DGST", ia5("abcd")),
        property("vnum", integer(26)),
    ], &[], 0);
    let input = write_fixture(&dir, "wrong.im4m", &wrong);
    let wrong_out = dir.join("wrong");
    run_json(&["--dump-im4m-props", "-o", wrong_out.to_str().unwrap(), input.to_str().unwrap()]);
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(wrong_out.join("im4m.props.json")).unwrap()).unwrap();
    let props = v["manifest_properties"].as_array().unwrap();
    assert!(props.iter().all(|p| p["anomaly"].is_string() && p["value"]["type"] == "Unknown"));
    assert_eq!(props.iter().find(|p| p["key"] == "DGST").unwrap()["value"]["hex_value"], "61626364");
}

#[test]
fn im4r_numeric_nonce_slots() {
    let dir = tmpdir("im4r-slots");
    let im4r = seq(&[ia5("IM4R"), set(&[
        property("anid", integer(0x1234)), property("snid", integer(0xFFFF_FFFF)),
    ])]);
    let input = write_fixture(&dir, "in.im4r", &im4r);
    let out = dir.join("out");
    let v = run_json(&["--dump-im4r", "-o", out.to_str().unwrap(), input.to_str().unwrap()]);
    let props = v["im4r_properties"].as_array().unwrap();
    assert_eq!(props[0]["value"]["value"], 0x1234);
    assert_eq!(props[1]["value"]["value"], 0xFFFF_FFFFu64);
    assert!(props.iter().all(|p| p.get("anomaly").is_none()));
    assert_eq!(std::fs::read(out.join("im4r.der")).unwrap(), im4r);
}
