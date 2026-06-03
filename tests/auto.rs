//! Tests for `--auto` one-shot decryption: key + iv + im4p -> "<input>.decrypted".

mod common;
use common::*;

use aes::Aes128;
use cbc::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};

/// AES-128-CBC encrypt a block-aligned plaintext (produces a real ciphertext
/// fixture for the decryptor to recover).
fn cbc_encrypt(pt: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    assert_eq!(pt.len() % 16, 0);
    let mut buf = pt.to_vec();
    let n = pt.len();
    cbc::Encryptor::<Aes128>::new(key.into(), iv.into())
        .encrypt_padded_mut::<NoPadding>(&mut buf, n)
        .unwrap()
        .to_vec()
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `--auto` decrypts a CBC payload with no `--aes-mode` flag and writes
/// "<input>.decrypted" right next to the input.
#[test]
fn auto_cbc_writes_sibling_and_recovers() {
    let dir = tmpdir("auto-cbc");
    let key = [0x11u8; 16];
    let iv = [0x22u8; 16];
    // Plaintext begins with a Mach-O magic so validation recognizes it.
    let mut pt = vec![0xcf, 0xfa, 0xed, 0xfe];
    pt.extend_from_slice(b"auto cbc one-shot decrypt fixture payload!!");
    while pt.len() % 16 != 0 {
        pt.push(0);
    }
    let ct = cbc_encrypt(&pt, &key, &iv);
    let im4p = Im4pBuilder::new("ibot", "iBoot-test", &ct).build();
    let input = write_fixture(&dir, "iBoot.test.im4p", &im4p);

    let out = run(&["--auto", "--iv", &hexs(&iv), "--key", &hexs(&key), input.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("AES-CBC"));

    // "<input>.decrypted" sits next to the input and equals the plaintext.
    let dec_path = {
        let mut s = input.clone().into_os_string();
        s.push(".decrypted");
        std::path::PathBuf::from(s)
    };
    assert_eq!(std::fs::read(&dec_path).unwrap(), pt);
}

/// `--auto --json` reports the chosen mode and output path.
#[test]
fn auto_json_reports_mode() {
    let dir = tmpdir("auto-json");
    let key = [0x33u8; 16];
    let iv = [0x44u8; 16];
    let mut pt = vec![0xcf, 0xfa, 0xed, 0xfe];
    pt.extend_from_slice(b"json mode report fixture .........");
    while pt.len() % 16 != 0 {
        pt.push(0);
    }
    let ct = cbc_encrypt(&pt, &key, &iv);
    let im4p = Im4pBuilder::new("krnl", "k", &ct).build();
    let input = write_fixture(&dir, "x.im4p", &im4p);

    let out = run(&["--auto", "--json", "--iv", &hexs(&iv), "--key", &hexs(&key), input.to_str().unwrap()]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["mode"], "cbc");
    assert_eq!(v["validated"], true);
    assert!(v["output"].as_str().unwrap().ends_with("x.im4p.decrypted"));
}

/// `--auto` with neither CLI keys nor a KBAG fails clearly.
#[test]
fn auto_without_keys_or_kbag_errors() {
    let dir = tmpdir("auto-nokey");
    let im4p = Im4pBuilder::new("krnl", "k", &[0u8; 32]).build();
    let input = write_fixture(&dir, "x.im4p", &im4p);
    let out = run(&["--auto", input.to_str().unwrap()]);
    assert!(!out.status.success());
}

/// `--auto` on input without an IM4P payload (standalone IM4M) errors clearly.
#[test]
fn auto_without_im4p_errors() {
    let dir = tmpdir("auto-noim4p");
    let manb = property("MANB", set(&[property("MANP", set(&[property("CHIP", integer(1))]))]));
    let im4m = seq(&[ia5("IM4M"), integer(0), set(&[manb]), octet(&[0x55; 64]), seq(&[seq(&[ia5("c")])])]);
    let input = write_fixture(&dir, "x.im4m", &im4m);
    let out = run(&["--auto", "--iv", &"00".repeat(16), "--key", &"00".repeat(16), input.to_str().unwrap()]);
    assert!(!out.status.success());
}
