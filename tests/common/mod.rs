//! Minimal, dependency-free DER builder for constructing synthetic Image4
//! test vectors (IMG4 / IM4P / IM4M / IM4R). Used by the black-box CLI tests.
//!
//! These builders emit *Distinguished* Encoding Rules: definite lengths,
//! minimal integer encoding, primitive strings. That matches what Apple's
//! Image4 parser (see `libimage4.c`) requires.

#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Encode a DER definite length.
pub fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let mut body = Vec::new();
        let mut x = n;
        while x > 0 {
            body.insert(0, (x & 0xff) as u8);
            x >>= 8;
        }
        let mut out = vec![0x80 | body.len() as u8];
        out.extend_from_slice(&body);
        out
    }
}

/// Tag-Length-Value with an explicit single-byte tag.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn ia5(s: &str) -> Vec<u8> {
    tlv(0x16, s.as_bytes())
}

pub fn octet(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

pub fn boolean(v: bool) -> Vec<u8> {
    tlv(0x01, &[if v { 0xff } else { 0x00 }])
}

/// Minimal (DER) unsigned INTEGER encoding.
pub fn integer(n: u64) -> Vec<u8> {
    if n == 0 {
        return tlv(0x02, &[0x00]);
    }
    let mut body = Vec::new();
    let mut x = n;
    while x > 0 {
        body.insert(0, (x & 0xff) as u8);
        x >>= 8;
    }
    if body[0] & 0x80 != 0 {
        body.insert(0, 0x00); // keep it positive
    }
    tlv(0x02, &body)
}

/// A raw INTEGER from explicit content octets (for crafting values wider than u64).
pub fn integer_raw(content: &[u8]) -> Vec<u8> {
    tlv(0x02, content)
}

pub fn seq(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &items.concat())
}

pub fn set(items: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &items.concat())
}

/// Context-specific [tag] EXPLICIT constructed wrapper (0xA0 | tag).
pub fn ctx_explicit(tag: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | tag, content)
}

/// Private-class, constructed wrapper whose *tag number* is the 4CC value,
/// encoded in high-tag-number form. This is exactly how Image4 wraps each
/// manifest/restore/payload property (class=private, constructed).
pub fn priv_fourcc(fourcc: &str, content: &[u8]) -> Vec<u8> {
    let n = u32::from_be_bytes(fourcc.as_bytes().try_into().expect("fourcc must be 4 bytes"));
    // class private (0xC0) | constructed (0x20) | high-tag marker (0x1f)
    let mut out = vec![0xE0 | 0x1f];
    // base-128 big-endian of the tag number, MSB set on all but the last byte
    let mut septets: Vec<u8> = Vec::new();
    let mut x = n;
    loop {
        septets.insert(0, (x & 0x7f) as u8);
        x >>= 7;
        if x == 0 {
            break;
        }
    }
    for i in 0..septets.len() - 1 {
        septets[i] |= 0x80;
    }
    out.extend_from_slice(&septets);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// A single property: `[private 4cc] SEQUENCE { IA5String(4cc), value }`.
pub fn property(fourcc: &str, value: Vec<u8>) -> Vec<u8> {
    priv_fourcc(fourcc, &seq(&[ia5(fourcc), value]))
}

// ---- High-level Image4 component builders ----

/// Classic IM4P: SEQUENCE { "IM4P", type, version, data, [keybag], [compression], [PAYP] }
pub struct Im4pBuilder {
    pub r#type: String,
    pub version: String,
    pub data: Vec<u8>,
    pub keybag: Option<Vec<u8>>,
    pub compression: Option<(u64, u64)>,
    pub payp: Option<Vec<u8>>,
}

impl Im4pBuilder {
    pub fn new(ty: &str, version: &str, data: &[u8]) -> Self {
        Self {
            r#type: ty.to_string(),
            version: version.to_string(),
            data: data.to_vec(),
            keybag: None,
            compression: None,
            payp: None,
        }
    }
    pub fn keybag_raw(mut self, der: Vec<u8>) -> Self {
        self.keybag = Some(der);
        self
    }
    pub fn compression(mut self, algo: u64, uncompressed: u64) -> Self {
        self.compression = Some((algo, uncompressed));
        self
    }
    pub fn payp(mut self, properties: &[Vec<u8>]) -> Self {
        self.payp = Some(seq(&[ia5("PAYP"), set(properties)]));
        self
    }
    pub fn build(&self) -> Vec<u8> {
        let mut items = vec![ia5("IM4P"), ia5(&self.r#type), ia5(&self.version), octet(&self.data)];
        if let Some(kb) = &self.keybag {
            items.push(octet(kb));
        }
        if let Some((a, u)) = self.compression {
            items.push(seq(&[integer(a), integer(u)]));
        }
        if let Some(p) = &self.payp {
            items.push(p.clone());
        }
        seq(&items)
    }
}

/// Build a KBAG DER (SEQUENCE OF SEQUENCE { INTEGER class, OCTET iv, OCTET key }).
pub fn kbag(entries: &[(u64, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let inner: Vec<Vec<u8>> = entries
        .iter()
        .map(|(c, iv, k)| seq(&[integer(*c), octet(iv), octet(k)]))
        .collect();
    seq(&inner)
}

// ---- test process helpers ----

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_img4-dump")
}

use std::sync::atomic::{AtomicUsize, Ordering};
static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Create a unique, empty temp directory for a test and return its path.
pub fn tmpdir(tag: &str) -> PathBuf {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("img4dump-test-{}-{}-{}", std::process::id(), tag, n));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Write `bytes` to `dir/name` and return the path.
pub fn write_fixture(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(bytes).unwrap();
    p
}

/// Run the CLI with args; returns the full Output.
pub fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run img4-dump")
}

/// Run with `--json` and parse stdout as JSON.
pub fn run_json(args: &[&str]) -> serde_json::Value {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let out = run(&full);
    assert!(
        out.status.success(),
        "img4-dump failed: stderr=\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\nstdout=\n{}", String::from_utf8_lossy(&out.stdout)))
}
