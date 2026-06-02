use std::fs;
use std::path::Path;
use anyhow::{anyhow, bail, Context, Result};
use hex::FromHex;

use crate::Cli;
use crate::parse::{Im4p, Im4pCompression};
use crate::KbagClass;

pub fn ensure_outdir(outdir: &Path, force: bool) -> Result<()> {
    if outdir.exists() {
        if !outdir.is_dir() { bail!("outdir exists and is not a directory"); }
        if !force && !is_empty_dir(outdir)? {
            bail!("outdir exists and is not empty; pass --force to proceed");
        }
    } else {
        fs::create_dir_all(outdir).with_context(|| format!("mkdir -p {:?}", outdir))?;
    }
    Ok(())
}

fn is_empty_dir(p: &Path) -> Result<bool> {
    if !p.is_dir() { return Ok(false); }
    for _ in fs::read_dir(p)? {
        return Ok(false);
    }
    Ok(true)
}

fn pick_ivk(e: &crate::parse::KbagEntry) -> Result<(Vec<u8>, Vec<u8>)> {
    if e.iv.len() != 16 { bail!("KBAG IV not 16 bytes"); }
    if !matches!(e.key.len(), 16|24|32) { bail!("KBAG key is not 16/24/32 bytes"); }
    Ok((e.iv.clone(), e.key.clone()))
}

pub fn resolve_iv_key(cli: &Cli, im4p: &Im4p) -> Result<(Vec<u8>, Vec<u8>)> {
    // CLI overrides KBAG
    let iv_cli = if let Some(ref hx) = cli.iv_hex {
        Some(decode_hex_exact(hx, 16)?)
    } else { None };
    let key_cli = if let Some(ref hx) = cli.key_hex {
        let k = decode_hex(hx)?;
        match k.len() { 16|24|32 => Some(k), _ => bail!("key hex must be 16/24/32 bytes"), }
    } else { None };

    if let (Some(iv), Some(key)) = (iv_cli, key_cli) {
        return Ok((iv, key));
    }

    // Otherwise use a KBAG entry if present (assumes already-unwrapped IV/Key in plaintext KBAG)
    if let Some(ref entries) = im4p.kbag_summary {
        if let Some(i) = cli.kbag_index {
            let e = entries.get(i).ok_or_else(|| anyhow!("KBAG index {} out of range", i))?;
            return pick_ivk(e);
        }
        // When a specific class is requested but absent, fail loudly rather than
        // silently decrypting with the *other* class's key (which yields garbage).
        let classes: Vec<u64> = entries.iter().map(|e| e.kclass).collect();
        let pick = match cli.kbag_class {
            KbagClass::Prod => entries.iter().find(|e| e.kclass == 1).ok_or_else(|| {
                anyhow!("no production (class 1) KBAG entry; present classes: {classes:?}. Use --kbag-class any or --kbag-index N to override.")
            })?,
            KbagClass::Dev => entries.iter().find(|e| e.kclass == 2).ok_or_else(|| {
                anyhow!("no development (class 2) KBAG entry; present classes: {classes:?}. Use --kbag-class any or --kbag-index N to override.")
            })?,
            KbagClass::Any => entries.first().ok_or_else(|| anyhow!("KBAG present but empty"))?,
        };
        return pick_ivk(pick);
    }

    bail!("no IV/Key provided and no KBAG available");
}

pub fn decode_hex_exact(h: &str, n: usize) -> Result<Vec<u8>> {
    let v: Vec<u8> = Vec::from_hex(h).map_err(|e| anyhow!("hex: {e}"))?;
    if v.len() != n { bail!("expected {n} bytes, got {}", v.len()); }
    Ok(v)
}
pub fn decode_hex(h: &str) -> Result<Vec<u8>> {
    Ok(Vec::from_hex(h).map_err(|e| anyhow!("hex: {e}"))?)
}

/// Check if decrypted data looks valid (heuristic)
pub fn validate_decryption(data: &[u8]) -> (bool, Option<String>) {
    if data.len() < 4 {
        return (false, Some("too short".into()));
    }

    // Check for common magic bytes
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    match magic {
        // Mach-O headers
        0xfeedfacf | 0xcffaedfe | 0xfeedface | 0xcefaedfe => {
            return (true, Some("Mach-O".into()));
        }
        // Compressed formats
        0x62767832 => return (true, Some("LZFSE (bvx2)".into())),      // "bvx2"
        0x636f6d70 => return (true, Some("complzss".into())),          // "comp"
        0x59535331 => return (true, Some("YSS1 (lzss)".into())),       // "YSS1"
        0x496d6733 => return (true, Some("IMG3".into())),              // "Img3"
        0x494d4734 => return (true, Some("IMG4".into())),              // "IMG4"
        _ => {}
    }

    // Check first 64 bytes for patterns (firmware usually has non-zero header)
    let header_len = data.len().min(64);
    let header_zeros = data[..header_len].iter().filter(|&&b| b == 0).count();
    let header_ones = data[..header_len].iter().filter(|&&b| b == 0xFF).count();

    // If header is ALL zeros or ALL 0xFF, likely garbage
    if header_zeros == header_len {
        return (false, Some("all-zero header".into()));
    }
    if header_ones == header_len {
        return (false, Some("all-0xFF header".into()));
    }

    // No known magic: judge by byte entropy. Correctly decrypted firmware that
    // lacks a recognized magic is still structured (entropy well under 8
    // bits/byte); output decrypted with the wrong key/mode is effectively uniform
    // random (entropy ~= 8). The old ">=3 distinct bytes" check flagged random
    // garbage as valid almost every time. Note: genuinely-compressed payloads are
    // already caught above by their magic (bvx2/complzss), so they do not reach
    // this branch. We sample several KiB so the finite-sample entropy of random
    // data lands close to its 8.0 ceiling. THRESHOLD chosen to separate uniform
    // random (~7.95) from structured firmware (typically < 7.0).
    const ENTROPY_THRESHOLD: f64 = 7.5;
    let sample = &data[..data.len().min(8192)];
    let entropy = shannon_entropy(sample);
    if entropy > ENTROPY_THRESHOLD {
        (
            false,
            Some(format!("high entropy {entropy:.2} bits/byte, no known magic (likely wrong key/mode)")),
        )
    } else {
        (
            true,
            Some(format!("no known magic, entropy {entropy:.2} bits/byte (plausibly structured)")),
        )
    }
}

/// Shannon entropy in bits/byte over `data` (0.0 for empty input).
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

pub fn try_decompress(_input: &[u8]) -> Result<Option<(String, Vec<u8>)>> {
    #[cfg(feature = "lzfse")]
    {
        if crate::decompress_lzfse::looks_like_lzfse(_input) {
let out = crate::decompress_lzfse::decompress_lzfse_with_hint(_input, None)?;
            return Ok(Some(("im4p.decompressed.lzfse".into(), out)));
        }
    }
    #[cfg(feature = "lzss")]
    {
        if crate::decompress_lzss::looks_like_lzss(_input) {
            let out = crate::decompress_lzss::decompress_lzss(_input)?;
            return Ok(Some(("im4p.decompressed.lzss".into(), out)));
        }
    }
    Ok(None)
}

pub fn try_decompress_with_metadata(input: &[u8], meta: Option<&Im4pCompression>) -> Result<Option<(String, Vec<u8>)>> {
    // Prefer the explicit IM4P compression metadata when present.
    if let Some(m) = meta {
        match m.method_id {
            0 => {
                #[cfg(feature = "lzss")]
                {
                    let out = crate::decompress_lzss::decompress_lzss(input)?;
                    warn_len_mismatch("lzss", out.len(), m.uncompressed_len);
                    return Ok(Some(("im4p.decompressed.lzss".into(), out)));
                }
                #[cfg(not(feature = "lzss"))]
                bail!("lzss feature disabled but IM4P.compression indicates LZSS");
            }
            1 => {
                #[cfg(feature = "lzfse")]
                {
                    let hint = m.uncompressed_len.map(|v| v as usize);
                    let out = crate::decompress_lzfse::decompress_lzfse_with_hint(input, hint)?;
                    warn_len_mismatch("lzfse", out.len(), m.uncompressed_len);
                    return Ok(Some(("im4p.decompressed.lzfse".into(), out)));
                }
                #[cfg(not(feature = "lzfse"))]
                bail!("lzfse feature disabled but IM4P.compression indicates LZFSE");
            }
            other => log::debug!("IM4P compression id {other} unrecognized; trying heuristics"),
        }
    }

    // Fall back to magic-based heuristics.
    try_decompress(input)
}

/// Surface (rather than silently ignore) a mismatch between the decompressed
/// length and the size declared in the IM4P compression metadata.
#[allow(dead_code)]
fn warn_len_mismatch(kind: &str, got: usize, declared: Option<u64>) {
    if let Some(d) = declared {
        if got as u64 != d {
            log::warn!("{kind}: decompressed {got} bytes != IM4P uncompressed_len {d}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes (xorshift) approximating cipher output.
    fn pseudo_random(n: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E3779B97F4A7C15;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn entropy_of_uniform_is_max() {
        // Every byte value exactly once -> 8 bits/byte.
        let all: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0xAB; 100]), 0.0);
    }

    #[test]
    fn validate_flags_known_magic_valid() {
        let macho = [0xCF, 0xFA, 0xED, 0xFE, 1, 2, 3, 4];
        let (ok, why) = validate_decryption(&macho);
        assert!(ok);
        assert_eq!(why.as_deref(), Some("Mach-O"));
    }

    #[test]
    fn validate_flags_random_as_invalid() {
        // Wrongly-decrypted output is ~uniform random: must NOT be called valid.
        let (ok, why) = validate_decryption(&pseudo_random(8192));
        assert!(!ok, "high-entropy data should be flagged invalid: {why:?}");
    }

    #[test]
    fn validate_flags_all_zero_invalid() {
        let (ok, _) = validate_decryption(&[0u8; 256]);
        assert!(!ok);
    }

    #[test]
    fn validate_flags_structured_valid() {
        // Low-entropy structured data (mostly one byte) is plausibly valid.
        let mut data = vec![0u8; 256];
        for (i, b) in data.iter_mut().enumerate() {
            *b = if i % 16 == 0 { 0xAA } else { 0x00 };
        }
        let (ok, _) = validate_decryption(&data);
        assert!(ok);
    }
}
