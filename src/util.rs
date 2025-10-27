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
        let pick = match cli.kbag_class {
            KbagClass::Prod => entries.iter().find(|e| e.kclass == 1).or(entries.get(0)),
            KbagClass::Dev  => entries.iter().find(|e| e.kclass == 2).or(entries.get(0)),
            KbagClass::Any  => entries.get(0),
        }.ok_or_else(|| anyhow!("KBAG present but empty"))?;
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

    // Check if there's any structure in first 16 bytes (non-uniform distribution)
    if data.len() >= 16 {
        let unique_bytes: std::collections::HashSet<u8> =
            data[..16].iter().copied().collect();
        if unique_bytes.len() >= 3 {
            // Has variety in first 16 bytes, likely structured data
            return (true, Some("structured binary".into()));
        }
    }

    // If we get here, it might be valid but we can't be sure
    (true, Some("unknown format".into()))
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
    // Prefer explicit metadata (A1)
    if let Some(m) = meta {
        match m.method_id {
            0 => { // LZSS
                #[cfg(feature = "lzss")]
                {
                    let out = crate::decompress_lzss::decompress_lzss(input)?;
                    if let Some(u) = m.uncompressed_len {
                        if out.len() as u64 != u {
                            return Ok(Some(("im4p.decompressed.lzss".into(), out))); // warn upstream
                        }
                    }
                    return Ok(Some(("im4p.decompressed.lzss".into(), out)));
                }
                #[cfg(not(feature = "lzss"))]
                bail!("lzss feature disabled but IM4P.compression indicates LZSS");
            }
            1 => { // LZFSE
                #[cfg(feature = "lzfse")]
                {
                    let hint = m.uncompressed_len.map(|v| v as usize);
                    let out = crate::decompress_lzfse::decompress_lzfse_with_hint(input, hint)?;
                    if let Some(u) = m.uncompressed_len {
                        if out.len() as u64 != u {
                            // length mismatch; upstream can log a warning
                        }
                    }
                    return Ok(Some(("im4p.decompressed.lzfse".into(), out)));
                }
                #[cfg(not(feature = "lzfse"))]
                bail!("lzfse feature disabled but IM4P.compression indicates LZFSE");
            }
            _ => { /* unknown id → fall through to heuristics */ }
        }
    }

    // Heuristics (existing)
    try_decompress(input)
}
