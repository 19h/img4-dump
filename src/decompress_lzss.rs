//! Native LZSS decompression for Apple IM4P payloads.
//!
//! Apple compresses some payloads (classically the kernelcache) with the
//! "complzss" container: an 8-byte `complzss` signature, an Adler-32 checksum of
//! the *uncompressed* data, the uncompressed and compressed sizes, and metadata,
//! all padded to 0x180 bytes, followed by a classic Okumura LZSS bitstream.
//!
//! The bitstream itself is the textbook Okumura LZSS used by XNU's
//! `decompress_lzss`: a 4096-byte ring buffer pre-filled with spaces (0x20),
//! 12-bit back-reference offsets and 4-bit lengths (match length =
//! `(len_nibble + THRESHOLD) + 1`, so 3..=18 bytes). Implementing it directly
//! guarantees byte-exact compatibility with Apple's decompressor, and the
//! Adler-32 in the container header gives a built-in correctness oracle.

#![cfg(feature = "lzss")]

use anyhow::{anyhow, bail, Result};

const RING: usize = 4096; // N: ring-buffer size (12-bit offsets)
const F: usize = 18; // upper bound on match length
const THRESHOLD: usize = 2; // matches shorter than this are stored literally
const HEADER_LEN: usize = 0x180; // complzss header size; bitstream starts here

/// Detect the Apple "complzss" container magic.
#[cfg(feature = "lzss")]
pub fn looks_like_lzss(buf: &[u8]) -> bool {
    buf.len() >= 8 && &buf[0..8] == b"complzss"
}

/// Decompress an IM4P LZSS payload. If the data is a "complzss" container, the
/// header is parsed and the result is validated against the declared
/// uncompressed size and Adler-32 checksum; otherwise the input is treated as a
/// bare Okumura LZSS bitstream.
#[cfg(feature = "lzss")]
pub fn decompress_lzss(buf: &[u8]) -> Result<Vec<u8>> {
    if looks_like_lzss(buf) {
        if buf.len() < HEADER_LEN {
            bail!("complzss header truncated ({} < {} bytes)", buf.len(), HEADER_LEN);
        }
        let adler = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let uncompressed_size = u32::from_be_bytes(buf[12..16].try_into().unwrap()) as usize;
        let compressed_size = u32::from_be_bytes(buf[16..20].try_into().unwrap()) as usize;

        let end = HEADER_LEN
            .checked_add(compressed_size)
            .ok_or_else(|| anyhow!("complzss compressed_size overflow"))?;
        let stream = buf
            .get(HEADER_LEN..end)
            .ok_or_else(|| anyhow!("complzss compressed_size {compressed_size} exceeds payload"))?;

        let out = lzss_decode(stream, Some(uncompressed_size));
        if out.len() != uncompressed_size {
            bail!(
                "complzss: decompressed {} bytes != header uncompressed_size {}",
                out.len(),
                uncompressed_size
            );
        }
        let got = adler32(&out);
        if got != adler {
            bail!("complzss: Adler-32 mismatch (computed {got:#010x}, header {adler:#010x})");
        }
        Ok(out)
    } else {
        // Bare LZSS bitstream: no header to validate against; decode to exhaustion.
        Ok(lzss_decode(buf, None))
    }
}

/// Classic Okumura LZSS decoder (XNU `decompress_lzss`-compatible).
fn lzss_decode(src: &[u8], expected_len: Option<usize>) -> Vec<u8> {
    let mut text = [0x20u8; RING + F - 1];
    let mut out = Vec::with_capacity(expected_len.unwrap_or(src.len().saturating_mul(4)));
    let mut r = RING - F; // ring write cursor (XNU starts at N - F)
    let mut it = src.iter().copied();
    let mut flags: u32 = 0;

    loop {
        flags >>= 1;
        if flags & 0x100 == 0 {
            // The high byte (0xFF00) counts down eight symbols before we reload.
            match it.next() {
                Some(c) => flags = c as u32 | 0xFF00,
                None => break,
            }
        }
        if flags & 1 != 0 {
            // Literal byte.
            let Some(c) = it.next() else { break };
            out.push(c);
            text[r] = c;
            r = (r + 1) & (RING - 1);
        } else {
            // Back-reference: 12-bit offset, 4-bit length.
            let Some(b0) = it.next() else { break };
            let Some(b1) = it.next() else { break };
            let mut i = b0 as usize | (((b1 as usize) & 0xF0) << 4);
            let len = ((b1 as usize) & 0x0F) + THRESHOLD;
            for _ in 0..=len {
                let c = text[i & (RING - 1)];
                out.push(c);
                text[r] = c;
                r = (r + 1) & (RING - 1);
                i += 1;
            }
        }
        if let Some(exp) = expected_len {
            if out.len() >= exp {
                break;
            }
        }
    }
    out
}

/// Adler-32 (RFC 1950), with the standard NMAX blocking so multi-megabyte
/// payloads do not pay a modulo per byte.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    const NMAX: usize = 5552; // largest n keeping b from overflowing u32
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(NMAX) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference Okumura LZSS *encoder* (greedy), matching `lzss_decode`'s format.
    /// Used only to round-trip-validate the decoder.
    fn lzss_encode(src: &[u8]) -> Vec<u8> {
        let mut text = [0x20u8; RING + F - 1];
        let mut out = Vec::new();
        let mut r = RING - F;
        // Pending symbols for one flag byte.
        let mut flag_pos = usize::MAX;
        let mut flag_bit = 0u8;
        let mut flags = 0u8;

        let mut emit = |out: &mut Vec<u8>, is_literal: bool, payload: &[u8], flags: &mut u8, flag_bit: &mut u8, flag_pos: &mut usize| {
            if *flag_bit == 0 {
                *flag_pos = out.len();
                out.push(0); // placeholder flag byte
                *flags = 0;
            }
            if is_literal {
                *flags |= 1 << *flag_bit;
            }
            out.extend_from_slice(payload);
            out[*flag_pos] = *flags;
            *flag_bit = (*flag_bit + 1) % 8;
        };

        let mut pos = 0usize;
        // Seed the ring with what the decoder will have: spaces, cursor at RING-F.
        while pos < src.len() {
            // Find the longest match in the ring for src[pos..].
            let max_len = F.min(src.len() - pos);
            let mut best_len = 0usize;
            let mut best_off = 0usize;
            if max_len >= THRESHOLD + 1 {
                for off in 0..RING {
                    let mut l = 0usize;
                    while l < max_len && text[(off + l) & (RING - 1)] == src[pos + l] {
                        l += 1;
                    }
                    if l > best_len {
                        best_len = l;
                        best_off = off;
                        if l == max_len {
                            break;
                        }
                    }
                }
            }
            if best_len >= THRESHOLD + 1 {
                let nibble = best_len - THRESHOLD - 1;
                let b0 = (best_off & 0xFF) as u8;
                let b1 = (((best_off >> 4) & 0xF0) as u8) | (nibble as u8);
                emit(&mut out, false, &[b0, b1], &mut flags, &mut flag_bit, &mut flag_pos);
                for k in 0..best_len {
                    text[r] = src[pos + k];
                    r = (r + 1) & (RING - 1);
                }
                pos += best_len;
            } else {
                let c = src[pos];
                emit(&mut out, true, &[c], &mut flags, &mut flag_bit, &mut flag_pos);
                text[r] = c;
                r = (r + 1) & (RING - 1);
                pos += 1;
            }
        }
        out
    }

    fn round_trip(data: &[u8]) {
        let comp = lzss_encode(data);
        let got = lzss_decode(&comp, Some(data.len()));
        assert_eq!(got, data, "round-trip mismatch ({} bytes)", data.len());
    }

    #[test]
    fn rt_empty() {
        round_trip(b"");
    }

    #[test]
    fn rt_literals() {
        round_trip(b"abcdefghijklmnopqrstuvwxyz0123456789");
    }

    #[test]
    fn rt_repetitive() {
        // Exercises back-references / RLE-style runs.
        let data = b"AAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBCCCCCCCCCCCCCCCC".repeat(40);
        round_trip(&data);
    }

    #[test]
    fn rt_structured() {
        let mut data = Vec::new();
        for i in 0..5000u32 {
            data.extend_from_slice(&i.to_le_bytes());
            if i % 7 == 0 {
                data.extend_from_slice(b"the quick brown fox ");
            }
        }
        round_trip(&data);
    }

    #[test]
    fn complzss_container_round_trip_and_validation() {
        let payload = b"complzss payloads validate via Adler-32 and length".repeat(30);
        let comp = lzss_encode(&payload);
        let mut blob = Vec::new();
        blob.extend_from_slice(b"complzss");
        blob.extend_from_slice(&adler32(&payload).to_be_bytes());
        blob.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        blob.resize(HEADER_LEN, 0);
        blob.extend_from_slice(&comp);

        assert!(looks_like_lzss(&blob));
        let out = decompress_lzss(&blob).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn complzss_bad_adler_is_rejected() {
        let payload = b"detect corruption".repeat(10);
        let comp = lzss_encode(&payload);
        let mut blob = Vec::new();
        blob.extend_from_slice(b"complzss");
        blob.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // wrong adler
        blob.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        blob.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        blob.resize(HEADER_LEN, 0);
        blob.extend_from_slice(&comp);
        assert!(decompress_lzss(&blob).is_err());
    }

    #[test]
    fn complzss_compressed_size_overrun_is_rejected() {
        let mut blob = Vec::new();
        blob.extend_from_slice(b"complzss");
        blob.extend_from_slice(&0u32.to_be_bytes());
        blob.extend_from_slice(&10u32.to_be_bytes());
        blob.extend_from_slice(&0xFFFFu32.to_be_bytes()); // claims 65535 compressed bytes
        blob.resize(HEADER_LEN, 0);
        blob.extend_from_slice(&[0u8; 4]); // but only 4 present
        assert!(decompress_lzss(&blob).is_err());
    }

    #[test]
    fn adler32_known_vector() {
        // Adler-32("Wikipedia") = 0x11E60398
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }
}
