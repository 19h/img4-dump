#![cfg(feature = "lzfse")]

/// LZFSE frame magics: `bvx2`/`bvxn` (compressed blocks) and `bvx-` (uncompressed
/// block). The end-of-stream marker `bvx$` is intentionally not treated as a
/// stream start.
#[cfg(feature = "lzfse")]
pub fn looks_like_lzfse(buf: &[u8]) -> bool {
    buf.len() >= 4 && matches!(&buf[0..4], b"bvx2" | b"bvxn" | b"bvx-")
}

/// Decompress an LZFSE buffer. The output size is unknown up front, so we size
/// the destination from the metadata hint when available and otherwise grow it
/// (doubling) until the decode fits, up to a hard safety ceiling. A too-small
/// hint can therefore never cause a spurious failure.
#[cfg(feature = "lzfse")]
pub fn decompress_lzfse_with_hint(buf: &[u8], hint_uncomp_len: Option<usize>) -> anyhow::Result<Vec<u8>> {
    use lzfse::{decode_buffer, Error};

    // Safety ceiling so a malformed/adversarial frame cannot drive unbounded
    // allocation. 2 GiB comfortably exceeds any real IM4P payload.
    const CEILING: usize = 1usize << 31;

    let mut cap = hint_uncomp_len
        .unwrap_or(0)
        .max(buf.len().saturating_mul(4))
        .max(64 * 1024)
        .min(CEILING);

    loop {
        let mut output = vec![0u8; cap];
        match decode_buffer(buf, &mut output) {
            Ok(decoded_size) => {
                output.truncate(decoded_size);
                return Ok(output);
            }
            Err(Error::BufferTooSmall) => {
                if cap >= CEILING {
                    anyhow::bail!("lzfse: decompressed output exceeds {CEILING} bytes");
                }
                cap = cap.saturating_mul(2).min(CEILING);
            }
            Err(e) => anyhow::bail!("lzfse: {e:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_detection() {
        assert!(looks_like_lzfse(b"bvx2\x00\x00"));
        assert!(looks_like_lzfse(b"bvxn...."));
        assert!(looks_like_lzfse(b"bvx-...."));
        assert!(!looks_like_lzfse(b"bvx$")); // end marker is not a start
        assert!(!looks_like_lzfse(b"bvx")); // too short
        assert!(!looks_like_lzfse(b"\xfe\xed\xfa\xcf"));
    }

    /// Round-trip through the real lzfse codec, including the case where the
    /// caller's size hint is far too small (the grow loop must recover).
    #[test]
    fn round_trip_with_undersized_hint() {
        let payload = b"LZFSE round-trip: grow the destination buffer as needed. ".repeat(200);
        let mut comp = vec![0u8; payload.len() + 4096];
        let n = lzfse::encode_buffer(&payload, &mut comp).expect("encode");
        comp.truncate(n);

        // Hint of 1 byte forces several growth iterations.
        let out = decompress_lzfse_with_hint(&comp, Some(1)).expect("decode");
        assert_eq!(out, payload);

        // No hint at all.
        let out2 = decompress_lzfse_with_hint(&comp, None).expect("decode");
        assert_eq!(out2, payload);
    }
}
