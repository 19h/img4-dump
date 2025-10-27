#[cfg(feature = "lzfse")]
pub fn looks_like_lzfse(buf: &[u8]) -> bool {
    // Heuristic: "bvx" magic is common in Apple LZFSE frames; tolerate short buffers.
    buf.len() >= 4 && &buf[0..3] == b"bvx"
}

#[cfg(feature = "lzfse")]
pub fn decompress_lzfse_with_hint(buf: &[u8], hint_uncomp_len: Option<usize>) -> anyhow::Result<Vec<u8>> {
    // Prefer caller hint (from IM4P metadata); else conservative heuristic
    let cap = hint_uncomp_len.unwrap_or_else(|| buf.len().saturating_mul(10).max(64 * 1024));
    let mut output = vec![0u8; cap];
    let decoded_size = lzfse::decode_buffer(buf, &mut output)
        .map_err(|e| anyhow::anyhow!("lzfse: {e:?}"))?;
    output.truncate(decoded_size);
    Ok(output)
}

// Backward compat for callers
#[cfg(feature = "lzfse")]
pub fn decompress_lzfse(buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    decompress_lzfse_with_hint(buf, None)
}
