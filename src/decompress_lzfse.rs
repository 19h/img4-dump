#[cfg(feature = "lzfse")]
pub fn looks_like_lzfse(buf: &[u8]) -> bool {
    // Heuristic: "bvx" magic is common in Apple LZFSE frames; tolerate short buffers.
    buf.len() >= 4 && &buf[0..3] == b"bvx"
}

#[cfg(feature = "lzfse")]
pub fn decompress_lzfse(buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    // The 'lzfse' crate exposes a simple API; if your version differs,
    // adapt accordingly.
    let out = lzfse::decode_buffer(buf)
        .map_err(|e| anyhow::anyhow!("lzfse: {e:?}"))?;
    Ok(out)
}
