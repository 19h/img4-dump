#[cfg(feature = "lzfse")]
pub fn looks_like_lzfse(buf: &[u8]) -> bool {
    // Heuristic: "bvx" magic is common in Apple LZFSE frames; tolerate short buffers.
    buf.len() >= 4 && &buf[0..3] == b"bvx"
}

#[cfg(feature = "lzfse")]
pub fn decompress_lzfse(buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    // The 'lzfse' crate requires pre-allocated output buffer
    // Allocate a buffer large enough for decompressed data (typically 2-10x compressed size)
    let mut output = vec![0u8; buf.len() * 10];
    let decoded_size = lzfse::decode_buffer(buf, &mut output)
        .map_err(|e| anyhow::anyhow!("lzfse: {e:?}"))?;
    output.truncate(decoded_size);
    Ok(output)
}
