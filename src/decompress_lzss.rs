#[cfg(feature = "lzss")]
pub fn looks_like_lzss(_buf: &[u8]) -> bool {
    // No reliable magic; caller must rely on metadata. Always attempt on request.
    false
}

#[cfg(feature = "lzss")]
pub fn decompress_lzss(buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    // The 'lzss' crate uses SliceReader/VecWriter pattern
    let reader = lzss::SliceReader::new(buf);
    let writer = lzss::VecWriter::with_capacity(buf.len() * 2);
    let output = lzss::Lzss::<10, 4, 0x20, { 1 << 10 }, { 2 << 10 }>::decompress_stack(reader, writer)
        .map_err(|e| anyhow::anyhow!("lzss: {e}"))?;
    Ok(output)
}
