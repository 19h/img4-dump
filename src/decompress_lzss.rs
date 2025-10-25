#[cfg(feature = "lzss")]
pub fn looks_like_lzss(_buf: &[u8]) -> bool {
    // No reliable magic; caller must rely on metadata. Always attempt on request.
    false
}

#[cfg(feature = "lzss")]
pub fn decompress_lzss(buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    // The 'lzss' crate API may require window params; adapt to your version if needed.
    let out = lzss::decompress(buf).map_err(|e| anyhow::anyhow!("lzss: {e}"))?;
    Ok(out)
}
