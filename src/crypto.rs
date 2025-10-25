use anyhow::{anyhow, bail, Result};
use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use cbc::cipher::{BlockDecryptMut, block_padding::NoPadding};

use crate::AesMode;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes192Ctr = ctr::Ctr128BE<Aes192>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes192CbcDec = cbc::Decryptor<Aes192>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn decrypt_aes(ciphertext: &[u8], iv: &[u8], key: &[u8], mode: AesMode) -> Result<Vec<u8>> {
    if iv.len() != 16 {
        bail!("IV must be 16 bytes");
    }
    match (mode, key.len()) {
        (AesMode::Ctr, 16) => {
            let mut buf = ciphertext.to_vec();
            let mut c = Aes128Ctr::new(key.into(), iv.into());
            c.apply_keystream(&mut buf);
            Ok(buf)
        }
        (AesMode::Ctr, 24) => {
            let mut buf = ciphertext.to_vec();
            let mut c = Aes192Ctr::new(key.into(), iv.into());
            c.apply_keystream(&mut buf);
            Ok(buf)
        }
        (AesMode::Ctr, 32) => {
            let mut buf = ciphertext.to_vec();
            let mut c = Aes256Ctr::new(key.into(), iv.into());
            c.apply_keystream(&mut buf);
            Ok(buf)
        }
        (AesMode::Cbc, 16) => cbc_nopad(ciphertext, iv, key, 16),
        (AesMode::Cbc, 24) => cbc_nopad(ciphertext, iv, key, 24),
        (AesMode::Cbc, 32) => cbc_nopad(ciphertext, iv, key, 32),
        (_, n) => bail!("unsupported AES key length: {n}"),
    }
}

fn cbc_nopad(ciphertext: &[u8], iv: &[u8], key: &[u8], klen: usize) -> Result<Vec<u8>> {
    if ciphertext.len() % 16 != 0 {
        bail!("CBC requires ciphertext length multiple of 16 (no padding)");
    }
    let mut buf = ciphertext.to_vec();
    let out = match klen {
        16 => Aes128CbcDec::new_from_slices(key, iv)
                  .map_err(|_| anyhow!("cbc init"))?
                  .decrypt_padded_mut::<NoPadding>(&mut buf),
        24 => Aes192CbcDec::new_from_slices(key, iv)
                  .map_err(|_| anyhow!("cbc init"))?
                  .decrypt_padded_mut::<NoPadding>(&mut buf),
        32 => Aes256CbcDec::new_from_slices(key, iv)
                  .map_err(|_| anyhow!("cbc init"))?
                  .decrypt_padded_mut::<NoPadding>(&mut buf),
        _ => unreachable!(),
    }.map_err(|_| anyhow!("cbc decrypt"))?;
    Ok(out.to_vec())
}
