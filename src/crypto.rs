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
    // An absent/zero-length payload must fail loudly rather than "succeed" with an
    // empty plaintext that downstream steps would silently treat as valid.
    if ciphertext.is_empty() {
        bail!("empty ciphertext");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// NIST SP 800-38A, F.5.1 CTR-AES128.Encrypt (first block). Ctr128BE must
    /// treat the IV as the initial 128-bit counter block, matching the standard.
    #[test]
    fn ctr_aes128_nist_vector() {
        let key = hx("2b7e151628aed2a6abf7158809cf4f3c");
        let ctr0 = hx("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let ct = hx("874d6191b620e3261bef6864990db6ce");
        let pt = hx("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(decrypt_aes(&ct, &ctr0, &key, AesMode::Ctr).unwrap(), pt);
    }

    /// NIST SP 800-38A, F.2.2 CBC-AES128.Decrypt (first block).
    #[test]
    fn cbc_aes128_nist_vector() {
        let key = hx("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hx("000102030405060708090a0b0c0d0e0f");
        let ct = hx("7649abac8119b246cee98e9b12e9197d");
        let pt = hx("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(decrypt_aes(&ct, &iv, &key, AesMode::Cbc).unwrap(), pt);
    }

    /// CTR is symmetric: applying the keystream twice is the identity, for any length.
    #[test]
    fn ctr_round_trip_any_length() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let pt = b"img4-dump CTR keystream is its own inverse - 47 bytes!!";
        let once = decrypt_aes(pt, &iv, &key, AesMode::Ctr).unwrap();
        let twice = decrypt_aes(&once, &iv, &key, AesMode::Ctr).unwrap();
        assert_eq!(twice, pt);
        assert_ne!(once, pt); // actually transformed
    }

    #[test]
    fn rejects_bad_iv_length() {
        assert!(decrypt_aes(&[0u8; 16], &[0u8; 12], &[0u8; 16], AesMode::Ctr).is_err());
    }

    #[test]
    fn rejects_bad_key_length() {
        assert!(decrypt_aes(&[0u8; 16], &[0u8; 16], &[0u8; 20], AesMode::Ctr).is_err());
    }

    #[test]
    fn rejects_empty_ciphertext() {
        assert!(decrypt_aes(&[], &[0u8; 16], &[0u8; 16], AesMode::Ctr).is_err());
        assert!(decrypt_aes(&[], &[0u8; 16], &[0u8; 16], AesMode::Cbc).is_err());
    }

    #[test]
    fn cbc_rejects_unaligned_length() {
        assert!(decrypt_aes(&[0u8; 17], &[0u8; 16], &[0u8; 16], AesMode::Cbc).is_err());
    }
}
