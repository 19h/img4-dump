use std::fs;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use serde::Serialize;

mod parse;
mod crypto;
mod util;
mod fourcc;
mod formatter;

#[cfg(feature = "lzfse")]
mod decompress_lzfse;
#[cfg(feature = "lzss")]
mod decompress_lzss;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum KbagClass {
    Prod,   // kclass=1
    Dev,    // kclass=2
    Any,    // first entry
}

/// IMG4 / IM4P / IM4M dumper & decryptor.
#[derive(Parser, Debug)]
#[command(name = "img4-dump", version)]
struct Cli {
    /// Input: .img4, .im4p, or .im4m
    #[arg(value_name = "INPUT", required = true)]
    input: PathBuf,

    /// Output directory; created if missing
    #[arg(short = 'o', long = "outdir", default_value = "img4_dump")]
    outdir: PathBuf,

    /// Overwrite into existing non-empty outdir
    #[arg(short = 'f', long = "force", action = ArgAction::SetTrue)]
    force: bool,

    /// Verbose metadata on stderr
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    verbose: bool,

    /// Write JSON metadata summary to stdout
    #[arg(long = "json", action = ArgAction::SetTrue)]
    json: bool,

    /// Attempt to decrypt payload (requires --iv and --key, or plaintext KBAG)
    #[arg(long = "decrypt", action = ArgAction::SetTrue)]
    decrypt: bool,

    /// AES mode to use when decrypting (not encoded in KBAG/IM4P)
    #[arg(long = "aes-mode", value_enum, default_value_t = AesMode::Ctr)]
    aes_mode: AesMode,

    /// Hex IV (32 hex chars), overrides KBAG IV (if present)
    #[arg(long = "iv")]
    iv_hex: Option<String>,

    /// Hex Key (32/48/64 hex chars), overrides KBAG Key (if present)
    #[arg(long = "key")]
    key_hex: Option<String>,

    /// If present, write undecoded (still-encrypted) payload too
    #[arg(long = "keep-ciphertext", action = ArgAction::SetTrue)]
    keep_ciphertext: bool,

    /// Try to decompress known formats (lzfse/lzss) after (optional) decryption
    #[arg(long = "decompress", action = ArgAction::SetTrue)]
    decompress: bool,

    /// Dump IM4M (manifest) to outdir
    #[arg(long = "dump-im4m", action = ArgAction::SetTrue)]
    dump_im4m: bool,

    /// Dump IM4R (restore info) to outdir
    #[arg(long = "dump-im4r", action = ArgAction::SetTrue)]
    dump_im4r: bool,

    /// Extract IM4M properties into JSON (img4_dump/im4m.props.json)
    #[arg(long = "dump-im4m-props", action = ArgAction::SetTrue)]
    dump_im4m_props: bool,

    /// Dump IM4M certificate chain (DER + PEM files)
    #[arg(long = "dump-im4m-certs", action = ArgAction::SetTrue)]
    dump_im4m_certs: bool,

    /// KBAG selection preference (prod=class 1, dev=class 2, any=first)
    #[arg(long = "kbag-class", value_enum, default_value_t = KbagClass::Prod)]
    kbag_class: KbagClass,

    /// Optional KBAG entry index override (0-based)
    #[arg(long = "kbag-index")]
    kbag_index: Option<usize>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum AesMode {
    Ctr,
    Cbc,
}

#[derive(Debug, Serialize)]
struct Summary {
    container: parse::ContainerKind,
    im4p: Option<parse::Im4pInfo>,
    im4m: Option<parse::Im4mInfoSummary>,
    im4r_len: Option<usize>,
    notes: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logger based on verbose flag
    if std::env::var("RUST_LOG").is_err() {
        let level = if cli.verbose { "debug" } else { "info" };
        std::env::set_var("RUST_LOG", level);
    }
    env_logger::init();

    log::debug!("Parsed CLI options: {:?}", cli);

    // Read entire input
    log::debug!("Opening input file: {:?}", cli.input);
    let mut f = fs::File::open(&cli.input).with_context(|| format!("open {:?}", cli.input))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    log::debug!("Read {} bytes from input file", bytes.len());

    // Parse container
    log::debug!("Starting container parsing");
    let parsed = parse::parse_img4_like(&bytes)?;
    log::debug!(
        "Parsed container kind: {:?}, im4p: {}, im4m: {}, im4r: {}",
        parsed.kind,
        parsed.im4p.is_some(),
        parsed.im4m.is_some(),
        parsed.im4r.is_some()
    );

    // Prepare output dir
    log::debug!("Ensuring output directory at {:?}", cli.outdir);
    util::ensure_outdir(&cli.outdir, cli.force)?;
    log::debug!("Output directory ready");

    let mut notes = Vec::new();
    let mut output_paths = formatter::OutputPaths::default();

    // Dump IM4P
    let mut im4p_info = None;
    if let Some(im4p) = &parsed.im4p {
        log::debug!("Processing IM4P payload ({} bytes)", im4p.data.len());

        let base = cli.outdir.join("im4p.bin");
        fs::write(&base, &im4p.data).context("write im4p.bin")?;
        output_paths.add("Payload", base.display().to_string());
        if cli.verbose {
            eprintln!("wrote {:?}", base);
        }

        // If present, persist KBAG DER blob
        if let Some(kbag_raw) = &im4p.kbag_der {
            log::debug!("KBAG detected, writing DER blob ({} bytes)", kbag_raw.len());
            let p = cli.outdir.join("im4p.kbag.der");
            fs::write(&p, kbag_raw)?;
            output_paths.add("KBAG", p.display().to_string());
            if cli.verbose {
                eprintln!("wrote {:?}", p);
            }
        }

        // Optionally keep ciphertext copy (if decryption requested)
        if cli.decrypt && cli.keep_ciphertext {
            log::debug!("Keeping ciphertext copy of IM4P");
            let p = cli.outdir.join("im4p.ciphertext");
            fs::write(&p, &im4p.data)?;
        }

        // Decrypt if requested and IV+Key available (from CLI or KBAG)
        let mut clear = None;
        if cli.decrypt {
            log::debug!("Decryption requested, resolving IV and key");
            let (iv, key) = util::resolve_iv_key(&cli, im4p)?;
            log::debug!("IV resolved ({} bytes), Key resolved ({} bytes)", iv.len(), key.len());

            let mode = cli.aes_mode;
            log::debug!("Using AES mode: {:?}", mode);
            let dec = crypto::decrypt_aes(&im4p.data, &iv, &key, mode)
                .with_context(|| "AES decryption failed (check mode/IV/Key)")?;
            log::debug!("Decryption succeeded, plaintext size {} bytes", dec.len());

            // Validate decryption
            let (valid, detected) = util::validate_decryption(&dec);
            if valid {
                if let Some(fmt) = detected {
                    log::debug!("Decryption validation: OK (detected: {})", fmt);
                    if cli.verbose {
                        eprintln!("Decryption appears valid: {}", fmt);
                    }
                }
            } else {
                let reason = detected.unwrap_or_else(|| "unknown".into());
                log::warn!("Decryption validation FAILED: {}", reason);
                log::warn!("The output may be garbage (wrong key/IV/mode?)");
                if cli.verbose {
                    eprintln!("TIP: Try different --aes-mode (cbc/ctr) or verify key/IV");
                }
                notes.push(format!("decryption validation failed: {}", reason));
            }

            let out = cli.outdir.join("im4p.decrypted");
            fs::write(&out, &dec)?;
            output_paths.add("Decrypted", out.display().to_string());
            if cli.verbose {
                eprintln!("wrote {:?}", out);
            }
            clear = Some(dec);
        }

        // Optionally decompress decrypted (preferred) or raw
        if cli.decompress {
            log::debug!("Decompression requested");
            let src: &[u8] = if let Some(ref d) = clear { d } else { &im4p.data };
            log::debug!("Decompression source size {} bytes", src.len());

            match util::try_decompress_with_metadata(src, im4p.compression.as_ref()) {
                Ok(Some((name, dec))) => {
                    log::debug!("Decompression succeeded, generated {} ({} bytes)", name, dec.len());
                    let p = cli.outdir.join(name);
                    fs::write(&p, &dec)?;
                    output_paths.add("Decompressed", p.display().to_string());
                    if cli.verbose {
                        eprintln!("wrote {:?}", p);
                    }
                }
                Ok(None) => {
                    log::debug!("No known compression detected");
                    notes.push("no known compression detected".into())
                }
                Err(e) => {
                    log::debug!("Decompression error: {}", e);
                    notes.push(format!("decompress error: {e}"))
                }
            }
        }

im4p_info = Some(parse::Im4pInfo {
            r#type: im4p.r#type.clone(),
            version: im4p.version.clone(),
            data_len: im4p.data.len(),
            kbag: im4p.kbag_summary.clone(),
        });
        log::debug!("IM4P info recorded");
    }

    // Dump IM4M
    let mut im4m_summary = None;
    if let Some(im4m) = &parsed.im4m {
        log::debug!("IM4M present, size {} bytes", im4m.raw.len());

        if cli.dump_im4m {
            let p = cli.outdir.join("im4m.der");
            fs::write(&p, &im4m.raw)?;
            output_paths.add("Manifest", p.display().to_string());
            if cli.verbose {
                eprintln!("wrote {:?}", p);
            }
        }

        // Dump IM4M certificate chain (DER + PEM)
        if cli.dump_im4m_certs {
            let certs = parse::extract_im4m_cert_chain(&im4m.raw)?;
            for (i, der) in certs.iter().enumerate() {
                let der_path = cli.outdir.join(format!("im4m.cert.{i}.der"));
                fs::write(&der_path, der)?;
                output_paths.add(format!("Certificate {} (DER)", i), der_path.display().to_string());
                
                let pem_path = cli.outdir.join(format!("im4m.cert.{i}.pem"));
                write_pem_certificate(&pem_path, der)?;
                output_paths.add(format!("Certificate {} (PEM)", i), pem_path.display().to_string());
                
                if cli.verbose {
                    eprintln!("wrote {:?} and {:?}", der_path, pem_path);
                }
            }
        }

// Dump IM4M properties (typed) if requested
if cli.dump_im4m_props {
    let props = parse::extract_im4m_properties_typed(&im4m.raw)?;
    let p = cli.outdir.join("im4m.props.json");
    fs::write(&p, serde_json::to_vec_pretty(&props)?)?;
    output_paths.add("Manifest Properties", p.display().to_string());
    if cli.verbose {
        eprintln!("wrote {:?}", p);
    }
}

        im4m_summary = Some(parse::summarize_im4m(im4m)?);
        log::debug!("IM4M summary generated");
    }


// Dump IM4R
let mut im4r_len = None;
if let Some(im4r) = &parsed.im4r {
    log::debug!("IM4R present, length {} bytes", im4r.len());

    // Extract all IM4R properties using structured parser
    match parse::extract_im4r_properties(im4r) {
        Ok(props) => {
            // Extract BNCN nonce if present
            if let Some(bncn_prop) = props.iter().find(|p| p.key == "BNCN") {
                if let parse::Im4mPropertyValue::OctetString { value: hex_nonce } = &bncn_prop.value {
                    if let Ok(nonce) = hex::decode(hex_nonce) {
                        let p = cli.outdir.join("im4r.bncn.bin");
                        fs::write(&p, &nonce)?;
                        if cli.verbose {
                            eprintln!("extracted BNCN nonce ({} bytes) -> {:?}", nonce.len(), p);
                        }
                    }
                }
            } else {
                log::debug!("IM4R contains no BNCN property");
            }
            // Dump all IM4R properties to JSON
            let p = cli.outdir.join("im4r.props.json");
            fs::write(&p, serde_json::to_vec_pretty(&props)?)?;
            output_paths.add("IM4R Properties", p.display().to_string());
            if cli.verbose {
                eprintln!("wrote IM4R properties to {:?}", p);
            }
        }
        Err(e) => {
            log::warn!("IM4R property parse error: {}", e);
        }
    }

    if cli.dump_im4r {
        let p = cli.outdir.join("im4r.der");
        fs::write(&p, im4r)?;
        output_paths.add("IM4R", p.display().to_string());
        if cli.verbose {
            eprintln!("wrote {:?}", p);
        }
    }

    im4r_len = Some(im4r.len());
}

    let summary = Summary {
        container: parsed.kind,
        im4p: im4p_info,
        im4m: im4m_summary,
        im4r_len,
        notes,
    };

    log::debug!("Final summary prepared: {:#?}", summary);

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        // Format and print clean output
        let formatted = formatter::format_summary(
            summary.container,
            summary.im4p.as_ref(),
            summary.im4m.as_ref(),
            summary.im4r_len,
            &output_paths,
        );
        print!("{}", formatted);
    }

    Ok(())
}

fn write_pem_certificate(path: &std::path::Path, der: &[u8]) -> Result<()> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let b64 = STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() * 4 / 3 + 128);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    fs::write(path, out)?;
    Ok(())
}
