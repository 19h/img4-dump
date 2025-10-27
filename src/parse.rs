use anyhow::{anyhow, bail, Result};
use der_parser::der::{parse_der, Class, DerObject};
use serde::Serialize;
use log::{debug, warn};
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Top-level kind detected
#[derive(Copy, Clone, Debug, Serialize)]
pub enum ContainerKind {
    Img4,
    Im4pStandalone,
    Im4mStandalone,
}

/// Fully-owned parse result (no lifetime ties to local parser temps)
#[derive(Debug)]
pub struct Parsed {
    pub kind: ContainerKind,
    pub im4p: Option<Im4p>,
    pub im4m: Option<Im4m>,
    pub im4r: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KbagEntry {
    pub kclass: u64,   // 1=prod, 2=dev
    pub iv: Vec<u8>,   // 16 bytes
    pub key: Vec<u8>,  // 16/24/32 bytes
}

#[derive(Debug, Clone, Serialize)]
pub struct Im4pCompression {
    pub method_id: u64,                 // 0=LZSS, 1=LZFSE (A1)
    pub uncompressed_len: Option<u64>,  // may be absent in some images
}

#[derive(Debug)]
pub struct Im4p {
    pub r#type: String,
    pub version: String,
    pub data: Vec<u8>,
    pub kbag_der: Option<Vec<u8>>,
    pub kbag_summary: Option<Vec<KbagEntry>>,
    pub compression: Option<Im4pCompression>,   // NEW
}

#[derive(Debug)]
pub struct Im4m {
    /// Raw DER bytes of the IM4M sequence (owned).
    pub raw: Vec<u8>,
}

/// Legacy untyped property value (kept for backwards compatibility)
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value")]
pub enum Im4mValue {
    Integer(u128),                     // DER INTEGER (non-negative, as commonly used in IM4M)
    Boolean(bool),                     // DER BOOLEAN
    Ia5String(String),                 // DER IA5String
    OctetString(String),               // hex
    BitString(String),                 // hex (unused bits not modeled)
    Null,                              // DER NULL
    SequenceLen(usize),                // for unexpected SEQUENCE payloads
    SetLen(usize),                     // for unexpected SET payloads
    Unknown { class_id: u8, tag: u32, len: usize },
}

/// Legacy untyped property structure (kept for backwards compatibility)
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct Im4mProperty {
    pub key: String,   // 4-char IA5 tag (e.g., "DGST","CEPO")
    pub value: Im4mValue,
}

/// Enhanced property value with type information
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum Im4mPropertyValue {
    Integer { value: u64 },
    Boolean { value: bool },
    String { value: String },
    OctetString { value: String }, // Hex-encoded
    Digest { value: String },      // Hex-encoded, specifically for properties known to be digests
    Unknown { der_type: String, #[serde(skip_serializing_if = "Option::is_none")] hex_value: Option<String>, #[serde(skip_serializing_if = "Option::is_none")] hex_values: Option<Vec<String>> },
}

/// Typed property structure with metadata
#[derive(Debug, Clone, Serialize)]
pub struct TypedIm4mProperty {
    pub key: String,
    pub name: String,
    pub description: String,
    pub value: Im4mPropertyValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anomaly: Option<String>,
}

/// Image manifest structure (kept for future use)
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct Im4mImageManifest {
    pub fourcc: String,  // e.g. "krnl", "bstc"
    pub properties: Vec<Im4mProperty>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Im4pInfo {
    pub r#type: String,
    pub version: String,
    pub data_len: usize,
    pub kbag: Option<Vec<KbagEntry>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Im4mInfoSummary {
    pub version: Option<u64>,
    pub manifest_property_tags: Vec<String>,
    pub images_present: Vec<String>,
    pub cert_chain_len: Option<usize>,
    pub signature_len: Option<usize>,
}

/// Property metadata from XNU headers
struct PropertyMetadata {
    name: &'static str,
    description: &'static str,
    expected_type: ExpectedDerType,
}

#[derive(Debug)]
enum ExpectedDerType {
    Boolean,
    Integer,
    OctetString,
    Digest,
    Ia5String,
}

/// Known Image4 properties from XNU headers
static KNOWN_PROPERTIES: Lazy<HashMap<&'static str, PropertyMetadata>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("CEPO", PropertyMetadata { name: "ChipEpoch", description: "Chip Epoch", expected_type: ExpectedDerType::Integer });
    m.insert("BORD", PropertyMetadata { name: "BoardId", description: "Board Identifier", expected_type: ExpectedDerType::Integer });
    m.insert("CHIP", PropertyMetadata { name: "ChipId", description: "Chip Identifier", expected_type: ExpectedDerType::Integer });
    m.insert("SDOM", PropertyMetadata { name: "SecurityDomain", description: "Security Domain", expected_type: ExpectedDerType::Integer });
    m.insert("ECID", PropertyMetadata { name: "ExclusiveChipId", description: "Unique Chip Identifier", expected_type: ExpectedDerType::Integer });
    m.insert("CPRO", PropertyMetadata { name: "CertificateProductionStatus", description: "Certificate Production Status", expected_type: ExpectedDerType::Boolean });
    m.insert("CSEC", PropertyMetadata { name: "CertificateSecurityMode", description: "Certificate Security Mode", expected_type: ExpectedDerType::Boolean });
    m.insert("EPRO", PropertyMetadata { name: "EffectiveProductionStatus", description: "Effective Production Status", expected_type: ExpectedDerType::Boolean });
    m.insert("ESEC", PropertyMetadata { name: "EffectiveSecurityMode", description: "Effective Security Mode", expected_type: ExpectedDerType::Boolean });
    m.insert("IUOU", PropertyMetadata { name: "InternalUseOnlyUnit", description: "Internal Use Only Unit", expected_type: ExpectedDerType::Boolean });
    m.insert("AMNM", PropertyMetadata { name: "AllowMixNMatch", description: "Allow Mix-n-Match", expected_type: ExpectedDerType::Boolean });
    m.insert("UDID", PropertyMetadata { name: "UniqueDeviceIdentifier", description: "Unique Device Identifier (digest)", expected_type: ExpectedDerType::Digest });
    m.insert("DGST", PropertyMetadata { name: "Digest", description: "Payload Digest", expected_type: ExpectedDerType::Digest });
    m.insert("BNCN", PropertyMetadata { name: "BootNonce", description: "Boot Nonce", expected_type: ExpectedDerType::OctetString });
    m.insert("love", PropertyMetadata { name: "LongOsVersion", description: "Long OS Version", expected_type: ExpectedDerType::Ia5String });
    m.insert("augs", PropertyMetadata { name: "AugmentedManifest", description: "Augmented Manifest", expected_type: ExpectedDerType::Integer });
    m.insert("clas", PropertyMetadata { name: "Class", description: "Manifest Class", expected_type: ExpectedDerType::Integer });
    m.insert("fchp", PropertyMetadata { name: "FusingChip", description: "Fusing Chip", expected_type: ExpectedDerType::Integer });
    m.insert("pave", PropertyMetadata { name: "PlatformVersion", description: "Platform Version", expected_type: ExpectedDerType::Integer });
    m.insert("srvn", PropertyMetadata { name: "SecurityRevision", description: "Security Revision", expected_type: ExpectedDerType::Integer });
    m.insert("styp", PropertyMetadata { name: "SystemType", description: "System Type", expected_type: ExpectedDerType::Integer });
    m.insert("type", PropertyMetadata { name: "Type", description: "Image Type", expected_type: ExpectedDerType::Ia5String });
    m.insert("upcl", PropertyMetadata { name: "UpgradeClaim", description: "Upgrade Claim", expected_type: ExpectedDerType::Integer });
    m.insert("vnum", PropertyMetadata { name: "VersionNumber", description: "Version Number", expected_type: ExpectedDerType::Integer });
    m.insert("gdmg", PropertyMetadata { name: "GlobalDigest", description: "Global Digest", expected_type: ExpectedDerType::Digest });
    m.insert("ginc", PropertyMetadata { name: "GlobalIncrement", description: "Global Increment", expected_type: ExpectedDerType::Integer });
    m.insert("ginf", PropertyMetadata { name: "GlobalInfo", description: "Global Info", expected_type: ExpectedDerType::Integer });
    m.insert("gtcd", PropertyMetadata { name: "GlobalTrustedCode", description: "Global Trusted Code", expected_type: ExpectedDerType::Integer });
    m.insert("gtgv", PropertyMetadata { name: "GlobalTrustGlobalVersion", description: "Global Trust Global Version", expected_type: ExpectedDerType::Integer });
    m
});

fn parse_im4p_compression(obj: &DerObject) -> Result<Im4pCompression> {
    let seq = obj.as_sequence().map_err(|_| anyhow!("compression not SEQUENCE"))?;

    if seq.is_empty() { bail!("compression SEQUENCE empty"); }

    let id = seq[0].as_u64().map_err(|_| anyhow!("compression id not INTEGER"))?;

    let uncl =
        if seq.len() > 1 {
            Some(seq[1].as_u64().map_err(|_| anyhow!("compression len not INTEGER"))?)
        } else {
            None
        };

    Ok(Im4pCompression { method_id: id, uncompressed_len: uncl })
}

/// Extract properties from IM4R using formal structure: SEQUENCE { "IM4R", SET { properties } }
pub fn extract_im4r_properties(raw: &[u8]) -> Result<Vec<TypedIm4mProperty>> {
    let (_, obj) = parse_der(raw).map_err(|e| anyhow!("IM4R DER: {e}"))?;
    let seq = obj.as_sequence().map_err(|_| anyhow!("IM4R not SEQUENCE"))?;

    let label = seq.get(0).and_then(ia5str).ok_or_else(|| anyhow!("IM4R label missing"))?;
    if label != "IM4R" {
        bail!("IM4R label is not 'IM4R'");
    }

    let prop_set = seq
        .get(1)
        .ok_or_else(|| anyhow!("IM4R missing property SET"))?
        .as_set()
        .map_err(|_| anyhow!("IM4R properties not in a SET"))?;

    let mut out = Vec::new();
    for prop_obj in prop_set {
        collect_typed_props_from_obj(prop_obj, &mut out)?;
    }
    Ok(out)
}

/// Legacy function for backwards compatibility - extracts only BNCN nonce
#[allow(dead_code)]
#[deprecated(note = "Use extract_im4r_properties instead")]
pub fn extract_im4r_bncn_nonce(raw: &[u8]) -> Result<Option<Vec<u8>>> {
    let props = extract_im4r_properties(raw)?;
    for prop in props {
        if prop.key == "BNCN" {
            if let Im4mPropertyValue::OctetString { value: hex_val } = prop.value {
                return Ok(Some(hex::decode(hex_val).unwrap_or_default()));
            }
        }
    }
    Ok(None)
}

pub fn parse_img4_like(bytes: &[u8]) -> Result<Parsed> {
    debug!("parse_img4_like: starting, input length {}", bytes.len());
    let (_, obj) = parse_der(bytes).map_err(|e| anyhow!("DER: {}", e))?;
    let seq = obj.as_sequence().map_err(|_| anyhow!("top-level not SEQUENCE"))?;

    let label_str = seq
        .get(0)
        .and_then(ia5str)
        .ok_or_else(|| anyhow!("missing label"))?;
    debug!("top-level label: {}", label_str);

    if label_str == "IMG4" {
        // IMG4: ["IMG4", IM4P, [0] IM4M?, [1] IM4R?]
        debug!("Detected IMG4 container");
        let im4p = parse_im4p_from_der_obj(
            seq.get(1)
                .ok_or_else(|| anyhow!("IMG4 missing IM4P"))?,
        )?;
        debug!("Parsed IM4P successfully");

        let mut im4m = None;
        let mut im4r = None;

        for child in &seq[2..] {
            let hdr = child.header.clone();
            if hdr.class() == Class::ContextSpecific {
                let t = hdr.tag().0;
                if t == 0 {
                    debug!("Found context-specific [0] (IM4M)");
                    // [0] contains the complete DER of IM4M: keep raw bytes, validate label
                    if let Ok(inner_der) = child.as_slice() {
                        im4m = Some(im4m_from_bytes(inner_der)?);
                        debug!("Parsed IM4M from context-specific tag");
                    }
                } else if t == 1 {
                    debug!("Found context-specific [1] (IM4R)");
                    // [1] IM4R opaque
                    if let Ok(bytes) = child.as_slice() {
                        im4r = Some(bytes.to_vec());
                        debug!("Captured IM4R payload, {} bytes", bytes.len());
                    }
                }
            }
        }

        Ok(Parsed {
            kind: ContainerKind::Img4,
            im4p: Some(im4p),
            im4m,
            im4r,
        })
    } else if label_str == "IM4P" {
        debug!("Detected standalone IM4P");
        let im4p = parse_im4p_from_der_obj(&obj)?;
        Ok(Parsed {
            kind: ContainerKind::Im4pStandalone,
            im4p: Some(im4p),
            im4m: None,
            im4r: None,
        })
    } else if label_str == "IM4M" {
        debug!("Detected standalone IM4M");
        // Standalone IM4M: use the entire input as raw DER, validate label
        let im4m = im4m_from_bytes(bytes)?;
        Ok(Parsed {
            kind: ContainerKind::Im4mStandalone,
            im4p: None,
            im4m: Some(im4m),
            im4r: None,
        })
    } else {
        warn!("Unknown top-level label: {}", label_str);
        bail!("unknown top-level label: {label_str}");
    }
}

fn parse_im4p_from_der_obj(obj: &DerObject) -> Result<Im4p> {
    debug!("parse_im4p_from_der_obj: entering");
    let seq = obj.as_sequence().map_err(|_| anyhow!("IM4P not SEQUENCE"))?;

    // 0: "IM4P"
    let s0 = seq
        .get(0)
        .and_then(ia5str)
        .ok_or_else(|| anyhow!("IM4P label missing"))?;
    if s0 != "IM4P" {
        bail!("IM4P[0] != \"IM4P\"");
    }
    debug!("IM4P label confirmed");

    // 1: type (4 ASCII)
    let ty = seq
        .get(1)
        .and_then(ia5str)
        .ok_or_else(|| anyhow!("IM4P type missing"))?
        .to_string();
    debug!("IM4P type: {}", ty);

// 2: version
let version_str = seq
    .get(2)
    .and_then(ia5str)
    .ok_or_else(|| anyhow!("IM4P version missing"))?
    .to_string();
debug!("IM4P version: {}", version_str);

    // 3: payload data
    let data = seq
        .get(3)
        .and_then(as_bytes)
        .ok_or_else(|| anyhow!("IM4P data missing"))?
        .to_vec();
    debug!("IM4P payload size: {} bytes", data.len());

    // 4: optional KBAG (OCTET STRING containing DER)
    let kbag_der_vec = seq.get(4).and_then(as_bytes).map(|b| b.to_vec());
    if kbag_der_vec.is_some() {
        debug!("IM4P contains KBAG");
    } else {
        debug!("IM4P does not contain KBAG");
    }

    let kbag_summary = if let Some(ref kraw) = kbag_der_vec {
        match parse_kbag_summary(kraw) {
            Ok(summary) => {
                debug!("Parsed KBAG with {} entries", summary.len());
                Some(summary)
            }
            Err(e) => {
                warn!("Failed to parse KBAG: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 5: optional compression (SEQUENCE { INTEGER id, INTEGER uncompressed_len })
    let compression =
        if let Some(cobj) = seq.get(5) {
            match parse_im4p_compression(cobj) {
                Ok(c) => { debug!("IM4P compression: id={}, uncompressed_len={:?}", c.method_id, c.uncompressed_len); Some(c) }
                Err(e) => { warn!("IM4P compression parse failed: {}", e); None }
            }
        } else {
            None
        };

Ok(Im4p {
    r#type: ty,
    version: version_str,
    data,
    kbag_der: kbag_der_vec,
    kbag_summary,
    compression,          // NEW
})
}

fn parse_kbag_summary(kbag_der: &[u8]) -> Result<Vec<KbagEntry>> {
    debug!(
        "parse_kbag_summary: entering, KBAG DER size {} bytes",
        kbag_der.len()
    );
    let (_, obj) = parse_der(kbag_der).map_err(|e| anyhow!("KBAG DER: {e}"))?;
    let seq = obj.as_sequence().map_err(|_| anyhow!("KBAG not SEQUENCE"))?;

    let mut out = Vec::new();
    for (idx, entry) in seq.iter().enumerate() {
        let es = entry
            .as_sequence()
            .map_err(|_| anyhow!("KBAG entry not SEQUENCE"))?;
        if es.len() != 3 {
            bail!("KBAG entry malformed");
        }
        let kclass = es[0].as_u64().map_err(|_| anyhow!("KBAG class not INTEGER"))?;
        let iv = es[1].as_slice().map_err(|_| anyhow!("KBAG iv not OCTET STRING"))?.to_vec();
        let key = es[2].as_slice().map_err(|_| anyhow!("KBAG key not OCTET STRING"))?.to_vec();
        debug!(
            "KBAG entry {}: class={}, iv_len={}, key_len={}",
            idx,
            kclass,
            iv.len(),
            key.len()
        );
        out.push(KbagEntry { kclass, iv, key });
    }
    debug!("parse_kbag_summary: finished, total {} entries", out.len());
    Ok(out)
}

/// Build an Im4m by **owning the exact raw DER bytes** and validating the label.
fn im4m_from_bytes(bytes: &[u8]) -> Result<Im4m> {
    debug!(
        "im4m_from_bytes: entering, candidate DER size {} bytes",
        bytes.len()
    );
    let (_, obj) = parse_der(bytes).map_err(|e| anyhow!("IM4M DER: {e}"))?;
    let seq = obj.as_sequence().map_err(|_| anyhow!("IM4M not SEQUENCE"))?;
    let lbl = seq
        .get(0)
        .and_then(ia5str)
        .ok_or_else(|| anyhow!("IM4M label missing"))?;
    if lbl != "IM4M" {
        bail!("label != IM4M");
    }
    debug!("IM4M label confirmed");
    Ok(Im4m { raw: bytes.to_vec() })
}

pub fn summarize_im4m(im4m: &Im4m) -> Result<Im4mInfoSummary> {
    debug!(
        "summarize_im4m: start, raw DER size {} bytes",
        im4m.raw.len()
    );

    // Decode top-level to extract version, signature, cert chain lengths (as before)
    let (_, obj) = parse_der(&im4m.raw).map_err(|e| anyhow!("IM4M DER: {e}"))?;
    let seq = obj.as_sequence().map_err(|_| anyhow!("IM4M not SEQUENCE"))?;

    let lbl = seq
        .get(0)
        .and_then(ia5str)
        .ok_or_else(|| anyhow!("IM4M label missing"))?;

    if lbl != "IM4M" {
        bail!("label != IM4M");
    }

    debug!("IM4M label validated");

    // Per pongoOS, IM4M[1] is INTEGER zero; validate if present
    if let Some(z) = seq.get(1).and_then(|o| o.as_u64().ok()) {
        if z != 0 { warn!("IM4M[1] expected 0, got {}", z); }
    }

    let version = seq.get(1).and_then(|o| o.as_u64().ok());
    debug!("IM4M version: {:?}", version);

    let signature_len = seq
        .get(3)
        .and_then(|o| o.as_slice().ok())
        .map(|b| b.len());
    debug!("IM4M signature length: {:?}", signature_len);

    let cert_chain_len = seq
        .get(4)
        .and_then(|o| o.as_sequence().ok())
        .map(|s| s.len());
    debug!("IM4M cert chain length: {:?}", cert_chain_len);

    // collect all IA5 strings (4-char) anywhere inside IM4M (including under private/context-specific)
    let mut tokens = Vec::<String>::new();
    scan_der_collect_ia5_fourccs(&im4m.raw, &mut tokens)?;
    debug!("Collected {} IA5 tokens before dedup", tokens.len());
    dedup_stable(&mut tokens);
    debug!("Token count after dedup: {}", tokens.len());

    // Populate fields
    let manifest_property_tags = tokens
        .iter()
        .filter(|s| s.as_str() == "MANB" || s.as_str() == "MANP")
        .cloned()
        .collect::<Vec<_>>();
    debug!(
        "Manifest property tags identified: {:?}",
        manifest_property_tags
    );

    // Heuristic: image 4CCs are commonly lowercase (e.g., "krnl","sepi").
    // We exclude all well-known property keys and manifest block tags.
    let images_present = tokens
        .iter()
        .filter(|s| {
            s.len() == 4
                && !KNOWN_PROPERTIES.contains_key(s.as_str())
                && !matches!(s.as_str(), "IM4M" | "MANB" | "MANP")
                && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
        .cloned()
        .collect::<Vec<_>>();
    debug!("Images present identified: {:?}", images_present);

    Ok(Im4mInfoSummary {
        version,
        manifest_property_tags,
        images_present,
        cert_chain_len,
        signature_len,
    })
}

/// Extract certificate chain from IM4M.
/// Returns a Vec of DER-encoded X.509 certificates (owned).
pub fn extract_im4m_cert_chain(raw: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    // Manually parse to extract raw DER bytes including headers
    let mut out: Vec<Vec<u8>> = Vec::new();

    // Parse top-level IM4M SEQUENCE to find chain at index 4
    let mut pos = 0usize;
    let (tag_len, _, _, _) = der_read_tag(&raw[pos..]).map_err(|e| anyhow::anyhow!("IM4M tag: {e}"))?;
    pos += tag_len;
    let (len_len, _) = der_read_len(&raw[pos..]).map_err(|e| anyhow::anyhow!("IM4M len: {e}"))?;
    pos += len_len;

    // Skip to index 4 by parsing elements 0..4
for idx in 0..5 {
        let _elem_start = pos;
        let (tag_len, class, _constructed, tag_no) = der_read_tag(&raw[pos..])
            .map_err(|e| anyhow::anyhow!("elem[{idx}] tag: {e}"))?;
        pos += tag_len;
        let (len_len, elem_len) = der_read_len(&raw[pos..])
            .map_err(|e| anyhow::anyhow!("elem[{idx}] len: {e}"))?;
        pos += len_len;

        if idx == 4 {
            // This is the cert chain container (should be SEQUENCE)
            if class != 0 || tag_no != 16 {
                return Ok(Vec::new()); // Not a SEQUENCE, no certs
            }

            // Parse inner SEQUENCE of certificates
            let chain_end = pos + elem_len;
            while pos < chain_end {
let cert_start = pos;
                let (cert_tag_len, cert_class, _cert_constructed, cert_tag) = der_read_tag(&raw[pos..])
                    .map_err(|e| anyhow::anyhow!("cert tag: {e}"))?;
                pos += cert_tag_len;
                let (cert_len_len, cert_len) = der_read_len(&raw[pos..])
                    .map_err(|e| anyhow::anyhow!("cert len: {e}"))?;
                pos += cert_len_len;
                let cert_full_len = cert_tag_len + cert_len_len + cert_len;

                debug!("cert[{}]: @{:04x} class={}, tag={}, len={}", out.len(), cert_start, cert_class, cert_tag, cert_len);

                // Extract certificate based on encoding
                match (cert_class, cert_tag) {
                    (0, 4) => {
                        // OCTET STRING: content is the DER cert
                        out.push(raw[pos..pos + cert_len].to_vec());
                    }
                    (0, 16) => {
                        // SEQUENCE: full TLV is the DER cert
                        out.push(raw[cert_start..cert_start + cert_full_len].to_vec());
                    }
                    _ => {
                        // Unknown: try to handle gracefully
                        let content = &raw[pos..pos + cert_len];
                        if !content.is_empty() && content[0] == 0x30 {
                            out.push(content.to_vec());
                        } else {
                            out.push(encode_der_sequence(content));
                        }
                    }
                }

                pos += cert_len;
            }
            break;
        } else {
            // Skip this element
            pos += elem_len;
        }
    }

    Ok(out)
}

/// Build a valid DER SEQUENCE (0x30) around `content`.
fn encode_der_sequence(content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + der_len_encoded_bytes(content.len()) + content.len());
    v.push(0x30); // UNIVERSAL SEQUENCE (constructed)
    write_der_len(&mut v, content.len());
    v.extend_from_slice(content);
    v
}

fn der_len_encoded_bytes(len: usize) -> usize {
    if len < 128 { 1 } else {
        let mut n = 0usize;
        let mut tmp = len;
        while tmp > 0 { n += 1; tmp >>= 8; }
        1 + n
    }
}

fn write_der_len(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        // Long-form definite length per DER
        let mut bytes = [0u8; 8]; // enough for usize on 64-bit
        let mut n = 0usize;
        let mut tmp = len;
        while tmp > 0 {
            bytes[7 - n] = (tmp & 0xFF) as u8;
            tmp >>= 8;
            n += 1;
        }
        buf.push(0x80 | (n as u8));
        buf.extend_from_slice(&bytes[8 - n..]);
    }
}

/// Extracts all properties of the form SEQUENCE { IA5String(4CC), ANY } found anywhere in the IM4M.
/// Returns the legacy untyped property structure for backwards compatibility.
#[allow(dead_code)]
pub fn extract_im4m_properties(raw: &[u8]) -> Result<Vec<Im4mProperty>> {
    let (_, obj) = parse_der(raw).map_err(|e| anyhow!("IM4M DER: {e}"))?;
    let mut out = Vec::<Im4mProperty>::new();
    collect_props_from_obj(&obj, &mut out)?;
    Ok(out)
}

/// Extracts typed properties with metadata from IM4M.
pub fn extract_im4m_properties_typed(raw: &[u8]) -> Result<Vec<TypedIm4mProperty>> {
    let (_, obj) = parse_der(raw).map_err(|e| anyhow!("IM4M DER: {e}"))?;
    let mut out = Vec::<TypedIm4mProperty>::new();
    collect_typed_props_from_obj(&obj, &mut out)?;
    Ok(out)
}

#[allow(dead_code)]
fn collect_props_from_obj(o: &DerObject, out: &mut Vec<Im4mProperty>) -> Result<()> {
    // If this is a SEQUENCE, check for the { IA5String(4CC), ANY } pattern
    if let Ok(seq) = o.as_sequence() {
        if seq.len() >= 2 {
            if let Some(k) = ia5str(&seq[0]) {
                if k.len() == 4 && k.chars().all(|c| c.is_ascii_graphic()) {
                    let v = decode_any_value(&seq[1])?;
                    out.push(Im4mProperty { key: k.to_string(), value: v });
                }
            }
        }
        // Recurse into children regardless, since properties can nest
        for ch in seq {
            collect_props_from_obj(ch, out)?;
        }
        return Ok(());
    }

    // If this is a SET, also recurse
    if let Ok(set) = o.as_set() {
        for ch in set {
            collect_props_from_obj(ch, out)?;
        }
        return Ok(());
    }

    // For any constructed object (context/private/application), parse its content as DER and recurse
    let h = &o.header;
    if h.is_constructed() {
        if let Ok(bytes) = o.as_slice() {
            let mut off = 0usize;
            while off < bytes.len() {
                let (rem, child) = parse_der(&bytes[off..]).map_err(|e| anyhow!("inner DER: {e}"))?;
                let consumed = bytes[off..].len() - rem.len();
                collect_props_from_obj(&child, out)?;
                off += consumed;
            }
        }
    }
    Ok(())
}

/// Collect typed properties with metadata
fn collect_typed_props_from_obj(o: &DerObject, out: &mut Vec<TypedIm4mProperty>) -> Result<()> {
    if let Ok(seq) = o.as_sequence() {
        if seq.len() >= 2 {
            if let Some(k) = ia5str(&seq[0]) {
                if k.len() == 4 && k.chars().all(|c| c.is_ascii_graphic()) {
                    let (value, anomaly) = decode_typed_value(&seq[1], Some(k))?;
                    let meta = KNOWN_PROPERTIES.get(k);
                    let (name, description) = if let Some(m) = meta {
                        (m.name.to_string(), m.description.to_string())
                    } else {
                        ("UnknownProperty".to_string(), "An unknown or undocumented property.".to_string())
                    };
                    out.push(TypedIm4mProperty {
                        key: k.to_string(),
                        name,
                        description,
                        value,
                        anomaly,
                    });
                }
            }
        }
        for ch in seq {
            collect_typed_props_from_obj(ch, out)?;
        }
        return Ok(());
    }

    if let Ok(set) = o.as_set() {
        for ch in set {
            collect_typed_props_from_obj(ch, out)?;
        }
        return Ok(());
    }

    let h = &o.header;
    if h.is_constructed() {
        if let Ok(bytes) = o.as_slice() {
            let mut off = 0usize;
            while off < bytes.len() {
                let (rem, child) = parse_der(&bytes[off..]).map_err(|e| anyhow!("inner DER: {e}"))?;
                let consumed = bytes[off..].len() - rem.len();
                collect_typed_props_from_obj(&child, out)?;
                off += consumed;
            }
        }
    }
    Ok(())
}

/// Decode a value with type hint from property metadata
fn decode_typed_value(o: &DerObject, key_hint: Option<&str>) -> Result<(Im4mPropertyValue, Option<String>)> {
    let meta = key_hint.and_then(|k| KNOWN_PROPERTIES.get(k));
    let mut anomaly = None;

    let val = match meta.map(|m| &m.expected_type) {
        Some(ExpectedDerType::Boolean) => {
            if let Ok(b) = o.as_bool() {
                Im4mPropertyValue::Boolean { value: b }
            } else {
                anomaly = Some(format!("Expected BOOLEAN, got {:?}", o.header.tag()));
                Im4mPropertyValue::Unknown {
                    der_type: format!("{:?}", o.header.tag()),
                    hex_value: Some(hex::encode(o.as_slice().unwrap_or_default())),
                    hex_values: None,
                }
            }
        }
        Some(ExpectedDerType::Integer) => {
            if let Ok(i) = o.as_u64() {
                Im4mPropertyValue::Integer { value: i }
            } else {
                anomaly = Some(format!("Expected INTEGER, got {:?}", o.header.tag()));
                Im4mPropertyValue::Unknown {
                    der_type: format!("{:?}", o.header.tag()),
                    hex_value: Some(hex::encode(o.as_slice().unwrap_or_default())),
                    hex_values: None,
                }
            }
        }
        Some(ExpectedDerType::Digest) => {
            if let Ok(s) = o.as_slice() {
                Im4mPropertyValue::Digest { value: hex::encode(s) }
            } else {
                anomaly = Some(format!("Expected OCTET STRING for Digest, got {:?}", o.header.tag()));
                Im4mPropertyValue::Unknown {
                    der_type: format!("{:?}", o.header.tag()),
                    hex_value: Some(hex::encode(o.as_slice().unwrap_or_default())),
                    hex_values: None,
                }
            }
        }
        Some(ExpectedDerType::OctetString) => {
            if let Ok(s) = o.as_slice() {
                Im4mPropertyValue::OctetString { value: hex::encode(s) }
            } else {
                anomaly = Some(format!("Expected OCTET STRING, got {:?}", o.header.tag()));
                Im4mPropertyValue::Unknown {
                    der_type: format!("{:?}", o.header.tag()),
                    hex_value: Some(hex::encode(o.as_slice().unwrap_or_default())),
                    hex_values: None,
                }
            }
        }
        Some(ExpectedDerType::Ia5String) => {
            if let Some(s) = ia5str(o) {
                Im4mPropertyValue::String { value: s.to_string() }
            } else {
                anomaly = Some(format!("Expected IA5String, got {:?}", o.header.tag()));
                Im4mPropertyValue::Unknown {
                    der_type: format!("{:?}", o.header.tag()),
                    hex_value: Some(hex::encode(o.as_slice().unwrap_or_default())),
                    hex_values: None,
                }
            }
        }
        None => {
            // Fallback for unknown keys
            match o.header.tag().0 {
                1 => Im4mPropertyValue::Boolean { value: o.as_bool().unwrap_or(false) },
                2 => Im4mPropertyValue::Integer { value: o.as_u64().unwrap_or(0) },
                4 => Im4mPropertyValue::OctetString { value: hex::encode(o.as_slice().unwrap_or_default()) },
                22 => Im4mPropertyValue::String { value: ia5str(o).unwrap_or("").to_string() },
                16 | 17 => {
                    // SEQUENCE (16) or SET (17) - recursively collect child elements
                    let (type_name, children) = if o.header.tag().0 == 16 {
                        ("Sequence", o.as_sequence().ok())
                    } else {
                        ("Set", o.as_set().ok())
                    };
                    
                    if let Some(items) = children {
                        if items.is_empty() {
                            Im4mPropertyValue::Unknown {
                                der_type: format!("{}(empty)", type_name),
                                hex_value: None,
                                hex_values: None,
                            }
                        } else {
                            // Recursively encode children for debugging
                            let mut parts = Vec::new();
                            for child in items {
                                if let Ok(slice) = child.as_slice() {
                                    parts.push(hex::encode(slice));
                                }
                            }
                            Im4mPropertyValue::Unknown {
                                der_type: format!("{}({} elements)", type_name, items.len()),
                                hex_value: None,
                                hex_values: Some(parts),
                            }
                        }
                    } else {
                        Im4mPropertyValue::Unknown {
                            der_type: format!("{}(malformed)", type_name),
                            hex_value: Some(hex::encode(o.as_slice().unwrap_or_default())),
                            hex_values: None,
                        }
                    }
                }
                _ => Im4mPropertyValue::Unknown {
                    der_type: format!("{:?}", o.header.tag()),
                    hex_value: Some(hex::encode(o.as_slice().unwrap_or_default())),
                    hex_values: None,
                },
            }
        }
    };
    Ok((val, anomaly))
}

#[allow(dead_code)]
fn decode_any_value(o: &DerObject) -> Result<Im4mValue> {
    let h = &o.header;
    // Convert the Class enum into its underlying integer representation
    let class_num = h.class() as u8;
    let tag = h.tag().0;
    // UNIVERSAL = 0; tag numbers per X.690
    if class_num == 0 {
        match tag {
            1 => {
                // BOOLEAN
                let b = o.as_bool().map_err(|_| anyhow!("BOOLEAN decode"))?;
                return Ok(Im4mValue::Boolean(b));
            }
            2 => {
                // INTEGER (treat as non-negative big-int; IM4M integers are typically small)
                // If negative occurs, map via two's complement to u128 magnitude.
                if let Ok(u) = o.as_u64() {
                    return Ok(Im4mValue::Integer(u as u128));
                }
                // Fallback: read raw bytes and decode as unsigned magnitude
                if let Ok(bytes) = o.as_slice() {
                    let mut acc: u128 = 0;
                    for &b in bytes {
                        acc = (acc << 8) | (b as u128);
                    }
                    return Ok(Im4mValue::Integer(acc));
                }
                return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: o.length().definite()? });
            }
            3 => {
                // BIT STRING
                if let Ok(bytes) = o.as_slice() {
                    return Ok(Im4mValue::BitString(hex::encode(bytes)));
                }
                return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: o.length().definite()? });
            }
            4 => {
                // OCTET STRING
                if let Ok(bytes) = o.as_slice() {
                    return Ok(Im4mValue::OctetString(hex::encode(bytes)));
                }
                return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: o.length().definite()? });
            }
            5 => return Ok(Im4mValue::Null),
            16 => {
                if let Ok(seq) = o.as_sequence() {
                    return Ok(Im4mValue::SequenceLen(seq.len()));
                }
                return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: o.length().definite()? });
            }
            17 => {
                if let Ok(set) = o.as_set() {
                    return Ok(Im4mValue::SetLen(set.len()));
                }
                return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: o.length().definite()? });
            }
            22 => {
                if let Some(s) = ia5str(o) {
                    return Ok(Im4mValue::Ia5String(s.to_string()));
                }
                return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: o.length().definite()? });
            }
            _ => {
                if let Ok(bytes) = o.as_slice() {
                    return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: bytes.len() });
                }
                return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: o.length().definite()? });
            }
        }
    } else {
        // Non-universal: leave as Unknown, but include tag class/tag number
        if let Ok(bytes) = o.as_slice() {
            return Ok(Im4mValue::Unknown { class_id: class_num, tag, len: bytes.len() });
        }
        Ok(Im4mValue::Unknown { class_id: class_num, tag, len: o.length().definite()? })
    }
}

// ---------- helpers (append these near existing helpers) ----------

fn dedup_stable(v: &mut Vec<String>) {
    v.sort();
    v.dedup();
}

/// Class-agnostic DER walker that collects IA5String tokens of length 4, recursively.
/// Handles constructed UNIVERSAL/PRIVATE/CONTEXT-SPECIFIC by parsing child DER items inside the value region.
///
/// DER assumptions: definite length (Image4 is DER). Indefinite lengths are rejected.
fn scan_der_collect_ia5_fourccs(input: &[u8], out: &mut Vec<String>) -> Result<()> {
    let mut off = 0usize;
    while off < input.len() {
        let (tag_len, class, constructed, tag_no) = der_read_tag(&input[off..])?;
        let len_off = off + tag_len;
        let (len_len, content_len) = der_read_len(&input[len_off..])?;
        let hdr_len = tag_len + len_len;

        let val_start = off + hdr_len;
        let val_end = val_start
            .checked_add(content_len)
            .ok_or_else(|| anyhow!("overflow"))?;
        if val_end > input.len() {
            bail!("IM4M: element exceeds buffer");
        }

        // Collect IA5String 4CCs (UNIVERSAL class, tag_no == 22)
        if class == 0 && tag_no == 22 {
            let s = &input[val_start..val_end];
            if let Ok(su) = std::str::from_utf8(s) {
                if su.len() == 4 && su.chars().all(|c| c.is_ascii_graphic()) {
                    out.push(su.to_string());
                    debug!("Found IA5 token: {}", su);
                }
            }
        }

        // Recurse into constructed values (any class): their content is a concatenation of DER elements.
        if constructed {
            debug!(
                "Recursing into constructed tag (class={}, tag_no={}) at offset {}",
                class, tag_no, off
            );
            scan_der_collect_ia5_fourccs(&input[val_start..val_end], out)?;
        }

        off = val_end;
    }
    Ok(())
}

/// Parse DER tag header: returns (bytes_consumed, class(0..3), constructed, tag_number)
fn der_read_tag(i: &[u8]) -> Result<(usize, u8, bool, u32)> {
    if i.is_empty() {
        bail!("short tag");
    }
    let b0 = i[0];
    let class = (b0 & 0b1100_0000) >> 6; // 0=universal,1=application,2=context,3=private
    let constructed = (b0 & 0b0010_0000) != 0;
    let mut tag_no = (b0 & 0b0001_1111) as u32;
    let mut idx = 1usize;

    if tag_no == 0b1_1111 {
        // High-tag-number form: base-128 big-endian, MSB=1 continuation, last MSB=0
        tag_no = 0;
        loop {
            if idx >= i.len() {
                bail!("short high-tag-number");
            }
            let b = i[idx];
            idx += 1;
            tag_no = (tag_no << 7) | (b & 0x7F) as u32;
            if (b & 0x80) == 0 {
                break;
            }
            // DER requires shortest form; unlimited loop bounded by buffer size here
        }
    }

    Ok((idx, class, constructed, tag_no))
}

/// Parse DER definite length: returns (bytes_consumed, content_length)
fn der_read_len(i: &[u8]) -> Result<(usize, usize)> {
    if i.is_empty() {
        bail!("short length");
    }
    let b0 = i[0];
    if (b0 & 0x80) == 0 {
        // short form
        Ok((1, (b0 & 0x7F) as usize))
    } else {
        let n = (b0 & 0x7F) as usize;
        if n == 0 {
            bail!("indefinite length not allowed in DER");
        }
        if i.len() < 1 + n {
            bail!("short long-form length");
        }
        let mut len: usize = 0;
        for &b in &i[1..=n] {
            len = (len << 8) | (b as usize);
        }
        Ok((1 + n, len))
    }
}

/* ---------- helpers ---------- */

fn as_bytes<'a>(o: &'a DerObject<'a>) -> Option<&'a [u8]> {
    o.as_slice().ok()
}
fn ia5str<'a>(o: &'a DerObject<'a>) -> Option<&'a str> {
    o.as_slice().ok().and_then(|s| std::str::from_utf8(s).ok())
}
