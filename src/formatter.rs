use crate::fourcc;
use crate::parse::{ContainerKind, Im4pInfo, Im4mInfoSummary};
use std::fmt::Write;

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const BLUE: &str = "\x1b[34m";
const MAGENTA: &str = "\x1b[35m";
const BRIGHT_GREEN: &str = "\x1b[92m";
const BRIGHT_YELLOW: &str = "\x1b[93m";
const BRIGHT_CYAN: &str = "\x1b[96m";

/// Check if color output should be enabled
fn use_colors() -> bool {
    // Check if stdout is a terminal and NO_COLOR env var is not set
    atty::is(atty::Stream::Stdout) && std::env::var("NO_COLOR").is_err()
}

/// Paths to output files written during processing
#[derive(Default)]
pub struct OutputPaths {
    pub files: Vec<(String, String)>,  // Vec of (label, path) pairs
}

impl OutputPaths {
    pub fn add(&mut self, label: impl Into<String>, path: impl Into<String>) {
        self.files.push((label.into(), path.into()));
    }
}

/// Format the summary in a clean, diskutil-style output
pub fn format_summary(
    container: ContainerKind,
    im4p: Option<&Im4pInfo>,
    im4m: Option<&Im4mInfoSummary>,
    im4r_len: Option<usize>,
    output_paths: &OutputPaths,
) -> String {
    let payload_type = im4p.map(|p| p.r#type.as_str());
    let mut out = String::new();
    
    // Header
    let colors = use_colors();
    
    let container_name = match container {
        ContainerKind::Img4 => "IMG4 Container",
        ContainerKind::Im4pStandalone => "IM4P Payload (Standalone)",
        ContainerKind::Im4mStandalone => "IM4M Manifest (Standalone)",
    };
    
    if colors {
        writeln!(out, "{}{}{}", BOLD, container_name, RESET).unwrap();
        writeln!(out, "{}{}{}", CYAN, "=".repeat(50), RESET).unwrap();
    } else {
        writeln!(out, "{}", container_name).unwrap();
        writeln!(out, "{}", "=".repeat(50)).unwrap();
    }
    writeln!(out).unwrap();
    
    // IM4P section
    if let Some(info) = im4p {
        render_im4p(&mut out, info, colors);
        writeln!(out).unwrap();
    }
    
    // IM4M section
    if let Some(info) = im4m {
        render_im4m(&mut out, info, payload_type, colors);
        writeln!(out).unwrap();
    }
    
    // IM4R section
    if let Some(len) = im4r_len {
        render_im4r(&mut out, len, colors);
        writeln!(out).unwrap();
    }
    
    // Output files section
    if has_output_files(output_paths) {
        render_output_files(&mut out, output_paths, colors);
    }
    
    out
}

fn render_im4p(out: &mut String, info: &Im4pInfo, colors: bool) {
    if colors {
        writeln!(out, "{}{}IM4P Payload{}", BOLD, BRIGHT_CYAN, RESET).unwrap();
    } else {
        writeln!(out, "IM4P Payload").unwrap();
    }
    
    // Special rendering for Type with extra highlighting if colors enabled
    if colors {
        let desc = fourcc::get_description(&info.r#type)
            .unwrap_or_else(|| "Unknown".to_string());
        writeln!(out, "   {}{}{}{}: {}{}{}{} ({}{}{})",
            BOLD, CYAN, "Type", RESET,
            BOLD, GREEN, info.r#type, RESET,
            BRIGHT_CYAN, desc, RESET
        ).unwrap();
    } else {
        let type_desc = if let Some(desc) = fourcc::get_description(&info.r#type) {
            format!("{} ({})", info.r#type, desc)
        } else {
            info.r#type.clone()
        };
        writeln!(out, "   Type     :  {}", type_desc).unwrap();
    }
    
    let kbag_str = if let Some(kbags) = &info.kbag {
        if kbags.is_empty() {
            "Not present".to_string()
        } else {
            format!("Present ({} entr{})", kbags.len(), if kbags.len() == 1 { "y" } else { "ies" })
        }
    } else {
        "Not present".to_string()
    };
    
    // Build key-value pairs for alignment (excluding Type which we rendered specially)
    let pairs = vec![
        ("Version", info.version.clone()),
        ("Data Size", format_bytes(info.data_len)),
        ("KBAG", kbag_str),
    ];
    
    render_kv_block(out, &pairs, 3, colors);
}

fn render_im4m(out: &mut String, info: &Im4mInfoSummary, payload_type: Option<&str>, colors: bool) {
    if colors {
        writeln!(out, "{}{}IM4M Manifest{}", BOLD, BRIGHT_YELLOW, RESET).unwrap();
    } else {
        writeln!(out, "IM4M Manifest").unwrap();
    }
    
    let version_str = info.version.map_or("Unknown".to_string(), |v| v.to_string());
    let cert_str = info.cert_chain_len.map_or("Unknown".to_string(), |n| {
        format!("{} certificate{}", n, if n == 1 { "" } else { "s" })
    });
    let sig_str = info.signature_len.map_or("Unknown".to_string(), |n| format_bytes(n));
    
    let pairs = vec![
        ("Version", version_str),
        ("Certificate Chain", cert_str),
        ("Signature Length", sig_str),
    ];
    
    render_kv_block(out, &pairs, 3, colors);
    
    writeln!(out).unwrap();
    
    // Manifest Properties
    if !info.manifest_property_tags.is_empty() {
        if colors {
            writeln!(out, "   {}Manifest Properties:{}", BOLD, RESET).unwrap();
        } else {
            writeln!(out, "   Manifest Properties:").unwrap();
        }
        for tag in &info.manifest_property_tags {
            let desc = fourcc::get_property_description(tag)
                .unwrap_or_else(|| tag.clone());
            if colors {
                writeln!(out, "      {}•{} {}", DIM, RESET, desc).unwrap();
            } else {
                writeln!(out, "      • {}", desc).unwrap();
            }
        }
        writeln!(out).unwrap();
    }
    
    // Images Referenced (for validation)
    if !info.images_present.is_empty() {
        let count = info.images_present.len();
        if colors {
            writeln!(out, "   {}Images Referenced:{} {}{}{} component{} {}(manifest covers full bundle){}", 
                BOLD, RESET,
                BRIGHT_CYAN, count, RESET,
                if count == 1 { "" } else { "s" },
                DIM, RESET
            ).unwrap();
        } else {
            writeln!(out, "   Images Referenced:   {} component{} (manifest covers full bundle)", count, if count == 1 { "" } else { "s" }).unwrap();
        }
        
        // Group images for better readability
        let (boot_chain, restore, firmware) = group_images(&info.images_present);
        
        if !boot_chain.is_empty() {
            for img in &boot_chain {
                render_image_item(out, img, payload_type, colors);
            }
        }
        
        if !restore.is_empty() {
            for img in &restore {
                render_image_item(out, img, payload_type, colors);
            }
        }
        
        if !firmware.is_empty() {
            for img in &firmware {
                render_image_item(out, img, payload_type, colors);
            }
        }
    }
}

fn render_im4r(out: &mut String, len: usize, colors: bool) {
    if colors {
        writeln!(out, "{}{}IM4R Restore Info{}", BOLD, MAGENTA, RESET).unwrap();
    } else {
        writeln!(out, "IM4R Restore Info").unwrap();
    }
    let pairs = vec![
        ("Data Size", format_bytes(len)),
    ];
    render_kv_block(out, &pairs, 3, colors);
}

fn render_output_files(out: &mut String, paths: &OutputPaths, colors: bool) {
    if colors {
        writeln!(out, "{}{}Output Files{}", BOLD, BLUE, RESET).unwrap();
    } else {
        writeln!(out, "Output Files").unwrap();
    }
    
    // Convert to slice of references for render_kv_block
    let pairs: Vec<(&str, String)> = paths.files.iter()
        .map(|(label, path)| (label.as_str(), path.clone()))
        .collect();
    
    render_kv_block(out, &pairs, 3, colors);
}

fn render_image_item(out: &mut String, code: &str, payload_type: Option<&str>, colors: bool) {
    let desc = fourcc::get_description(code)
        .unwrap_or_else(|| "Unknown component".to_string());
    
    if payload_type == Some(code) {
        // This is the payload in THIS file - highlight it
        if colors {
            writeln!(out, "      {}•{} {}{}{}{} - {} {}{}← THIS FILE{}",
                DIM, RESET,
                BOLD, GREEN, code, RESET, desc, 
                BOLD, BRIGHT_GREEN, RESET
            ).unwrap();
        } else {
            writeln!(out, "      • {} - {} ← THIS FILE", code, desc).unwrap();
        }
    } else {
        // Other referenced images
        if colors {
            writeln!(out, "      {}•{} {}{}{} - {}{}{}",
                DIM, RESET,
                BOLD, code, RESET,
                DIM, desc, RESET
            ).unwrap();
        } else {
            writeln!(out, "      • {} - {}", code, desc).unwrap();
        }
    }
}

/// Group images into boot chain, restore, and firmware categories
fn group_images(images: &[String]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut boot_chain = Vec::new();
    let mut restore = Vec::new();
    let mut firmware = Vec::new();
    
    for img in images {
        let code = img.as_str();
        if matches!(code, "ibot" | "ibec" | "ibss" | "ibdt") {
            boot_chain.push(img.clone());
        } else if code.starts_with('r') && code.len() == 4 {
            restore.push(img.clone());
        } else {
            firmware.push(img.clone());
        }
    }
    
    (boot_chain, restore, firmware)
}

/// Render a block of key-value pairs with aligned colons
fn render_kv_block(out: &mut String, pairs: &[(&str, String)], indent: usize, colors: bool) {
    if pairs.is_empty() {
        return;
    }
    
    let max_key_len = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let indent_str = " ".repeat(indent);
    
    for (key, value) in pairs {
        let padding = " ".repeat(max_key_len - key.len());
        if colors {
            writeln!(out, "{}{}{}{}{}: {}{}{}", 
                indent_str, 
                BOLD, CYAN, key, RESET,
                BRIGHT_CYAN, value, RESET
            ).unwrap();
        } else {
            writeln!(out, "{}{}{}:  {}", indent_str, key, padding, value).unwrap();
        }
    }
}

/// Format bytes with thousands separators
fn format_bytes(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    
    for (i, ch) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*ch);
    }
    
    format!("{} bytes", result)
}

fn has_output_files(paths: &OutputPaths) -> bool {
    !paths.files.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1296806), "1,296,806 bytes");
        assert_eq!(format_bytes(512), "512 bytes");
        assert_eq!(format_bytes(1000000), "1,000,000 bytes");
    }
    
    #[test]
    fn test_group_images() {
        let images = vec![
            "ibot".to_string(),
            "krnl".to_string(),
            "rdsk".to_string(),
            "rkrn".to_string(),
            "anef".to_string(),
        ];
        
        let (boot, restore, firmware) = group_images(&images);
        
        assert_eq!(boot, vec!["ibot"]);
        assert_eq!(restore, vec!["rdsk", "rkrn"]);
        assert_eq!(firmware, vec!["krnl", "anef"]);
    }
}
