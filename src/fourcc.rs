use once_cell::sync::Lazy;
use std::collections::HashMap;

static FOURCC_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    
    // Boot chain components - The primary bootloader stages that execute during system startup
    // Main bootloader that loads the kernel and validates the boot chain
    map.insert("ibot", "iBoot");
    // Recovery/restore mode bootloader used during DFU/Recovery flows
    map.insert("ibec", "iBEC (recovery/restore bootloader)");
    // Early-stage bootloader used during restore (single-stage iBoot)
    map.insert("ibss", "iBSS (early-stage bootloader)");
    // Ancillary data bundle used by iBoot
    map.insert("ibdt", "iBoot Data");
    
    // Restore components - Images used during device restore/recovery operations (r-prefixed)
    // Restore-variant of the Display Coprocessor 2 firmware
    map.insert("rdc2", "Restore Display Coprocessor 2");
    // Restore-mode ramdisk containing recovery tools and utilities
    map.insert("rdsk", "Restore RamDisk");
    // DeviceTree used during restore operations
    map.insert("rdtr", "Restore DeviceTree");
    // Kernel cache specifically for restore context
    map.insert("rkrn", "Restore KernelCache");
    // Boot/recovery logo image displayed during restore
    map.insert("rlgo", "Restore Logo");
    // Restore operating system component
    map.insert("rosi", "RestoreOS");
    // Restore variant of Secure Page Table Monitor firmware
    map.insert("rspt", "Restore Secure Page Table Monitor");
    // Restore variant of Trusted Execution Monitor firmware
    map.insert("rtrx", "Restore Trusted Execution Monitor");
    // Trust cache used by RestoreOS
    map.insert("rtsc", "Restore Trust Cache");
    
    // Kernel and system - Core OS components and device configuration
    // Prelinked kernel cache containing kernel and kexts
    map.insert("krnl", "KernelCache");
    // Flattened device tree blob describing hardware platform
    map.insert("dtre", "DeviceTree");
    // APFS Sealed System Volume root hash for system volume
    map.insert("isys", "System Volume Root Hash");
    // APFS SSV root hash for base-system snapshot
    map.insert("csys", "Base System Volume Root Hash");
    // Gzip-compressed canonical metadata bundle for Sealed System Volume
    map.insert("msys", "System Volume Canonical Metadata");
    
    // Trust caches - Code signature validation databases
    // System trust cache for production use
    map.insert("trst", "Static Trust Cache");
    // Trust cache for base system in restore context
    map.insert("bstc", "Base System Trust Cache");
    
    // Firmware components - Coprocessor and peripheral firmware images
    // Apple Neural Engine firmware for ML acceleration
    map.insert("anef", "ANE Firmware (Neural Engine)");
    // Always-On Processor firmware for low-power operations
    map.insert("aopf", "AOP Firmware (Always-On Processor)");
    // Apple Video Encoder firmware
    map.insert("avef", "AVE Firmware (Video Encoder)");
    // Second-generation Display Coprocessor firmware for Apple Silicon
    map.insert("dcp2", "Display Coprocessor 2 Firmware");
    // GPU firmware for AGX/RTKit graphics complex
    map.insert("gfxf", "GPU Firmware");
    // Input device (touch/keyboard) firmware payload
    map.insert("ipdf", "Input Device Firmware");
    // Touch controller firmware
    map.insert("mtfw", "Multitouch Firmware");
    // Media Transfer Protocol firmware for USB-C devices
    map.insert("mtpf", "MTP Firmware (Media Transfer Protocol)");
    // Power Management Controller firmware
    map.insert("pmcf", "PMC Firmware (Power Management)");
    // Power Measurement Processor firmware
    map.insert("pmpf", "PMP Firmware (Power Measurement)");
    // SmartIO (ASC-class peripheral) firmware
    map.insert("siof", "SmartIO Firmware");
    // High-privilege page table monitor firmware
    map.insert("sptm", "Secure Page Table Monitor");
    // Trusted Execution Monitor for policy enforcement under SPTM
    map.insert("trxm", "Trusted Execution Monitor");
    
    // Manifest properties - Uppercase 4CCs typically found in IM4M manifests
    // Manifest body container
    map.insert("MANB", "Manifest Body");
    // Manifest properties container
    map.insert("MANP", "Manifest Properties");
    // Board/model identifier for target hardware
    map.insert("BORD", "Board Identifier");
    // SoC epoch/version indicator
    map.insert("CEPO", "Chip Epoch");
    // SoC model identifier
    map.insert("CHIP", "Chip Identifier");
    // Certificate production status flag
    map.insert("CPRO", "Certificate Production Status");
    // Certificate security mode configuration
    map.insert("CSEC", "Certificate Security Mode");
    // Per-device 64-bit unique identifier
    map.insert("ECID", "Exclusive Chip ID");
    // Security domain indicator
    map.insert("SDOM", "Security Domain");
    
    // Lowercase manifest properties - Policy flags and metadata fields
    // Human-readable OS version string
    map.insert("apmv", "Apple Manifest Version");
    // Consolidated security mode indicator
    map.insert("esdm", "Effective Security Domain Mode");
    // LocalPolicy flag recording OS version
    map.insert("love", "Local OS Version");
    // SHA-384 hash of main OS manifest in LocalPolicy
    map.insert("nsih", "Next Stage Image Hash");
    // ASCII product/model identifier (e.g., Mac16,5)
    map.insert("prtp", "Platform Identifier");
    // ASCII SDK platform string (e.g., macosx)
    map.insert("sdkp", "SDK Platform");
    // Disable CTRR lock (kernel write-protect) under Reduced Security
    map.insert("sip2", "SIP Flag 2 (CTRR lock disable)");
    // Disable iBoot boot-args allow-list
    map.insert("sip3", "SIP Flag 3 (boot-args allow-list disable)");
    // Reduced Security mode enabled
    map.insert("smb0", "Security Mode Boot 0 (Reduced Security)");
    // Allow user-managed kernel extensions
    map.insert("smb2", "Security Mode Boot 2 (user kexts)");
    // IM4M/AppleRART nonce field
    map.insert("snon", "Secure Nonce");
    // Undocumented nonce-related field
    map.insert("snuf", "Secure Nonce Update");
    // SHA-384 hash of Cryptex1/RSR manifest in LocalPolicy
    map.insert("spih", "Supplemental Policy Image Hash");
    // Monotonic counter for Cryptex/RSR anti-replay protection
    map.insert("stng", "Supplemental Generation (anti-replay)");
    // UNIX epoch timestamp field
    map.insert("tstp", "Timestamp");
    // Indicates binding to UID-derived encryption keys
    map.insert("uidm", "Unique ID Manifest Flag");
    
    // Unknown/undocumented - Observed in manifests but function not publicly documented
    // Seen in manifests; purpose not established
    map.insert("ispf", "iSpoof");
    // Mentioned for disambiguation; no established IM4P mapping
    map.insert("rtpf", "RT(P)");
    // Undocumented manifest property, possibly target board
    map.insert("tagt", "Target (undocumented)");
    // Undocumented manifest property, possibly Tatsu timestamp
    map.insert("tatp", "Tatsu Timestamp (undocumented)");
    
    map
});

/// Get description for any 4CC code (image or property)
pub fn get_description(code: &str) -> Option<String> {
    FOURCC_MAP.get(code).map(|s| s.to_string())
}

/// Get description for an image type code
#[allow(dead_code)]
pub fn get_image_description(code: &str) -> Option<String> {
    get_description(code)
}

/// Get description for a manifest property code
pub fn get_property_description(code: &str) -> Option<String> {
    // Try FOURCC_MAP first
    if let Some(desc) = get_description(code) {
        return Some(desc);
    }
    
    // Fallback to KNOWN_PROPERTIES from parse.rs
    // Import the metadata from parse module
    crate::parse::get_property_metadata(code)
}

/// Format a 4CC code with its description if available
#[allow(dead_code)]
pub fn format_with_description(code: &str) -> String {
    if let Some(desc) = get_description(code) {
        format!("{} ({})", code, desc)
    } else {
        code.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_known_codes() {
        assert_eq!(get_description("ibot"), Some("iBoot".to_string()));
        assert_eq!(get_description("CEPO"), Some("Chip Epoch".to_string()));
        assert_eq!(get_description("krnl"), Some("KernelCache".to_string()));
        assert_eq!(get_description("MANB"), Some("Manifest Body".to_string()));
    }
    
    #[test]
    fn test_unknown_code() {
        assert!(get_description("ZZZZ").is_none());
    }
    
    #[test]
    fn test_property_fallback() {
        // Test fallback to KNOWN_PROPERTIES for codes not in FOURCC_MAP
        // This tests codes that exist only in parse.rs KNOWN_PROPERTIES
        assert!(get_property_description("DGST").is_some());
    }
}
