<h1 align="center">img4-dump</h1>

<h5 align="center">A toolkit for extracting, analyzing, and decrypting Apple IMG4 firmware components (IM4P, IM4M, IM4R).</h5>

<div align="center">
  <a href="https://crates.io/crates/img4-dump">
    crates.io
  </a>
  —
  <a href="https://github.com/19h/img4-dump">
    Github
  </a>
</div>

<br />

`img4-dump` is a command-line utility for low-level analysis of Apple's IMG4 firmware format. It parses IMG4 containers and their standalone components (IM4P payloads, IM4M manifests), extracts all embedded data, and provides tools for decryption and decompression. Its primary function is to support security research and reverse engineering of firmware for Apple devices.

### Installation

```shell
cargo install img4-dump --features lzfse,lzss
```
*Note: The `--features lzfse,lzss` flags are recommended to enable all decompression capabilities.*

### Example Output

<details>
<summary>Click to expand: <code>img4-dump --dump-im4m -f iBoot.img4</code></summary>

```
IMG4 Container
==================================================

IM4P Payload
   Type: ibot (iBoot)
   Version: iBoot-13822.41.1
   Data Size: 1,296,806 bytes
   KBAG: Not present

IM4M Manifest
   Version: 0
   Certificate Chain: 1 certificate
   Signature Length: 512 bytes

   Manifest Properties:
      • Manifest Body
      • Manifest Properties

   Images Referenced: 43 components (manifest covers full bundle)
      • ibdt - iBoot Data
      • ibec - iBEC (recovery/restore bootloader)
      • ibot - iBoot ← THIS FILE
      • rdc2 - Restore Display Coprocessor 2
      • rdsk - Restore RamDisk
      • rdtr - Restore DeviceTree
      • rkrn - Restore KernelCache
      • rlgo - Restore Logo
      • rosi - RestoreOS
      • rspt - Restore Secure Page Table Monitor
      • rtrx - Restore Trusted Execution Monitor
      • rtsc - Restore Trust Cache
      • anef - ANE Firmware (Neural Engine)
      • aopf - AOP Firmware (Always-On Processor)
      • apmv - Apple Manifest Version
      ... (30 more components)

Output Files
   Payload: img4_dump/im4p.bin
   Manifest: img4_dump/im4m.der
```

**Note:** Output includes color highlighting when viewed in a terminal. The "← THIS FILE" marker shows which component is actually contained in the current file, while other entries are references to the full firmware bundle.

</details>

### Usage Examples

**1. One-shot decrypt (`--auto`)**
Give it an IV, a key, and an IM4P; it decrypts the payload and writes
`<input>.decrypted` right next to the input. It tries CBC then CTR and keeps
whichever validates, so you don't have to know the mode:

```shell
img4-dump --auto \
  --iv e9e9248584860be85a82754e4fb06b3f \
  --key 40b4610d6b5acb044df751da3d2af4ad30402b832e798f4656295423c33dda40 \
  iBoot.j42d.RELEASE.im4p
# -> iBoot.j42d.RELEASE.im4p.decrypted
```

**2. Basic Dump (Metadata and Payloads)**
Extracts all components from an `.img4` file into the `dump_output/` directory with verbose logging.

```shell
img4-dump -v my_firmware.img4 -o dump_output
```

**3. Decrypt Payload with Command-Line IV and Key**
Decrypts the IM4P payload into an output directory. The AES mode defaults to
**CBC** (correct for iBoot/iBEC/iBSS/LLB/SEP/ramdisk/logo images); pass
`--aes-mode ctr` for the rare CTR payload.

```shell
img4-dump --decrypt \
  --iv 0123456789abcdef0123456789abcdef \
  --key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  -o decrypted_firmware \
  firmware.im4p
```

**4. Decrypt and Decompress**
Decrypts using keys from a plaintext KBAG within the IM4P, then attempts to decompress the result using LZFSE or LZSS.

```shell
img4-dump --decrypt --decompress -o processed_firmware firmware_with_kbag.im4p
```

**5. Full Manifest Analysis**
Dumps the raw IM4M, extracts its full property list to JSON, and saves the embedded certificate chain as individual `.der` and `.pem` files.

```shell
img4-dump --dump-im4m --dump-im4m-props --dump-im4m-certs \
  -o manifest_analysis \
  my_firmware.img4
```

**6. JSON Summary Output**
Parses the input file and prints a structured JSON summary of its contents to standard output.

```shell
img4-dump --json my_firmware.img4 > summary.json
```

### Features

*   **Comprehensive Parsing:** Handles `IMG4` containers, standalone `IM4P` payloads, and standalone `IM4M` manifests.
*   **Component Extraction:** Dumps the raw DER-encoded bytes of the IM4P, IM4M, and IM4R components.
*   **AES Decryption:** Decrypts IM4P payloads using user-supplied IV and Key.
    *   Supports AES-128, AES-192, and AES-256.
    *   Supports Counter (CTR) and Cipher Block Chaining (CBC) modes.
    *   Automatically reads IV/Key from plaintext `KBAG` tags if present in the IM4P.
*   **Decompression:** Optionally decompresses decrypted payloads (requires feature flags).
    *   LZFSE via the `lzfse` codec.
    *   LZSS via a self-contained, dependency-free implementation of Apple's `complzss`/Okumura format, with Adler-32 self-validation of the decompressed result.
*   **Manifest Analysis:**
    *   Extracts a structured property list from an IM4M (global properties plus per-image groups) into JSON.
    *   Dumps the full X.509 certificate chain used for signature validation.
*   **Flexible Output:** Provides verbose logging for detailed analysis and a machine-readable JSON summary for automation. In `--json` mode, errors are emitted as a structured `{"error": ...}` object so consumers always receive valid JSON.
*   **Key Hygiene:** The JSON summary never serializes raw KBAG IV/key bytes — only the key class and lengths — so piping `--json` output to logs cannot leak plaintext key material.

### Technical Background

The IMG4 format is a container structure used by Apple for distributing and verifying firmware components. It is based on ASN.1 DER (Abstract Syntax Notation One, Distinguished Encoding Rules), a standard for encoding structured data.

A typical `IMG4` file contains three main components:

1.  **IM4P (Image Payload):** The core data file, such as a kernel (`krnl`), bootloader (`ibot`), or Secure Enclave processor firmware (`sepi`).
    *   **Structure:** An ASN.1 `SEQUENCE` containing a four-character code (4CC) type, a description string, the payload data (octet string), and an optional `KBAG` tag.
    *   **Encryption:** The payload data is often encrypted with AES. The `KBAG` (keybag) tag contains the necessary decryption IV and the AES key. In production firmware, the key within the KBAG is "wrapped" (encrypted) with a device-specific hardware key (GID key). **This tool requires a plaintext KBAG or a user-supplied raw key; it does not perform GID key unwrapping.**
    *   **AES Mode:** The AES block cipher mode (CBC or CTR) is not encoded in the format. Nearly all Apple images (iBoot/iBEC/iBSS/LLB/SEP/ramdisk/logo) use **CBC**, which is the tool's default; pass `--aes-mode ctr` for the rare CTR payload, or use `--auto` to try both and keep whichever decrypts to a valid-looking result.

2.  **IM4M (Image Manifest):** A cryptographically signed manifest that ensures the integrity and authenticity of the IM4P.
    *   **Structure:** An ASN.1 `SEQUENCE` containing properties like the payload's SHA hash (`DGST`), security domain (`SDOM`), and various other boot-time parameters.
    *   **Verification:** The manifest is signed by Apple, and the signature is verified by the device's Boot ROM or a preceding bootloader stage against a chain of trust rooted in an Apple hardware certificate. This tool can extract the certificate chain but does not perform signature validation.

3.  **IM4R (Image Restore Info):** An opaque data blob related to the device restore process. This tool extracts it without further interpretation.

### Output File Structure

When run, `img4-dump` creates the following files in the specified output directory (names are examples):

*   `im4p.bin`: The raw, possibly encrypted, IM4P payload.
*   `im4p.kbag.der`: The raw DER of the KBAG tag, if present.
*   `im4p.payp.json`: Payload-scoped properties from the with-properties (PAYP) IM4P variant, if present.
*   `im4p.ciphertext`: A copy of the encrypted payload, if `--keep-ciphertext` is used.
*   `im4p.decrypted`: The plaintext payload after successful decryption.
*   `im4p.decompressed.lzfse` / `im4p.decompressed.lzss`: The final data after decompression.
*   `im4m.der`: The raw DER of the IM4M manifest.
*   `im4m.props.json`: A **structured** view of the manifest: `{ "manifest_properties": [...], "images": [{ "fourcc", "name", "properties": [...] }] }`. Global (MANP) properties are separated from each per-image object's own property set, mirroring the manifest's `MANB → { MANP, <image> }` structure.
*   `im4m.cert.0.der`, `im4m.cert.0.pem`, ...: The certificate chain from the manifest.
*   `im4r.der`: The raw IM4R data blob.
*   `im4r.props.json`: All IM4R restore-info properties.
*   `im4r.bncn.bin`: The raw boot nonce (BNCN), if present.

### Notes

*   If you intend to analyze the executable code within a decrypted payload, note that modern Apple devices use 64-bit ARMv8-A architecture (AArch64). Embedded micro-controllers (e.g., in peripherals) may use other architectures like ARMv7-M (e.g., Arm Cortex-M series).
*   The decryption validation logic is heuristic-based. It checks for common file magic numbers and data entropy patterns. It is a best-effort check and not a guarantee of correctness. Always verify the decrypted output.

### License

MIT License

Copyright (c) 2025 Kenan Sulayman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
