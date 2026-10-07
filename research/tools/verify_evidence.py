#!/usr/bin/env python3
"""Verify audit identity, native tables, and generated image aliases.

Usage: python3 research/tools/verify_evidence.py [--input-dir /private/tmp/img4]
Uses only Python's standard library. Addresses are pinned to the recorded hashes.
"""
import argparse
import collections
import hashlib
import json
import struct
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "research" / "ida"


class MachO:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        header = struct.unpack_from("<8I", self.data)
        assert header[0] == 0xFEEDFACF, f"not little-endian Mach-O 64: {path}"
        self.segments = []
        self.identity = {}
        pos = 32
        limit = pos + header[5]
        for _ in range(header[4]):
            cmd, size = struct.unpack_from("<II", self.data, pos)
            assert size >= 8 and pos + size <= limit <= len(self.data)
            if cmd == 0x19:  # LC_SEGMENT_64
                row = struct.unpack_from("<II16sQQQQiiII", self.data, pos)
                name = row[2].split(b"\0", 1)[0].decode("ascii")
                start, length, offset, file_size = row[3:7]
                assert offset + file_size <= len(self.data)
                self.segments.append((name, start, length, offset, file_size))
            elif cmd == 0x1B:  # LC_UUID
                self.identity["uuid"] = str(uuid.UUID(bytes=self.data[pos + 8:pos + 24]))
            elif cmd == 0xD:  # LC_ID_DYLIB
                _, _, name_at, timestamp, current, compatibility = struct.unpack_from("<6I", self.data, pos)
                tail = self.data[pos + name_at:pos + size]
                self.identity["install_name"] = tail.split(b"\0", 1)[0].decode("utf8")
                self.identity["current_version"] = self.version(current)
                self.identity["compatibility_version"] = self.version(compatibility)
            elif cmd == 0x32:  # LC_BUILD_VERSION
                _, _, platform, minimum, sdk, _ = struct.unpack_from("<6I", self.data, pos)
                self.identity["build_platform"] = platform
                self.identity["minimum_os"] = self.version(minimum)
                self.identity["sdk"] = self.version(sdk)
            pos += size
        assert pos == limit

    @staticmethod
    def version(v):
        return f"{v >> 16}.{(v >> 8) & 255}.{v & 255}"

    def read(self, ea, size):
        for _, start, _, offset, length in self.segments:
            if start <= ea and ea + size <= start + length:
                at = offset + ea - start
                return self.data[at:at + size]
        raise ValueError(f"unmapped file bytes: {self.path.name}: {ea:#x}+{size}")

    def cstring(self, ea):
        chars = bytearray()
        for i in range(4096):
            byte = self.read(ea + i, 1)[0]
            if byte == 0:
                return chars.decode("utf8")
            chars.append(byte)
        raise ValueError("unterminated string")

    def cfstring(self, ea):
        _, flags, pointer, length = struct.unpack("<4Q", self.read(ea, 32))
        assert flags == 0x7C8, "unexpected CFString flags in this pinned build"
        return self.read(pointer, length).decode("utf8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path)
    args = parser.parse_args()
    inputs, identities = {}, []
    for path in sorted(EVIDENCE.glob("*.inventory.json")):
        inventory = json.loads(path.read_text())
        name = path.name.removesuffix(".inventory.json")
        source = args.input_dir / name if args.input_dir else Path(inventory["file"])
        image = MachO(source)
        digest = hashlib.sha256(image.data).hexdigest()
        assert digest == inventory["sha256"], f"SHA-256 mismatch: {name}"
        assert inventory["function_count"] == len(inventory["functions"])
        assert not inventory["patched_bytes_primary"], f"patched primary text: {name}"
        inputs[name] = image
        identities.append({"binary": name, "sha256": digest, **image.identity})
    assert len(inputs) == 10

    specs = json.loads((EVIDENCE / "der-item-specs.json").read_text())
    for row in specs:
        raw = bytes.fromhex(row["bytes"])
        assert inputs[row["binary"]].read(int(row["ea"], 16), len(raw)) == raw
        decoded = [{"offset": off, "tag": hex(tag), "flags": flags}
                   for off, tag, flags in struct.iter_unpack("<QQQ", raw)]
        assert decoded == row["entries"]

    properties = json.loads((EVIDENCE / "libimage4.dylib.properties.json").read_text())
    image = inputs["libimage4.dylib"]
    for row in properties:
        raw = bytes.fromhex(row["bytes"])
        assert image.read(int(row["ea"], 16), 104) == raw
        fields = struct.unpack("<13Q", raw)
        assert (fields[3] & 0xFFFFFFFF).to_bytes(4, "big").decode("ascii") == row["fourcc"]
        assert image.cstring(fields[0]) == row["label"]

    aliases = collections.defaultdict(list)
    rows = json.loads((EVIDENCE / "libauthinstall.dylib.image-types.json").read_text())
    image = inputs["libauthinstall.dylib"]
    assert len(rows) == 223
    for i, row in enumerate(rows):
        assert row["index"] == i and int(row["ea"], 16) == 0x269176518 + i * 16
        entry, code = struct.unpack("<QQ", image.read(int(row["ea"], 16), 16))
        assert image.cfstring(entry) == row["entry_name"]
        assert image.cfstring(code) == row["fourcc"]
        aliases[row["fourcc"]].append(row["entry_name"])
    assert dict(aliases) == json.loads((ROOT / "src" / "image_types.json").read_text())
    assert len(aliases) == 203

    fingerprint = json.loads((EVIDENCE / "fingerprint-object-order.json").read_text())
    raw = bytes.fromhex(fingerprint["table_hex"])
    assert inputs["libcryptex_core.dylib"].read(int(fingerprint["table_ea"], 16), 16) == raw
    assert [v.to_bytes(4, "big").decode("ascii") for v in struct.unpack("<4I", raw)] == fingerprint["fourccs"]
    print(json.dumps({"binaries": identities, "der_spec_tables": len(specs),
                      "property_records": len(properties), "image_entries": len(rows),
                      "distinct_image_codes": len(aliases)}, indent=2))


if __name__ == "__main__":
    main()
