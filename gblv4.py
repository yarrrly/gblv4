#!/usr/bin/env python3
"""gblv4.py: parse and verify a Silicon Labs GBL v4 (Series 3 Gecko Bootloader)
update file, with or without the Matter OTA image header that wraps it when
the file is distributed through the Matter Distributed Compliance Ledger.

Written from public documentation only:

  [1] Silicon Labs, Gecko Bootloader User's Guide for Series 3 and Higher,
      "Gecko Bootloader File Format v4":
      https://docs.silabs.com/mcu-bootloader/latest/bootloader-user-guide-series3-and-higher/02-gecko-bootloader-file-format-v4
  [2] Silicon Labs, Gecko Bootloader API Reference, "Application Properties"
      (APPLICATION_PROPERTIES_MAGIC, APPLICATION_TYPE_* and
      APPLICATION_SIGNATURE_* values, ApplicationProperties_t,
      ApplicationData_t, ApplicationCertificate_t):
      https://docs.silabs.com/mcu-bootloader/latest/gecko-bootloader-api/application-properties
  [3] CSA, Matter Core Specification 1.4, section 11.21 "Over-the-Air (OTA)
      Software Update File Format" and Appendix A "Tag-length-value (TLV)
      Encoding Format".
  [4] Silicon Labs, Zigbee Stack API Reference 8.1.1, sl_zigbee_version_t and
      sl_zigbee_version_type_t (only for the optional stack-version search).
  [5] Silicon Labs, AN1496 "EFR32xG21 to SiXG301 Compatibility and Migration
      Guide", table 3.2 (code-bus and secure address ranges; only used to
      explain the difference between the two bases reported).

Field widths that [1] leaves open (signature and nonce sizes, the split of
the 212-byte MEMORY_SECTION_INFO, the layout of memSecHash) were taken from
the TLV lengths in real files and are confirmed by the hash and signature
checks this tool performs. README.md lists every such inference.

Only the Python standard library is required. If the optional "cryptography"
package is importable, the manifest signature and the application signature
are verified as ECDSA P-256 / SHA-256; otherwise those two steps are
reported as skipped.
"""

import argparse
import hashlib
import json
import lzma
import re
import struct
import sys

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# GBL v4 tag ids from [1]. PAD is not in [1]; see decode notes below.

TAG_GBLV4 = 0x84A617EB
TAG_MANIFEST = 0xAA01012A
TAG_MANIFEST_CERTIFICATE = 0x2B01012B
TAG_MANIFEST_SIGNATURE = 0x2B02022B
TAG_MANIFEST_INFO = 0x2B03032B
TAG_BUNDLE_VERSION = 0x2B04042B
TAG_CONTENT_HASH = 0x2B05052B
TAG_UPDATE_PROCESS = 0xAB06062B
TAG_UPDATE_SE = 0x2C02022C
TAG_UPDATE_MEMORY_SECTION = 0x2C03032C
TAG_MANIFEST_FINISH = 0x2C04042C
TAG_MEMORY_SECTION = 0xBA01013A
TAG_MEMORY_SECTION_INFO = 0x3B01013B
TAG_BLOB = 0x3B02023B
TAG_PAD = 0xEE0101EE

TAG_NAMES = {
    TAG_GBLV4: "GBLV4",
    TAG_MANIFEST: "MANIFEST",
    TAG_MANIFEST_CERTIFICATE: "MANIFEST_CERTIFICATE",
    TAG_MANIFEST_SIGNATURE: "MANIFEST_SIGNATURE",
    TAG_MANIFEST_INFO: "MANIFEST_INFO",
    TAG_BUNDLE_VERSION: "BUNDLE_VERSION",
    TAG_CONTENT_HASH: "CONTENT_HASH",
    TAG_UPDATE_PROCESS: "UPDATE_PROCESS",
    TAG_UPDATE_SE: "UPDATE_SE",
    TAG_UPDATE_MEMORY_SECTION: "UPDATE_MEMORY_SECTION",
    TAG_MANIFEST_FINISH: "MANIFEST_FINISH",
    TAG_MEMORY_SECTION: "MEMORY_SECTION",
    TAG_MEMORY_SECTION_INFO: "MEMORY_SECTION_INFO",
    TAG_BLOB: "BLOB",
    TAG_PAD: "PAD",
}

CONTAINER_TAGS = {TAG_GBLV4, TAG_MANIFEST, TAG_UPDATE_PROCESS, TAG_MEMORY_SECTION}

# GBL v3 header tag (Gecko Bootloader User's Guide for GSDK 4.0 and higher,
# "GBL file format"), recognised only to give a clear error message.
TAG_GBL_V3_HEADER = 0x03A617EB

# Application type bits, from [2].
APPLICATION_TYPES = {
    1 << 0: "ZIGBEE",
    1 << 1: "THREAD",
    1 << 2: "FLEX",
    1 << 3: "BLUETOOTH",
    1 << 4: "MCU",
    1 << 5: "BLUETOOTH_APP",
    1 << 6: "BOOTLOADER",
    1 << 7: "ZWAVE",
}

# Application signature types, from [2].
APPLICATION_SIGNATURE_TYPES = {0: "NONE", 1: "ECDSA_P256", 2: "CRC32"}

# ApplicationProperties_t magic, from [2].
APPLICATION_PROPERTIES_MAGIC = bytes.fromhex("13b779fac925ddb7adf3cfe0f1b614b8")

# MANIFEST_INFO.features: [1] says "encryption, compression etc." without
# listing bit values. Bit 0 is observed together with an LZMA-compressed
# blob, so it is labelled COMPRESSION here; other bits are shown by number.
FEATURE_BITS = {1: "COMPRESSION"}

COMPRESSION_SCHEMES = {0: "none", 1: "LZ4", 2: "LZMA"}      # [1]
ENCRYPTION_SCHEMES = {0: "none", 1: "AES-CCM"}              # [1]
HASH_TYPES = {1: "SHA-256"}          # [1] says "1=SHA"; the digests are 32 bytes
SIGNATURE_TYPES = {2: "ECDSA-P256"}  # observed value; verified as ECDSA P-256 / SHA-256

# sl_zigbee_version_type_t, from [4]: PRE_RELEASE 0x00, ALPHA_1..3 0x11..0x13,
# BETA_1..3 0x21..0x23, GA 0xAA. Only GA is searched for: the other codes
# are small values that occur all over a binary and produce false hits.
ZIGBEE_VERSION_TYPES = {0xAA: "GA"}

MATTER_OTA_MAGIC = 0x1BEEF11E        # [3] 11.21.2.1 FileIdentifier
MATTER_OTA_FIXED_HEADER = 16         # FileIdentifier u32, TotalSize u64, HeaderSize u32

MATTER_HEADER_FIELDS = {             # [3] 11.21.2.4 Header field, context tags
    0: "vendorId",
    1: "productId",
    2: "softwareVersion",
    3: "softwareVersionString",
    4: "payloadSize",
    5: "minApplicableVersion",
    6: "maxApplicableVersion",
    7: "releaseNotesUrl",
    8: "imageDigestType",
    9: "imageDigest",
}

OPENTHREAD_RE = re.compile(rb"SL-OPENTHREAD/[\x20-\x7e]+")
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


class FormatError(Exception):
    pass


# ---------------------------------------------------------------------------
# Matter TLV, [3] Appendix A. Only what the OTA header needs: one anonymous
# structure holding context-tagged integers, strings and byte strings.

def read_matter_tlv_struct(buf):
    out = {}
    if not buf or buf[0] != 0x15:
        raise FormatError("Matter OTA header does not start with an anonymous structure")
    i = 1
    while i < len(buf):
        control = buf[i]
        i += 1
        tag_control = control >> 5
        element = control & 0x1F
        if element == 0x18:            # end of container
            break
        if tag_control == 1:           # context-specific tag, 1 byte
            tag = buf[i]
            i += 1
        else:
            raise FormatError("unexpected tag control %d in Matter OTA header" % tag_control)
        if element in (0x00, 0x04):    # int8 / uint8
            value = buf[i]
            i += 1
        elif element in (0x01, 0x05):  # int16 / uint16
            value = struct.unpack_from("<H", buf, i)[0]
            i += 2
        elif element in (0x02, 0x06):  # int32 / uint32
            value = struct.unpack_from("<I", buf, i)[0]
            i += 4
        elif element in (0x03, 0x07):  # int64 / uint64
            value = struct.unpack_from("<Q", buf, i)[0]
            i += 8
        elif element in (0x0C, 0x0D, 0x10, 0x11):   # utf8 / byte string, 1- or 2-byte length
            if element in (0x0C, 0x10):
                length = buf[i]
                i += 1
            else:
                length = struct.unpack_from("<H", buf, i)[0]
                i += 2
            raw = buf[i:i + length]
            i += length
            value = raw.decode("utf-8", "replace") if element in (0x0C, 0x0D) else raw.hex()
        else:
            raise FormatError("unsupported Matter TLV element type 0x%02x" % element)
        out[MATTER_HEADER_FIELDS.get(tag, "tag%d" % tag)] = value
    return out


def parse_matter_header(data):
    """Return (header dict, payload offset) or (None, 0) if not a Matter OTA file."""
    if len(data) < MATTER_OTA_FIXED_HEADER:
        return None, 0
    magic, total_size, header_size = struct.unpack_from("<IQI", data, 0)
    if magic != MATTER_OTA_MAGIC:
        return None, 0
    if MATTER_OTA_FIXED_HEADER + header_size > len(data):
        raise FormatError("Matter OTA header (%d bytes) runs past the end of the file" % header_size)
    header = {
        "magic": "0x%08x" % magic,
        "totalSize": total_size,
        "headerSize": header_size,
    }
    tlv = data[MATTER_OTA_FIXED_HEADER:MATTER_OTA_FIXED_HEADER + header_size]
    header.update(read_matter_tlv_struct(tlv))
    payload_offset = MATTER_OTA_FIXED_HEADER + header_size
    header["payloadOffset"] = payload_offset
    checks = header.setdefault("checks", {})
    checks["totalSize == file size"] = (total_size == len(data))
    if "payloadSize" in header:
        checks["payloadSize == remaining bytes"] = (header["payloadSize"] == len(data) - payload_offset)
    if header.get("imageDigestType") == 1 and "imageDigest" in header:
        digest = hashlib.sha256(data[payload_offset:]).hexdigest()
        checks["imageDigest == sha256(payload)"] = (digest == header["imageDigest"])
    return header, payload_offset


# ---------------------------------------------------------------------------
# GBL v4 TLV walk.

class Tlv:
    __slots__ = ("offset", "tag", "length", "depth", "body_offset")

    def __init__(self, offset, tag, length, depth):
        self.offset = offset
        self.tag = tag
        self.length = length
        self.depth = depth
        self.body_offset = offset + 8

    @property
    def end(self):
        return self.body_offset + self.length

    @property
    def name(self):
        return TAG_NAMES.get(self.tag, "UNKNOWN")


def walk_tlvs(data, start, end, depth=0, out=None):
    """Flatten the TLV tree between start and end into a list in file order."""
    if out is None:
        out = []
    i = start
    while i + 8 <= end:
        tag, length = struct.unpack_from("<II", data, i)
        tlv = Tlv(i, tag, length, depth)
        if tlv.end > end:
            raise FormatError("TLV 0x%08x at 0x%x (length %d) runs past its container, which ends at 0x%x; truncated file?" % (tag, i, length, end))
        out.append(tlv)
        if tag in CONTAINER_TAGS:
            walk_tlvs(data, tlv.body_offset, tlv.end, depth + 1, out)
        i = tlv.end
    if i != end:
        raise FormatError("%d stray bytes at 0x%x" % (end - i, i))
    return out


def first(tlvs, tag):
    for t in tlvs:
        if t.tag == tag:
            return t
    return None


def bits_named(value, names):
    parts = [name for bit, name in names.items() if value & bit]
    rest = value & ~sum(names)
    if rest:
        parts.append("0x%x" % rest)
    return parts or ["none"]


def version_dotted(v):
    return "%d.%d.%d.%d" % ((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF)


# ---------------------------------------------------------------------------
# Leaf decoders. Each takes the body bytes and returns a dict.

def decode_certificate(body):
    # ApplicationCertificate_t, [2]: structVersion u8, flags[3], key[64]
    # (P-256 X then Y), version u32, signature[64] = 136 bytes.
    if len(body) != 136:
        return {"note": "unexpected length %d (ApplicationCertificate_t is 136 bytes)" % len(body)}
    key = body[4:68]
    return {
        "structVersion": body[0],
        "flags": body[1:4].hex(),
        "publicKeyLen": len(key),
        "publicKeySha256": hashlib.sha256(key).hexdigest(),
        "version": struct.unpack_from("<I", body, 68)[0],
        "signatureLen": len(body[72:136]),
    }


def decode_signature(body):
    if len(body) < 4:
        return {"note": "too short"}
    sig_type = struct.unpack_from("<I", body, 0)[0]
    return {
        "signatureType": sig_type,
        "signatureTypeName": SIGNATURE_TYPES.get(sig_type, "unknown"),
        "signatureLen": len(body) - 4,
    }


def decode_manifest_info(body):
    if len(body) < 8:
        return {"note": "too short"}
    version, features = struct.unpack_from("<II", body, 0)
    return {
        "version": "0x%08x" % version,
        "versionDotted": version_dotted(version),
        "features": features,
        "featureNames": bits_named(features, FEATURE_BITS),
    }


def decode_bundle_version(body):
    if len(body) < 24:
        return {"note": "too short"}
    product_id = body[:16]
    bundle_version, min_version = struct.unpack_from("<II", body, 16)
    return {
        "productId": product_id.hex(),
        "bundleVersion": bundle_version,
        "minVersion": min_version,
    }


def decode_content_hash(body):
    if len(body) < 4:
        return {"note": "too short"}
    hash_type = struct.unpack_from("<I", body, 0)[0]
    return {
        "hashType": hash_type,
        "hashTypeName": HASH_TYPES.get(hash_type, "unknown"),
        "hash": body[4:].hex(),
    }


def decode_update_se(body):
    if len(body) < 8:
        return {"note": "too short"}
    version, position = struct.unpack_from("<II", body, 0)
    return {"version": version, "tlvPosition": position}


def decode_update_memory_section(body):
    if len(body) < 28:
        return {"note": "too short"}
    target_memory = body[0]
    plain_image_size = int.from_bytes(body[1:4], "little")
    target_addr, app_type, version, capabilities, section_pos = struct.unpack_from("<IIIII", body, 4)
    hash_type = struct.unpack_from("<I", body, 24)[0]
    return {
        "targetMemory": target_memory,
        "plainImageSize": plain_image_size,
        "targetAddr": "0x%08x" % target_addr,
        "type": "0x%02x" % app_type,
        "typeNames": bits_named(app_type, APPLICATION_TYPES),
        "version": version,
        "capabilities": "0x%08x" % capabilities,
        "memorySectionPos": section_pos,
        "memSecHashType": hash_type,
        "memSecHashTypeName": HASH_TYPES.get(hash_type, "unknown"),
        "memSecHash": body[28:].hex(),
    }


def decode_memory_section_info(body):
    # 212 bytes = 8 fixed + nonce(12) + finalImageHash(64) + secureBootSign(128).
    # [1] marks finalImageHash and secureBootSign as reserved; the files seen
    # carry the SHA-256 of the plain image in finalImageHash[0:32].
    if len(body) < 8:
        return {"note": "too short"}
    compression, encryption, secure_boot, _reserved, sign_block_size, num_blocks = struct.unpack_from("<BBBBHH", body, 0)
    out = {
        "compressionScheme": compression,
        "compressionName": COMPRESSION_SCHEMES.get(compression, "unknown"),
        "encryptionScheme": encryption,
        "encryptionName": ENCRYPTION_SCHEMES.get(encryption, "unknown"),
        "secureBootScheme": secure_boot,
        "signBlockSize": sign_block_size,
        "numBlocks": num_blocks,
        "nonce": body[8:20].hex(),
        "finalImageHash": body[20:84].hex(),
        "secureBootSignAllZero": not any(body[84:]),
    }
    if len(body) != 212:
        out["note"] = "unexpected length %d (212 seen in every file so far)" % len(body)
    return out


def decode_lzma_alone_header(blob):
    if len(blob) < 13:
        return {"note": "too short for an LZMA-alone header"}
    props = blob[0]
    dict_size = struct.unpack_from("<I", blob, 1)[0]
    unpacked = struct.unpack_from("<Q", blob, 5)[0]
    return {
        "props": "0x%02x" % props,
        "lc": props % 9,
        "lp": (props // 9) % 5,
        "pb": props // 45,
        "dictSize": dict_size,
        "uncompressedSize": None if unpacked == 0xFFFFFFFFFFFFFFFF else unpacked,
    }


# ---------------------------------------------------------------------------
# Plain image: ApplicationProperties_t [2] and version strings.

def find_application_properties(plain, pointer_base):
    """Locate ApplicationProperties_t by its magic and decode it.

    Pointers inside the struct (cert, longTokenSectionAddress) and
    signatureLocation are absolute addresses; they are converted to image
    offsets with pointer_base, which is the GBL targetAddr for the image.
    Word 13 of the vector table holds a pointer to the struct ([2]); the
    base address it implies (word13 minus the struct offset) is reported as
    word13Base so it can be compared with targetAddr.
    """
    off = plain.find(APPLICATION_PROPERTIES_MAGIC)
    if off < 0:
        return None
    if off + 80 > len(plain):
        return {"offset": off, "note": "struct runs past the end of the image"}
    struct_version, sig_type, sig_loc = struct.unpack_from("<III", plain, off + 16)
    app_type, app_version, capabilities = struct.unpack_from("<III", plain, off + 28)
    product_id = plain[off + 40:off + 56]
    cert_ptr, long_token_ptr = struct.unpack_from("<II", plain, off + 56)
    decrypt_key = plain[off + 64:off + 80]
    ap = {
        "offset": off,
        "structVersion": "0x%08x" % struct_version,
        "signatureType": sig_type,
        "signatureTypeName": APPLICATION_SIGNATURE_TYPES.get(sig_type, "unknown"),
        "signatureLocation": "0x%08x" % sig_loc,
        "app": {
            "type": "0x%02x" % app_type,
            "typeNames": bits_named(app_type, APPLICATION_TYPES),
            "version": "0x%08x" % app_version,
            "capabilities": "0x%08x" % capabilities,
            "productId": product_id.hex(),
        },
        "cert": "0x%08x" % cert_ptr,
        "longTokenSectionAddress": "0x%08x" % long_token_ptr,
        "decryptKeyAllZero": not any(decrypt_key),
        "pointerBase": "0x%08x" % pointer_base if pointer_base is not None else None,
    }
    if len(plain) >= 56:
        word13 = struct.unpack_from("<I", plain, 13 * 4)[0]
        ap["word13"] = "0x%08x" % word13
        if word13 >= off:
            ap["word13Base"] = "0x%08x" % (word13 - off)
    if pointer_base is not None:
        cert_off = cert_ptr - pointer_base
        sig_off = sig_loc - pointer_base
        ap["certOffset"] = cert_off if 0 <= cert_off <= len(plain) - 136 else None
        ap["signatureOffset"] = sig_off if 0 <= sig_off <= len(plain) - 64 else None
        if ap["certOffset"] is not None:
            ap["embeddedCertificate"] = decode_certificate(plain[cert_off:cert_off + 136])
        if ap["signatureOffset"] is not None:
            ap["bytesAfterSignature"] = len(plain) - (sig_off + 64)
    return ap


def find_stack_versions(plain):
    """Heuristic search for an EmberZNet sl_zigbee_version_t [4].

    [4] lists the fields as major, minor, patch, special (uint8 each), build
    (uint16) and type; the images this tool was tested on carry build first
    (build u16, major, minor, patch, special, type). Both orders are tried
    and the matching one is named. Only type GA (0xAA) with special == 0
    and a following zero pad byte is searched for; this is a heuristic and
    every hit is printed so the reader can judge it.
    """
    hits = []
    n = len(plain)
    for i in range(0, n - 8, 2):
        b, ma, mi, pa, sp, ty, pad = struct.unpack_from("<HBBBBBB", plain, i)
        if ty in ZIGBEE_VERSION_TYPES and pad == 0 and sp == 0 and 5 <= ma <= 12 and mi < 10 and pa < 10 and 0 < b < 2048:
            hits.append({"offset": i, "layout": "build,major,minor,patch,special,type", "version": "%d.%d.%d" % (ma, mi, pa), "build": b, "type": ZIGBEE_VERSION_TYPES[ty]})
        ma, mi, pa, sp, b, ty, pad = struct.unpack_from("<BBBBHBB", plain, i)
        if ty in ZIGBEE_VERSION_TYPES and pad == 0 and sp == 0 and 5 <= ma <= 12 and mi < 10 and pa < 10 and 0 < b < 2048:
            hits.append({"offset": i, "layout": "major,minor,patch,special,build,type", "version": "%d.%d.%d" % (ma, mi, pa), "build": b, "type": ZIGBEE_VERSION_TYPES[ty]})
    return hits


def find_strings(plain, pattern, min_len=4):
    """Printable ASCII runs of at least min_len bytes that match pattern (a regex on the run)."""
    rx = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, plain):
        s = m.group(0)
        if rx.search(s):
            out.append((m.start(), s.decode("ascii")))
    return out


# ---------------------------------------------------------------------------
# Signature verification (optional, needs "cryptography").

def _ecdsa_p256_verify(key_xy, sig_rs, message):
    """Return 'valid', 'INVALID' or a dict with a skip reason."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError:
        return {"status": "skipped", "reason": "python package 'cryptography' not installed"}
    if len(key_xy) != 64 or len(sig_rs) != 64:
        return {"status": "skipped", "reason": "key or signature is not 64 bytes"}
    x = int.from_bytes(key_xy[:32], "big")
    y = int.from_bytes(key_xy[32:], "big")
    try:
        public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError:
        return {"status": "INVALID", "reason": "public key is not a point on P-256"}
    der = encode_dss_signature(int.from_bytes(sig_rs[:32], "big"), int.from_bytes(sig_rs[32:], "big"))
    try:
        public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return {"status": "valid"}
    except InvalidSignature:
        return {"status": "INVALID"}


def verify_manifest_signature(data, tlvs, cert, sig_tlv):
    """ECDSA P-256 / SHA-256 over the manifest content that follows the
    MANIFEST_SIGNATURE TLV, up to the end of the MANIFEST container: the
    MANIFEST_INFO, BUNDLE_VERSION, CONTENT_HASH and UPDATE_PROCESS TLVs
    including their headers. That range was found by trial against real
    files; [1] does not say what the signature covers."""
    manifest = first(tlvs, TAG_MANIFEST)
    signed_start = sig_tlv.end
    signed_end = manifest.end
    key = data[cert.body_offset + 4:cert.body_offset + 68]
    sig = data[sig_tlv.body_offset + 4:sig_tlv.end]
    res = _ecdsa_p256_verify(key, sig, data[signed_start:signed_end])
    res["signedRange"] = "0x%x..0x%x" % (signed_start, signed_end)
    return res


def verify_application_signature(plain, ap):
    """ECDSA P-256 / SHA-256 over plain[0:signatureOffset] with the key of the
    certificate embedded in the image ([2]: the signature is over the
    SHA-256 digest of the application; the range up to signatureLocation is
    what verifies against real files)."""
    if ap.get("signatureType") != 1:
        return {"status": "skipped", "reason": "application signatureType %s is not ECDSA_P256" % ap.get("signatureType")}
    if ap.get("certOffset") is None or ap.get("signatureOffset") is None:
        return {"status": "skipped", "reason": "certificate or signature pointer does not fall inside the image"}
    key = plain[ap["certOffset"] + 4:ap["certOffset"] + 68]
    sig = plain[ap["signatureOffset"]:ap["signatureOffset"] + 64]
    res = _ecdsa_p256_verify(key, sig, plain[:ap["signatureOffset"]])
    res["signedRange"] = "plain[0x0..0x%x]" % ap["signatureOffset"]
    return res


# ---------------------------------------------------------------------------
# Main parse.

def parse_file(data, want_plain=False, want_versions=True):
    report = {"size": len(data), "checks": {}}
    matter, base = parse_matter_header(data)
    report["matterHeader"] = matter
    report["gblOffset"] = base

    if len(data) < base + 8:
        raise FormatError("file is too short to hold a GBL header at offset 0x%x" % base)
    head = struct.unpack_from("<I", data, base)[0]
    if head == TAG_GBL_V3_HEADER:
        raise FormatError("payload at offset 0x%x is a GBL v3 file (header tag 0x%08x); this tool handles GBL v4 only" % (base, head))
    if head != TAG_GBLV4:
        raise FormatError("no GBLV4 tag at offset 0x%x (found 0x%08x); not a GBL v4 payload" % (base, head))

    tlvs = walk_tlvs(data, base, len(data))
    rows = []
    for t in tlvs:
        rows.append({
            "offset": t.offset,
            "gblOffset": t.offset - base,
            "tag": "0x%08x" % t.tag,
            "name": t.name,
            "length": t.length,
            "depth": t.depth,
        })
    report["tlvs"] = rows
    checks = report["checks"]

    gbl = tlvs[0]
    checks["GBLV4 spans to end of file"] = (gbl.end == len(data))
    if gbl.end == len(data):
        checks["GBLV4 length is a multiple of 4"] = ((gbl.end - base) % 4 == 0)

    cert = first(tlvs, TAG_MANIFEST_CERTIFICATE)
    sig = first(tlvs, TAG_MANIFEST_SIGNATURE)
    info = first(tlvs, TAG_MANIFEST_INFO)
    bundle = first(tlvs, TAG_BUNDLE_VERSION)
    content_hash = first(tlvs, TAG_CONTENT_HASH)
    manifest = first(tlvs, TAG_MANIFEST)
    ums = first(tlvs, TAG_UPDATE_MEMORY_SECTION)
    use = first(tlvs, TAG_UPDATE_SE)
    mem = first(tlvs, TAG_MEMORY_SECTION)
    msi = first(tlvs, TAG_MEMORY_SECTION_INFO)
    blob = first(tlvs, TAG_BLOB)
    pad = first(tlvs, TAG_PAD)

    def body(t):
        return data[t.body_offset:t.end]

    if cert:
        report["certificate"] = decode_certificate(body(cert))
    if sig:
        report["manifestSignature"] = decode_signature(body(sig))
    if info:
        report["manifestInfo"] = decode_manifest_info(body(info))
    if bundle:
        report["bundleVersion"] = decode_bundle_version(body(bundle))
    if use:
        report["updateSe"] = decode_update_se(body(use))
    if pad:
        report["pad"] = {"length": pad.length, "allFF": all(b == 0xFF for b in body(pad))}
    if content_hash and manifest:
        ch = decode_content_hash(body(content_hash))
        report["contentHash"] = ch
        if ch.get("hashType") == 1:
            actual = hashlib.sha256(data[manifest.end:]).hexdigest()
            checks["CONTENT_HASH == sha256(file after MANIFEST)"] = (actual == ch["hash"])
    target_addr = None
    if ums:
        u = decode_update_memory_section(body(ums))
        report["updateMemorySection"] = u
        if "targetAddr" in u:
            target_addr = int(u["targetAddr"], 16)
            if mem:
                checks["memorySectionPos points at MEMORY_SECTION"] = (base + u["memorySectionPos"] == mem.offset)
            if msi and u["memSecHashType"] == 1:
                actual = hashlib.sha256(data[msi.offset:msi.end]).hexdigest()
                checks["memSecHash == sha256(MEMORY_SECTION_INFO tlv)"] = (actual == u["memSecHash"])
    m = {}
    if msi:
        m = decode_memory_section_info(body(msi))
        report["memorySectionInfo"] = m
    plain = None
    if blob:
        b = body(blob)
        report["blob"] = {"offset": blob.body_offset, "length": len(b), "sha256": hashlib.sha256(b).hexdigest()}
        if m.get("encryptionScheme", 0) != 0:
            report["blob"]["note"] = "encrypted blob (scheme %d), not decompressed" % m["encryptionScheme"]
        elif m.get("compressionScheme") == 2:
            report["blob"]["lzma"] = decode_lzma_alone_header(b)
            try:
                plain = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(b)
            except lzma.LZMAError as e:
                report["blob"]["lzmaError"] = str(e)
                checks["BLOB decompresses"] = False
        elif m.get("compressionScheme") == 0:
            plain = b
        else:
            report["blob"]["note"] = "compression scheme %s not handled" % m.get("compressionScheme")
    if plain is not None:
        p = {
            "length": len(plain),
            "sha256": hashlib.sha256(plain).hexdigest(),
        }
        if len(plain) >= 8:
            sp, pc = struct.unpack_from("<II", plain, 0)
            p["word0"] = "0x%08x" % sp
            p["word1"] = "0x%08x" % pc
        report["plainImage"] = p
        if "finalImageHash" in m:
            checks["finalImageHash[0:32] == sha256(plain image)"] = (m["finalImageHash"][:64] == p["sha256"])
        if ums and "plainImageSize" in report["updateMemorySection"]:
            checks["plainImageSize == len(plain image)"] = (report["updateMemorySection"]["plainImageSize"] == len(plain))
        ap = find_application_properties(plain, target_addr)
        if ap:
            report["applicationProperties"] = ap
            if cert and ap.get("certOffset") is not None:
                checks["embedded certificate == MANIFEST_CERTIFICATE"] = (plain[ap["certOffset"]:ap["certOffset"] + 136] == body(cert))
            if ums and "type" in report["updateMemorySection"]:
                checks["ApplicationProperties app.type == UPDATE_MEMORY_SECTION.type"] = (ap["app"]["type"] == report["updateMemorySection"]["type"])
            report["applicationSignatureCheck"] = verify_application_signature(plain, ap)
            if report["applicationSignatureCheck"]["status"] == "INVALID":
                checks["application signature"] = False
        if want_versions:
            v = {}
            ot = OPENTHREAD_RE.search(plain)
            if ot:
                v["openThread"] = {"offset": ot.start(), "string": ot.group(0).decode("ascii", "replace")}
            v["zigbeeStackCandidates"] = find_stack_versions(plain)
            report["versions"] = v
        if want_plain:
            report["_plain"] = plain
    if cert and sig and manifest and report.get("manifestSignature", {}).get("signatureType") == 2:
        report["manifestSignatureCheck"] = verify_manifest_signature(data, tlvs, cert, sig)
        if report["manifestSignatureCheck"]["status"] == "INVALID":
            checks["manifest signature"] = False
    return report


def all_checks(report):
    out = []
    mh = report.get("matterHeader")
    if mh:
        out += [("matter: " + k, v) for k, v in mh.get("checks", {}).items()]
    out += list(report["checks"].items())
    return out


# ---------------------------------------------------------------------------
# Output.

def print_report(path, report, out=None):
    w = (out or sys.stdout).write
    w("== %s (%d bytes)\n" % (path, report["size"]))
    mh = report.get("matterHeader")
    if mh:
        w("Matter OTA header: vendorId=0x%04x productId=0x%04x softwareVersion=%s (%s) payloadSize=%s digestType=%s\n" % (
            mh.get("vendorId", 0), mh.get("productId", 0), mh.get("softwareVersion"),
            mh.get("softwareVersionString"), mh.get("payloadSize"), mh.get("imageDigestType")))
        w("  payload (GBL) starts at file offset %d\n" % mh["payloadOffset"])
    else:
        w("No Matter OTA header; GBL starts at offset 0\n")
    w("\n%-10s %-10s %-10s %-22s %10s\n" % ("file off", "gbl off", "tag", "name", "length"))
    for r in report["tlvs"]:
        w("0x%08x 0x%08x %s %s%-22s %10d\n" % (
            r["offset"], r["gblOffset"], r["tag"], "  " * r["depth"], r["name"], r["length"]))
    w("\n")
    if "certificate" in report:
        c = report["certificate"]
        if "note" in c:
            w("MANIFEST_CERTIFICATE: %s\n" % c["note"])
        else:
            w("MANIFEST_CERTIFICATE: structVersion=%d flags=%s version=%d key P-256 (%d bytes) sha256=%s\n" % (
                c["structVersion"], c["flags"], c["version"], c["publicKeyLen"], c["publicKeySha256"]))
    if "manifestSignature" in report and "signatureType" in report["manifestSignature"]:
        s = report["manifestSignature"]
        w("MANIFEST_SIGNATURE: type=%d (%s), %d bytes\n" % (s["signatureType"], s["signatureTypeName"], s["signatureLen"]))
    if "manifestInfo" in report and "version" in report["manifestInfo"]:
        i = report["manifestInfo"]
        w("MANIFEST_INFO: version=%s (%s) features=%d %s\n" % (i["version"], i["versionDotted"], i["features"], i["featureNames"]))
    if "bundleVersion" in report and "productId" in report["bundleVersion"]:
        b = report["bundleVersion"]
        w("BUNDLE_VERSION: productId=%s bundleVersion=%d minVersion=%d\n" % (b["productId"], b["bundleVersion"], b["minVersion"]))
    if "contentHash" in report and "hash" in report["contentHash"]:
        c = report["contentHash"]
        w("CONTENT_HASH: type=%d (%s) %s\n" % (c["hashType"], c["hashTypeName"], c["hash"]))
    if "updateSe" in report and "version" in report["updateSe"]:
        u = report["updateSe"]
        w("UPDATE_SE: version=%d tlvPosition=%d\n" % (u["version"], u["tlvPosition"]))
    if "updateMemorySection" in report and "targetAddr" in report["updateMemorySection"]:
        u = report["updateMemorySection"]
        w("UPDATE_MEMORY_SECTION: targetMemory=%d plainImageSize=%d targetAddr=%s type=%s %s version=%d capabilities=%s memorySectionPos=%d\n" % (
            u["targetMemory"], u["plainImageSize"], u["targetAddr"], u["type"], "|".join(u["typeNames"]),
            u["version"], u["capabilities"], u["memorySectionPos"]))
        w("  memSecHash type=%d (%s) %s\n" % (u["memSecHashType"], u["memSecHashTypeName"], u["memSecHash"]))
    if "memorySectionInfo" in report and "compressionScheme" in report["memorySectionInfo"]:
        m = report["memorySectionInfo"]
        w("MEMORY_SECTION_INFO: compression=%d (%s) encryption=%d (%s) secureBoot=%d signBlockSize=%d numBlocks=%d nonce=%s\n" % (
            m["compressionScheme"], m["compressionName"], m["encryptionScheme"], m["encryptionName"],
            m["secureBootScheme"], m["signBlockSize"], m["numBlocks"], m["nonce"]))
        w("  finalImageHash=%s\n" % m["finalImageHash"])
    if "blob" in report:
        b = report["blob"]
        w("BLOB: offset=%d length=%d sha256=%s\n" % (b["offset"], b["length"], b["sha256"]))
        if "lzma" in b and "props" in b["lzma"]:
            l = b["lzma"]
            w("  LZMA-alone header: props=%s lc=%d lp=%d pb=%d dictSize=%d uncompressedSize=%s\n" % (
                l["props"], l["lc"], l["lp"], l["pb"], l["dictSize"], l["uncompressedSize"]))
        if "lzmaError" in b:
            w("  LZMA error: %s\n" % b["lzmaError"])
        if "note" in b:
            w("  %s\n" % b["note"])
    if "pad" in report:
        w("PAD: %d byte(s)%s\n" % (report["pad"]["length"], ", all 0xFF" if report["pad"]["allFF"] else ""))
    if "plainImage" in report:
        p = report["plainImage"]
        w("plain image: %d bytes sha256=%s" % (p["length"], p["sha256"]))
        if "word0" in p:
            w(" word0=%s word1=%s" % (p["word0"], p["word1"]))
        w("\n")
    if "applicationProperties" in report:
        ap = report["applicationProperties"]
        if "note" in ap:
            w("ApplicationProperties at plain offset 0x%x: %s\n" % (ap["offset"], ap["note"]))
        else:
            w("ApplicationProperties at plain offset 0x%x: structVersion=%s signatureType=%d (%s) signatureLocation=%s\n" % (
                ap["offset"], ap["structVersion"], ap["signatureType"], ap["signatureTypeName"], ap["signatureLocation"]))
            a = ap["app"]
            w("  app: type=%s %s version=%s capabilities=%s productId=%s\n" % (
                a["type"], "|".join(a["typeNames"]), a["version"], a["capabilities"], a["productId"]))
            w("  cert=%s longTokenSectionAddress=%s decryptKey=%s\n" % (
                ap["cert"], ap["longTokenSectionAddress"], "all zero" if ap["decryptKeyAllZero"] else "present"))
            if "word13" in ap:
                w("  vector table word 13=%s -> implies base %s; pointer base used here (targetAddr)=%s\n" % (
                    ap["word13"], ap.get("word13Base", "?"), ap.get("pointerBase")))
            if ap.get("certOffset") is not None:
                ec_ = ap.get("embeddedCertificate", {})
                w("  embedded certificate at plain offset 0x%x: version=%s key sha256=%s\n" % (
                    ap["certOffset"], ec_.get("version"), ec_.get("publicKeySha256")))
            if ap.get("signatureOffset") is not None:
                w("  application signature at plain offset 0x%x (%d bytes follow it)\n" % (ap["signatureOffset"], ap["bytesAfterSignature"]))
    if "versions" in report:
        v = report["versions"]
        if "openThread" in v:
            w("OpenThread build string at plain offset 0x%x: %s\n" % (v["openThread"]["offset"], v["openThread"]["string"]))
        cands = v.get("zigbeeStackCandidates", [])
        if cands:
            for c in cands:
                w("Zigbee stack version candidate at plain offset 0x%x: %s build %d %s (layout %s)\n" % (
                    c["offset"], c["version"], c["build"], c["type"], c["layout"]))
        else:
            w("Zigbee stack version: no sl_zigbee_version_t candidate found\n")
    for key, label in (("manifestSignatureCheck", "manifest signature"), ("applicationSignatureCheck", "application signature")):
        if key in report:
            s = report[key]
            w("%s: %s" % (label, s["status"]))
            if "signedRange" in s and s["status"] != "skipped":
                w(" over %s" % s["signedRange"])
            if "reason" in s:
                w(" (%s)" % s["reason"])
            w("\n")
    w("\nchecks:\n")
    checks = all_checks(report)
    for name, ok in checks:
        w("  [%s] %s\n" % ("ok" if ok else "FAIL", name))
    return all(v for _, v in checks)


# ---------------------------------------------------------------------------
# --diff

def merge_runs(diff_positions, gap=8):
    runs = []
    for pos in diff_positions:
        if runs and pos - runs[-1][1] <= gap:
            runs[-1][1] = pos + 1
        else:
            runs.append([pos, pos + 1])
    return runs


def region_name(ap, start, end):
    """Name the ApplicationProperties-related region a byte run falls into, if any."""
    if not ap or "note" in ap:
        return ""
    labels = []
    if ap.get("certOffset") is not None and start < ap["certOffset"] + 136 and end > ap["certOffset"]:
        labels.append("embedded certificate")
    if ap.get("signatureOffset") is not None and start < ap["signatureOffset"] + 64 and end > ap["signatureOffset"]:
        labels.append("application signature")
    if start < ap["offset"] + 80 and end > ap["offset"]:
        labels.append("ApplicationProperties struct")
    return ", ".join(labels)


def diff_reports(a_path, a, a_plain, b_path, b, b_plain, out=None, max_runs=40):
    w = (out or sys.stdout).write
    w("== diff %s | %s\n\n" % (a_path, b_path))

    def field(label, fa, fb):
        w("%-34s %-44s %-44s %s\n" % (label, str(fa)[:44], str(fb)[:44], "same" if fa == fb else "DIFFERENT"))

    w("%-34s %-44s %-44s\n" % ("field", "A", "B"))
    field("file size", a["size"], b["size"])
    ma, mb = a.get("matterHeader") or {}, b.get("matterHeader") or {}
    for k in ("vendorId", "productId", "softwareVersion", "softwareVersionString", "payloadSize", "minApplicableVersion", "maxApplicableVersion"):
        if k in ma or k in mb:
            field("matter " + k, ma.get(k), mb.get(k))
    for section, keys in (
        ("certificate", ("structVersion", "flags", "version", "publicKeySha256")),
        ("manifestInfo", ("version", "features")),
        ("bundleVersion", ("productId", "bundleVersion", "minVersion")),
        ("contentHash", ("hash",)),
        ("updateMemorySection", ("targetMemory", "plainImageSize", "targetAddr", "type", "version", "capabilities", "memorySectionPos", "memSecHash")),
        ("memorySectionInfo", ("compressionScheme", "encryptionScheme", "secureBootScheme", "signBlockSize", "numBlocks", "nonce", "finalImageHash")),
        ("blob", ("length", "sha256")),
        ("plainImage", ("length", "sha256", "word0", "word1")),
        ("pad", ("length",)),
    ):
        sa, sb = a.get(section) or {}, b.get(section) or {}
        for k in keys:
            if k in sa or k in sb:
                field("%s.%s" % (section, k), sa.get(k), sb.get(k))
    apa, apb = a.get("applicationProperties") or {}, b.get("applicationProperties") or {}
    for k in ("offset", "structVersion", "signatureType", "signatureLocation", "cert", "longTokenSectionAddress"):
        if k in apa or k in apb:
            field("appProps." + k, apa.get(k), apb.get(k))
    for k in ("type", "version", "capabilities", "productId"):
        if apa.get("app") or apb.get("app"):
            field("appProps.app." + k, (apa.get("app") or {}).get(k), (apb.get("app") or {}).get(k))
    va, vb = a.get("versions") or {}, b.get("versions") or {}
    field("openThread", (va.get("openThread") or {}).get("string"), (vb.get("openThread") or {}).get("string"))
    field("zigbeeStackCandidates", ["%s build %d %s" % (c["version"], c["build"], c["type"]) for c in va.get("zigbeeStackCandidates", [])],
          ["%s build %d %s" % (c["version"], c["build"], c["type"]) for c in vb.get("zigbeeStackCandidates", [])])

    w("\n")
    if a_plain is None or b_plain is None:
        w("plain image comparison skipped (one of the files has no decompressed image)\n")
        return
    if len(a_plain) != len(b_plain):
        common = 0
        for x, y in zip(a_plain, b_plain):
            if x != y:
                break
            common += 1
        w("plain images differ in size (%d vs %d bytes); common prefix %d bytes; these are different builds\n" % (len(a_plain), len(b_plain), common))
        return
    positions = [i for i in range(len(a_plain)) if a_plain[i] != b_plain[i]]
    if not positions:
        w("plain images are identical (%d bytes)\n" % len(a_plain))
        return
    runs = merge_runs(positions)
    w("plain images: %d bytes differ in %d run(s) (runs closer than 8 bytes merged):\n" % (len(positions), len(runs)))
    for start, end in runs[:max_runs]:
        w("  0x%08x..0x%08x  %6d bytes  %s\n" % (start, end, end - start, region_name(apa, start, end)))
    if len(runs) > max_runs:
        w("  ... %d more run(s)\n" % (len(runs) - max_runs))


# ---------------------------------------------------------------------------

def load(path):
    with open(path, "rb") as f:
        return f.read()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Parse and verify a Silicon Labs GBL v4 file, with or without a Matter OTA header.",
        epilog="Exit status: 0 all checks ok, 1 a check failed or extraction impossible, 2 the file could not be parsed.")
    ap.add_argument("file", nargs="+", help="input .ota or .gbl file(s); exactly two with --diff")
    ap.add_argument("--extract", metavar="OUT", help="write the decompressed plain image to OUT (single input file only)")
    ap.add_argument("--json", metavar="OUT", help="write the report as JSON to OUT (single input file only)")
    ap.add_argument("--strings", metavar="REGEX", help="print printable strings of the plain image that match REGEX, with offsets, instead of the report")
    ap.add_argument("--min-len", type=int, default=4, help="minimum string length for --strings (default 4)")
    ap.add_argument("--diff", action="store_true", help="compare two files: header fields side by side, then byte runs that differ in the plain images")
    ap.add_argument("--version", action="version", version="gblv4.py " + __version__)
    args = ap.parse_args(argv)
    if (args.extract or args.json) and len(args.file) != 1:
        ap.error("--extract and --json take exactly one input file")
    if args.diff and len(args.file) != 2:
        ap.error("--diff takes exactly two input files")

    exit_code = 0
    if args.diff:
        reports = []
        for path in args.file:
            try:
                r = parse_file(load(path), want_plain=True)
            except (FormatError, struct.error, IndexError) as e:
                print("== %s: parse error: %s" % (path, e))
                return 2
            reports.append((path, r, r.pop("_plain", None)))
        (pa, ra, pla), (pb, rb, plb) = reports
        diff_reports(pa, ra, pla, pb, rb, plb)
        return 0

    for path in args.file:
        try:
            report = parse_file(load(path), want_plain=bool(args.extract or args.strings is not None))
        except (FormatError, struct.error, IndexError) as e:
            print("== %s: parse error: %s" % (path, e))
            exit_code = 2
            continue
        plain = report.pop("_plain", None)
        if args.strings is not None:
            print("== %s" % path)
            if plain is None:
                print("no plain image available")
                exit_code = 1
            else:
                for off, s in find_strings(plain, args.strings, args.min_len):
                    print("0x%08x %s" % (off, s))
            continue
        ok = print_report(path, report)
        if not ok:
            exit_code = 1
        if args.extract:
            if plain is None:
                print("no plain image available to extract")
                exit_code = 1
            else:
                with open(args.extract, "wb") as f:
                    f.write(plain)
                print("plain image written to %s (%d bytes)" % (args.extract, len(plain)))
        if args.json:
            report["file"] = path
            with open(args.json, "w") as f:
                json.dump(report, f, indent=1)
            print("report written to %s" % args.json)
        print()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
