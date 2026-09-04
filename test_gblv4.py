#!/usr/bin/env python3
"""Tests for gblv4.py.

Most tests build a small synthetic GBL v4 file in memory (no vendor firmware
is included in this repository). The synthetic file follows the layout of
the IKEA KAJPLATS images: Matter OTA header, MANIFEST with certificate and
ECDSA P-256 signature, UPDATE_MEMORY_SECTION, LZMA-alone blob, optional PAD,
and an ApplicationProperties_t struct with an embedded certificate and an
application signature inside the plain image.

Signature-related assertions run only when the optional "cryptography"
package is installed; without it the tool reports those checks as skipped
and the tests accept that.

Set GBLV4_DCL_TESTS=1 to also download three public IKEA OTA files from the
URLs published in the CSA Distributed Compliance Ledger and check the
figures quoted in README.md. Set GBLV4_DCL_CACHE to a directory to keep the
downloads between runs.

Run:  python3 -m unittest -v
"""

import contextlib
import hashlib
import io
import json
import lzma
import os
import struct
import tempfile
import unittest
import urllib.request

import gblv4

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

POINTER_BASE = 0x01008000   # what the GBL calls targetAddr
LINK_BASE = 0x11008000      # what the reset vector uses (a different alias of the same memory)


def tlv(tag, body):
    return struct.pack("<II", tag, len(body)) + body


def prng(seed, n):
    """Deterministic filler bytes (SHA-256 counter stream)."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"%d:%d" % (seed, i)).digest()
        i += 1
    return bytes(out[:n])


class Signer:
    """ECDSA P-256 signer with a throwaway key, or a dummy when cryptography is absent."""

    def __init__(self, seed=99):
        if HAVE_CRYPTO:
            self.key = ec.generate_private_key(ec.SECP256R1())
            nums = self.key.public_key().public_numbers()
            self.xy = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
        else:
            self.key = None
            self.xy = prng(seed, 64)
        # ApplicationCertificate_t: structVersion u8, flags[3], key[64], version u32, signature[64].
        # Real certificates are signed by a vendor key that is not in the file; here the
        # certificate signs itself so that it differs between signers like the real ones do.
        # ECDSA signatures are randomised, so the certificate is made once per signer.
        body = bytes([1]) + bytes(3) + self.xy + struct.pack("<I", 2)
        self.cert = body + self.sign(body)

    def sign(self, message):
        if not HAVE_CRYPTO:
            return bytes(64)
        der = self.key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def make_certificate(signer):
    return signer.cert


def make_plain_image(signer, seed=1, size=4096, app_type=0x23, app_version=1):
    """A fake Cortex-M image: vector table, filler, planted strings, a
    sl_zigbee_version_t-shaped struct, ApplicationProperties_t, embedded
    certificate, application signature at the very end."""
    cert = make_certificate(signer)
    sig_off = size - 64
    cert_off = sig_off - 136
    ap_off = cert_off - 80
    ap_off -= ap_off % 4
    img = bytearray(prng(seed, size))
    # vector table: word0 initial SP, word1 reset vector (Thumb, secure alias), word13 -> ApplicationProperties
    struct.pack_into("<II", img, 0, 0x20001000, LINK_BASE + 0x41)
    struct.pack_into("<I", img, 13 * 4, POINTER_BASE + ap_off)
    # planted strings and a GA version struct (build 12, 8.1.1, special 0, type GA, pad)
    planted = b"\x00SYNTHETIC-GBL4-TEST v1.2.3\x00SL-OPENTHREAD/9.9.9.9_test; EFR32; Jan  1 2000 00:00:00\x00"
    img[0x200:0x200 + len(planted)] = planted
    img[0x300:0x308] = struct.pack("<HBBBBBB", 12, 8, 1, 1, 0, 0xAA, 0)
    # ApplicationProperties_t [2]: magic[16], structVersion, signatureType, signatureLocation,
    # app{type, version, capabilities, productId[16]}, cert*, longTokenSectionAddress*, decryptKey[16]
    ap = gblv4.APPLICATION_PROPERTIES_MAGIC + struct.pack("<III", 0x201, 1, POINTER_BASE + sig_off)
    ap += struct.pack("<III", app_type, app_version, 0) + bytes(16)
    ap += struct.pack("<II", POINTER_BASE + cert_off, 0) + bytes(16)
    img[ap_off:ap_off + 80] = ap
    img[cert_off:cert_off + 136] = cert
    img[sig_off:sig_off + 64] = signer.sign(bytes(img[:sig_off]))
    return bytes(img), {"ap_off": ap_off, "cert_off": cert_off, "sig_off": sig_off}


def lzma_alone(plain):
    return lzma.compress(plain, format=lzma.FORMAT_ALONE,
                         filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 8192, "lc": 1, "lp": 1, "pb": 2}])


def make_gbl(signer, plain, app_type=0x23, app_version=1, pad=True):
    cert = make_certificate(signer)
    blob = lzma_alone(plain)
    msi_body = struct.pack("<BBBBHH", 2, 0, 0, 0, 0, 0) + bytes(12) + hashlib.sha256(plain).digest() + bytes(32) + bytes(128)
    msi = tlv(gblv4.TAG_MEMORY_SECTION_INFO, msi_body)
    mem = tlv(gblv4.TAG_MEMORY_SECTION, msi + tlv(gblv4.TAG_BLOB, blob))
    # manifest body sizes are fixed, so memorySectionPos is known in advance: 8 (GBLV4 hdr) + 8 + 396
    manifest_len = (8 + 136) + (8 + 68) + (8 + 8) + (8 + 24) + (8 + 36) + (8 + (8 + 60) + 8)
    mem_pos = 8 + 8 + manifest_len
    ums_body = bytes([0]) + len(plain).to_bytes(3, "little")
    ums_body += struct.pack("<IIIII", POINTER_BASE, app_type, app_version, 0, mem_pos)
    ums_body += struct.pack("<I", 1) + hashlib.sha256(msi).digest()
    update = tlv(gblv4.TAG_UPDATE_PROCESS, tlv(gblv4.TAG_UPDATE_MEMORY_SECTION, ums_body) + tlv(gblv4.TAG_MANIFEST_FINISH, b""))
    tail = mem
    if pad:
        n = (4 - (8 + manifest_len + len(mem)) % 4) % 4
        if n:
            tail += tlv(gblv4.TAG_PAD, b"\xff" * n)
    content_hash = tlv(gblv4.TAG_CONTENT_HASH, struct.pack("<I", 1) + hashlib.sha256(tail).digest())
    signed = tlv(gblv4.TAG_MANIFEST_INFO, struct.pack("<II", 0x04000000, 1)) + tlv(gblv4.TAG_BUNDLE_VERSION, bytes(24)) + content_hash + update
    sig = tlv(gblv4.TAG_MANIFEST_SIGNATURE, struct.pack("<I", 2) + signer.sign(signed))
    manifest = tlv(gblv4.TAG_MANIFEST, tlv(gblv4.TAG_MANIFEST_CERTIFICATE, cert) + sig + signed)
    assert len(manifest) == 8 + manifest_len
    return tlv(gblv4.TAG_GBLV4, manifest + tail)


def matter_wrap(gbl, vendor_id=0x1234, product_id=0x5678, version=0x01020000, version_string="1.2.0"):
    """Matter OTA image header [3] 11.21: FileIdentifier, TotalSize, HeaderSize, then a TLV structure."""
    body = b"\x15"
    body += b"\x25\x00" + struct.pack("<H", vendor_id)          # uint16, context tag 0
    body += b"\x25\x01" + struct.pack("<H", product_id)         # uint16, tag 1
    body += b"\x26\x02" + struct.pack("<I", version)            # uint32, tag 2
    body += b"\x2c\x03" + bytes([len(version_string)]) + version_string.encode()  # utf8, tag 3
    body += b"\x26\x04" + struct.pack("<I", len(gbl))           # uint32, tag 4
    body += b"\x24\x08" + b"\x01"                               # uint8, tag 8 (SHA-256)
    body += b"\x30\x09" + b"\x20" + hashlib.sha256(gbl).digest()  # octet string, tag 9
    body += b"\x18"
    total = 16 + len(body) + len(gbl)
    return struct.pack("<IQI", gblv4.MATTER_OTA_MAGIC, total, len(body)) + body + gbl


def run_main(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = gblv4.main(argv)
    return rc, out.getvalue()


class SyntheticBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = Signer()
        cls.plain, cls.layout = make_plain_image(cls.signer)
        cls.gbl = make_gbl(cls.signer, cls.plain)
        cls.ota = matter_wrap(cls.gbl)
        cls.tmp = tempfile.mkdtemp(prefix="gblv4-test-")

    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path


class TestParse(SyntheticBase):
    def test_raw_gbl_all_checks_ok(self):
        r = gblv4.parse_file(self.gbl)
        self.assertIsNone(r["matterHeader"])
        self.assertEqual(r["gblOffset"], 0)
        failed = [k for k, v in gblv4.all_checks(r) if not v]
        self.assertEqual(failed, [])
        names = [t["name"] for t in r["tlvs"]]
        self.assertEqual(names[:3], ["GBLV4", "MANIFEST", "MANIFEST_CERTIFICATE"])
        self.assertIn("MEMORY_SECTION_INFO", names)
        self.assertIn("BLOB", names)

    def test_matter_wrapper(self):
        r = gblv4.parse_file(self.ota)
        mh = r["matterHeader"]
        self.assertEqual(mh["vendorId"], 0x1234)
        self.assertEqual(mh["productId"], 0x5678)
        self.assertEqual(mh["softwareVersionString"], "1.2.0")
        self.assertEqual(r["gblOffset"], 16 + mh["headerSize"])
        self.assertTrue(all(mh["checks"].values()))
        failed = [k for k, v in gblv4.all_checks(r) if not v]
        self.assertEqual(failed, [])
        # memorySectionPos is relative to the GBL start, so the check must still hold behind a Matter header
        self.assertTrue(r["checks"]["memorySectionPos points at MEMORY_SECTION"])

    def test_plain_image_hash_size_and_words(self):
        r = gblv4.parse_file(self.ota)
        p = r["plainImage"]
        self.assertEqual(p["length"], len(self.plain))
        self.assertEqual(p["sha256"], hashlib.sha256(self.plain).hexdigest())
        self.assertEqual(p["word0"], "0x20001000")
        self.assertEqual(p["word1"], "0x%08x" % (LINK_BASE + 0x41))
        self.assertEqual(r["updateMemorySection"]["plainImageSize"], len(self.plain))
        self.assertEqual(r["blob"]["lzma"]["dictSize"], 8192)
        self.assertEqual((r["blob"]["lzma"]["lc"], r["blob"]["lzma"]["lp"], r["blob"]["lzma"]["pb"]), (1, 1, 2))

    def test_application_properties(self):
        r = gblv4.parse_file(self.ota)
        ap = r["applicationProperties"]
        self.assertEqual(ap["offset"], self.layout["ap_off"])
        self.assertEqual(ap["structVersion"], "0x00000201")
        self.assertEqual(ap["signatureTypeName"], "ECDSA_P256")
        self.assertEqual(ap["app"]["typeNames"], ["ZIGBEE", "THREAD", "BLUETOOTH_APP"])
        self.assertEqual(ap["certOffset"], self.layout["cert_off"])
        self.assertEqual(ap["signatureOffset"], self.layout["sig_off"])
        self.assertEqual(ap["bytesAfterSignature"], 0)
        self.assertEqual(ap["pointerBase"], "0x%08x" % POINTER_BASE)
        self.assertEqual(ap["word13Base"], "0x%08x" % POINTER_BASE)
        self.assertTrue(ap["decryptKeyAllZero"])
        self.assertTrue(r["checks"]["embedded certificate == MANIFEST_CERTIFICATE"])
        self.assertTrue(r["checks"]["ApplicationProperties app.type == UPDATE_MEMORY_SECTION.type"])
        self.assertEqual(ap["embeddedCertificate"]["publicKeySha256"], r["certificate"]["publicKeySha256"])

    def test_signatures(self):
        r = gblv4.parse_file(self.ota)
        expected = "valid" if HAVE_CRYPTO else "skipped"
        self.assertEqual(r["manifestSignatureCheck"]["status"], expected)
        self.assertEqual(r["applicationSignatureCheck"]["status"], expected)
        self.assertEqual(r["manifestSignatureCheck"]["signedRange"], "0x%x..0x%x" % (16 + r["matterHeader"]["headerSize"] + 0xec, 16 + r["matterHeader"]["headerSize"] + 0x19c))

    def test_version_strings(self):
        r = gblv4.parse_file(self.ota)
        v = r["versions"]
        self.assertTrue(v["openThread"]["string"].startswith("SL-OPENTHREAD/9.9.9.9_test"))
        hits = [c for c in v["zigbeeStackCandidates"] if c["offset"] == 0x300]
        self.assertEqual(len(hits), 1)
        self.assertEqual((hits[0]["version"], hits[0]["build"], hits[0]["type"]), ("8.1.1", 12, "GA"))
        self.assertEqual(hits[0]["layout"], "build,major,minor,patch,special,type")

    def test_find_strings(self):
        found = gblv4.find_strings(self.plain, r"SYNTHETIC-GBL4")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][0], 0x201)
        self.assertEqual(found[0][1], "SYNTHETIC-GBL4-TEST v1.2.3")
        self.assertEqual(gblv4.find_strings(self.plain, r"NOT-THERE"), [])

    def test_pad_alignment(self):
        r = gblv4.parse_file(self.gbl)
        self.assertTrue(r["checks"]["GBLV4 length is a multiple of 4"])
        self.assertEqual(len(self.gbl) % 4, 0)
        if "pad" in r:
            self.assertTrue(r["pad"]["allFF"])
            self.assertIn(r["pad"]["length"], (1, 2, 3))
        # a plain image whose blob length forces every pad size
        seen = set()
        for seed in range(2, 40):
            plain, _ = make_plain_image(self.signer, seed=seed, size=2048 + seed)
            gbl = make_gbl(self.signer, plain)
            rr = gblv4.parse_file(gbl)
            self.assertTrue(rr["checks"]["GBLV4 length is a multiple of 4"])
            seen.add(rr.get("pad", {}).get("length", 0))
            if seen == {0, 1, 2, 3}:
                break
        self.assertEqual(seen, {0, 1, 2, 3})

    def test_print_report_and_exit_code(self):
        path = self.write("good.ota", self.ota)
        rc, out = run_main([path])
        self.assertEqual(rc, 0)
        self.assertIn("[ok] CONTENT_HASH == sha256(file after MANIFEST)", out)
        self.assertIn("[ok] finalImageHash[0:32] == sha256(plain image)", out)
        self.assertNotIn("FAIL", out)
        self.assertIn("ApplicationProperties at plain offset", out)


class TestCli(SyntheticBase):
    def test_extract(self):
        path = self.write("good.ota", self.ota)
        out_path = os.path.join(self.tmp, "plain.bin")
        rc, out = run_main([path, "--extract", out_path])
        self.assertEqual(rc, 0)
        with open(out_path, "rb") as f:
            self.assertEqual(f.read(), self.plain)

    def test_json(self):
        path = self.write("good.ota", self.ota)
        out_path = os.path.join(self.tmp, "report.json")
        rc, out = run_main([path, "--json", out_path])
        self.assertEqual(rc, 0)
        with open(out_path) as f:
            r = json.load(f)
        self.assertEqual(r["plainImage"]["sha256"], hashlib.sha256(self.plain).hexdigest())
        self.assertTrue(all(r["checks"].values()))
        self.assertNotIn("_plain", r)

    def test_strings_cli(self):
        path = self.write("good.ota", self.ota)
        rc, out = run_main([path, "--strings", "OPENTHREAD|SYNTHETIC"])
        self.assertEqual(rc, 0)
        self.assertIn("0x00000201 SYNTHETIC-GBL4-TEST v1.2.3", out)
        self.assertIn("SL-OPENTHREAD/9.9.9.9_test", out)

    def test_diff_same_build(self):
        # same plain image, different certificate and signatures: the only differing run must be the cert+signature region
        other = Signer(seed=98)
        plain_b, layout_b = make_plain_image(other)
        self.assertEqual(layout_b, self.layout)
        pa = self.write("a.ota", self.ota)
        pb = self.write("b.ota", matter_wrap(make_gbl(other, plain_b), product_id=0x5679))
        rc, out = run_main(["--diff", pa, pb])
        self.assertEqual(rc, 0)
        self.assertIn("matter productId", out)
        self.assertIn("1 run(s)", out)
        self.assertIn("embedded certificate", out)
        if HAVE_CRYPTO:
            # key, certificate signature and application signature differ; structVersion, flags and version do not:
            # 4 unchanged bytes at the start, then 196 bytes, exactly what the real KAJPLATS siblings show
            self.assertIn("embedded certificate, application signature", out)
            self.assertRegex(out, r"0x%08x\.\.0x%08x\s+196 bytes" % (self.layout["cert_off"] + 4, self.layout["sig_off"] + 64))

    def test_diff_different_builds(self):
        plain_b, _ = make_plain_image(self.signer, seed=7, size=5000)
        pa = self.write("a.ota", self.ota)
        pb = self.write("c.ota", make_gbl(self.signer, plain_b))
        rc, out = run_main(["--diff", pa, pb])
        self.assertEqual(rc, 0)
        self.assertIn("differ in size (4096 vs 5000 bytes)", out)

    def test_diff_needs_two_files(self):
        path = self.write("good.ota", self.ota)
        with self.assertRaises(SystemExit):
            run_main(["--diff", path])


class TestBrokenInputs(SyntheticBase):
    def test_truncated(self):
        path = self.write("trunc.ota", self.ota[:len(self.ota) // 2])
        rc, out = run_main([path])
        self.assertEqual(rc, 2)
        self.assertIn("runs past its container", out)
        self.assertNotIn("Traceback", out)

    def test_truncated_inside_matter_header(self):
        path = self.write("trunc2.ota", self.ota[:30])
        rc, out = run_main([path])
        self.assertEqual(rc, 2)
        self.assertIn("parse error", out)

    def test_empty_and_random(self):
        rc, out = run_main([self.write("empty.ota", b"")])
        self.assertEqual(rc, 2)
        rc, out = run_main([self.write("random.ota", prng(5, 3000))])
        self.assertEqual(rc, 2)
        self.assertIn("not a GBL v4 payload", out)

    def test_gbl_v3_is_reported(self):
        data = bytearray(self.gbl)
        struct.pack_into("<I", data, 0, gblv4.TAG_GBL_V3_HEADER)
        rc, out = run_main([self.write("v3.gbl", bytes(data))])
        self.assertEqual(rc, 2)
        self.assertIn("GBL v3", out)

    def test_corrupt_blob(self):
        data = bytearray(self.ota)
        data[-100] ^= 0xFF
        rc, out = run_main([self.write("blob.ota", bytes(data))])
        self.assertEqual(rc, 1)
        self.assertIn("[FAIL] matter: imageDigest == sha256(payload)", out)
        self.assertIn("[FAIL] CONTENT_HASH == sha256(file after MANIFEST)", out)
        self.assertTrue("LZMA error" in out or "[FAIL] finalImageHash[0:32] == sha256(plain image)" in out)

    def test_corrupt_content_hash(self):
        r0 = gblv4.parse_file(self.gbl)
        ch = [t for t in r0["tlvs"] if t["name"] == "CONTENT_HASH"][0]
        data = bytearray(self.gbl)
        data[ch["offset"] + 8 + 10] ^= 0x01
        r = gblv4.parse_file(bytes(data))
        self.assertFalse(r["checks"]["CONTENT_HASH == sha256(file after MANIFEST)"])
        if HAVE_CRYPTO:
            self.assertEqual(r["manifestSignatureCheck"]["status"], "INVALID")
        rc, out = run_main([self.write("ch.gbl", bytes(data))])
        self.assertEqual(rc, 1)

    def test_corrupt_memory_section_info(self):
        r0 = gblv4.parse_file(self.gbl)
        msi = [t for t in r0["tlvs"] if t["name"] == "MEMORY_SECTION_INFO"][0]
        data = bytearray(self.gbl)
        data[msi["offset"] + 8 + 30] ^= 0x01     # inside finalImageHash
        r = gblv4.parse_file(bytes(data))
        self.assertFalse(r["checks"]["memSecHash == sha256(MEMORY_SECTION_INFO tlv)"])
        self.assertFalse(r["checks"]["finalImageHash[0:32] == sha256(plain image)"])

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_tampered_manifest_info_breaks_signature(self):
        r0 = gblv4.parse_file(self.gbl)
        info = [t for t in r0["tlvs"] if t["name"] == "MANIFEST_INFO"][0]
        data = bytearray(self.gbl)
        data[info["offset"] + 8 + 4] ^= 0x02     # features bit
        r = gblv4.parse_file(bytes(data))
        self.assertEqual(r["manifestSignatureCheck"]["status"], "INVALID")
        self.assertFalse(r["checks"]["manifest signature"])

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_tampered_plain_image_breaks_application_signature(self):
        plain = bytearray(self.plain)
        plain[0x100] ^= 0x01
        gbl = make_gbl(self.signer, bytes(plain))
        r = gblv4.parse_file(gbl)
        # container checks still pass (the GBL was rebuilt around the tampered image) ...
        self.assertTrue(r["checks"]["finalImageHash[0:32] == sha256(plain image)"])
        # ... but the signature inside the image no longer verifies
        self.assertEqual(r["applicationSignatureCheck"]["status"], "INVALID")
        self.assertFalse(r["checks"]["application signature"])

    def test_encrypted_blob_is_left_alone(self):
        r0 = gblv4.parse_file(self.gbl)
        msi = [t for t in r0["tlvs"] if t["name"] == "MEMORY_SECTION_INFO"][0]
        data = bytearray(self.gbl)
        data[msi["offset"] + 8 + 1] = 1          # encryptionScheme = AES-CCM
        r = gblv4.parse_file(bytes(data))
        self.assertNotIn("plainImage", r)
        self.assertIn("encrypted blob", r["blob"]["note"])


# ---------------------------------------------------------------------------
# Public files from the DCL (opt-in, needs network).

DCL_FILES = [
    # (pid, url, file size, sha256 of the file as in the DCL, plain image size, plain image sha256, certificate key sha256)
    (36871, "https://ota.matter.ikea.com/files/4476_36871_16908288_18482475-a249-4ca5-8fd0-a7f70c23c1b1.ota",
     812204, "b0a5c16b73f7c92121e11fcbb7412d582fe3d9f52edd33c912a5af70469b4b6a",
     1372980, "626718e5a5fd5d7bae65b0ad6067b4a00dbe60bd07839e76c01620dbe55e90ee",
     "0d12d14b457c388dd52a3b6dceb294335f5cc2dc12a2ee4e4671992aa21d942f"),
    (36866, "https://ota.matter.ikea.com/files/4476_36866_16908288_9844be7c-e3c9-4a98-80c0-34b77615b817.ota",
     797428, "61a4563a7c3baf65d1abb282eec988cb25c58d92bf68d5779c4be9adb5b8c68f",
     1345856, "babeb4f69f3e9d4cd14af1968e115cadc07f76f1c1a89ef0b855d51f93cbc5e9",
     "96a02abbdb38f81637214fb0a3c5278f394b83f340db1bb8bac36aa6b4bb8db1"),
]
DCL_GBL_V3 = ("https://ota.matter.ikea.com/files/4476_12289_16777231_57dc5bcf-8c27-4db6-ba37-fc3aa976be0f.ota",
              514929, "516db19fef595719b970bd2942968b5286e9235f9dcd793aeb87fe25698e6e45")


def fetch(url):
    cache = os.environ.get("GBLV4_DCL_CACHE")
    name = url.rsplit("/", 1)[-1]
    if cache:
        path = os.path.join(cache, name)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
    with urllib.request.urlopen(url, timeout=120) as r:
        data = r.read()
    if cache:
        os.makedirs(cache, exist_ok=True)
        with open(os.path.join(cache, name), "wb") as f:
            f.write(data)
    return data


@unittest.skipUnless(os.environ.get("GBLV4_DCL_TESTS"), "set GBLV4_DCL_TESTS=1 to download public IKEA OTA files from the DCL")
class TestDclFiles(unittest.TestCase):
    def test_kajplats_images(self):
        for pid, url, size, sha, plain_size, plain_sha, key_sha in DCL_FILES:
            data = fetch(url)
            self.assertEqual(len(data), size, url)
            self.assertEqual(hashlib.sha256(data).hexdigest(), sha, url)
            r = gblv4.parse_file(data)
            self.assertEqual(r["matterHeader"]["vendorId"], 4476)
            self.assertEqual(r["matterHeader"]["productId"], pid)
            self.assertEqual(r["matterHeader"]["softwareVersionString"], "1.2.0")
            self.assertEqual([k for k, v in gblv4.all_checks(r) if not v], [], url)
            self.assertEqual(r["plainImage"]["length"], plain_size)
            self.assertEqual(r["plainImage"]["sha256"], plain_sha)
            self.assertEqual(r["certificate"]["publicKeySha256"], key_sha)
            self.assertEqual(r["updateMemorySection"]["targetAddr"], "0x01008000")
            self.assertEqual(r["updateMemorySection"]["typeNames"], ["ZIGBEE", "THREAD", "BLUETOOTH_APP"])
            self.assertEqual(r["plainImage"]["word1"], "0x1100804d")
            self.assertEqual(r["applicationProperties"]["word13Base"], "0x01008000")
            self.assertTrue(r["versions"]["openThread"]["string"].startswith("SL-OPENTHREAD/2.6.1.0_GitHub-7f6723ffb"))
            ga = [c for c in r["versions"]["zigbeeStackCandidates"] if c["type"] == "GA"]
            self.assertEqual([(c["version"], c["build"]) for c in ga], [("8.1.1", 341)])
            expected = "valid" if HAVE_CRYPTO else "skipped"
            self.assertEqual(r["manifestSignatureCheck"]["status"], expected)
            self.assertEqual(r["applicationSignatureCheck"]["status"], expected)

    def test_gbl_v3_file_is_refused(self):
        url, size, sha = DCL_GBL_V3
        data = fetch(url)
        self.assertEqual(len(data), size)
        self.assertEqual(hashlib.sha256(data).hexdigest(), sha)
        with self.assertRaises(gblv4.FormatError) as cm:
            gblv4.parse_file(data)
        self.assertIn("GBL v3", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
