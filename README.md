# gblv4

`gblv4.py` parses a Silicon Labs GBL v4 file, the update container of the
Series 3 Gecko Bootloader, and checks every hash and signature in it. It
also reads the Matter OTA image header that wraps such a file when a vendor
publishes it through the CSA Distributed Compliance Ledger (DCL). It is one
Python script on the standard library; the optional `cryptography` package
adds the two ECDSA checks.

The format is documented on docs.silabs.com. The one open implementation
found, [zigpy/pygbl](https://github.com/zigpy/pygbl) (Apache-2.0, August
2026), is a library that parses and re-serialises GBL v4 byte for byte, with
tag layouts taken from the SDK's Series 3 parser; it does not check the
hashes or signatures of a v4 file, decompress its sections, read the Matter
header, or offer a command line. The Silicon Labs tooling is Simplicity
Commander, which is closed, plus SDK sources under the MSLA. This script
covers the verification side from the public format page and the public
bootloader API reference, without reading SDK source. The section "Sources,
and what they leave out" lists every field width that had to be inferred
from real files instead.

The second half of this file is a case study: what the 18 IKEA KAJPLATS
images in the DCL contain, checked against a lamp on a bench.

## Quick start

```
python3 gblv4.py 4476_36871_16908288_18482475-a249-4ca5-8fd0-a7f70c23c1b1.ota
```

The report for that file (the KAJPLATS GU10 CWS 1.2.0 image) reads:

```
== 4476_36871_16908288_18482475-a249-4ca5-8fd0-a7f70c23c1b1.ota (812204 bytes)
Matter OTA header: vendorId=0x117c productId=0x9007 softwareVersion=16908288 (1.2.0) payloadSize=812120 digestType=1
  payload (GBL) starts at file offset 84

file off   gbl off    tag        name                       length
0x00000054 0x00000000 0x84a617eb GBLV4                      812112
0x0000005c 0x00000008 0xaa01012a   MANIFEST                      396
0x00000064 0x00000010 0x2b01012b     MANIFEST_CERTIFICATE          136
0x000000f4 0x000000a0 0x2b02022b     MANIFEST_SIGNATURE             68
0x00000140 0x000000ec 0x2b03032b     MANIFEST_INFO                   8
0x00000150 0x000000fc 0x2b04042b     BUNDLE_VERSION                 24
0x00000170 0x0000011c 0x2b05052b     CONTENT_HASH                   36
0x0000019c 0x00000148 0xab06062b     UPDATE_PROCESS                 76
0x000001a4 0x00000150 0x2c03032c       UPDATE_MEMORY_SECTION          60
0x000001e8 0x00000194 0x2c04042c       MANIFEST_FINISH                 0
0x000001f0 0x0000019c 0xba01013a   MEMORY_SECTION             811700
0x000001f8 0x000001a4 0x3b01013b     MEMORY_SECTION_INFO           212
0x000002d4 0x00000280 0x3b02023b     BLOB                       811472

MANIFEST_CERTIFICATE: structVersion=1 flags=000000 version=2 key P-256 (64 bytes) sha256=0d12d14b457c388dd52a3b6dceb294335f5cc2dc12a2ee4e4671992aa21d942f
MANIFEST_SIGNATURE: type=2 (ECDSA-P256), 64 bytes
MANIFEST_INFO: version=0x04000000 (4.0.0.0) features=1 ['COMPRESSION']
BUNDLE_VERSION: productId=00000000000000000000000000000000 bundleVersion=0 minVersion=0
CONTENT_HASH: type=1 (SHA-256) d1f7cf9c85d37a51fe37cc36435deba2a934ba89698c2df47afba02c8fd4aaf0
UPDATE_MEMORY_SECTION: targetMemory=0 plainImageSize=1372980 targetAddr=0x01008000 type=0x23 ZIGBEE|THREAD|BLUETOOTH_APP version=1 capabilities=0x00000000 memorySectionPos=412
  memSecHash type=1 (SHA-256) c604f17b1366b7c45ef65629f83fbaae724987b88653cce470602e30dff27532
MEMORY_SECTION_INFO: compression=2 (LZMA) encryption=0 (none) secureBoot=0 signBlockSize=0 numBlocks=0 nonce=000000000000000000000000
  finalImageHash=626718e5a5fd5d7bae65b0ad6067b4a00dbe60bd07839e76c01620dbe55e90ee0000000000000000000000000000000000000000000000000000000000000000
BLOB: offset=732 length=811472 sha256=98cd00ccba6ecec444c48d9d2a22f688cfeedfac34003732d6a3b55965ab948c
  LZMA-alone header: props=0x64 lc=1 lp=1 pb=2 dictSize=8192 uncompressedSize=1372980
plain image: 1372980 bytes sha256=626718e5a5fd5d7bae65b0ad6067b4a00dbe60bd07839e76c01620dbe55e90ee word0=0x20021da0 word1=0x1100804d
ApplicationProperties at plain offset 0x13c03c: structVersion=0x00000201 signatureType=1 (ECDSA_P256) signatureLocation=0x011572f4
  app: type=0x23 ZIGBEE|THREAD|BLUETOOTH_APP version=0x00000001 capabilities=0x00000000 productId=00000000000000000000000000000000
  cert=0x0115726c longTokenSectionAddress=0x00000000 decryptKey=all zero
  vector table word 13=0x0114403c -> implies base 0x01008000; pointer base used here (targetAddr)=0x01008000
  embedded certificate at plain offset 0x14f26c: version=2 key sha256=0d12d14b457c388dd52a3b6dceb294335f5cc2dc12a2ee4e4671992aa21d942f
  application signature at plain offset 0x14f2f4 (0 bytes follow it)
OpenThread build string at plain offset 0x14b7e2: SL-OPENTHREAD/2.6.1.0_GitHub-7f6723ffb; EFR32; Jun 18 2025 00:22:54
Zigbee stack version candidate at plain offset 0x14bfba: 8.1.1 build 341 GA (layout build,major,minor,patch,special,type)
manifest signature: valid over 0x140..0x1f0
application signature: valid over plain[0x0..0x14f2f4]

checks:
  [ok] matter: totalSize == file size
  [ok] matter: payloadSize == remaining bytes
  [ok] matter: imageDigest == sha256(payload)
  [ok] GBLV4 spans to end of file
  [ok] GBLV4 length is a multiple of 4
  [ok] CONTENT_HASH == sha256(file after MANIFEST)
  [ok] memorySectionPos points at MEMORY_SECTION
  [ok] memSecHash == sha256(MEMORY_SECTION_INFO tlv)
  [ok] finalImageHash[0:32] == sha256(plain image)
  [ok] plainImageSize == len(plain image)
  [ok] embedded certificate == MANIFEST_CERTIFICATE
  [ok] ApplicationProperties app.type == UPDATE_MEMORY_SECTION.type
```

Requirements: Python 3 (tested with 3.12 and 3.14). With the
`cryptography` package installed (tested with 50.0.0) the two signature
lines say `valid` or `INVALID`; without it they say `skipped` and every
other line is unchanged.

## Options

```
python3 gblv4.py FILE [FILE ...]
python3 gblv4.py FILE --extract plain.bin
python3 gblv4.py FILE --json report.json
python3 gblv4.py FILE --strings 'REGEX' [--min-len N]
python3 gblv4.py --diff FILE_A FILE_B
```

Input is a raw `.gbl` file or a Matter `.ota` file.

`--extract` writes the decompressed image. `--json` writes the whole report,
including every decoded field and the check results, as JSON.

`--strings` prints the printable ASCII runs of the decompressed image that
match a Python regular expression, with their offsets. This is how the model
strings and build paths quoted in the case study were found:

```
python3 gblv4.py FILE --strings 'LED2[0-9]{3}'
python3 gblv4.py FILE --strings 'OPENTHREAD|GNU-toolchain|simplicity_sdk'
```

`--diff` prints the header fields of two files side by side and then the
byte runs in which their decompressed images differ, each run labelled when
it falls inside the embedded certificate, the application signature or the
ApplicationProperties struct. Two files of different size are reported as
different builds with the length of their common prefix.

Exit status is 0 when every check passes, 1 when a check fails or an
extraction was requested without a plain image, and 2 when the file cannot
be parsed at all. A GBL v3 file, a truncated file and a file that is not GBL
each get a one-line reason and exit 2, without a traceback.

## Checks

| check | what is compared |
|---|---|
| matter: totalSize == file size | Matter header TotalSize field |
| matter: payloadSize == remaining bytes | Matter header PayloadSize field |
| matter: imageDigest == sha256(payload) | Matter header ImageDigest, when ImageDigestType is 1 |
| GBLV4 spans to end of file | length of the outer TLV |
| GBLV4 length is a multiple of 4 | see PAD below |
| CONTENT_HASH == sha256(file after MANIFEST) | as the format page describes it |
| memorySectionPos points at MEMORY_SECTION | the position field, relative to the start of the GBL |
| memSecHash == sha256(MEMORY_SECTION_INFO tlv) | the hash in UPDATE_MEMORY_SECTION over the info TLV including its 8-byte header |
| finalImageHash[0:32] == sha256(plain image) | first 32 bytes of the 64-byte field |
| plainImageSize == len(plain image) | the 24-bit size in UPDATE_MEMORY_SECTION |
| embedded certificate == MANIFEST_CERTIFICATE | the 136 bytes at the address ApplicationProperties.cert points to |
| ApplicationProperties app.type == UPDATE_MEMORY_SECTION.type | the application type bitfield in both places |
| manifest signature | ECDSA P-256 / SHA-256 with the certificate key over file bytes from the end of MANIFEST_SIGNATURE to the end of MANIFEST |
| application signature | ECDSA P-256 / SHA-256 with the embedded certificate key over the plain image up to signatureLocation |

The last two appear in the check list only when they fail; their status is
printed on its own line above the list.

## Sources, and what they leave out

1. Silicon Labs, Gecko Bootloader User's Guide for Series 3 and Higher,
   [Gecko Bootloader File Format v4](https://docs.silabs.com/mcu-bootloader/latest/bootloader-user-guide-series3-and-higher/02-gecko-bootloader-file-format-v4)
   (documentation version 3.3.1 at the time of writing; the text is the same
   as in 3.1.1). Tag ids, field names, field order, the compression and
   encryption scheme values.
2. Silicon Labs, Gecko Bootloader API Reference,
   [Application Properties](https://docs.silabs.com/mcu-bootloader/latest/gecko-bootloader-api/application-properties)
   and its `ApplicationProperties_t`, `ApplicationData_t` and
   `ApplicationCertificate_t` pages. The 16-byte magic, the application type
   bits, the signature type values, and the full layout of the certificate
   (structVersion, flags[3], key[64], version, signature[64] = 136 bytes)
   and of the properties struct, including that word 13 of the vector table
   points at it.
3. CSA, Matter Core Specification 1.4, section 11.21 (OTA image header:
   FileIdentifier 0x1BEEF11E, TotalSize, HeaderSize, the TLV header with
   context tags 0 to 9) and Appendix A (TLV encoding).
4. Silicon Labs, Zigbee Stack API Reference 8.1.1, `sl_zigbee_version_t`
   and `sl_zigbee_version_type_t` (GA = 0xAA), for the stack-version
   search only.
5. Silicon Labs, AN1496 "EFR32xG21 to SiXG301 Compatibility and Migration
   Guide", table 3.2, for the meaning of the two address bases seen in the
   KAJPLATS images.

What the format page does not say, and how this script fills the gap:

* MANIFEST_SIGNATURE: the page gives a 32-bit "signature function" and a
  byte array. The value 2 comes with 64 bytes that verify as ECDSA P-256
  over SHA-256, so 2 is printed as ECDSA-P256. Other values are printed as
  numbers.
* What the manifest signature covers. Found by trial: the bytes from the
  end of the MANIFEST_SIGNATURE TLV to the end of the MANIFEST container,
  which is MANIFEST_INFO, BUNDLE_VERSION, CONTENT_HASH and UPDATE_PROCESS
  with their headers. It verifies on all 18 files tested.
* `hashType` 1 is "SHA" on the page; the digests are 32 bytes, so it is
  printed as SHA-256.
* `memSecHash` in UPDATE_MEMORY_SECTION is typed `HashValue_t` without a
  layout. It has the same shape as CONTENT_HASH, a 32-bit type followed by
  the digest, and it is the SHA-256 of the MEMORY_SECTION_INFO TLV
  including the 8-byte TLV header.
* `memorySectionPos` is "the absolute position of the MEMORY_SECTION TLV
  in the file". In a Matter `.ota` file it counts from the start of the GBL
  payload, not from the start of the `.ota` file.
* MEMORY_SECTION_INFO is 212 bytes in every file seen: 8 fixed bytes, then
  arrays the page lists without sizes. The split used here is nonce 12,
  finalImageHash 64, secureBootSign 128. The page marks finalImageHash as
  reserved; the files carry the SHA-256 of the decompressed image in its
  first 32 bytes, which is why the tool can check it.
* MANIFEST_INFO.features: the page says "encryption, compression etc."
  without bit values. Bit 0 is set in every file, and every file has an
  LZMA blob, so bit 0 is labelled COMPRESSION. Nothing more is claimed.
* The LZMA blob is a plain LZMA-alone stream (13-byte header: properties
  byte, dictionary size, uncompressed size), which Python's `lzma` module
  decodes with `FORMAT_ALONE`. The page only says "LZMA".
* A trailing TLV with tag 0xEE0101EE is not on the page. Its body is one to
  three 0xFF bytes and it is present exactly when the file would otherwise
  not end on a 4-byte boundary, so the tool names it PAD and checks that
  the GBLV4 container length is a multiple of 4.
* Pointers inside ApplicationProperties (`cert`, `signatureLocation`) and
  word 13 of the vector table are absolute addresses. The tool converts
  them to image offsets with `targetAddr` from UPDATE_MEMORY_SECTION and
  prints the base that word 13 implies next to it, so a mismatch is visible.
* The application signature covers the image from offset 0 up to
  `signatureLocation`. The API page says the signature is over the SHA-256
  digest of the application; the range is what verifies against the files.
* The stack-version search is a heuristic. It looks for an 8-byte pattern
  with type 0xAA (GA), special 0 and a zero pad byte, in both field orders
  (the API page lists major, minor, patch, special, build, type; the images
  tested carry build first). Every hit is printed with its offset. On the
  18 KAJPLATS images it finds exactly one hit each.

## Limitations

* GBL v3 files (header tag 0x03A617EB) are recognised only to print a clear
  message. They are a different format.
* Encrypted blobs (encryptionScheme 1) are reported and left alone.
* LZ4 blobs (compressionScheme 1) are not decompressed; the LZ4 framing the
  bootloader expects is not on the public page.
* Block-wise signing (`signBlockSize`, `numBlocks`) is decoded but not
  verified. The files seen do not use it.
* The certificate's own signature (the one over the certificate structure)
  is not verified; the issuing key is not in the file.
* The Matter TLV reader handles only what the OTA header needs.
* Other vendors' GBL v4 files may contain TLVs this tool only lists by tag
  id. Issues with such a file, or with a file where a check fails for a
  reason other than corruption, are welcome; requests for encryption, LZ4,
  GBL v3 or a GUI are out of scope.

## Tests

```
python3 -m unittest -v
```

The tests build a small GBL v4 file in memory with the same TLV layout as
the IKEA images (Matter header, certificate, signed manifest, LZMA blob,
PAD, an ApplicationProperties struct with embedded certificate and
application signature) and run the parser on it and on corrupted copies:
truncated, a flipped byte in the blob, in CONTENT_HASH, in
MEMORY_SECTION_INFO, in MANIFEST_INFO, a v3 header tag, random bytes, an
empty file, an "encrypted" flag. No vendor firmware is in the repository.

```
GBLV4_DCL_TESTS=1 GBLV4_DCL_CACHE=.dcl-cache python3 -m unittest -v
```

adds three downloads from the URLs listed in the DCL (two KAJPLATS images
and one GBL v3 image from another IKEA product) and checks the sizes,
digests and decoded values quoted below.

## Test record

Run on 2026-09-04 with Python 3.14.6 and cryptography 50.0.0 on the 27
IKEA files that have an OTA URL in the DCL (vendor 4476). Every file
matched the DCL `otaFileSize` and `otaChecksum` (SHA-256, base64 in the
ledger). The 18 KAJPLATS files are GBL v4 and passed all checks with both
signatures valid; the other nine are not GBL v4 and exit with code 2:
ALPSTUGA (two versions), TIMMERFLOTTE and KLIPPBOK (two versions) are GBL
v3, and MYGGSPRAY, BILRESA (two products) and MYGGBETT use a container
that is not GBL at all.

| PID | part number | DCL product name | version | .ota bytes | sha256 of .ota (= DCL otaChecksum) | plain bytes | sha256 of plain image | certificate key sha256 | build |
|---|---|---|---|---|---|---|---|---|---|
| 36865 (0x9001) | LED2407G8 | KAJPLATS E27 WS globe 1055lm | 1.2.0 | 797428 | `ea1d5eb84407ad1082ade2c72747b9a01658eda9d35b024ef55c8d95b40df331` | 1345856 | `51e368ba797e7be69b144065f3b5b5d6c45f62080f3248ea58bfd2e72fab2328` | `bd2dea65146108bb3e479134550f9024183473794589e4a825bfdc846c643ce0` | WS 1.2.0 |
| 36866 (0x9002) | LED2403R5 | KAJPLATS GU10 WS 575lm | 1.2.0 | 797428 | `61a4563a7c3baf65d1abb282eec988cb25c58d92bf68d5779c4be9adb5b8c68f` | 1345856 | `babeb4f69f3e9d4cd14af1968e115cadc07f76f1c1a89ef0b855d51f93cbc5e9` | `96a02abbdb38f81637214fb0a3c5278f394b83f340db1bb8bac36aa6b4bb8db1` | WS 1.2.0 |
| 36867 (0x9003) | LED2408G10 | KAJPLATS E27 WS globe 1521lm | 1.2.0 | 797428 | `62e83d3a121b45598397b156b29e533959c08b74bd809882c212a7e40a49aad6` | 1345856 | `1a734b4bf39eec983824ff5ea95bd4e4553ebebd37513e5df7bb6433787b1e20` | `9875360141a62a016af83acfe2e1de349338238e50190b49e9fb696dc1f2776d` | WS 1.2.0 |
| 36868 (0x9004) | LED2404G6 | KAJPLATS E14 WS globe 806lm | 1.2.0 | 797432 | `75895e10e5ad35357e142d36f58a1389e498910e04783c9d6ac1b419399d4b98` | 1345856 | `b76dffba81cca0f5e409b4ecaf7dd50a23269c409ef14c6876bd722570556a6f` | `cef1d88a9abb388bd04207587faaf5478c168d5aaa52b1c897e9d08409b01de1` | WS 1.2.0 |
| 36869 (0x9005) | LED2405G8 | KAJPLATS E27 CWS globe 1055lm | 1.2.0 | 812204 | `5d34f1a7f3cc8a545a2a1d6d9ea0974b7dfdc899483d6b399ea9a16d798516ca` | 1372980 | `3a7d4a39a551924d3f23b2c9eb56e2a567d8ada5aaef49454038cf375a42ac3b` | `f4dfc290b431d2f3731220c16deb4d2f7ecc144623fc3fc944abe10efef524ae` | CWS 1.2.0 |
| 36870 (0x9006) | LED2409G6 | KAJPLATS E14 CWS globe 806lm | 1.2.0 | 812212 | `d4d0e7f8994171511b6ade4a70e978d8cfc5b5aa9144f75a85815c4a941c965f` | 1372980 | `cc88607fd0d2fe6d3b3dc1c528d760116d8f6531868bcc2911b41239bfb90a38` | `6aa03da200d8adfd04a760876a516ebafc2aa3771d532fa12d68a5109ed85a63` | CWS 1.2.0 |
| 36871 (0x9007) | LED2410R5 | KAJPLATS GU10 CWS 575lm | 1.2.0 | 812204 | `b0a5c16b73f7c92121e11fcbb7412d582fe3d9f52edd33c912a5af70469b4b6a` | 1372980 | `626718e5a5fd5d7bae65b0ad6067b4a00dbe60bd07839e76c01620dbe55e90ee` | `0d12d14b457c388dd52a3b6dceb294335f5cc2dc12a2ee4e4671992aa21d942f` | CWS 1.2.0 |
| 36872 (0x9008) | 36872 | KAJPLATS E14 WS B38 CL 470lm | 1.2.0 | 797428 | `47b8cc795631683c1343cb84b1c337da87fb8ac9f2070dadf440285df5239c58` | 1345856 | `5bb31799f0177194285c8bf6554fb0a3332c988ebaebdb8db76bb08473818576` | `4d7ce1ceeb1bd3fbf2eaa134f0ec2abddc09b18fcee7fb09121808935a5fc628` | WS 1.2.0 |
| 36873 (0x9009) | LED2401G5 | KAJPLATS E27 WS G95 clear 806lm | 1.1.0 | 751740 | `f55d31439420116ffb12c082712f17393a2ad3bd08d7dfaca3337d99e9fb2bcc` | 1260128 | `c323d402191cd0388b623de29819435e99a3dbb7318d717d52615bca8f441476` | `ebc6004fa3353eb927ad5737af1316643cc3f54ea97296a11c613c91932ca26b` | clear WS 1.1.0 |
| 36874 (0x900A) | LED2411G3 | KAJPLATS E27 WS G60 clear 470lm | 1.1.0 | 751728 | `e19b848fec3e77868757a2c04f3204d34226be1cfe1979c40d5c7fe738b2b54e` | 1260128 | `6ebc143d32929daaeae1b1ef87464e81e995b8f65f65d5028073b8c22a924044` | `552de902ffd34f5af8758e137b2fc8bf60ded89ad153552e6cc00b092d2f90c6` | clear WS 1.1.0 |
| 36882 (0x9012) | LED2407G8NA | KAJPLATS E26 WS globe 1100lm | 1.2.0 | 797432 | `9c1f8499be67fd5a7a29b855378b84bb2d55556ed3f5f4b9a1bbb6ef222680f9` | 1345856 | `c186c2b108118dcb7feaaf489ed7714dd0e67fcbb09f9e3325bab9a74117d055` | `a6fd525775958d0eaaa72346f08721ab369506e95b8655c92348b939cb88aca6` | WS 1.2.0 |
| 36883 (0x9013) | LED2403R5NA | KAJPLATS GU10 WS 575lm | 1.2.0 | 797428 | `8ab0d643de1b4d6977a47390c5c34078e572f9ae70a9b2aae3f3a8b0c020da40` | 1345856 | `51ae1cc0381d89daac894e1f42afcd4c322269c67b5e04f00d5382a5541225c0` | `bdfd14211c0943186d40c69a863ec1cff2db45d77922120694e32d2f5334d256` | WS 1.2.0 |
| 36884 (0x9014) | LED2408G10NA | KAJPLATS E26 WS globe 1600lm | 1.2.0 | 797428 | `e96a794accfc1fb87b977f22ea2b94b1136236bd5d9bd41446d81209a2aa9ec9` | 1345856 | `9df560552220ad091ec4ba82842870a8613482bde610cbc99484ea196e4d966c` | `d70168dc0afe6d20eb7aea94fceb82f90c6953cfe23916c02137e063fcf8d7c8` | WS 1.2.0 |
| 36885 (0x9015) | LED2404G6NA | KAJPLATS E12 WS globe 800lm | 1.2.0 | 797428 | `79f98e5629a0b257a470c9d50089fbe3af0c84f3c4297c3189c1cb596b326103` | 1345856 | `c605d14773c594a159edfe83c83c2b83e769ca34f62ade98bff5f231d03f925f` | `8fd8bbe9d5bd69548d485b7045a347773e0e8fc7d9a696658420cf47441d30b6` | WS 1.2.0 |
| 36886 (0x9016) | LED2405G8NA | KAJPLATS E26 CWS globe 1100lm | 1.2.0 | 812212 | `1c574aa2de3199d6bc877096f79db83b34fc6cd1b2a0ff7639f40712755fa9dd` | 1372980 | `e2bbdabdad2803263f590a8cf96721455c3c1cd0cf642ae29c153ebf06d884a8` | `ec77af36e857266d45349dc79617f181b617259018617c18ab5c42dc787972ee` | CWS 1.2.0 |
| 36887 (0x9017) | LED2409G6NA | KAJPLATS E12 CWS globe 800lm | 1.2.0 | 812212 | `46b37c0046f2b746d5aecfd5628e4b05edd880ab6c8bbafd904c95914b970aa3` | 1372980 | `258a753c01ff4fd48de0c63672d528e583ad6d50b4eeac8165ad46780d09c4b6` | `a3012cd30c9f6ec751aa77f1eea4351abc8114dfdc27ed6962157bec9e04e811` | CWS 1.2.0 |
| 36888 (0x9018) | LED2410R5NA | KAJPLATS GU10 CWS 575lm | 1.2.0 | 812212 | `2a0b525a4bb2b0119475de091cbbc14096f1c299e4e9e9bf50e31dee3f3ed910` | 1372980 | `6779f1ca14b21fe465319ce97690a7126e48f7c7f293543da0bba52c1a1cc107` | `97bf281140e2a4576d890871a18e82394969d0cec3ea1d81f29dc381aaed7846` | CWS 1.2.0 |
| 36889 (0x9019) | LED2402C3NA | KAJPLATS E12 WS B38 CL 450lm | 1.2.0 | 797428 | `ed6e6069001200883fb0c0d6bc96b1ed1e892dcffd9d51b0079acd834c3d10a1` | 1345856 | `d72d85df0a106347333f0b26c40c261ebde350dc6c404ac7f040cc0358a92904` | `8897127de3076b6d2cf379765b80d5aa542e3377743977cd5b8f6e1465fcd395` | WS 1.2.0 |

The files live at `https://ota.matter.ikea.com/files/<name>`; the DCL
entry `https://on.dcl.csa-iot.org/dcl/model/versions/4476/<PID>/<version>`
gives the full URL (`otaUrl`), the size and the checksum. Names of the 18
files, for copy and paste:

```
4476_36865_16908288_d7ad9139-0517-4a96-a3be-e77306b26d93.ota
4476_36866_16908288_9844be7c-e3c9-4a98-80c0-34b77615b817.ota
4476_36867_16908288_cf1aafc3-5c5e-4165-b25e-a36c8f5afbd4.ota
4476_36868_16908288_39a3bd0d-cdb8-4ed0-9b86-e50c5f1f27ce.ota
4476_36869_16908288_e9301d36-dcba-4d60-bf77-cef3697b3f1a.ota
4476_36870_16908288_78c41127-f053-4d22-a5f8-a8e8386fdded.ota
4476_36871_16908288_18482475-a249-4ca5-8fd0-a7f70c23c1b1.ota
4476_36872_16908288_6e1a9569-81cc-47a8-b60d-96f324f94b30.ota
4476_36873_16842752_2b9c3286-829e-489e-be6f-f6e18ee25d35.ota
4476_36874_16842752_af691c98-f637-4739-9057-7aca271a7b09.ota
4476_36882_16908288_e2d00a4b-6f93-4a14-b0c5-18e673acd0d9.ota
4476_36883_16908288_e90bf4cc-9b2c-4b74-9d5b-80d5fd5f9036.ota
4476_36884_16908288_cd93f22a-0149-4859-9fc3-42e6cd39b636.ota
4476_36885_16908288_24af3510-d851-4c9c-827d-6210873eb3f4.ota
4476_36886_16908288_d76af86c-2512-49ee-a5ec-2ab7c2ca63cc.ota
4476_36887_16908288_0e4a8af8-d47e-4e5c-bed9-093b90a84751.ota
4476_36888_16908288_8d1731c2-cf19-4b57-98c6-a80fe23deb00.ota
4476_36889_16908288_78e6cf8a-d91b-402b-a4cc-ead7c4b3ae55.ota
```

Common to all 18: MANIFEST_INFO version 0x04000000 with features 1,
BUNDLE_VERSION all zero, targetMemory 0, targetAddr 0x01008000, LZMA with
props 0x64 (lc 1, lp 1, pb 2) and an 8 KB dictionary, no encryption, a
zero nonce, no block signing, certificate structVersion 1 and version 2,
ApplicationProperties structVersion 0x201 with a zero decrypt key and a
zero product id, word 0 of the vector table 0x20021DA0 (0x20021740 in the
clear builds), word 1 0x1100804D. 15 of the 18 files end with a PAD of one
to three 0xFF bytes. The 1.2.0 builds carry type 0x23 (ZIGBEE, THREAD,
BLUETOOTH_APP) and version 1 in both the GBL and the ApplicationProperties;
the clear 1.1.0 builds carry type 0x21 (no THREAD bit) and version
0x01010000. All 18 certificate keys are different.

## Case study: the IKEA KAJPLATS firmware

### The device and what was already public

IKEA sells the KAJPLATS bulbs as Matter over Thread lamps. The unit on the
bench is the GU10 colour model LED2410R5, Matter vendor id 4476 (0x117C),
product id 36871 (0x9007). Read over Bluetooth LE with a Matter controller
(a PASE session, no commissioning), its Basic Information cluster reports
ProductName "KAJPLATS GU10 CWS 470lm", SoftwareVersionString "1.1.0",
HardwareVersionString "P2.0" and a manufacturing date in February 2026. The
DCL entry for the same product id says "KAJPLATS GU10 CWS 575lm"; which of
the two lumen figures is the typo is not known.

The lamps also have a Zigbee mode, entered by power cycling. That is
documented in the Home Assistant threads
[Ikea Kajplats Zigbee mode](https://community.home-assistant.io/t/ikea-kajplats-zigbee-mode/960714)
and [power-cycle blueprint](https://community.home-assistant.io/t/ikea-kajplats-smart-bulb-zigbee-pairing-mode-power-cycle/988507),
a [matteralpha article](https://www.matteralpha.com/news/ikea-kajplats-smart-bulbs-have-a-secret-zigbee-mode),
the Zigbee2MQTT device pages for
[KAJPLATS_CWS](https://www.zigbee2mqtt.io/devices/KAJPLATS_CWS.html),
[KAJPLATS_WS](https://www.zigbee2mqtt.io/devices/KAJPLATS_WS.html) and
[KAJPLATS_WS_clear](https://www.zigbee2mqtt.io/devices/KAJPLATS_WS_clear.html),
and ZHA issue [zigpy/zha-device-handlers#4686](https://github.com/zigpy/zha-device-handlers/issues/4686).
The FCC exhibits for [FHO-LED2410R5NA](https://fccid.io/FHO-LED2410R5NA)
include internal photos, and the DCL lists the models and the OTA download
URLs.

In Zigbee mode the Basic cluster strings are empty and the node descriptor
carries manufacturer code 4169 (0x1049). In zigbee-herdsman's manufacturer
code table that value is `SILICON_LABORATORIES`; Leedarson, the module
maker, is 4456 (0x1168). The ZHA issue above labels 4169 as "LEEDARSON
(IKEA OEM)" in its quirk; that label is wrong.

Everything below was measured on 2026-09-03 and 04 unless stated
otherwise. The Zigbee side ran on Zigbee2MQTT 2.13.0 with zigbee-herdsman
10.8.0, zigbee-herdsman-converters 26.90.0 and the ember adapter (EmberZNet
7.4.5) on a SONOFF Dongle Max. The Matter reads went over Bluetooth LE from
a Linux host with BlueZ and the CHIP Python controller.

### How the OTA image is packaged

The DCL entry for vendor 4476, product 36871, version 16908288 points at
`4476_36871_16908288_18482475-a249-4ca5-8fd0-a7f70c23c1b1.ota`, 812204
bytes, software version string 1.2.0. The file starts with a Matter OTA
image header: FileIdentifier 0x1BEEF11E, a 64-bit TotalSize, a 32-bit
HeaderSize (68 here) and a Matter TLV structure with vendor id, product id,
software version 16908288 (0x01020000), the string "1.2.0", the payload
size, digest type 1 and the SHA-256 of the payload. The payload starts at
offset 84.

The payload is a Silicon Labs GBL v4 file, the format the Series 3 Gecko
Bootloader consumes. The TLV table in the quick start above is this file.
The certificate is 136 bytes: structVersion 1, three zero flag bytes, a
64-byte P-256 public key, version 2, and a 64-byte signature over the
certificate itself. MANIFEST_SIGNATURE holds type 2 and 64 bytes of r and
s. MANIFEST_INFO has version 0x04000000 and features 1. BUNDLE_VERSION is
24 zero bytes. CONTENT_HASH is the SHA-256 of everything after the MANIFEST
container. UPDATE_MEMORY_SECTION says plainImageSize 1372980 (1345856 for
the WS build, 1260128 for the clear build), targetAddr 0x01008000, type
0x23, version 1, memorySectionPos 412, and the SHA-256 of the
MEMORY_SECTION_INFO TLV. MEMORY_SECTION_INFO says LZMA, no encryption, a
zero nonce, and the SHA-256 of the decompressed image in the first 32 bytes
of a field the format page calls reserved. The BLOB is an LZMA-alone
stream with an 8 KB dictionary.

The signature chain is short. The manifest signature verifies with the
certificate's key over file bytes 0x140 to 0x1F0. The same 136-byte
certificate sits inside the decompressed image at the address
`ApplicationProperties.cert` points to (plain offset 0x14F26C in the CWS
build), immediately followed by the 64-byte application signature, which
verifies with the same key over the image up to that point. Each of the 18
files has its own certificate key; the certificate's own signature is by a
key that is not in the files. Consequence: the images can be read without
any key, but the bootloader will only accept an image that carries an
IKEA-signed certificate, a manifest signed with it, and an application
signed with it.

### What the decompressed image says

The plain image is a Cortex-M binary. Its vector table starts with stack
pointer 0x20021DA0 and reset vector 0x1100804D, and word 13 holds
0x0114403C, which is 0x01008000 plus the offset of the ApplicationProperties
struct (0x13C03C). So the reset vector uses the address 0x11008000 while
the data pointers, and the GBL targetAddr, use 0x01008000. AN1496, table
3.2, lists 0x01000000 to 0x04FFFFFF as external memory on the code bus of
the SiXG301 and 0x11000000 to 0x14FFFFFF as its secure alias. The
application therefore starts 32 KB into that region, with room for a
bootloader in front, and executes from the secure alias.

Strings in the image (`--strings`): the OpenThread build string
"SL-OPENTHREAD/2.6.1.0_GitHub-7f6723ffb; EFR32; Jun 18 2025 00:22:54",
build paths under `../../sdk/third_party/simplicity_sdk/` that include
`extension/matter_extension` and `protocol/zigbee/app/framework`, a newlib
source path from a "GNU-toolchain/arm-12" build, and two IKEA strings from
the OTA requestor: "debug or dev can not ota to product verserion" (sic)
and "the type between debug or dev should be the same requestor:%x ,
provider:%x". An 8-byte struct shaped like `sl_zigbee_version_t` at plain
offset 0x14BFBA reads build 341, version 8.1.1, type GA.

Those two versions date the SDK. The Simplicity SDK release notes for
v2024.12.1 (8 February 2025) pair EmberZNet 8.1.1.0 with OpenThread
2.6.1.0; v2024.12.0 has 8.1.0.0 and 2.6.0.0, v2024.12.2 has 8.1.2.0 and
2.6.2.0. In the public simplicity_sdk repository the directory
`platform/bootloader/series3/parser/gbl` and the SiMG301 and SiBG301 device
folders first appear in v2025.6.0 (June 2025); v2024.12.2 has only a
`series3/component` directory. The IKEA build, dated 18 June 2025 in the
OpenThread string, was therefore made with a Series 3 SDK that was not yet
public in the 2024.12 line. How the vendor obtained it is not visible in
the image.

The CWS image contains a model table at plain offset 0x14E649: twelve
16-byte slots holding LED2405G8, LED2409G6 and LED2410R5 with no suffix
and with the suffixes JP, KR and NA, plus the two NUL-terminated strings
LED2409G6 and LED2410R5 at 0x14AF87. The WS image has no model strings at
all. The clear 1.1.0 builds come from a different tree: their paths read
`/home/runner/work/rs-hs-external-keetat-fw-dev/rs-hs-external-keetat-fw-dev/silabs_mg301/sdk/...`,
they contain "KAJPLATS WS BULB" and "IKEA of Sweden", their application
type lacks the THREAD bit, and their ApplicationProperties version is
0x01010000 where the 1.2.0 builds carry 1.

### Three builds for 18 product ids

| build | plain image | product ids | what differs between product ids |
|---|---|---|---|
| WS 1.2.0 | 1345856 bytes | 36865, 36866, 36867, 36868, 36872, 36882, 36883, 36884, 36885, 36889 | 196 bytes at 0x14887C: certificate key, certificate signature, application signature |
| CWS 1.2.0 | 1372980 bytes | 36869, 36870, 36871, 36886, 36887, 36888 | 196 bytes at 0x14F270 |
| clear WS 1.1.0 | 1260128 bytes | 36873, 36874 | 196 bytes at 0x13399C |

`--diff` on two files of one build prints a single differing run of 196
bytes, labelled "embedded certificate, application signature" (the first
four bytes of the certificate, structVersion and flags, are the same in
every file, and the version field is the same, so the run starts four
bytes into the certificate). `--diff` on a CWS and a WS file reports
different sizes with a common prefix of 52 bytes. The EU and NA files of
one build are the same code with a different certificate; the NA files on
the IKEA server carry a Last-Modified date of 2 February 2026, the EU
files 23 December 2025. Which product id a lamp reports, and which model
string it uses in Zigbee mode, must therefore come from manufacturing
data on the device, not from the OTA image.

### Zigbee and Matter tables inside the image

This part comes from a disassembler session (rizin) on the CWS 1.2.0
image, not from `gblv4.py`, and is included because it was checked against
the lamp.

The Zigbee application framework tables in the image match what the lamp
answers on the air: endpoint 1 with Basic, Identify, Groups, Scenes,
On/Off, Level Control, Color Control and Touchlink as servers, endpoint
242 with the Green Power client, the same attribute sets and the same
ClusterRevision values, 59 attribute records in all. The stack
configuration in the image gives a scene table of 12 entries, a binding
table of 18, an address table of 4 and a Green Power proxy table of 5. The
lamp confirmed 12 scenes (the thirteenth store did not raise the count).
The reporting table in the image has 12 slots of 20 bytes, yet the lamp
accepted 14 configured reports before answering INSUFFICIENT_SPACE; where
the extra two live is an open question. Touchlink policy at init is
0x07: enabled, target role, stealing allowed, remote reset not allowed;
primary channel mask 0x02108800 (channels 11, 15, 20, 25).

The Matter tables in the same image describe endpoint 0 with Descriptor,
Access Control, Basic Information, OTA Provider (client), OTA Requestor,
Time Format Localization, General Commissioning, Network Commissioning,
General Diagnostics, Thread Network Diagnostics, Administrator
Commissioning, Operational Credentials and Group Key Management, and
endpoint 1 with Identify (revision 5), Groups (4), On/Off (6), Level
Control (6), Descriptor and Color Control (7) with FeatureMap 0x1F: hue
and saturation, enhanced hue, colour loop, XY and colour temperature. The
WS build has 0x18 (XY and colour temperature). The lamp read over BLE
reported ColorCapabilities 31 on the Matter side. In Zigbee mode the same
lamp reports colorCapabilities 24 (XY and CT), answers enhanced-hue
commands and ColorLoopSet with UNSUP_COMMAND, and still executes
MoveToHue and MoveToSaturation. The two stacks do not share attribute
state: with the lamp at Zigbee level 100, the Matter CurrentLevel read back
254.

### Which chip, and how sure

The reading "Silicon Labs Series 3, SiMG301" rests on the firmware: the
format page says GBL v4 is for Series 3 devices, the 0x01008000 and
0x11008000 addresses match the SiXG301 memory map in AN1496, the clear
builds' paths name `silabs_mg301`, and the BLE Device Information service
answers Manufacturer "Silicon Labs", Model "Blue Gecko". The FCC internal
photos of LED2410R5NA show a radio daughterboard marked "M-LDT63S000A
V2.0-Y2", a Leedarson module, with the caption "SILABS RF PCB"; the part
marking is not readable. No part number has been read off a chip, so
SiMG301 is the best reading, not a confirmed fact.

A [matter-smarthome.de article](https://matter-smarthome.de/en/products/how-ikea-masters-the-combination-of-thread-and-zigbee/)
from December 2025 attributes the IKEA devices to the Qorvo QPG6200L,
based on an opened BILRESA remote. Nothing here speaks to the remote. For
the bulbs, the firmware format, the memory map, the SDK strings and the
FCC photos all point to Silicon Labs, and nothing in the images points to
Qorvo.

### The power-cycle counter

From the disassembly, with the caveat that it was read without symbols:
one non-volatile token (key 0x3d) is incremented on every boot, another
(key 0x3c) holds a baseline, and a dispatcher that runs about 2000 ms after
boot takes the difference and compares it with 6, 8, 9, 12 and more than
12, with two branches depending on a 23-byte mode token (key 0x3e) that
selects the Zigbee or the Thread stack. On the lamp: six cycles with 3.0 s
on and 1.5 s off did not reset it, six with 2.5 s on did not either, six
with 1.0 s on and 1.5 s off did (Zigbee2MQTT logged device_leave, the lamp
went back to Matter mode, and it did not rejoin within six minutes of an
open permit-join; the twelve-cycle procedure brought it back). So a cycle
only counts when power is cut before the dispatcher has run. The
community timings (700 ms on and 1500 ms off in the blueprint thread,
around 1 s on elsewhere) stay under that limit; none of the sources say
why. What the 8 and 9 thresholds do was not tested. The Zigbee2MQTT notes
generator uses 15 cycles for models whose description contains "clear"
and not "E1", and 12 for the rest; the clear models are the separate code
base above.

### Bluetooth LE

Captured with btmon on Linux: the advertisement carries Flags 0x06 and 8
bytes of Service Data under UUID 0xFFF6, `00 0e 03 7c 11 07 90 00`, that is
opcode 0, discriminator 782 (0x30E), vendor id 0x117C, product id 0x9007
and a zero flags byte; the scan response carries the name "LED
Light0x07C2". There is no 16-bit Service UUID list, and the Matter 1.4
core specification, section 5.4.2.5.6, defines the discovery payload as
exactly that Service Data element. Fast advertising ran for about 40 s in
the captures; the image has a 30000 ms constant in its advertising setup,
next to the slow intervals of 150 and 1200 ms. The 10 s gap is not
explained.

In two scans the commissionable advertisement stayed on for about 906 s
after power-on, then stopped. That matches the CHIP SDK default
`CHIP_DEVICE_CONFIG_DISCOVERY_TIMEOUT_SECS` of 15 times 60 and IKEA's own
[support page](https://www.ikea.com/nl/en/customer-service/product-support/smart-lighting/smart-lighting-support-pubd8491250/),
which says the products are ready to connect for 15 minutes after power-on.
The Zigbee2MQTT device page says 5 minutes; a correction is proposed in
[Koenkk/zigbee2mqtt.io#5487](https://github.com/Koenkk/zigbee2mqtt.io/pull/5487).
While that window is open, anyone with the pairing code from the box can
commission a lamp that is already on a Zigbee network.

The GATT server has Generic Attribute 0x1801, the Matter service 0xFFF6
with the C1, C2 and C3 characteristics, and Device Information 0x180A
with Manufacturer "Silicon Labs" and Model "Blue Gecko", the stack
defaults. There is no firmware update path over BLE: the Silicon Labs
AppLoader service is absent, there are no AppLoader strings in the image,
and Matter OTA runs over BDX on the operational network, which for this
lamp is Thread.

### Notes for Zigbee2MQTT users

Dim to warm is built in and off by default. The Level Control cluster's
Options attribute (0x000F) has bit 1, CoupleColorTempToLevel, described in
ZCL8 section 5.2.2.1.1. Writing it on this lamp:

```
zigbee2mqtt/<device>/set
{"write":{"cluster":"genLevelCtrl","payload":{"options":2}}}
```

After that, every level change in colour temperature mode sets the colour
temperature along a straight line in mireds from 370 at level 254 to 555
at level 1. Measured in two runs: 254 gives 370, 200 gives 410, 128 gives
462, 64 gives 509, 10 gives 548, 1 gives 555. That is 555 minus 185 times
level over 254, with CoupleColorTempToLevelMinMireds (0x400D) at 370 (2700
K, read-only on this lamp) and ColorTempPhysicalMaxMireds at 555 (1800 K).
The coupling applies in colour temperature mode only; in XY mode a level
change leaves the colour alone. A manual colour temperature command holds
until the next level change. The bit survives a power cycle and also fires
on Zigbee2MQTT's normal brightness command.

One caveat in the converter library: the `level_config` converter in
zigbee-herdsman-converters writes the whole Options byte when it handles
`execute_if_off`, so it clears bit 1, and the matching fromZigbee converter
reads only bit 0. Reproduced on this lamp: write options 2, read back 2;
publish `{"level_config":{"execute_if_off":false}}`, read back 0. Issue
[#2284](https://github.com/Koenkk/zigbee-herdsman-converters/issues/2284)
from 2021 asked for this coupling and was closed as stale;
[#13104](https://github.com/Koenkk/zigbee-herdsman-converters/pull/13104)
proposes a `couple_color_temp_to_level` key that writes the bit without
touching its neighbour.

On the power-cycle procedure: keep the on phase around 1 s. If the lamp
stays on for more than about 2 s, the firmware has already evaluated the
counter before the next cut.

After a power cut the lamp does not send a Device Announce, which the
device page already notes
([Koenkk/zigbee2mqtt#32115](https://github.com/Koenkk/zigbee2mqtt/issues/32115)).
With attribute reporting configured it is usable again about 2 s after
power returns: the first report arrived 0.7 s after power-on and the first
ZCL answer 1.7 s, the same after a 3 s and after a 25 s outage.

Scenes: GetSceneMembership reports a capacity of 12 on this GU10 with
firmware 1.1.0. ViewScene shows stored fields for On/Off and Level, plus
Color X and Y when the scene was stored in XY mode. A recall writes X and
Y back but does not switch ColorMode away from colour temperature, and
colour temperature itself is never stored.
[Koenkk/zigbee2mqtt#30211](https://github.com/Koenkk/zigbee2mqtt/issues/30211)
reports a scene capacity of 8 on an LED2408G10, dropping to 0 after the
bulb joins a group; on this GU10, adding 12 groups did not reduce the scene
capacity.

### What is deliberately not here

The repository links the OTA files in the DCL instead of redistributing
them, and contains no decompressed image. Left out on purpose: the ZLL and
certification key values and their offsets, the certificate bytes (only
SHA-256 fingerprints of the public keys are given), the lamp's UniqueID,
IEEE address, Thread and BLE addresses, and any pairing code. The
disassembly is summarised, not published.

### Reproduce

Download the two GU10 files from the URLs in the DCL (product ids 36871
and 36866, version 16908288), check them against the table above, then:

```
python3 gblv4.py 4476_36871_16908288_18482475-a249-4ca5-8fd0-a7f70c23c1b1.ota
python3 gblv4.py 4476_36866_16908288_9844be7c-e3c9-4a98-80c0-34b77615b817.ota
python3 gblv4.py --diff 4476_36871_16908288_18482475-a249-4ca5-8fd0-a7f70c23c1b1.ota 4476_36869_16908288_e9301d36-dcba-4d60-bf77-cef3697b3f1a.ota
python3 gblv4.py 4476_36871_16908288_18482475-a249-4ca5-8fd0-a7f70c23c1b1.ota --strings 'LED2[0-9]{3}|OPENTHREAD'
```

Expected: every check ok, both signatures valid with `cryptography`
installed, plain image SHA-256 `626718e5...e55e90ee` (1372980 bytes) for
the CWS file and `babeb4f6...93cbc5e9` (1345856 bytes) for the WS file,
certificate key fingerprints `0d12d14b...a21d942f` and
`96a02abb...b4bb8db1`, one 196-byte differing run at 0x14F270 in the diff,
fourteen `LED2...` strings and one OpenThread string in the CWS file.

## License

MIT, see `LICENSE`.
