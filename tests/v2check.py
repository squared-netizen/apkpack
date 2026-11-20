#!/usr/bin/env python3
# An independent check of an APK's v2 signature, on Python's cryptography
# package rather than apkpack's own code: the digest of the three sections,
# the signature over the signed data, and the certificate's key. Exit 0 when
# it verifies. Used by tests/cross_check.sh where cryptography is installed.
import hashlib, struct, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

def fail(why):
    print(f"v2check: {why}")
    sys.exit(1)

apk = open(sys.argv[1], "rb").read()
eocd = apk.rfind(b"PK\x05\x06")
cd_size, cd_off = struct.unpack_from("<II", apk, eocd + 12)
if apk[cd_off - 16:cd_off] != b"APK Sig Block 42":
    fail("no signing block")
size = struct.unpack_from("<Q", apk, cd_off - 24)[0]
start = cd_off - size - 8
pairs = apk[start + 8:cd_off - 24]
v2 = None
while pairs:
    n, pid = struct.unpack_from("<QI", pairs, 0)
    if pid == 0x7109871A:
        v2 = pairs[12:8 + n]
    pairs = pairs[8 + n:]
if v2 is None:
    fail("no v2 block")

def take(b):
    n = struct.unpack_from("<I", b, 0)[0]
    return b[4:4 + n], b[4 + n:]

signers, _ = take(v2)
signer, _ = take(signers)
signed, rest = take(signer)
sigs, rest = take(rest)
pubkey_der, _ = take(rest)
sig, _ = take(sigs)
alg = struct.unpack_from("<I", sig, 0)[0]
signature, _ = take(sig[4:])
key = serialization.load_der_public_key(pubkey_der)
if alg == 0x0201:
    key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
elif alg == 0x0103:
    key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
else:
    fail(f"algorithm {alg:#x}")

digests, rest = take(signed)
certs, _ = take(rest)
d, _ = take(digests)
digest, _ = take(d[4:])
cert, _ = take(certs)
c = x509.load_der_x509_certificate(cert)
if c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != pubkey_der:
    fail("certificate key differs")

eocd_rec = bytearray(apk[eocd:])
struct.pack_into("<I", eocd_rec, 16, start)
chunks = []
for section in (apk[:start], apk[cd_off:cd_off + cd_size], bytes(eocd_rec)):
    for i in range(0, len(section), 1 << 20):
        piece = section[i:i + (1 << 20)]
        chunks.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(piece)) + piece).digest())
top = hashlib.sha256(b"\x5a" + struct.pack("<I", len(chunks)) + b"".join(chunks)).digest()
if top != digest:
    fail("digest differs")
print(f"v2check: ok ({'ECDSA' if alg == 0x0201 else 'RSA'})")
