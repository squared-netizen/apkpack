#!/usr/bin/env bash
# tests/cross_check.sh APKPACK: apkpack against the tools it replaces.
#
#   keygen   openssl reads the key and the certificate, and checks the
#            certificate's self-signature
#   sign     an ECDSA key of apkpack's; an RSA key refused
#   verify   apkpack's own, tests/v2check.py (Python's cryptography, where
#            installed) and apksigner (where on PATH): all three must agree
#   tamper   one byte changed in a signed APK fails apkpack verify
#
# Needs openssl and zip; python3 with cryptography and apksigner
# are used when present, and their checks are skipped (and said) otherwise.
set -euo pipefail

apkpack=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -r -f "$work"' EXIT
cd "$work"

ok() { printf '  ok   %s\n' "$*"; }
skip() { printf '  skip %s\n' "$*"; }
die() { printf '  FAIL %s\n' "$*" >&2; exit 1; }

have_python=0
python3 -c 'import cryptography' 2>/dev/null && have_python=1
have_apksigner=0
command -v apksigner >/dev/null 2>&1 && have_apksigner=1

# An unsigned APK-shaped ZIP: a manifest-like entry, a stored 3 MiB entry
# (several digest chunks), and a deflated one.
mkdir -p in/lib/arm64-v8a
printf 'not really a manifest\n' > in/AndroidManifest.xml
head -c 3145728 /dev/urandom > in/lib/arm64-v8a/libbig.so
seq 1 20000 > in/numbers.txt
(cd in && zip -q -X -0 ../unsigned.apk AndroidManifest.xml lib/arm64-v8a/libbig.so && zip -q -X -9 ../unsigned.apk numbers.txt)

check_signed() {  # check_signed APK WHAT
    "$apkpack" verify "$1" >/dev/null || die "$2: apkpack verify"
    if [ "$have_python" = 1 ]; then python3 "$here/v2check.py" "$1" >/dev/null || die "$2: v2check.py"; fi
    if [ "$have_apksigner" = 1 ]; then apksigner verify --min-sdk-version 28 "$1" || die "$2: apksigner verify"; fi
    unzip -tq "$1" >/dev/null || die "$2: unzip -t (the ZIP itself)"
    ok "$2: verified by apkpack$([ "$have_python" = 1 ] && echo ', v2check.py')$([ "$have_apksigner" = 1 ] && echo ', apksigner'), unzip -t"
}

# keygen, read by openssl.
"$apkpack" keygen ec.pem --name "cross check" >/dev/null
openssl pkey -in ec.pem -noout || die "openssl cannot read the key"
openssl verify -check_ss_sig -CAfile ec.pem ec.pem >/dev/null || die "openssl rejects the certificate"
[ "$(openssl x509 -in ec.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum)" = \
  "$(openssl pkey -in ec.pem -pubout -outform DER | sha256sum)" ] || die "the certificate is not the key's"
"$apkpack" keygen ec.pem >/dev/null 2>&1 && die "keygen replaced a key"
ok "keygen: openssl reads the key and the certificate, and the self-signature checks"

# sign with ECDSA, then again over the signed APK (the block is replaced).
"$apkpack" sign ec.pem unsigned.apk ec.apk >/dev/null
check_signed ec.apk "ECDSA P-256"
"$apkpack" sign ec.pem ec.apk ec-again.apk >/dev/null
check_signed ec-again.apk "ECDSA, signed twice"

# An RSA key is refused: apkpack signs with its own ECDSA keys.
openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -out rsa.crt -days 30 -subj /CN=rsa -sha256 2>/dev/null
cat rsa.key rsa.crt > rsa.pem
"$apkpack" sign rsa.pem unsigned.apk rsa.apk >/dev/null 2>&1 && die "an RSA key was taken"
ok "RSA key: refused"

# One byte changed in an entry: verify fails.
cp ec.apk tampered.apk
printf 'X' | dd of=tampered.apk bs=1 seek=200 conv=notrunc 2>/dev/null
"$apkpack" verify tampered.apk >/dev/null 2>&1 && die "a tampered APK verified"
ok "tampered: refused"

[ "$have_python" = 1 ] || skip "v2check.py (no python3 cryptography)"
[ "$have_apksigner" = 1 ] || skip "apksigner (not on PATH; CI has it)"
echo "cross-check passed"
