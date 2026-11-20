#!/usr/bin/env bash
# tests/link_check.sh APKPACK: apkpack link, add and sign against aapt2.
#
# tests/app (sqterm's own manifest and resources, a small assets/) is built
# twice: by apkpack (link, add, sign), and by aapt2 (compile, link, with
# android.jar). Where aapt2 and android.jar are found (CI: the runner's
# Android SDK), they must agree on what Android reads: the package, its
# version, the SDK levels, the label, the icon, the debuggable flag, every
# manifest attribute's value, and every resource's value. aapt2 must read
# apkpack's APK at all (dump badging, xmltree, resources), and apksigner
# must accept its signature. Without them, apkpack's own dump and verify
# run alone, and that is said.
set -euo pipefail

apkpack=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
app=$(cd "$(dirname "$0")" && pwd)/app
work=$(mktemp -d)
trap 'rm -r -f "$work"' EXIT
cd "$work"
ok() { printf '  ok   %s\n' "$*"; }
skip() { printf '  skip %s\n' "$*"; }
die() { printf '  FAIL %s\n' "$*" >&2; exit 1; }

# apkpack: link, add a library and a dex, sign.
mkdir -p lib/arm64-v8a
head -c 70000 /dev/urandom > lib/arm64-v8a/libsqterm.so
printf 'dex\n035\0' > classes.dex
"$apkpack" link -o app.apk --manifest "$app/AndroidManifest.xml" --res "$app/res" --assets "$app/assets" \
    --min-sdk 28 --target-sdk 28 --debuggable >/dev/null
"$apkpack" add app.apk lib/arm64-v8a/libsqterm.so classes.dex >/dev/null
"$apkpack" keygen key.pem >/dev/null
"$apkpack" sign key.pem app.apk signed.apk >/dev/null
"$apkpack" verify signed.apk >/dev/null || die "apkpack verify"
"$apkpack" dump signed.apk | grep -q 'android:debuggable(0x0101000f)=true' || die "debuggable not in the manifest"
unzip -tq signed.apk >/dev/null || die "unzip -t"
ok "link, add, sign, verify, dump"

# Stored entries aligned: 4 bytes, and 16384 for the .so (zipalign -c -P 16).
python3 - signed.apk <<'PY'
import struct, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
data = open(sys.argv[1], "rb").read()
for i in z.infolist():
    at = i.header_offset
    n, extra = struct.unpack_from("<HH", data, at + 26)
    start = at + 30 + n + extra
    want = 16384 if i.filename.endswith(".so") else 4
    if i.compress_type == 0 and start % want:
        sys.exit(f"{i.filename} at {start}, not {want}-aligned")
PY
ok "entries aligned (4; 16384 for .so)"

jar=$(ls -d "${ANDROID_HOME:-/nonexistent}"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -n 1 || true)
if ! command -v aapt2 >/dev/null 2>&1 || [ -z "$jar" ]; then
    skip "aapt2 comparison (no aapt2 or android.jar; CI has both)"
    exit 0
fi

# aapt2 reads apkpack's APK.
aapt2 dump badging signed.apk > ours.badging || die "aapt2 dump badging refuses apkpack's APK"
aapt2 dump xmltree --file AndroidManifest.xml signed.apk > ours.xmltree || die "aapt2 dump xmltree"
aapt2 dump resources signed.apk > ours.resources || die "aapt2 dump resources"
aapt2 dump xmltree --file res/mipmap-anydpi-v26/ic_launcher.xml signed.apk > ours.icon || die "aapt2 dump xmltree (icon)"
if command -v apksigner >/dev/null 2>&1; then
    apksigner verify --min-sdk-version 28 signed.apk || die "apksigner verify"
fi
ok "aapt2 reads it (badging, xmltree, resources); apksigner verifies it"

# aapt2's own build of the same app.
aapt2 compile --dir "$app/res" -o res.zip
aapt2 link -o ref.apk -I "$jar" --manifest "$app/AndroidManifest.xml" --min-sdk-version 28 --target-sdk-version 28 \
    --debug-mode -A "$app/assets" res.zip
aapt2 dump badging ref.apk > ref.badging
aapt2 dump xmltree --file AndroidManifest.xml ref.apk > ref.xmltree
aapt2 dump resources ref.apk > ref.resources

# What Android reads, compared. badging: aapt2 adds what apkpack does not
# write (platformBuildVersion, compileSdkVersion), which Android does not need.
keep() { grep -E "^(package|sdkVersion|targetSdkVersion|uses-permission|uses-feature|application-label|application-icon|application-debuggable|launchable-activity|uses-gl-es|native-code)" "$1" |
         sed -E "s/ (platformBuildVersion[A-Za-z]*|compileSdkVersion[A-Za-z]*)='[^']*'//g" | LC_ALL=C sort; }
diff <(keep ref.badging) <(keep ours.badging | grep -v native-code) || die "badging differs from aapt2's"
ok "badging matches aapt2's"
# The manifest's attributes and values (aapt2 adds compileSdkVersion and
# platformBuildVersion*, which apkpack does not write).
attrs() { grep -E '^\s*(E|A):' "$1" | sed -E 's/\(Raw: "[^"]*"\)//; s/[[:space:]]+$//' |
          grep -vE 'compileSdkVersion|platformBuildVersion'; }
diff <(attrs ref.xmltree) <(attrs ours.xmltree) || die "the manifest differs from aapt2's"
ok "manifest matches aapt2's, attribute for attribute"
# Every resource and its value.
res() { grep -E '^\s*(type|resource|\(|\[)' "$1" | sed -E 's/[[:space:]]+$//'; }
diff <(res ref.resources) <(res ours.resources) || die "resources differ from aapt2's"
ok "resources match aapt2's"
echo "link check passed"
