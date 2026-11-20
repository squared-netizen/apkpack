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

# assets/ as squared's apps lay it out: folders in folders (fonts/, skins/
# default/raw/, packages/), stored archives, a hidden file and a folder
# starting with _ (both of which aapt2 dropped without a word), an empty
# folder, a name with a space; and the index, written the way the build
# writes it (mk/squared_android_package.mk). Every file must reach the APK,
# byte for byte, stored.
mkdir -p assets/fonts assets/skins/default/raw assets/packages assets/_private assets/empty "assets/with space"
head -c 300000 /dev/urandom > assets/fonts/Mono-Regular.ttf
printf '{"skin": "default"}\n' > assets/skins/default/raw/pack.json
head -c 2000000 /dev/urandom > assets/packages/zsh-5.9.2-0123456789abcdef.sq
printf 'sqterm packages 1\n' > assets/packages/index
printf 'set -o vi\n' > assets/.zshrc
printf 'kept\n' > assets/_private/note.txt
printf 'spaced\n' > "assets/with space/file.txt"
write_index() {
    mkdir -p assets/SQ-INF
    (cd assets && find . -type f ! -path './SQ-INF/*' | sed 's|^\./||' | LC_ALL=C sort) > assets/SQ-INF/index
}
write_index
"$apkpack" link -o assets.apk --manifest "$app/AndroidManifest.xml" --res "$app/res" --assets assets >/dev/null || die "link refused the assets"
python3 - assets.apk assets <<'PY'
import os, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
names = {i.filename: i for i in z.infolist() if i.filename.startswith("assets/")}
on_disk = []
for root, dirs, files in os.walk(sys.argv[2]):
    for f in files:
        on_disk.append(os.path.relpath(os.path.join(root, f), sys.argv[2]))
for rel in on_disk:
    i = names.get("assets/" + rel)
    if i is None:
        sys.exit(f"assets/{rel} is not in the APK")
    if i.compress_type != 0:
        sys.exit(f"assets/{rel} is compressed")
    if z.read(i) != open(os.path.join(sys.argv[2], rel), "rb").read():
        sys.exit(f"assets/{rel} differs")
if len(names) != len(on_disk):
    sys.exit(f"{len(names)} assets in the APK, {len(on_disk)} on disk")
PY
ok "assets: every file (hidden, _folder, spaced, archives), stored, byte for byte; the index checked"

# A stale index fails the link, saying what differs.
printf 'gone.txt\n' >> assets/SQ-INF/index
if "$apkpack" link -o stale.apk --manifest "$app/AndroidManifest.xml" --res "$app/res" --assets assets 2> stale.err >/dev/null; then
    die "a stale index was accepted"
fi
grep -q 'listed, not in assets/: gone.txt' stale.err || die "the stale index's message: $(cat stale.err)"
write_index
printf 'new\n' > assets/fonts/added.txt
"$apkpack" link -o stale.apk --manifest "$app/AndroidManifest.xml" --res "$app/res" --assets assets 2> stale.err >/dev/null && die "an unlisted asset was accepted"
grep -q 'in assets/, not listed: fonts/added.txt' stale.err || die "the unlisted asset's message: $(cat stale.err)"
ok "assets: a stale index refused, naming the difference"

# No assets/ folder, or an empty one: nothing to add, no error.
mkdir -p none
"$apkpack" link -o none.apk --manifest "$app/AndroidManifest.xml" --res "$app/res" --assets none >/dev/null || die "an empty assets/ refused"
"$apkpack" link -o none.apk --manifest "$app/AndroidManifest.xml" --res "$app/res" --assets missing >/dev/null || die "a missing assets/ refused"
ok "assets: an empty or missing folder is fine"

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
