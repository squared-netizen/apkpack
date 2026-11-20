# apkpack

Builds and signs Android APKs with no Java, no Android SDK and no SDK
licence: one native C++ tool for the [squared SDK](https://squared-netizen.github.io/squared-netizen/)
in place of keytool, apksigner, aapt2, zipalign and android.jar.

**Status: phases 1 to 3 built** (`keygen`, `sign`, `verify`, `add`, `link`,
`dump`); phase 4, squared's template calling it, is next.

## What it will be

One program with subcommands, so the build can move to it a step at a time:

| Command | Replaces | Does |
| --- | --- | --- |
| `apkpack keygen` | keytool | an ECDSA P-256 key and a self-signed certificate; an existing debug key can be imported |
| `apkpack sign`, `apkpack verify` | apksigner | APK Signature Scheme v2 (Android 7.0 and later) |
| `apkpack add` | zip, zipalign | lib/ and classes.dex, stored entries aligned (4 bytes, 16 KB for a stored .so) |
| `apkpack link` | aapt2, android.jar | the manifest and XML resources as binary XML, resources.arsc, assets |
| `apkpack dump` | aapt2 dump | the binary manifest as text |
| `apkpack explain` | none | what a dex shim does, its bytecode and spec references, as JSON |

The framework attribute IDs android.jar supplied come from AOSP's public
tables (Apache-2.0), pinned as a source. Dex code is never compiled here:
dexgen writes squared's shims, and apkpack packs them.

## Using it

```sh
make CXX=clang++                          # clang and libc++ 23; make test checks it
apkpack keygen ~/.android/apkpack.pem     # a new ECDSA P-256 key and certificate
apkpack sign KEY unsigned.apk app.apk     # APK Signature Scheme v2
apkpack verify app.apk                    # the signature checked, the signer printed
apkpack link -o app.apk --manifest AndroidManifest.xml --res res --assets assets \
             --min-sdk 28 --target-sdk 28 [--debuggable]   # in place of aapt2
apkpack add app.apk -C build lib/arm64-v8a/libapp.so classes.dex  # in place of zip
apkpack dump app.apk                      # the manifest, as Android reads it
```

`link` compiles what squared's templates use: the manifest, `values/`
(string, color, bool, integer, dimen), XML files (drawables, adaptive
icons, layouts) and other files (PNG) as they are, with densities, `vN`,
night, land/port and language qualifiers. Every `android:` attribute is
typed from Android's own table of public attributes, generated from AOSP
(`tools/gen_android_table.py`, `NOTICE.android`), so no android.jar. Every
entry is stored, and aligned as zipalign aligns it (4 bytes; 16384 for a
`.so`). `make test` builds a test app with apkpack and, on CI, with aapt2,
and they must agree on everything Android reads.

`sign` writes only a v2 signature, which Android 7.0 and later check, so
an app signed by apkpack needs Android 7.0 or later. squared's apps need
Android 9.

**A new key, a new install.** apkpack signs with ECDSA P-256 keys it makes,
not with an older key (decided 2026-11-20). Android refuses an update
signed with another key, so an app installed from an older build (Termux's
debug keystore) is uninstalled once and installed again.

A key file is PEM: an ECDSA P-256 private key (PKCS#8 or SEC 1, not
encrypted) and its certificate, as `keygen` writes it. `make test` checks every APK
apkpack signs with its own `verify`, an independent checker on Python's
cryptography (`tests/v2check.py`) and, where it is on PATH, the Android
SDK's `apksigner`.

## The plan

1. **Sign** (done): keygen, sign, verify. The build no longer needs Java.
2. **Package** (done): the zip writer with alignment.
3. **Link** (done): binary XML, resources.arsc, the attribute table. No aapt2 or android.jar.
4. **Switch**: squared's template calls apkpack. No SDK at all.

Each phase is checked against the tool it replaces, and on the phone by
installing and launching the APK.

## Licence

MIT: see [LICENSE](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
