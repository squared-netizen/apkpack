# apkpack

Builds and signs Android APKs with no Java, no Android SDK and no SDK
licence: one native C++ tool for the [squared SDK](https://squared-netizen.github.io/squared-netizen/)
in place of keytool, apksigner, aapt2, zipalign and android.jar.

**Status: phase 1 (sign) built: `keygen`, `sign`, `verify`.** The rest is
planned.

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
```

`sign` writes only a v2 signature, which Android 7.0 and later check, so
an app signed by apkpack needs Android 7.0 or later. squared's apps need
Android 9.

**Keep your existing key.** Android refuses an update signed with another
key, unless you uninstall first, which deletes the app's files. An app
already installed from Termux's build was signed with its debug keystore
(RSA). Export that key once, and apkpack signs with it:

```sh
keytool -importkeystore -srckeystore ~/.android/debug.keystore -srcstorepass android \
        -srcalias androiddebugkey -destkeystore debug.p12 -deststoretype PKCS12 \
        -deststorepass android -destkeypass android
openssl pkcs12 -in debug.p12 -passin pass:android -nodes -out ~/.android/apkpack.pem
rm debug.p12
```

A key file is PEM: a private key (EC P-256 or RSA, as PKCS#8, SEC 1 or
PKCS#1, not encrypted) and its certificate. `make test` checks every APK
apkpack signs with its own `verify`, an independent checker on Python's
cryptography (`tests/v2check.py`) and, where it is on PATH, the Android
SDK's `apksigner`.

## The plan

1. **Sign** (done): keygen, sign, verify. The build no longer needs Java.
2. **Package**: the zip writer with alignment.
3. **Link**: binary XML, resources.arsc, the attribute table. No aapt2 or android.jar.
4. **Switch**: squared's template calls apkpack. No SDK at all.

Each phase is checked against the tool it replaces, and on the phone by
installing and launching the APK.

## Licence

MIT: see [LICENSE](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
