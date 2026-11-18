# apkpack

Builds and signs Android APKs with no Java, no Android SDK and no SDK
licence: one native C++ tool for the [squared SDK](https://squared-netizen.github.io/squared-netizen/)
in place of keytool, apksigner, aapt2, zipalign and android.jar.

**Status: planned, not yet built.**

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

## The plan

1. **Sign**: keygen, sign, verify. The build no longer needs Java.
2. **Package**: the zip writer with alignment.
3. **Link**: binary XML, resources.arsc, the attribute table. No aapt2 or android.jar.
4. **Switch**: squared's template calls apkpack. No SDK at all.

Each phase is checked against the tool it replaces, and on the phone by
installing and launching the APK.

## Licence

MIT: see [LICENSE](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
