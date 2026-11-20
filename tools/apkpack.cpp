// SPDX-License-Identifier: MIT
//
// apkpack: Android APKs built and signed with no Java and no Android SDK.
//
//   apkpack keygen KEY [--name NAME] [--years N]
//                                a new ECDSA P-256 key and a self-signed
//                                certificate (CN=NAME, valid N years), one
//                                PEM file; an existing one is never replaced
//   apkpack sign KEY IN.apk OUT.apk
//                                IN signed with APK Signature Scheme v2 by
//                                KEY (PEM: a private key, EC P-256 or RSA,
//                                and its certificate), written to OUT
//   apkpack verify APK           its v2 signature checked; the signer printed
//   apkpack --help | --version
//
// Phase 1 of apkpack's plan (README.md): the build no longer needs keytool
// or apksigner, so no Java.

#include <stdio.h>  // stdout, stderr (macros, not in the std module)

import std;
import apkpack.crypto;
import apkpack.der;
import apkpack.apk;

using namespace apkpack;

namespace {

constexpr std::string_view version = "0.1.0";

int usage(std::FILE* out = stderr, int status = 2) {
    std::println(out, "usage: apkpack keygen KEY [--name NAME] [--years N]\n"
                      "       apkpack sign KEY IN.apk OUT.apk\n"
                      "       apkpack verify APK\n"
                      "       apkpack --help | --version");
    return status;
}

int fail(std::string_view why) {
    std::println(stderr, "apkpack: {}", why);
    return 1;
}

std::optional<Bytes> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return Bytes(std::istreambuf_iterator<char>(in), {});
}

/// Written beside, then renamed into place.
bool write_file(const std::string& path, ByteView data, std::filesystem::perms mode) {
    const std::string part = path + ".apkpack-part";
    {
        std::ofstream out(part, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out) return false;
    }
    std::error_code ec;
    std::filesystem::permissions(part, mode, ec);
    std::filesystem::rename(part, path, ec);
    if (ec) std::filesystem::remove(part);
    return !ec;
}

std::string fingerprint(ByteView certificate) {
    std::string out;
    for (std::uint8_t b : Sha256::of(certificate)) out += std::format("{:02x}", b);
    return out;
}

int keygen(const std::vector<std::string_view>& args) {
    if (args.empty()) return usage();
    const std::string path(args[0]);
    std::string name = "squared debug";
    int years = 30;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--name" && i + 1 < args.size()) {
            name = args[++i];
        } else if (args[i] == "--years" && i + 1 < args.size()) {
            const std::string_view v = args[++i];
            if (std::from_chars(v.data(), v.data() + v.size(), years).ec != std::errc() || years < 1 || years > 100)
                return fail("--years: a number from 1 to 100");
        } else {
            return usage();
        }
    }
    if (std::filesystem::exists(path)) return fail(path + " exists; apkpack never replaces a key");
    auto key = ec_generate();
    if (!key) return fail("no random source for a key");
    auto cert = self_signed(*key, name, years);
    if (!cert) return fail("could not sign the certificate");
    const std::string text = pem("PRIVATE KEY", pkcs8_of(*key)) + pem("CERTIFICATE", *cert);
    if (!write_file(path, {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()},
                    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write))
        return fail("cannot write " + path);
    std::println("{}: ECDSA P-256, CN={}, {} years; certificate SHA-256 {}", path, name, years, fingerprint(*cert));
    return 0;
}

int sign(const std::vector<std::string_view>& args) {
    if (args.size() != 3) return usage();
    auto key_file = read_file(std::string(args[0]));
    if (!key_file) return fail(std::format("cannot read {}", args[0]));
    const std::string_view text(reinterpret_cast<const char*>(key_file->data()), key_file->size());
    auto key = parse_private_key(text);
    if (!key) return fail(std::format("{}: {}", args[0], key.error()));
    auto cert = unpem(text, "CERTIFICATE");
    if (!cert) return fail(std::format("{}: no CERTIFICATE beside the key", args[0]));
    auto apk = read_file(std::string(args[1]));
    if (!apk) return fail(std::format("cannot read {}", args[1]));
    auto signed_apk = sign_v2(*apk, *key, *cert);
    if (!signed_apk) return fail(std::format("{}: {}", args[1], signed_apk.error()));
    if (!write_file(std::string(args[2]), *signed_apk,
                    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write | std::filesystem::perms::group_read |
                        std::filesystem::perms::others_read))
        return fail(std::format("cannot write {}", args[2]));
    std::println("{}: signed (v2, {}), certificate SHA-256 {}", args[2], std::holds_alternative<EcKey>(key->key) ? "ECDSA P-256" : "RSA",
                 fingerprint(*cert));
    return 0;
}

int verify(const std::vector<std::string_view>& args) {
    if (args.size() != 1) return usage();
    auto apk = read_file(std::string(args[0]));
    if (!apk) return fail(std::format("cannot read {}", args[0]));
    auto v = verify_v2(*apk);
    if (!v) return fail(std::format("{}: {}", args[0], v.error()));
    std::println("{}: verified (v2, {}), certificate SHA-256 {}", args[0], v->algorithm == algorithm_ecdsa_sha256 ? "ECDSA P-256" : "RSA",
                 fingerprint(v->certificate));
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    const std::vector<std::string_view> all(argv + 1, argv + argc);
    if (all.empty()) return usage();
    const std::string_view cmd = all[0];
    const std::vector<std::string_view> args(all.begin() + 1, all.end());
    if (cmd == "--help" || cmd == "-h" || cmd == "help") return usage(stdout, 0);
    if (cmd == "--version" || cmd == "version") {
        std::println("apkpack {}", version);
        return 0;
    }
    if (cmd == "keygen") return keygen(args);
    if (cmd == "sign") return sign(args);
    if (cmd == "verify") return verify(args);
    std::println(stderr, "apkpack: unknown command '{}'", cmd);
    return usage();
}
