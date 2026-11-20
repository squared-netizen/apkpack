// SPDX-License-Identifier: MIT
// SHA-256 against FIPS 180-4's examples; ECDSA and RSA signing round trips;
// DER and PEM round trips.
#include <stdio.h>

import std;
import apkpack.crypto;
import apkpack.der;

using namespace apkpack;

namespace {

int failures = 0;
void check(bool ok, std::string_view what) {
    if (!ok) {
        std::println(stderr, "FAIL {}", what);
        ++failures;
    }
}

std::string hex(std::span<const std::uint8_t> b) {
    std::string out;
    for (auto v : b) out += std::format("{:02x}", v);
    return out;
}

ByteView text(std::string_view s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }

}  // namespace

int main() {
    check(hex(Sha256::of(text(""))) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256('')");
    check(hex(Sha256::of(text("abc"))) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256(abc)");
    check(hex(Sha256::of(text("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "sha256(two blocks)");
    Bytes million(1000000, 'a');
    check(hex(Sha256::of(million)) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "sha256(a million a)");

    auto ec = ec_generate();
    check(ec.has_value(), "ec_generate");
    const auto digest = Sha256::of(text("signed data"));
    auto rs = ec_sign(*ec, digest);
    check(rs && ec_verify(ec->point, digest, *rs), "ECDSA sign, verify");
    auto other = Sha256::of(text("other data"));
    check(rs && !ec_verify(ec->point, other, *rs), "ECDSA refuses another digest");
    check(rs && ecdsa_raw(ecdsa_der(*rs)) == *rs, "ECDSA DER round trip");

    // A small RSA key (p = 61, q = 53 is too small for PKCS#1 padding), so
    // RSA's arithmetic alone: m^e^d = m for n = 3233, e = 17, d = 2753.
    const Big m = Big::from_bytes(std::array<std::uint8_t, 1>{65});
    const Big n = Big::from_bytes(std::array<std::uint8_t, 2>{0x0c, 0xa1});
    const Big c = Big::pow_mod(m, Big::from_bytes(std::array<std::uint8_t, 1>{17}), n);
    check(c.to_bytes(2) == Bytes{0x0a, 0xe6}, "RSA textbook: 65^17 mod 3233 = 2790");
    check(Big::pow_mod(c, Big::from_bytes(std::array<std::uint8_t, 2>{0x0a, 0xc1}), n).to_bytes(1) == Bytes{65}, "RSA textbook: back");

    const Bytes data = {0, 1, 2, 250, 251, 252, 253, 254, 255};
    for (std::size_t len = 0; len <= data.size(); ++len) {
        const ByteView part(data.data(), len);
        check(unbase64(base64(part)) == Bytes(part.begin(), part.end()), std::format("base64 round trip, {} bytes", len));
    }
    auto pk = parse_private_key(pem("PRIVATE KEY", pkcs8_of(*ec)));
    check(pk && std::get<EcKey>(pk->key).point == ec->point, "PKCS#8 round trip");
    auto cert = self_signed(*ec, "t", 1);
    auto key = cert ? certificate_key(*cert) : std::nullopt;
    check(key && std::get<EcKey>(key->key).point == ec->point, "certificate's key");

    if (failures == 0) std::println("ok   crypto");
    return failures == 0 ? 0 : 1;
}
