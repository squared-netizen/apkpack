// SPDX-License-Identifier: MIT
//
// apkpack.crypto: what signing an APK needs, and no more.
//
//   sha256         FIPS 180-4, incremental
//   ECDSA P-256    over micro-ecc (third_party/micro-ecc): keys, sign, verify
//   RSA            PKCS#1 v1.5 with SHA-256, sign and verify, for a key made
//                  elsewhere (the debug key an installed app was signed with:
//                  Android refuses an update signed by another key)
//
// The RSA arithmetic is a plain Montgomery exponentiation. It is not
// constant-time: apkpack signs on the machine that holds the key, for apps
// that are side-loaded, and a debug key is no secret worth that.

module;

#include "uECC.h"

export module apkpack.crypto;

import std;

export namespace apkpack {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

// ---------------------------------------------------------------------------
// SHA-256

class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        state_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        length_ = 0;
        used_ = 0;
    }

    void update(ByteView data) {
        for (std::uint8_t byte : data) {
            block_[used_++] = byte;
            if (used_ == 64) {
                compress();
                used_ = 0;
            }
        }
        length_ += data.size();
    }

    std::array<std::uint8_t, 32> finish() {
        const std::uint64_t bits = length_ * 8;
        const std::uint8_t one = 0x80;
        update({&one, 1});
        const std::uint8_t zero = 0;
        while (used_ != 56) update({&zero, 1});
        std::array<std::uint8_t, 8> tail{};
        for (int i = 0; i < 8; ++i) tail[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
        update(tail);
        std::array<std::uint8_t, 32> out{};
        for (std::size_t i = 0; i < 8; ++i)
            for (std::size_t j = 0; j < 4; ++j) out[4 * i + j] = static_cast<std::uint8_t>(state_[i] >> (24 - 8 * j));
        reset();
        return out;
    }

    static std::array<std::uint8_t, 32> of(ByteView data) {
        Sha256 h;
        h.update(data);
        return h.finish();
    }

private:
    static constexpr std::array<std::uint32_t, 64> k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
        0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
        0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
        0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    void compress() {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0; i < 16; ++i)
            w[i] = (std::uint32_t{block_[4 * i]} << 24) | (std::uint32_t{block_[4 * i + 1]} << 16) | (std::uint32_t{block_[4 * i + 2]} << 8) |
                   std::uint32_t{block_[4 * i + 3]};
        for (std::size_t i = 16; i < 64; ++i) {
            const std::uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        auto [a, b, c, d, e, f, g, h] = state_;
        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint32_t t1 = h + (std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i];
            const std::uint32_t t2 = (std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
        }
        const std::array<std::uint32_t, 8> add = {a, b, c, d, e, f, g, h};
        for (std::size_t i = 0; i < 8; ++i) state_[i] += add[i];
    }

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> block_{};
    std::uint64_t length_ = 0;
    std::size_t used_ = 0;
};

// ---------------------------------------------------------------------------
// ECDSA over P-256

struct EcKey {
    std::array<std::uint8_t, 32> secret{};  // empty (all zero) for a public key alone
    std::array<std::uint8_t, 64> point{};   // x || y, big-endian
};

/// A new key from the system's random source.
std::optional<EcKey> ec_generate() {
    EcKey key;
    if (!uECC_make_key(key.point.data(), key.secret.data(), uECC_secp256r1())) return std::nullopt;
    return key;
}

/// The public point of a secret.
std::optional<std::array<std::uint8_t, 64>> ec_point_of(const std::array<std::uint8_t, 32>& secret) {
    std::array<std::uint8_t, 64> point{};
    if (!uECC_compute_public_key(secret.data(), point.data(), uECC_secp256r1())) return std::nullopt;
    return point;
}

/// r || s, 32 bytes each, over a SHA-256 digest.
std::optional<std::array<std::uint8_t, 64>> ec_sign(const EcKey& key, const std::array<std::uint8_t, 32>& digest) {
    std::array<std::uint8_t, 64> rs{};
    if (!uECC_sign(key.secret.data(), digest.data(), digest.size(), rs.data(), uECC_secp256r1())) return std::nullopt;
    return rs;
}

bool ec_verify(const std::array<std::uint8_t, 64>& point, const std::array<std::uint8_t, 32>& digest, const std::array<std::uint8_t, 64>& rs) {
    return uECC_verify(point.data(), digest.data(), digest.size(), rs.data(), uECC_secp256r1()) != 0;
}

// ---------------------------------------------------------------------------
// RSA

/// Unsigned big integers, 32-bit limbs, least significant first: as much as
/// modular exponentiation needs.
class Big {
public:
    Big() = default;
    static Big from_bytes(ByteView be) {
        Big x;
        x.limbs_.assign((be.size() + 3) / 4, 0);
        for (std::size_t i = 0; i < be.size(); ++i) {
            const std::size_t bit = 8 * (be.size() - 1 - i);
            x.limbs_[bit / 32] |= std::uint32_t{be[i]} << (bit % 32);
        }
        x.trim();
        return x;
    }
    Bytes to_bytes(std::size_t length) const {
        Bytes out(length, 0);
        for (std::size_t i = 0; i < length; ++i) {
            const std::size_t bit = 8 * (length - 1 - i);
            if (bit / 32 < limbs_.size()) out[i] = static_cast<std::uint8_t>(limbs_[bit / 32] >> (bit % 32));
        }
        return out;
    }
    std::size_t bits() const {
        if (limbs_.empty()) return 0;
        return 32 * (limbs_.size() - 1) + (32 - static_cast<std::size_t>(std::countl_zero(limbs_.back())));
    }
    bool bit(std::size_t i) const { return i / 32 < limbs_.size() && ((limbs_[i / 32] >> (i % 32)) & 1U) != 0; }
    bool odd() const { return !limbs_.empty() && (limbs_[0] & 1U) != 0; }

    /// base^exponent mod modulus (modulus odd), by Montgomery multiplication.
    static Big pow_mod(const Big& base, const Big& exponent, const Big& modulus) {
        const std::size_t k = modulus.limbs_.size();
        // n' = -n^-1 mod 2^32 (Newton's iteration).
        std::uint32_t inverse = 1;
        for (int i = 0; i < 5; ++i) inverse *= 2 - modulus.limbs_[0] * inverse;
        const std::uint32_t n_prime = 0U - inverse;
        auto mont = [&](const std::vector<std::uint32_t>& a, const std::vector<std::uint32_t>& b) {
            std::vector<std::uint32_t> t(k + 2, 0);
            for (std::size_t i = 0; i < k; ++i) {
                std::uint64_t carry = 0;
                for (std::size_t j = 0; j < k; ++j) {
                    const std::uint64_t v = std::uint64_t{t[j]} + std::uint64_t{a[i]} * b[j] + carry;
                    t[j] = static_cast<std::uint32_t>(v);
                    carry = v >> 32;
                }
                std::uint64_t v = std::uint64_t{t[k]} + carry;
                t[k] = static_cast<std::uint32_t>(v);
                t[k + 1] = static_cast<std::uint32_t>(v >> 32);
                const std::uint32_t m = t[0] * n_prime;
                carry = (std::uint64_t{t[0]} + std::uint64_t{m} * modulus.limbs_[0]) >> 32;
                for (std::size_t j = 1; j < k; ++j) {
                    v = std::uint64_t{t[j]} + std::uint64_t{m} * modulus.limbs_[j] + carry;
                    t[j - 1] = static_cast<std::uint32_t>(v);
                    carry = v >> 32;
                }
                v = std::uint64_t{t[k]} + carry;
                t[k - 1] = static_cast<std::uint32_t>(v);
                t[k] = t[k + 1] + static_cast<std::uint32_t>(v >> 32);
                t[k + 1] = 0;
            }
            std::vector<std::uint32_t> r(t.begin(), t.begin() + static_cast<std::ptrdiff_t>(k));
            if (t[k] != 0 || !less(r, modulus.limbs_)) subtract(r, modulus.limbs_);
            return r;
        };
        // R^2 mod n, by doubling 1 (2 * 32k times), reducing each time.
        std::vector<std::uint32_t> r2(k, 0);
        r2[0] = 1;
        for (std::size_t i = 0; i < 64 * k; ++i) {
            const std::uint32_t top = r2[k - 1] >> 31;
            for (std::size_t j = k; j-- > 1;) r2[j] = (r2[j] << 1) | (r2[j - 1] >> 31);
            r2[0] <<= 1;
            if (top != 0 || !less(r2, modulus.limbs_)) subtract(r2, modulus.limbs_);
        }
        std::vector<std::uint32_t> b = base.limbs_;
        b.resize(k, 0);
        std::vector<std::uint32_t> one(k, 0);
        one[0] = 1;
        const std::vector<std::uint32_t> base_m = mont(b, r2);
        std::vector<std::uint32_t> x = mont(one, r2);
        for (std::size_t i = exponent.bits(); i-- > 0;) {
            x = mont(x, x);
            if (exponent.bit(i)) x = mont(x, base_m);
        }
        Big result;
        result.limbs_ = mont(x, one);
        result.trim();
        return result;
    }

private:
    static bool less(const std::vector<std::uint32_t>& a, const std::vector<std::uint32_t>& b) {
        for (std::size_t i = std::max(a.size(), b.size()); i-- > 0;) {
            const std::uint32_t x = i < a.size() ? a[i] : 0, y = i < b.size() ? b[i] : 0;
            if (x != y) return x < y;
        }
        return false;
    }
    static void subtract(std::vector<std::uint32_t>& a, const std::vector<std::uint32_t>& b) {
        std::int64_t borrow = 0;
        for (std::size_t i = 0; i < a.size(); ++i) {
            const std::int64_t v = std::int64_t{a[i]} - (i < b.size() ? std::int64_t{b[i]} : 0) - borrow;
            a[i] = static_cast<std::uint32_t>(v);
            borrow = v < 0 ? 1 : 0;
        }
    }
    void trim() {
        while (!limbs_.empty() && limbs_.back() == 0) limbs_.pop_back();
    }
    std::vector<std::uint32_t> limbs_;
};

struct RsaKey {
    Bytes n, e, d;  // big-endian; d empty for a public key alone
};

/// EMSA-PKCS1-v1_5 for SHA-256: 00 01 FF.. 00 DigestInfo digest.
std::optional<Bytes> rsa_encode(const std::array<std::uint8_t, 32>& digest, std::size_t length) {
    static constexpr std::array<std::uint8_t, 19> info = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                          0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    if (length < info.size() + digest.size() + 11) return std::nullopt;
    Bytes em(length, 0xff);
    em[0] = 0x00;
    em[1] = 0x01;
    const std::size_t at = length - info.size() - digest.size();
    em[at - 1] = 0x00;
    std::ranges::copy(info, em.begin() + static_cast<std::ptrdiff_t>(at));
    std::ranges::copy(digest, em.begin() + static_cast<std::ptrdiff_t>(at + info.size()));
    return em;
}

std::size_t rsa_length(const RsaKey& key) { return (Big::from_bytes(key.n).bits() + 7) / 8; }

std::optional<Bytes> rsa_sign(const RsaKey& key, const std::array<std::uint8_t, 32>& digest) {
    const Big n = Big::from_bytes(key.n);
    if (!n.odd() || key.d.empty()) return std::nullopt;
    const std::size_t length = rsa_length(key);
    auto em = rsa_encode(digest, length);
    if (!em) return std::nullopt;
    return Big::pow_mod(Big::from_bytes(*em), Big::from_bytes(key.d), n).to_bytes(length);
}

bool rsa_verify(const RsaKey& key, const std::array<std::uint8_t, 32>& digest, ByteView signature) {
    const Big n = Big::from_bytes(key.n);
    const std::size_t length = rsa_length(key);
    if (!n.odd() || signature.size() != length) return false;
    const auto em = rsa_encode(digest, length);
    return em && Big::pow_mod(Big::from_bytes(signature), Big::from_bytes(key.e), n).to_bytes(length) == *em;
}

}  // namespace apkpack
