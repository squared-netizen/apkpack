// SPDX-License-Identifier: MIT
//
// apkpack.der: the ASN.1 DER, PEM and X.509 that signing needs.
//
//   a key file          PEM: a private key (PKCS#8 "PRIVATE KEY", SEC 1
//                       "EC PRIVATE KEY" or PKCS#1 "RSA PRIVATE KEY") and a
//                       certificate ("CERTIFICATE"), as openssl writes them
//   a certificate       read for its SubjectPublicKeyInfo; made self-signed
//                       by keygen (ECDSA P-256 with SHA-256, X.509 v3)

export module apkpack.der;

import std;
import apkpack.crypto;

export namespace apkpack {

// ---------------------------------------------------------------------------
// Writing

namespace der {

inline Bytes tlv(std::uint8_t tag, ByteView content) {
    Bytes out{tag};
    const std::size_t n = content.size();
    if (n < 0x80) {
        out.push_back(static_cast<std::uint8_t>(n));
    } else {
        Bytes length;
        for (std::size_t v = n; v != 0; v >>= 8) length.insert(length.begin(), static_cast<std::uint8_t>(v));
        out.push_back(static_cast<std::uint8_t>(0x80 | length.size()));
        out.insert(out.end(), length.begin(), length.end());
    }
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

inline Bytes join(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const Bytes& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

inline Bytes seq(std::initializer_list<Bytes> parts) { return tlv(0x30, join(parts)); }
inline Bytes set(std::initializer_list<Bytes> parts) { return tlv(0x31, join(parts)); }
inline Bytes octets(ByteView v) { return tlv(0x04, v); }
inline Bytes null() { return {0x05, 0x00}; }
inline Bytes utf8(std::string_view s) { return tlv(0x0c, {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}); }
inline Bytes explicit_tag(int n, const Bytes& inner) { return tlv(static_cast<std::uint8_t>(0xa0 + n), inner); }

/// BIT STRING with no unused bits.
inline Bytes bits(ByteView v) {
    Bytes content{0x00};
    content.insert(content.end(), v.begin(), v.end());
    return tlv(0x03, content);
}

/// An unsigned big-endian INTEGER: leading zeros dropped, one added where
/// the top bit is set.
inline Bytes integer(ByteView be) {
    std::size_t at = 0;
    while (at + 1 < be.size() && be[at] == 0) ++at;
    Bytes content;
    if (be.empty() || (be[at] & 0x80) != 0) content.push_back(0x00);
    content.insert(content.end(), be.begin() + static_cast<std::ptrdiff_t>(at), be.end());
    return tlv(0x02, content);
}
inline Bytes integer(std::uint64_t v) {
    Bytes be;
    for (int i = 7; i >= 0; --i) be.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    return integer(be);
}

inline Bytes oid(std::string_view dotted) {
    std::vector<std::uint64_t> arcs;
    for (auto part : dotted | std::views::split('.')) {
        std::uint64_t v = 0;
        for (char c : part) v = v * 10 + static_cast<std::uint64_t>(c - '0');
        arcs.push_back(v);
    }
    Bytes content{static_cast<std::uint8_t>(arcs[0] * 40 + arcs[1])};
    for (std::size_t i = 2; i < arcs.size(); ++i) {
        Bytes base128;
        std::uint64_t v = arcs[i];
        base128.insert(base128.begin(), static_cast<std::uint8_t>(v & 0x7f));
        for (v >>= 7; v != 0; v >>= 7) base128.insert(base128.begin(), static_cast<std::uint8_t>(0x80 | (v & 0x7f)));
        content.insert(content.end(), base128.begin(), base128.end());
    }
    return tlv(0x06, content);
}

/// UTCTime before 2050, GeneralizedTime from then on (RFC 5280 4.1.2.5).
inline Bytes time(std::chrono::sys_seconds t) {
    const auto day = std::chrono::floor<std::chrono::days>(t);
    const std::chrono::year_month_day ymd{day};
    const std::chrono::hh_mm_ss hms{t - day};
    const int year = static_cast<int>(ymd.year());
    const std::string rest = std::format("{:02}{:02}{:02}{:02}{:02}Z", static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()),
                                         hms.hours().count(), hms.minutes().count(), hms.seconds().count());
    const std::string text = (year < 2050 ? std::format("{:02}", year % 100) : std::format("{:04}", year)) + rest;
    return tlv(year < 2050 ? 0x17 : 0x18, {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()});
}

// ---------------------------------------------------------------------------
// Reading

struct Item {
    std::uint8_t tag = 0;
    ByteView content;  // the value
    ByteView whole;    // tag, length and value
};

/// The item at the start of `in`, or nothing when it is not well formed.
inline std::optional<Item> read(ByteView in) {
    if (in.size() < 2) return std::nullopt;
    std::size_t at = 1, length = in[at++];
    if (length & 0x80) {
        const std::size_t n = length & 0x7f;
        if (n == 0 || n > 4 || at + n > in.size()) return std::nullopt;
        length = 0;
        for (std::size_t i = 0; i < n; ++i) length = (length << 8) | in[at++];
    }
    if (length > in.size() - at) return std::nullopt;
    return Item{in[0], in.subspan(at, length), in.subspan(0, at + length)};
}

/// The items one after another inside a constructed item.
inline std::optional<std::vector<Item>> children(const Item& parent) {
    std::vector<Item> out;
    for (ByteView rest = parent.content; !rest.empty();) {
        auto item = read(rest);
        if (!item) return std::nullopt;
        out.push_back(*item);
        rest = rest.subspan(item->whole.size());
    }
    return out;
}

/// An INTEGER's value as unsigned big-endian bytes, leading zeros dropped.
inline Bytes unsigned_of(const Item& item) {
    ByteView v = item.content;
    while (v.size() > 1 && v[0] == 0) v = v.subspan(1);
    return {v.begin(), v.end()};
}

inline bool is_oid(const Item& item, std::string_view dotted) {
    const Bytes want = oid(dotted);
    return std::ranges::equal(item.whole, want);
}

}  // namespace der

// ---------------------------------------------------------------------------
// PEM

inline std::string base64(ByteView in) {
    static constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (std::size_t i = 0; i < in.size(); i += 3) {
        const std::uint32_t v = (std::uint32_t{in[i]} << 16) | (i + 1 < in.size() ? std::uint32_t{in[i + 1]} << 8 : 0) |
                                (i + 2 < in.size() ? std::uint32_t{in[i + 2]} : 0);
        out += alphabet[(v >> 18) & 63];
        out += alphabet[(v >> 12) & 63];
        out += i + 1 < in.size() ? alphabet[(v >> 6) & 63] : '=';
        out += i + 2 < in.size() ? alphabet[v & 63] : '=';
    }
    return out;
}

inline std::optional<Bytes> unbase64(std::string_view in) {
    Bytes out;
    std::uint32_t v = 0;
    int have = 0;
    for (char c : in) {
        int d;
        if (c >= 'A' && c <= 'Z') d = c - 'A';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
        else if (c >= '0' && c <= '9') d = c - '0' + 52;
        else if (c == '+') d = 62;
        else if (c == '/') d = 63;
        else if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        else return std::nullopt;
        v = (v << 6) | static_cast<std::uint32_t>(d);
        if (++have == 4) {
            out.push_back(static_cast<std::uint8_t>(v >> 16));
            out.push_back(static_cast<std::uint8_t>(v >> 8));
            out.push_back(static_cast<std::uint8_t>(v));
            v = 0, have = 0;
        }
    }
    if (have == 2) out.push_back(static_cast<std::uint8_t>(v >> 4));
    if (have == 3) {
        out.push_back(static_cast<std::uint8_t>(v >> 10));
        out.push_back(static_cast<std::uint8_t>(v >> 2));
    }
    return out;
}

inline std::string pem(std::string_view label, ByteView der) {
    std::string out = std::format("-----BEGIN {}-----\n", label);
    const std::string b = base64(der);
    for (std::size_t i = 0; i < b.size(); i += 64) out += b.substr(i, 64) + "\n";
    return out + std::format("-----END {}-----\n", label);
}

/// The first block with this label in a PEM text.
inline std::optional<Bytes> unpem(std::string_view text, std::string_view label) {
    const std::string begin = std::format("-----BEGIN {}-----", label), end = std::format("-----END {}-----", label);
    const std::size_t from = text.find(begin);
    if (from == std::string_view::npos) return std::nullopt;
    const std::size_t to = text.find(end, from);
    if (to == std::string_view::npos) return std::nullopt;
    return unbase64(text.substr(from + begin.size(), to - from - begin.size()));
}

// ---------------------------------------------------------------------------
// Keys and certificates

inline constexpr std::string_view oid_ec_public_key = "1.2.840.10045.2.1";
inline constexpr std::string_view oid_prime256v1 = "1.2.840.10045.3.1.7";
inline constexpr std::string_view oid_rsa = "1.2.840.113549.1.1.1";
inline constexpr std::string_view oid_ecdsa_sha256 = "1.2.840.10045.4.3.2";

/// A signing key: ECDSA P-256 or RSA.
struct PrivateKey {
    std::variant<EcKey, RsaKey> key;
};

/// A public key, from a SubjectPublicKeyInfo.
struct PublicKey {
    std::variant<EcKey, RsaKey> key;
    Bytes spki;  // the SubjectPublicKeyInfo, DER
};

inline Bytes ec_spki(const std::array<std::uint8_t, 64>& point) {
    Bytes uncompressed{0x04};
    uncompressed.insert(uncompressed.end(), point.begin(), point.end());
    return der::seq({der::seq({der::oid(oid_ec_public_key), der::oid(oid_prime256v1)}), der::bits(uncompressed)});
}

inline std::optional<PublicKey> parse_spki(ByteView spki) {
    auto top = der::read(spki);
    if (!top || top->tag != 0x30) return std::nullopt;
    auto parts = der::children(*top);
    if (!parts || parts->size() != 2 || (*parts)[1].tag != 0x03 || (*parts)[1].content.empty()) return std::nullopt;
    auto alg = der::children((*parts)[0]);
    if (!alg || alg->empty()) return std::nullopt;
    const ByteView key_bits = (*parts)[1].content.subspan(1);
    PublicKey out;
    out.spki.assign(top->whole.begin(), top->whole.end());
    if (der::is_oid((*alg)[0], oid_ec_public_key)) {
        if (alg->size() < 2 || !der::is_oid((*alg)[1], oid_prime256v1)) return std::nullopt;
        if (key_bits.size() != 65 || key_bits[0] != 0x04) return std::nullopt;
        EcKey ec;
        std::ranges::copy(key_bits.subspan(1), ec.point.begin());
        out.key = ec;
        return out;
    }
    if (der::is_oid((*alg)[0], oid_rsa)) {
        auto rsa = der::read(key_bits);
        if (!rsa) return std::nullopt;
        auto ne = der::children(*rsa);
        if (!ne || ne->size() < 2) return std::nullopt;
        out.key = RsaKey{der::unsigned_of((*ne)[0]), der::unsigned_of((*ne)[1]), {}};
        return out;
    }
    return std::nullopt;
}

/// A certificate's SubjectPublicKeyInfo (tbsCertificate's seventh field, or
/// sixth in a v1 certificate without the [0] version).
inline std::optional<PublicKey> certificate_key(ByteView certificate) {
    auto top = der::read(certificate);
    if (!top) return std::nullopt;
    auto parts = der::children(*top);
    if (!parts || parts->empty()) return std::nullopt;
    auto tbs = der::children((*parts)[0]);
    if (!tbs || tbs->empty()) return std::nullopt;
    const std::size_t at = (*tbs)[0].tag == 0xa0 ? 6 : 5;
    if (tbs->size() <= at) return std::nullopt;
    return parse_spki((*tbs)[at].whole);
}

inline std::optional<PrivateKey> parse_ec_private(ByteView sec1) {
    auto top = der::read(sec1);
    if (!top) return std::nullopt;
    auto parts = der::children(*top);
    if (!parts || parts->size() < 2 || (*parts)[1].tag != 0x04 || (*parts)[1].content.size() > 32) return std::nullopt;
    EcKey ec;
    const ByteView secret = (*parts)[1].content;
    std::ranges::copy(secret, ec.secret.begin() + static_cast<std::ptrdiff_t>(32 - secret.size()));
    auto point = ec_point_of(ec.secret);
    if (!point) return std::nullopt;
    ec.point = *point;
    return PrivateKey{ec};
}

inline std::optional<PrivateKey> parse_rsa_private(ByteView pkcs1) {
    auto top = der::read(pkcs1);
    if (!top) return std::nullopt;
    auto parts = der::children(*top);
    if (!parts || parts->size() < 4) return std::nullopt;
    return PrivateKey{RsaKey{der::unsigned_of((*parts)[1]), der::unsigned_of((*parts)[2]), der::unsigned_of((*parts)[3])}};
}

/// The private key in a PEM text: PKCS#8, SEC 1 or PKCS#1. An encrypted
/// key is refused (openssl pkey -in KEY -out PLAIN takes the password off).
inline std::expected<PrivateKey, std::string> parse_private_key(std::string_view text) {
    if (text.find("ENCRYPTED PRIVATE KEY") != std::string_view::npos)
        return std::unexpected("the key is encrypted: openssl pkey -in KEY -out PLAIN.pem takes the password off");
    if (auto sec1 = unpem(text, "EC PRIVATE KEY")) {
        if (auto k = parse_ec_private(*sec1)) return *k;
        return std::unexpected("EC PRIVATE KEY: not a P-256 key apkpack can read");
    }
    if (auto pkcs1 = unpem(text, "RSA PRIVATE KEY")) {
        if (auto k = parse_rsa_private(*pkcs1)) return *k;
        return std::unexpected("RSA PRIVATE KEY: not a key apkpack can read");
    }
    auto pkcs8 = unpem(text, "PRIVATE KEY");
    if (!pkcs8) return std::unexpected("no private key (PEM: PRIVATE KEY, EC PRIVATE KEY or RSA PRIVATE KEY)");
    auto top = der::read(*pkcs8);
    auto parts = top ? der::children(*top) : std::nullopt;
    if (!parts || parts->size() < 3 || (*parts)[2].tag != 0x04) return std::unexpected("PRIVATE KEY: not PKCS#8");
    auto alg = der::children((*parts)[1]);
    if (!alg || alg->empty()) return std::unexpected("PRIVATE KEY: no algorithm");
    if (der::is_oid((*alg)[0], oid_ec_public_key)) {
        if (alg->size() < 2 || !der::is_oid((*alg)[1], oid_prime256v1)) return std::unexpected("an EC key on another curve than P-256");
        if (auto k = parse_ec_private((*parts)[2].content)) return *k;
        return std::unexpected("PRIVATE KEY: an EC key apkpack cannot read");
    }
    if (der::is_oid((*alg)[0], oid_rsa)) {
        if (auto k = parse_rsa_private((*parts)[2].content)) return *k;
        return std::unexpected("PRIVATE KEY: an RSA key apkpack cannot read");
    }
    return std::unexpected("PRIVATE KEY: neither EC P-256 nor RSA");
}

inline Bytes pkcs8_of(const EcKey& ec) {
    Bytes uncompressed{0x04};
    uncompressed.insert(uncompressed.end(), ec.point.begin(), ec.point.end());
    const Bytes sec1 = der::seq({der::integer(1), der::octets(ec.secret), der::explicit_tag(1, der::bits(uncompressed))});
    return der::seq({der::integer(0), der::seq({der::oid(oid_ec_public_key), der::oid(oid_prime256v1)}), der::octets(sec1)});
}

/// An ECDSA signature, r || s, as DER (ECDSA-Sig-Value).
inline Bytes ecdsa_der(const std::array<std::uint8_t, 64>& rs) {
    return der::seq({der::integer(ByteView(rs).first(32)), der::integer(ByteView(rs).subspan(32))});
}

/// r || s from DER, each padded to 32 bytes.
inline std::optional<std::array<std::uint8_t, 64>> ecdsa_raw(ByteView signature) {
    auto top = der::read(signature);
    auto parts = top ? der::children(*top) : std::nullopt;
    if (!parts || parts->size() != 2) return std::nullopt;
    std::array<std::uint8_t, 64> rs{};
    for (std::size_t i = 0; i < 2; ++i) {
        const Bytes v = der::unsigned_of((*parts)[i]);
        if (v.size() > 32) return std::nullopt;
        std::ranges::copy(v, rs.begin() + static_cast<std::ptrdiff_t>(32 * i + 32 - v.size()));
    }
    return rs;
}

/// A self-signed X.509 v3 certificate for an EC key: subject and issuer
/// CN=name, valid from now for `years`.
inline std::optional<Bytes> self_signed(const EcKey& ec, std::string_view name, int years) {
    std::array<std::uint8_t, 16> serial{};
    std::random_device random;
    for (auto& b : serial) b = static_cast<std::uint8_t>(random());
    serial[0] &= 0x7f;
    serial[0] |= 0x01;  // positive, and 16 bytes long
    const auto now = std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now());
    // The same day and time, `years` calendar years on (29 February: 1 March).
    const auto today = std::chrono::floor<std::chrono::days>(now);
    const std::chrono::year_month_day then = std::chrono::year_month_day{today} + std::chrono::years(years);
    const auto until = std::chrono::sys_days(then.ok() ? then : then.year() / std::chrono::March / 1) + (now - today);
    const Bytes name_der = der::seq({der::set({der::seq({der::oid("2.5.4.3"), der::utf8(name)})})});
    const Bytes alg = der::seq({der::oid(oid_ecdsa_sha256)});
    const Bytes tbs = der::seq({der::explicit_tag(0, der::integer(2)), der::integer(serial), alg, name_der,
                                der::seq({der::time(now), der::time(std::chrono::floor<std::chrono::seconds>(until))}),
                                name_der, ec_spki(ec.point)});
    auto rs = ec_sign(ec, Sha256::of(tbs));
    if (!rs) return std::nullopt;
    return der::seq({tbs, alg, der::bits(ecdsa_der(*rs))});
}

}  // namespace apkpack
