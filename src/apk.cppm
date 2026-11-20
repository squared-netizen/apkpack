// SPDX-License-Identifier: MIT
//
// apkpack.apk: APK Signature Scheme v2 (Android 7.0 and later), signing and
// verifying (source.android.com/docs/security/features/apksigning/v2).
//
// An APK is a ZIP. v2 puts an "APK Signing Block" between the entries and
// the central directory, and signs digests of the three sections around it:
// the entries, the central directory, and the end-of-central-directory
// record with its central-directory offset as if there were no block. Each
// section is cut into 1 MiB chunks; a chunk's digest is
// SHA-256(0xa5 || length || chunk), and the APK's is
// SHA-256(0x5a || count || every chunk digest).
//
// One signer, one signature: ECDSA P-256 over SHA-256 (algorithm 0x0201). Without v1 (JAR) signing, so for
// Android 7.0 and later only: squared's apps need Android 9.

export module apkpack.apk;

import std;
import apkpack.crypto;
import apkpack.der;

export namespace apkpack {

inline constexpr std::uint32_t v2_block_id = 0x7109871a;
inline constexpr std::uint32_t algorithm_ecdsa_sha256 = 0x0201;
inline constexpr std::string_view block_magic = "APK Sig Block 42";

namespace detail {

inline std::uint32_t u32(ByteView b, std::size_t at) {
    return std::uint32_t{b[at]} | std::uint32_t{b[at + 1]} << 8 | std::uint32_t{b[at + 2]} << 16 | std::uint32_t{b[at + 3]} << 24;
}
inline std::uint64_t u64(ByteView b, std::size_t at) { return std::uint64_t{u32(b, at)} | std::uint64_t{u32(b, at + 4)} << 32; }
inline void put32(Bytes& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}
inline void put64(Bytes& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}
/// uint32 length, then the bytes.
inline void put_prefixed(Bytes& out, ByteView v) {
    put32(out, static_cast<std::uint32_t>(v.size()));
    out.insert(out.end(), v.begin(), v.end());
}

/// A cursor over length-prefixed values.
class Reader {
public:
    explicit Reader(ByteView in) : in_(in) {}
    bool empty() const { return in_.empty(); }
    std::optional<std::uint32_t> u32() {
        if (in_.size() < 4) return std::nullopt;
        const std::uint32_t v = detail::u32(in_, 0);
        in_ = in_.subspan(4);
        return v;
    }
    std::optional<ByteView> prefixed() {
        auto n = u32();
        if (!n || *n > in_.size()) return std::nullopt;
        const ByteView v = in_.first(*n);
        in_ = in_.subspan(*n);
        return v;
    }

private:
    ByteView in_;
};

}  // namespace detail

/// Where the parts of an APK are.
struct Layout {
    std::size_t entries_end = 0;  // where the signing block, or the central directory, starts
    std::size_t cd_offset = 0;
    std::size_t cd_size = 0;
    std::size_t eocd_offset = 0;
    std::optional<ByteView> signing_block;  // its ID-value pairs, when there is one
};

inline std::expected<Layout, std::string> layout_of(ByteView apk) {
    using detail::u32, detail::u64;
    if (apk.size() < 22) return std::unexpected("not a ZIP: too short");
    // The end-of-central-directory record: its signature, 22 bytes from the
    // end plus at most a 65535-byte comment.
    std::optional<std::size_t> eocd;
    for (std::size_t at = apk.size() - 22, stop = apk.size() > 22 + 65535 ? apk.size() - 22 - 65535 : 0;; --at) {
        if (u32(apk, at) == 0x06054b50 && at + 22 + (std::size_t{apk[at + 20]} | std::size_t{apk[at + 21]} << 8) == apk.size()) {
            eocd = at;
            break;
        }
        if (at == stop) break;
    }
    if (!eocd) return std::unexpected("not a ZIP: no end-of-central-directory record");
    Layout l;
    l.eocd_offset = *eocd;
    l.cd_size = u32(apk, *eocd + 12);
    l.cd_offset = u32(apk, *eocd + 16);
    if (l.cd_offset == 0xffffffff || l.cd_size == 0xffffffff) return std::unexpected("a ZIP64 archive, which an APK is not");
    if (l.cd_offset + l.cd_size != l.eocd_offset) return std::unexpected("the central directory does not end at the end record");
    l.entries_end = l.cd_offset;
    // A signing block ends with its size and the magic, just before the
    // central directory.
    if (l.cd_offset >= 32 && std::ranges::equal(apk.subspan(l.cd_offset - 16, 16), block_magic)) {
        const std::uint64_t size = u64(apk, l.cd_offset - 24);
        if (size < 24 || size + 8 > l.cd_offset) return std::unexpected("a signing block of impossible size");
        const std::size_t start = l.cd_offset - static_cast<std::size_t>(size) - 8;
        if (u64(apk, start) != size) return std::unexpected("a signing block whose two sizes differ");
        l.entries_end = start;
        l.signing_block = apk.subspan(start + 8, static_cast<std::size_t>(size) - 24);
    }
    return l;
}

/// The v2 digest of the three sections.
inline std::array<std::uint8_t, 32> v2_digest(ByteView apk, const Layout& l) {
    // The end record as if the central directory followed the entries.
    Bytes eocd(apk.begin() + static_cast<std::ptrdiff_t>(l.eocd_offset), apk.end());
    for (int i = 0; i < 4; ++i) eocd[16 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(l.entries_end >> (8 * i));
    const std::array<ByteView, 3> sections = {apk.first(l.entries_end), apk.subspan(l.cd_offset, l.cd_size), ByteView(eocd)};
    constexpr std::size_t chunk = 1 << 20;
    std::uint32_t count = 0;
    for (ByteView s : sections) count += static_cast<std::uint32_t>((s.size() + chunk - 1) / chunk);
    Sha256 top;
    Bytes head{0x5a};
    detail::put32(head, count);
    top.update(head);
    for (ByteView s : sections) {
        for (std::size_t at = 0; at < s.size(); at += chunk) {
            const ByteView piece = s.subspan(at, std::min(chunk, s.size() - at));
            Sha256 h;
            Bytes prefix{0xa5};
            detail::put32(prefix, static_cast<std::uint32_t>(piece.size()));
            h.update(prefix);
            h.update(piece);
            top.update(h.finish());
        }
    }
    return top.finish();
}

/// The APK signed with v2 by `key`, whose certificate is `certificate`
/// (DER). An earlier signing block is replaced.
inline std::expected<Bytes, std::string> sign_v2(ByteView apk, const PrivateKey& key, ByteView certificate) {
    auto l = layout_of(apk);
    if (!l) return std::unexpected(l.error());
    auto cert_key = certificate_key(certificate);
    if (!cert_key) return std::unexpected("the certificate's public key cannot be read");
    if (cert_key->key.point != key.key.point) return std::unexpected("the certificate is not the key's");
    const std::uint32_t algorithm = algorithm_ecdsa_sha256;

    const auto digest = v2_digest(apk, *l);
    Bytes digests, one, certificates, signed_data;
    detail::put32(one, algorithm);
    detail::put_prefixed(one, digest);
    detail::put_prefixed(digests, one);
    detail::put_prefixed(certificates, certificate);
    detail::put_prefixed(signed_data, digests);
    detail::put_prefixed(signed_data, certificates);
    detail::put_prefixed(signed_data, {});  // no additional attributes

    const auto signed_digest = Sha256::of(signed_data);
    auto rs = ec_sign(key.key, signed_digest);
    if (!rs) return std::unexpected("ECDSA signing failed");
    const Bytes signature = ecdsa_der(*rs);
    Bytes sig_record, signatures, signer, signers, v2;
    detail::put32(sig_record, algorithm);
    detail::put_prefixed(sig_record, signature);
    detail::put_prefixed(signatures, sig_record);
    detail::put_prefixed(signer, signed_data);
    detail::put_prefixed(signer, signatures);
    detail::put_prefixed(signer, cert_key->spki);
    detail::put_prefixed(signers, signer);
    detail::put_prefixed(v2, signers);

    Bytes pairs;
    detail::put64(pairs, 4 + v2.size());
    detail::put32(pairs, v2_block_id);
    pairs.insert(pairs.end(), v2.begin(), v2.end());
    const std::uint64_t block_size = pairs.size() + 8 + 16;
    Bytes block;
    detail::put64(block, block_size);
    block.insert(block.end(), pairs.begin(), pairs.end());
    detail::put64(block, block_size);
    block.insert(block.end(), block_magic.begin(), block_magic.end());

    Bytes out(apk.begin(), apk.begin() + static_cast<std::ptrdiff_t>(l->entries_end));
    out.insert(out.end(), block.begin(), block.end());
    out.insert(out.end(), apk.begin() + static_cast<std::ptrdiff_t>(l->cd_offset), apk.end());
    const std::size_t cd_at = l->entries_end + block.size();
    if (cd_at > 0xffffffffu) return std::unexpected("the APK is too large for a ZIP without ZIP64");
    const std::size_t eocd_at = out.size() - (apk.size() - l->eocd_offset);
    for (int i = 0; i < 4; ++i) out[eocd_at + 16 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(cd_at >> (8 * i));
    return out;
}

/// What verify found.
struct Verified {
    std::uint32_t algorithm = 0;
    Bytes certificate;
};

/// Checks an APK's v2 signature: its one signer's signature over its signed
/// data, the digest against the APK, and the certificate against the key.
inline std::expected<Verified, std::string> verify_v2(ByteView apk) {
    auto l = layout_of(apk);
    if (!l) return std::unexpected(l.error());
    if (!l->signing_block) return std::unexpected("not signed: no APK Signing Block");
    std::optional<ByteView> v2;
    for (ByteView rest = *l->signing_block; !rest.empty();) {
        if (rest.size() < 12) return std::unexpected("a signing block cut short");
        const std::uint64_t n = detail::u64(rest, 0);
        if (n < 4 || n > rest.size() - 8) return std::unexpected("a signing block pair of impossible size");
        if (detail::u32(rest, 8) == v2_block_id) v2 = rest.subspan(12, static_cast<std::size_t>(n) - 4);
        rest = rest.subspan(8 + static_cast<std::size_t>(n));
    }
    if (!v2) return std::unexpected("no v2 signature in the signing block");
    detail::Reader block(*v2);
    auto signers = block.prefixed();
    if (!signers) return std::unexpected("v2: no signers");
    detail::Reader signer_list(*signers);
    auto signer = signer_list.prefixed();
    if (!signer || !signer_list.empty()) return std::unexpected("v2: apkpack checks exactly one signer");
    detail::Reader s(*signer);
    auto signed_data = s.prefixed(), signatures = s.prefixed(), public_key = s.prefixed();
    if (!signed_data || !signatures || !public_key) return std::unexpected("v2: a signer cut short");
    auto key = parse_spki(*public_key);
    if (!key) return std::unexpected("v2: a public key apkpack cannot read (it checks ECDSA P-256)");

    detail::Reader sigs(*signatures);
    auto sig = sigs.prefixed();
    if (!sig) return std::unexpected("v2: no signature");
    detail::Reader sig_r(*sig);
    auto algorithm = sig_r.u32();
    auto signature = sig_r.prefixed();
    if (!algorithm || !signature) return std::unexpected("v2: a signature cut short");
    const auto signed_digest = Sha256::of(*signed_data);
    if (*algorithm != algorithm_ecdsa_sha256)
        return std::unexpected(std::format("v2: signature algorithm {:#06x}; apkpack checks ECDSA P-256 (0x0201)", *algorithm));
    auto rs = ecdsa_raw(*signature);
    if (!rs || !ec_verify(key->key.point, signed_digest, *rs)) return std::unexpected("v2: the signature does not verify");

    detail::Reader data(*signed_data);
    auto digests = data.prefixed(), certificates = data.prefixed();
    if (!digests || !certificates) return std::unexpected("v2: signed data cut short");
    detail::Reader ds(*digests);
    auto d = ds.prefixed();
    if (!d) return std::unexpected("v2: no digest");
    detail::Reader dr(*d);
    auto digest_algorithm = dr.u32();
    auto digest = dr.prefixed();
    if (!digest_algorithm || !digest || *digest_algorithm != *algorithm) return std::unexpected("v2: a digest of another algorithm");
    const auto actual = v2_digest(apk, *l);
    if (!std::ranges::equal(*digest, actual)) return std::unexpected("v2: the APK's contents do not match the signed digest");
    detail::Reader cs(*certificates);
    auto cert = cs.prefixed();
    if (!cert) return std::unexpected("v2: no certificate");
    auto cert_key = certificate_key(*cert);
    if (!cert_key || cert_key->spki != key->spki) return std::unexpected("v2: the certificate's key is not the signer's");
    return Verified{*algorithm, Bytes(cert->begin(), cert->end())};
}

}  // namespace apkpack
