// SPDX-License-Identifier: MIT
//
// apkpack.zip: the ZIP an APK is, read and written.
//
// Written entries are stored (not compressed): an APK's large parts are
// stored anyway (native libraries, resources.arsc, squared's fonts and
// packages, already compressed), and what is left is small. Each stored
// entry's data is aligned as zipalign does it, by padding the local
// header's extra field: 4 bytes, and 16384 for a .so, so that Android can
// map it in place (16 KB pages: Android 15's devices).
//
// Reading keeps each existing entry as it is (local header, data,
// compressed or not), so `apkpack add` copies what another tool wrote
// unchanged and only re-aligns where it must not. No ZIP64, no encryption,
// no spanning: an APK has none.

export module apkpack.zip;

import std;
import apkpack.crypto;

export namespace apkpack {

/// CRC-32 (IEEE), as ZIP uses it.
inline std::uint32_t crc32(ByteView data, std::uint32_t crc = 0) {
    static const auto table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xedb88320U ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }();
    crc = ~crc;
    for (std::uint8_t b : data) crc = table[(crc ^ b) & 0xff] ^ (crc >> 8);
    return ~crc;
}

/// One entry: either new data to store, or an existing entry's raw record.
struct ZipEntry {
    std::string name;
    Bytes data;                        // new: the bytes, stored
    std::optional<Bytes> raw_local;    // existing: local header + data, as read
    std::uint16_t method = 0;          // existing: 0 stored, 8 deflated
    std::uint32_t crc = 0, compressed = 0, size = 0;
    std::uint16_t flags = 0, time = 0, date = 0;
};

/// The alignment of a stored entry's data: 16384 for a native library, 4
/// for everything else.
inline std::size_t alignment_for(std::string_view name) {
    return name.ends_with(".so") ? 16384 : 4;
}

namespace zipdetail {
inline std::uint16_t u16(ByteView b, std::size_t at) { return static_cast<std::uint16_t>(b[at] | b[at + 1] << 8); }
inline std::uint32_t u32(ByteView b, std::size_t at) {
    return std::uint32_t{b[at]} | std::uint32_t{b[at + 1]} << 8 | std::uint32_t{b[at + 2]} << 16 | std::uint32_t{b[at + 3]} << 24;
}
inline void p16(Bytes& o, std::uint32_t v) {
    o.push_back(static_cast<std::uint8_t>(v));
    o.push_back(static_cast<std::uint8_t>(v >> 8));
}
inline void p32(Bytes& o, std::uint32_t v) {
    p16(o, v & 0xffff);
    p16(o, v >> 16);
}
}  // namespace zipdetail

/// The entries of a ZIP, in order. A signing block, if any, is dropped (the
/// archive is signed again after it changes).
inline std::expected<std::vector<ZipEntry>, std::string> read_zip(ByteView zip) {
    using namespace zipdetail;
    if (zip.size() < 22) return std::unexpected("not a ZIP");
    std::size_t eocd = zip.size() - 22;
    while (u32(zip, eocd) != 0x06054b50) {
        if (eocd == 0 || zip.size() - eocd > 22 + 65535) return std::unexpected("not a ZIP: no end record");
        --eocd;
    }
    const std::size_t count = u16(zip, eocd + 10), cd = u32(zip, eocd + 16);
    std::vector<ZipEntry> out;
    std::vector<std::size_t> offsets;
    for (std::size_t i = 0, at = cd; i < count; ++i) {
        if (at + 46 > zip.size() || u32(zip, at) != 0x02014b50) return std::unexpected("a broken central directory");
        ZipEntry e;
        e.flags = u16(zip, at + 8);
        e.method = u16(zip, at + 10);
        e.time = u16(zip, at + 12);
        e.date = u16(zip, at + 14);
        e.crc = u32(zip, at + 16);
        e.compressed = u32(zip, at + 20);
        e.size = u32(zip, at + 24);
        const std::size_t n = u16(zip, at + 28), extra = u16(zip, at + 30), comment = u16(zip, at + 32);
        if ((e.flags & 1) != 0) return std::unexpected("an encrypted entry");
        e.name.assign(reinterpret_cast<const char*>(zip.data() + at + 46), n);
        offsets.push_back(u32(zip, at + 42));
        out.push_back(std::move(e));
        at += 46 + n + extra + comment;
    }
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::size_t at = offsets[i];
        if (at + 30 > zip.size() || u32(zip, at) != 0x04034b50) return std::unexpected("a broken local header: " + out[i].name);
        const std::size_t data = at + 30 + u16(zip, at + 26) + u16(zip, at + 28);
        const std::size_t end = data + out[i].compressed;
        if (end > zip.size()) return std::unexpected("an entry past the end: " + out[i].name);
        // A data descriptor (flag bit 3) follows the data: kept with it.
        const std::size_t tail = (out[i].flags & 8) != 0 ? (u32(zip, end) == 0x08074b50 ? 16 : 12) : 0;
        out[i].raw_local = Bytes(zip.begin() + static_cast<std::ptrdiff_t>(at), zip.begin() + static_cast<std::ptrdiff_t>(end + tail));
    }
    return out;
}

/// A ZIP of these entries. New entries are stored and aligned; an existing
/// stored entry is re-aligned when its offset moved off its alignment.
inline Bytes write_zip(const std::vector<ZipEntry>& entries) {
    using namespace zipdetail;
    Bytes out, cd;
    // 1980-01-01 00:00: the same bytes for the same inputs.
    constexpr std::uint16_t dos_time = 0, dos_date = (0 << 9) | (1 << 5) | 1;
    for (const ZipEntry& e : entries) {
        const std::size_t offset = out.size();
        std::uint16_t method = 0, flags = 0, time = dos_time, date = dos_date;
        std::uint32_t crc = 0, csize = 0, size = 0;
        ByteView name(reinterpret_cast<const std::uint8_t*>(e.name.data()), e.name.size());
        const bool keep_raw = e.raw_local && e.method != 0;  // compressed: copied as it is
        if (keep_raw) {
            method = e.method, flags = e.flags, time = e.time, date = e.date;
            crc = e.crc, csize = e.compressed, size = e.size;
            out.insert(out.end(), e.raw_local->begin(), e.raw_local->end());
        } else {
            ByteView data;
            if (e.raw_local) {  // an existing stored entry: its data, re-aligned
                const ByteView raw = *e.raw_local;
                const std::size_t start = 30 + u16(raw, 26) + u16(raw, 28);
                data = raw.subspan(start, e.size);
                crc = e.crc, time = e.time, date = e.date;
            } else {
                data = e.data;
                crc = crc32(data);
            }
            size = csize = static_cast<std::uint32_t>(data.size());
            const std::size_t align = alignment_for(e.name);
            const std::size_t data_at = offset + 30 + name.size();
            const std::size_t pad = (align - data_at % align) % align;
            p32(out, 0x04034b50);
            p16(out, 10);
            p16(out, 0);
            p16(out, 0);
            p16(out, time);
            p16(out, date);
            p32(out, crc);
            p32(out, csize);
            p32(out, size);
            p16(out, static_cast<std::uint32_t>(name.size()));
            p16(out, static_cast<std::uint32_t>(pad));
            out.insert(out.end(), name.begin(), name.end());
            out.insert(out.end(), pad, 0);
            out.insert(out.end(), data.begin(), data.end());
        }
        p32(cd, 0x02014b50);
        p16(cd, 20);  // made by: MS-DOS, 2.0
        p16(cd, method == 0 ? 10 : 20);
        p16(cd, flags);
        p16(cd, method);
        p16(cd, time);
        p16(cd, date);
        p32(cd, crc);
        p32(cd, csize);
        p32(cd, size);
        p16(cd, static_cast<std::uint32_t>(name.size()));
        p16(cd, 0);
        p16(cd, 0);
        p16(cd, 0);
        p16(cd, 0);
        p32(cd, 0);
        p32(cd, static_cast<std::uint32_t>(offset));
        cd.insert(cd.end(), name.begin(), name.end());
    }
    const std::size_t cd_at = out.size();
    out.insert(out.end(), cd.begin(), cd.end());
    p32(out, 0x06054b50);
    p16(out, 0);
    p16(out, 0);
    p16(out, static_cast<std::uint32_t>(entries.size()));
    p16(out, static_cast<std::uint32_t>(entries.size()));
    p32(out, static_cast<std::uint32_t>(cd.size()));
    p32(out, static_cast<std::uint32_t>(cd_at));
    p16(out, 0);
    return out;
}

/// `entries` with `name` set to `data`: replaced where it is, else added.
inline void put_entry(std::vector<ZipEntry>& entries, std::string name, Bytes data) {
    for (ZipEntry& e : entries) {
        if (e.name == name) {
            e = ZipEntry{std::move(name), std::move(data)};
            return;
        }
    }
    entries.push_back(ZipEntry{std::move(name), std::move(data)});
}

}  // namespace apkpack
