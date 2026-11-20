// SPDX-License-Identifier: MIT
//
// apkpack.res: what aapt2 compile and aapt2 link did for squared's apps.
//
//   the manifest      text XML to Android's binary XML, every android:
//                     attribute typed by Android's own table (formats, enum
//                     and flag values, IDs: src/android_table.inc, from
//                     AOSP), <uses-sdk> and android:debuggable put in
//   res/              values/*.xml (string, color, bool, integer, dimen)
//                     into resources.arsc; other XML files compiled to
//                     binary XML; anything else (PNG) copied as it is
//   references        @type/name and @+id/name to the app's resources,
//                     @android:type/name to Android's, ?attr to attributes
//
// Qualifiers: densities (ldpi .. xxxhdpi, anydpi, nodpi), vN, night and
// notnight, land and port, a two-letter language and rXX region. Enough for
// squared's templates; an unknown qualifier is refused, never guessed.
//
// Formats, from AOSP's frameworks/base (libs/androidfw/ResourceTypes.h):
// chunks of {type u16, header size u16, size u32}; string pools UTF-8 in
// resources.arsc and UTF-16 in binary XML, as aapt2 writes them.

export module apkpack.res;

import std;
import apkpack.crypto;

export namespace apkpack {

namespace android {
struct AttrInfo {
    std::string_view name;
    std::uint32_t id;
    std::uint16_t formats;
    std::uint16_t first_value, value_count;
};
struct NamedValue {
    std::string_view name;
    std::uint32_t value;
};
struct PublicResource {
    std::string_view type, name;
    std::uint32_t id;
};
#include "android_table.inc"
enum Format : std::uint16_t {
    f_reference = 1, f_string = 2, f_integer = 4, f_boolean = 8, f_color = 16, f_float = 32,
    f_dimension = 64, f_fraction = 128, f_enum = 256, f_flags = 512
};
inline const AttrInfo* attr(std::string_view name) {
    for (const AttrInfo& a : attr_table)
        if (a.name == name) return &a;
    return nullptr;
}
inline std::optional<std::uint32_t> public_id(std::string_view type, std::string_view name) {
    if (type == "attr") {
        if (auto a = attr(name)) return a->id;
        return std::nullopt;
    }
    for (const PublicResource& r : public_table)
        if (r.type == type && r.name == name) return r.id;
    return std::nullopt;
}
}  // namespace android

inline constexpr std::string_view ns_android = "http://schemas.android.com/apk/res/android";
inline constexpr std::string_view ns_tools = "http://schemas.android.com/tools";

// ---------------------------------------------------------------------------
// Text XML, as much as resource files use: elements, attributes, comments,
// processing instructions, CDATA and text (kept for <string> values).

struct XmlNode {
    std::string name;  // as written: "manifest", "android:label" style prefixes kept
    std::vector<std::pair<std::string, std::string>> attrs;
    std::vector<XmlNode> children;
    std::string text;
    int line = 0;
};

inline std::expected<XmlNode, std::string> parse_xml(std::string_view s) {
    std::size_t at = 0;
    int line = 1;
    auto advance = [&](std::size_t n) {
        for (std::size_t i = 0; i < n && at < s.size(); ++i, ++at)
            if (s[at] == '\n') ++line;
    };
    auto skip_space = [&] {
        while (at < s.size() && (s[at] == ' ' || s[at] == '\t' || s[at] == '\r' || s[at] == '\n')) advance(1);
    };
    auto unescape = [](std::string_view v) -> std::string {
        std::string out;
        for (std::size_t i = 0; i < v.size(); ++i) {
            if (v[i] != '&') {
                out += v[i];
                continue;
            }
            const std::size_t end = v.find(';', i);
            if (end == std::string_view::npos) {
                out += v[i];
                continue;
            }
            const std::string_view e = v.substr(i + 1, end - i - 1);
            std::uint32_t cp = 0;
            if (e == "amp") cp = '&';
            else if (e == "lt") cp = '<';
            else if (e == "gt") cp = '>';
            else if (e == "quot") cp = '"';
            else if (e == "apos") cp = '\'';
            else if (e.starts_with("#x")) std::from_chars(e.data() + 2, e.data() + e.size(), cp, 16);
            else if (e.starts_with("#")) std::from_chars(e.data() + 1, e.data() + e.size(), cp);
            if (cp == 0) {
                out += v.substr(i, end - i + 1);
            } else if (cp < 0x80) {
                out += static_cast<char>(cp);
            } else if (cp < 0x800) {
                out += static_cast<char>(0xc0 | (cp >> 6));
                out += static_cast<char>(0x80 | (cp & 0x3f));
            } else if (cp < 0x10000) {
                out += static_cast<char>(0xe0 | (cp >> 12));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
                out += static_cast<char>(0x80 | (cp & 0x3f));
            } else {
                out += static_cast<char>(0xf0 | (cp >> 18));
                out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
                out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
                out += static_cast<char>(0x80 | (cp & 0x3f));
            }
            i = end;
        }
        return out;
    };
    // Skips <?..?>, <!--..-->, <!DOCTYPE..>; true when it skipped one.
    auto skip_markup = [&]() -> std::expected<bool, std::string> {
        for (auto [open, close] : {std::pair{"<?", "?>"}, std::pair{"<!--", "-->"}, std::pair{"<!DOCTYPE", ">"}}) {
            if (s.substr(at).starts_with(open)) {
                const std::size_t end = s.find(close, at);
                if (end == std::string_view::npos) return std::unexpected(std::format("line {}: {} not closed", line, open));
                advance(end + std::string_view(close).size() - at);
                return true;
            }
        }
        return false;
    };
    std::function<std::expected<XmlNode, std::string>()> element = [&]() -> std::expected<XmlNode, std::string> {
        XmlNode node;
        node.line = line;
        advance(1);  // <
        const std::size_t name_start = at;
        while (at < s.size() && s[at] != ' ' && s[at] != '>' && s[at] != '/' && s[at] != '\n' && s[at] != '\t' && s[at] != '\r') advance(1);
        node.name = s.substr(name_start, at - name_start);
        for (;;) {
            skip_space();
            if (at >= s.size()) return std::unexpected(std::format("line {}: <{}> not closed", node.line, node.name));
            if (s[at] == '/') {
                if (at + 1 >= s.size() || s[at + 1] != '>') return std::unexpected(std::format("line {}: stray /", line));
                advance(2);
                return node;
            }
            if (s[at] == '>') {
                advance(1);
                break;
            }
            const std::size_t a = at;
            while (at < s.size() && s[at] != '=' && s[at] != ' ' && s[at] != '\n') advance(1);
            const std::string attr_name(s.substr(a, at - a));
            skip_space();
            if (at >= s.size() || s[at] != '=') return std::unexpected(std::format("line {}: attribute {} without a value", line, attr_name));
            advance(1);
            skip_space();
            if (at >= s.size() || (s[at] != '"' && s[at] != '\'')) return std::unexpected(std::format("line {}: {}: no quote", line, attr_name));
            const char q = s[at];
            advance(1);
            const std::size_t end = s.find(q, at);
            if (end == std::string_view::npos) return std::unexpected(std::format("line {}: {}: quote not closed", line, attr_name));
            node.attrs.emplace_back(attr_name, unescape(s.substr(at, end - at)));
            advance(end + 1 - at);
        }
        for (;;) {
            if (at >= s.size()) return std::unexpected(std::format("line {}: <{}> never ends", node.line, node.name));
            if (s[at] != '<') {
                const std::size_t end = s.find('<', at);
                node.text += unescape(s.substr(at, end - at));
                advance(end - at);
                continue;
            }
            if (s.substr(at).starts_with("<![CDATA[")) {
                const std::size_t end = s.find("]]>", at);
                if (end == std::string_view::npos) return std::unexpected(std::format("line {}: CDATA not closed", line));
                node.text += s.substr(at + 9, end - at - 9);
                advance(end + 3 - at);
                continue;
            }
            auto skipped = skip_markup();
            if (!skipped) return std::unexpected(skipped.error());
            if (*skipped) continue;
            if (s.substr(at).starts_with("</")) {
                const std::size_t end = s.find('>', at);
                if (end == std::string_view::npos) return std::unexpected(std::format("line {}: </{}> not closed", line, node.name));
                const std::string_view closing = s.substr(at + 2, end - at - 2);
                if (closing != node.name) return std::unexpected(std::format("line {}: </{}> closes <{}>", line, closing, node.name));
                advance(end + 1 - at);
                return node;
            }
            auto child = element();
            if (!child) return child;
            node.children.push_back(std::move(*child));
        }
    };
    for (;;) {
        skip_space();
        if (at >= s.size()) return std::unexpected("no root element");
        auto skipped = skip_markup();
        if (!skipped) return std::unexpected(skipped.error());
        if (*skipped) continue;
        if (s[at] != '<') return std::unexpected(std::format("line {}: text before the root element", line));
        return element();
    }
}

// ---------------------------------------------------------------------------
// Values (Res_value)

struct Value {
    std::uint8_t type = 0;  // Res_value::dataType
    std::uint32_t data = 0;
    std::optional<std::string> string;  // TYPE_STRING: the string, its index found when written
};
inline constexpr std::uint8_t t_reference = 0x01, t_attribute = 0x02, t_string = 0x03, t_float = 0x04, t_dimension = 0x05,
                              t_int_dec = 0x10, t_int_hex = 0x11, t_boolean = 0x12, t_argb8 = 0x1c, t_rgb8 = 0x1d,
                              t_argb4 = 0x1e, t_rgb4 = 0x1f;

inline std::optional<Value> parse_color(std::string_view v) {
    if (v.empty() || v[0] != '#') return std::nullopt;
    const std::string_view h = v.substr(1);
    std::uint32_t x = 0;
    if (h.empty() || std::from_chars(h.data(), h.data() + h.size(), x, 16).ptr != h.data() + h.size()) return std::nullopt;
    auto dup = [](std::uint32_t n) { return (n << 4) | n; };
    switch (h.size()) {
        case 3: return Value{t_rgb4, 0xff000000 | dup((x >> 8) & 15) << 16 | dup((x >> 4) & 15) << 8 | dup(x & 15)};
        case 4: return Value{t_argb4, dup((x >> 12) & 15) << 24 | dup((x >> 8) & 15) << 16 | dup((x >> 4) & 15) << 8 | dup(x & 15)};
        case 6: return Value{t_rgb8, 0xff000000 | x};
        case 8: return Value{t_argb8, x};
        default: return std::nullopt;
    }
}

inline std::optional<Value> parse_integer(std::string_view v) {
    std::string_view t = v;
    while (!t.empty() && t.front() == ' ') t.remove_prefix(1);
    while (!t.empty() && t.back() == ' ') t.remove_suffix(1);
    if (t.starts_with("0x") || t.starts_with("0X")) {
        std::uint32_t x = 0;
        const std::string_view h = t.substr(2);
        if (h.empty() || std::from_chars(h.data(), h.data() + h.size(), x, 16).ptr != h.data() + h.size()) return std::nullopt;
        return Value{t_int_hex, x};
    }
    std::int64_t x = 0;
    if (t.empty() || std::from_chars(t.data(), t.data() + t.size(), x).ptr != t.data() + t.size()) return std::nullopt;
    if (x < std::numeric_limits<std::int32_t>::min() || x > std::numeric_limits<std::uint32_t>::max()) return std::nullopt;
    return Value{t_int_dec, static_cast<std::uint32_t>(x)};
}

inline std::optional<float> parse_float(std::string_view v) {
    float f = 0;
    if (v.empty() || std::from_chars(v.data(), v.data() + v.size(), f).ptr != v.data() + v.size()) return std::nullopt;
    return f;
}

/// A dimension, "16dp", encoded as Res_value's complex number.
inline std::optional<Value> parse_dimension(std::string_view v) {
    static constexpr std::array<std::pair<std::string_view, std::uint32_t>, 7> units = {
        {{"px", 0}, {"dip", 1}, {"dp", 1}, {"sp", 2}, {"pt", 3}, {"in", 4}, {"mm", 5}}};
    for (auto [suffix, unit] : units) {
        if (!v.ends_with(suffix)) continue;
        auto f = parse_float(v.substr(0, v.size() - suffix.size()));
        if (!f) return std::nullopt;
        const bool negative = *f < 0;
        const double magnitude = std::abs(static_cast<double>(*f));
        const std::uint64_t bits = static_cast<std::uint64_t>(magnitude * (1 << 23) + 0.5);
        std::uint32_t radix, shift;
        if ((bits & 0x7fffff) == 0) radix = 0, shift = 23;
        else if ((bits & 0xffffffffff800000ULL) == 0) radix = 3, shift = 0;
        else if ((bits & 0xffffffff80000000ULL) == 0) radix = 2, shift = 8;
        else if ((bits & 0xffffff8000000000ULL) == 0) radix = 1, shift = 16;
        else radix = 0, shift = 23;
        std::uint32_t mantissa = static_cast<std::uint32_t>((bits >> shift) & 0xffffff);
        if (negative) mantissa = (0U - mantissa) & 0xffffff;
        return Value{t_dimension, (mantissa << 8) | (radix << 4) | unit};
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// The app's resources

struct Config {
    std::uint16_t density = 0, sdk = 0;
    std::uint8_t orientation = 0, ui_mode = 0;
    std::array<char, 2> language{}, region{};
    auto operator<=>(const Config&) const = default;

    /// The qualifiers after a folder's type ("hdpi-v4" of "mipmap-hdpi-v4").
    static std::expected<Config, std::string> parse(std::string_view qualifiers) {
        Config c;
        static constexpr std::array<std::pair<std::string_view, std::uint16_t>, 9> densities = {
            {{"ldpi", 120}, {"mdpi", 160}, {"tvdpi", 213}, {"hdpi", 240}, {"xhdpi", 320}, {"xxhdpi", 480}, {"xxxhdpi", 640},
             {"anydpi", 0xfffe}, {"nodpi", 0xffff}}};
        for (auto part : qualifiers | std::views::split('-')) {
            const std::string_view q(part.begin(), part.end());
            if (q.empty()) continue;
            bool done = false;
            for (auto [n, d] : densities)
                if (q == n) c.density = d, done = true;
            if (done) continue;
            if (q == "land") c.orientation = 2;
            else if (q == "port") c.orientation = 1;
            else if (q == "night") c.ui_mode = 0x20;
            else if (q == "notnight") c.ui_mode = 0x10;
            else if (q.size() > 1 && q[0] == 'v' && std::ranges::all_of(q.substr(1), [](char ch) { return ch >= '0' && ch <= '9'; }))
                std::from_chars(q.data() + 1, q.data() + q.size(), c.sdk);
            else if (q.size() == 2 && std::ranges::all_of(q, [](char ch) { return ch >= 'a' && ch <= 'z'; }))
                c.language = {q[0], q[1]};
            else if (q.size() == 3 && q[0] == 'r' && q[1] >= 'A' && q[1] <= 'Z')
                c.region = {q[1], q[2]};
            else
                return std::unexpected(std::format("qualifier '{}', which apkpack does not know", q));
        }
        return c;
    }
    /// ResTable_config, 64 bytes.
    Bytes bytes() const {
        Bytes b(64, 0);
        b[0] = 64;
        b[8] = static_cast<std::uint8_t>(language[0]), b[9] = static_cast<std::uint8_t>(language[1]);
        b[10] = static_cast<std::uint8_t>(region[0]), b[11] = static_cast<std::uint8_t>(region[1]);
        b[12] = orientation;
        b[14] = static_cast<std::uint8_t>(density), b[15] = static_cast<std::uint8_t>(density >> 8);
        b[24] = static_cast<std::uint8_t>(sdk), b[25] = static_cast<std::uint8_t>(sdk >> 8);
        b[29] = ui_mode;
        return b;
    }
    /// ResTable_config's change bits for what this config sets.
    std::uint32_t changes() const {
        return (language[0] ? 0x0004U : 0U) | (orientation ? 0x0080U : 0U) | (density ? 0x0100U : 0U) | (sdk ? 0x0400U : 0U) |
               (ui_mode ? 0x1000U : 0U);
    }
};

struct ResourceValue {
    Config config;
    std::string raw;          // values: the text, typed once every name is known
    std::string value_kind;   // values: string, color, bool, integer, dimen
    std::string file;         // files: the path in the APK
    std::optional<Value> typed;
};

class ResourceTable {
public:
    std::string package;
    // type -> name -> its values
    std::map<std::string, std::map<std::string, std::vector<ResourceValue>>> types;
    std::vector<std::pair<std::string, Bytes>> files;  // path in the APK, contents

    /// The ID of the app's @type/name, by the order types and names sort in.
    std::optional<std::uint32_t> id_of(std::string_view type, std::string_view name) const {
        std::uint32_t t = 1;
        for (const auto& [type_name, entries] : types) {
            if (type_name == type) {
                std::uint32_t e = 0;
                for (const auto& [entry_name, _] : entries) {
                    if (entry_name == name) return 0x7f000000U | t << 16 | e;
                    ++e;
                }
                return std::nullopt;
            }
            ++t;
        }
        return std::nullopt;
    }
};

/// A reference, "@type/name", "@android:type/name", "@+id/name", "@null",
/// "?attr", "?android:attr/name", resolved.
inline std::expected<Value, std::string> resolve_reference(std::string_view v, const ResourceTable& table) {
    if (v == "@null") return Value{t_reference, 0};
    const bool attribute = v[0] == '?';
    std::string_view r = v.substr(1);
    if (r.starts_with("+")) r.remove_prefix(1);
    bool android_ns = false;
    if (r.starts_with("android:")) android_ns = true, r.remove_prefix(8);
    std::string_view type = "attr", name = r;
    if (const std::size_t slash = r.find('/'); slash != std::string_view::npos) type = r.substr(0, slash), name = r.substr(slash + 1);
    else if (!attribute) return std::unexpected(std::format("{}: not @type/name", v));
    const auto id = android_ns ? android::public_id(type, name) : table.id_of(type, name);
    if (!id) return std::unexpected(std::format("{}: no such {}resource", v, android_ns ? "public Android " : ""));
    return Value{attribute ? t_attribute : t_reference, *id};
}

/// An attribute's value, typed by its formats (an android: attribute's from
/// Android's table; any other is a string).
inline std::expected<Value, std::string> type_value(std::string_view attr_name, std::string_view v, const android::AttrInfo* info,
                                                    const ResourceTable& table) {
    if (!v.empty() && (v[0] == '@' || v[0] == '?') && !v.starts_with("@@") && !v.starts_with("??")) return resolve_reference(v, table);
    if (!info || info->formats == 0) return Value{t_string, 0, std::string(v)};
    const std::uint16_t f = info->formats;
    const std::span<const android::NamedValue> named(android::attr_values + info->first_value, info->value_count);
    if (f & android::f_enum) {
        for (const auto& n : named)
            if (n.name == v) return Value{t_int_dec, n.value};
    }
    if (f & android::f_flags) {
        std::uint32_t bits = 0;
        bool all = true;
        for (auto part : v | std::views::split('|')) {
            const std::string_view p(part.begin(), part.end());
            auto found = std::ranges::find_if(named, [&](const auto& n) { return n.name == p; });
            if (found == named.end()) {
                all = false;
                break;
            }
            bits |= found->value;
        }
        if (all) return Value{t_int_hex, bits};
    }
    if ((f & android::f_boolean) && (v == "true" || v == "false")) return Value{t_boolean, v == "true" ? 0xffffffffU : 0U};
    if (f & android::f_color)
        if (auto c = parse_color(v)) return *c;
    if (f & android::f_integer)
        if (auto i = parse_integer(v)) return *i;
    if (f & android::f_dimension)
        if (auto d = parse_dimension(v)) return *d;
    if (f & android::f_float)
        if (auto x = parse_float(v)) return Value{t_float, std::bit_cast<std::uint32_t>(*x)};
    if (f & android::f_string) return Value{t_string, 0, std::string(v)};
    return std::unexpected(std::format("android:{}=\"{}\": not a value it takes", attr_name, v));
}

// ---------------------------------------------------------------------------
// Chunks

namespace chunk {
inline void p8(Bytes& o, std::uint32_t v) { o.push_back(static_cast<std::uint8_t>(v)); }
inline void p16(Bytes& o, std::uint32_t v) {
    p8(o, v);
    p8(o, v >> 8);
}
inline void p32(Bytes& o, std::uint32_t v) {
    p16(o, v & 0xffff);
    p16(o, v >> 16);
}
inline void set32(Bytes& o, std::size_t at, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) o[at + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v >> (8 * i));
}
inline void pad4(Bytes& o) {
    while (o.size() % 4) o.push_back(0);
}
inline void value(Bytes& o, std::uint8_t type, std::uint32_t data) {
    p16(o, 8);
    p8(o, 0);
    p8(o, type);
    p32(o, data);
}

/// UTF-8 to UTF-16 code units.
inline std::u16string utf16(std::string_view s) {
    std::u16string out;
    for (std::size_t i = 0; i < s.size();) {
        const std::uint8_t c = static_cast<std::uint8_t>(s[i]);
        std::uint32_t cp;
        std::size_t n;
        if (c < 0x80) cp = c, n = 1;
        else if ((c >> 5) == 6) cp = c & 0x1f, n = 2;
        else if ((c >> 4) == 14) cp = c & 0x0f, n = 3;
        else cp = c & 0x07, n = 4;
        for (std::size_t k = 1; k < n && i + k < s.size(); ++k) cp = (cp << 6) | (static_cast<std::uint8_t>(s[i + k]) & 0x3f);
        i += n;
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out += static_cast<char16_t>(0xd800 + (cp >> 10));
            out += static_cast<char16_t>(0xdc00 + (cp & 0x3ff));
        } else {
            out += static_cast<char16_t>(cp);
        }
    }
    return out;
}

/// A ResStringPool chunk.
inline Bytes string_pool(const std::vector<std::string>& strings, bool utf8) {
    Bytes data;
    std::vector<std::uint32_t> offsets;
    for (const std::string& s : strings) {
        offsets.push_back(static_cast<std::uint32_t>(data.size()));
        const std::u16string u = utf16(s);
        if (utf8) {
            auto len8 = [&](std::size_t n) {
                if (n > 0x7f) p8(data, static_cast<std::uint32_t>(0x80 | (n >> 8)));
                p8(data, n & 0xff);
            };
            len8(u.size());
            len8(s.size());
            data.insert(data.end(), s.begin(), s.end());
            p8(data, 0);
        } else {
            if (u.size() > 0x7fff) p16(data, static_cast<std::uint32_t>(0x8000 | (u.size() >> 16)));
            p16(data, u.size() & 0xffff);
            for (char16_t ch : u) p16(data, ch);
            p16(data, 0);
        }
    }
    pad4(data);
    Bytes out;
    const std::uint32_t header = 28, starts = header + 4 * static_cast<std::uint32_t>(strings.size());
    p16(out, 0x0001);
    p16(out, header);
    p32(out, starts + static_cast<std::uint32_t>(data.size()));
    p32(out, static_cast<std::uint32_t>(strings.size()));
    p32(out, 0);
    p32(out, utf8 ? 0x100 : 0);
    p32(out, strings.empty() ? 0 : starts);
    p32(out, 0);
    for (std::uint32_t o : offsets) p32(out, o);
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

/// Indexes into a pool being built.
class Strings {
public:
    std::uint32_t index(const std::string& s) {
        if (auto it = at_.find(s); it != at_.end()) return it->second;
        list_.push_back(s);
        return at_[s] = static_cast<std::uint32_t>(list_.size() - 1);
    }
    const std::vector<std::string>& list() const { return list_; }

private:
    std::vector<std::string> list_;
    std::map<std::string, std::uint32_t> at_;
};
}  // namespace chunk

// ---------------------------------------------------------------------------
// Binary XML

/// A text XML document compiled to binary XML (ResXMLTree): android:
/// attributes typed and sorted by ID, a resource map for their names,
/// references resolved against `table`.
inline std::expected<Bytes, std::string> compile_xml(const XmlNode& root, const ResourceTable& table) {
    using namespace chunk;
    // Namespaces: prefix -> URI, from the xmlns attributes (the root's, and
    // any below, which binary XML declares around the whole document).
    std::vector<std::pair<std::string, std::string>> namespaces;
    std::function<void(const XmlNode&)> collect = [&](const XmlNode& n) {
        for (const auto& [k, v] : n.attrs)
            if (k.starts_with("xmlns:") && v != ns_tools &&
                std::ranges::find(namespaces, std::pair{k.substr(6), v}) == namespaces.end())
                namespaces.emplace_back(k.substr(6), v);
        for (const XmlNode& c : n.children) collect(c);
    };
    collect(root);
    auto uri_of = [&](std::string_view prefix) -> std::optional<std::string> {
        if (prefix == "tools") return std::string(ns_tools);
        for (const auto& [p, u] : namespaces)
            if (p == prefix) return u;
        return std::nullopt;
    };

    // Attribute names with resource IDs come first in the pool, in the order
    // of the resource map.
    struct Attr {
        std::string uri, name, raw;
        std::uint32_t id = 0;
        Value value;
    };
    struct Element {
        const XmlNode* node;
        std::vector<Attr> attrs;
    };
    std::vector<std::uint32_t> resource_ids;
    std::vector<std::string> mapped_names;
    std::function<std::expected<void, std::string>(const XmlNode&, std::vector<Element>&)> typed =
        [&](const XmlNode& n, std::vector<Element>& out) -> std::expected<void, std::string> {
        Element e{&n, {}};
        for (const auto& [k, v] : n.attrs) {
            if (k == "xmlns" || k.starts_with("xmlns:")) continue;
            Attr a;
            a.raw = v;
            a.name = k;
            if (const std::size_t colon = k.find(':'); colon != std::string::npos) {
                auto uri = uri_of(k.substr(0, colon));
                if (!uri) return std::unexpected(std::format("line {}: {}: an undeclared namespace", n.line, k));
                if (*uri == ns_tools) continue;
                a.uri = *uri;
                a.name = k.substr(colon + 1);
            }
            const android::AttrInfo* info = nullptr;
            if (a.uri == ns_android) {
                info = android::attr(a.name);
                if (!info) return std::unexpected(std::format("line {}: android:{}: not a public Android attribute", n.line, a.name));
                a.id = info->id;
            }
            auto value = type_value(a.name, v, info, table);
            if (!value) return std::unexpected(std::format("line {}: {}", n.line, value.error()));
            a.value = *value;
            e.attrs.push_back(std::move(a));
        }
        // Attributes with IDs sorted by them, then the rest as written.
        std::ranges::stable_sort(e.attrs, [](const Attr& x, const Attr& y) {
            return (x.id != 0 && y.id != 0) ? x.id < y.id : (x.id != 0 && y.id == 0);
        });
        for (const Attr& a : e.attrs) {
            if (a.id != 0 && std::ranges::find(resource_ids, a.id) == resource_ids.end()) {
                resource_ids.push_back(a.id);
                mapped_names.push_back(a.name);
            }
        }
        out.push_back(std::move(e));
        for (const XmlNode& c : n.children)
            if (auto r = typed(c, out); !r) return r;
        return {};
    };
    std::vector<Element> elements;
    if (auto r = typed(root, elements); !r) return std::unexpected(r.error());

    Strings pool;
    for (const std::string& n : mapped_names) pool.index(n);
    // Mapped names are indices 0..n-1; any later use of the same text by an
    // unmapped name gets its own index, past them.
    std::map<std::string, std::uint32_t> unmapped;
    std::vector<std::string> extra;
    auto str = [&](const std::string& s, bool mapped) -> std::uint32_t {
        if (mapped) return pool.index(s);
        if (auto it = std::ranges::find(mapped_names, s); it == mapped_names.end()) return pool.index(s);
        if (auto it = unmapped.find(s); it != unmapped.end()) return it->second;
        const std::uint32_t i = static_cast<std::uint32_t>(pool.list().size() + extra.size());
        extra.push_back(s);
        return unmapped[s] = i;
    };

    Bytes body;
    for (const auto& [prefix, uri] : namespaces) {
        p16(body, 0x0100);
        p16(body, 16);
        p32(body, 24);
        p32(body, static_cast<std::uint32_t>(root.line));
        p32(body, 0xffffffff);
        p32(body, str(prefix, false));
        p32(body, str(uri, false));
    }
    // Elements, in document order, closed in reverse.
    std::function<void(const XmlNode&, std::size_t&)> emit = [&](const XmlNode& n, std::size_t& index) {
        const Element& e = elements[index++];
        std::string uri, local = n.name;
        if (const std::size_t colon = n.name.find(':'); colon != std::string::npos) {
            uri = uri_of(n.name.substr(0, colon)).value_or("");
            local = n.name.substr(colon + 1);
        }
        const std::uint32_t ns = uri.empty() ? 0xffffffff : str(uri, false), name = str(local, false);
        p16(body, 0x0102);
        p16(body, 16);
        p32(body, 36 + 20 * static_cast<std::uint32_t>(e.attrs.size()));
        p32(body, static_cast<std::uint32_t>(n.line));
        p32(body, 0xffffffff);
        p32(body, ns);
        p32(body, name);
        p16(body, 20);
        p16(body, 20);
        p16(body, static_cast<std::uint32_t>(e.attrs.size()));
        std::uint16_t id_index = 0, class_index = 0, style_index = 0;
        for (std::size_t i = 0; i < e.attrs.size(); ++i) {
            if (!e.attrs[i].uri.empty()) continue;
            if (e.attrs[i].name == "id") id_index = static_cast<std::uint16_t>(i + 1);
            if (e.attrs[i].name == "class") class_index = static_cast<std::uint16_t>(i + 1);
            if (e.attrs[i].name == "style") style_index = static_cast<std::uint16_t>(i + 1);
        }
        p16(body, id_index);
        p16(body, class_index);
        p16(body, style_index);
        for (const Attr& a : e.attrs) {
            p32(body, a.uri.empty() ? 0xffffffff : str(a.uri, false));
            p32(body, str(a.name, a.id != 0));
            const bool is_string = a.value.type == t_string;
            p32(body, is_string ? str(a.raw, false) : 0xffffffff);
            value(body, a.value.type, is_string ? str(*a.value.string, false) : a.value.data);
        }
        for (const XmlNode& c : n.children) emit(c, index);
        p16(body, 0x0103);
        p16(body, 16);
        p32(body, 24);
        p32(body, static_cast<std::uint32_t>(n.line));
        p32(body, 0xffffffff);
        p32(body, ns);
        p32(body, name);
    };
    std::size_t index = 0;
    emit(root, index);
    for (auto it = namespaces.rbegin(); it != namespaces.rend(); ++it) {
        p16(body, 0x0101);
        p16(body, 16);
        p32(body, 24);
        p32(body, static_cast<std::uint32_t>(root.line));
        p32(body, 0xffffffff);
        p32(body, str(it->first, false));
        p32(body, str(it->second, false));
    }

    std::vector<std::string> all = pool.list();
    all.insert(all.end(), extra.begin(), extra.end());
    Bytes out;
    p16(out, 0x0003);
    p16(out, 8);
    p32(out, 0);
    const Bytes strings = string_pool(all, false);
    out.insert(out.end(), strings.begin(), strings.end());
    p16(out, 0x0180);
    p16(out, 8);
    p32(out, 8 + 4 * static_cast<std::uint32_t>(resource_ids.size()));
    for (std::uint32_t id : resource_ids) p32(out, id);
    out.insert(out.end(), body.begin(), body.end());
    set32(out, 4, static_cast<std::uint32_t>(out.size()));
    return out;
}

// ---------------------------------------------------------------------------
// resources.arsc

inline Bytes compile_table(const ResourceTable& table) {
    using namespace chunk;
    Strings global, type_names, keys;
    for (const auto& [type, entries] : table.types) {
        type_names.index(type);
        for (const auto& [name, _] : entries) keys.index(name);
    }
    // The values first, so every string is in the global pool.
    for (const auto& [type, entries] : table.types)
        for (const auto& [name, values] : entries)
            for (const ResourceValue& v : values)
                if (v.typed && v.typed->type == t_string) global.index(*v.typed->string);

    Bytes package;
    p16(package, 0x0200);
    p16(package, 288);
    p32(package, 0);
    p32(package, 0x7f);
    const std::u16string name16 = utf16(table.package);
    for (std::size_t i = 0; i < 128; ++i) p16(package, i < name16.size() && i < 127 ? name16[i] : 0);
    const std::size_t type_strings_at = package.size();
    p32(package, 0);
    p32(package, static_cast<std::uint32_t>(type_names.list().size()));
    const std::size_t key_strings_at = package.size();
    p32(package, 0);
    p32(package, static_cast<std::uint32_t>(keys.list().size()));
    p32(package, 0);
    set32(package, type_strings_at, static_cast<std::uint32_t>(package.size()));
    const Bytes ts = string_pool(type_names.list(), true);
    package.insert(package.end(), ts.begin(), ts.end());
    set32(package, key_strings_at, static_cast<std::uint32_t>(package.size()));
    const Bytes ks = string_pool(keys.list(), true);
    package.insert(package.end(), ks.begin(), ks.end());

    std::uint32_t type_id = 1;
    for (const auto& [type, entries] : table.types) {
        // typeSpec: what each entry's configs vary in.
        std::set<Config> configs;
        p16(package, 0x0202);
        p16(package, 16);
        p32(package, 16 + 4 * static_cast<std::uint32_t>(entries.size()));
        p8(package, type_id);
        p8(package, 0);
        p16(package, 0);
        p32(package, static_cast<std::uint32_t>(entries.size()));
        for (const auto& [name, values] : entries) {
            std::uint32_t changes = 0;
            for (const ResourceValue& v : values) {
                configs.insert(v.config);
                if (values.size() > 1) changes |= v.config.changes();
            }
            p32(package, changes);
        }
        for (const Config& config : configs) {
            Bytes offsets, data;
            for (const auto& [name, values] : entries) {
                auto found = std::ranges::find_if(values, [&](const ResourceValue& v) { return v.config == config; });
                if (found == values.end() || !found->typed) {
                    p32(offsets, 0xffffffff);
                    continue;
                }
                p32(offsets, static_cast<std::uint32_t>(data.size()));
                p16(data, 8);
                p16(data, 0);
                p32(data, keys.index(name));
                const Value& v = *found->typed;
                value(data, v.type, v.type == t_string ? global.index(*v.string) : v.data);
            }
            const std::uint32_t header = 20 + 64;
            p16(package, 0x0201);
            p16(package, header);
            p32(package, header + static_cast<std::uint32_t>(offsets.size() + data.size()));
            p8(package, type_id);
            p8(package, 0);
            p16(package, 0);
            p32(package, static_cast<std::uint32_t>(entries.size()));
            p32(package, header + static_cast<std::uint32_t>(offsets.size()));
            const Bytes c = config.bytes();
            package.insert(package.end(), c.begin(), c.end());
            package.insert(package.end(), offsets.begin(), offsets.end());
            package.insert(package.end(), data.begin(), data.end());
        }
        ++type_id;
    }
    set32(package, 4, static_cast<std::uint32_t>(package.size()));

    Bytes out;
    p16(out, 0x0002);
    p16(out, 12);
    p32(out, 0);
    p32(out, 1);
    const Bytes gs = string_pool(global.list(), true);
    out.insert(out.end(), gs.begin(), gs.end());
    out.insert(out.end(), package.begin(), package.end());
    set32(out, 4, static_cast<std::uint32_t>(out.size()));
    return out;
}

// ---------------------------------------------------------------------------
// Reading binary XML back, for `apkpack dump` and the build's checks.

inline std::expected<std::string, std::string> dump_xml(ByteView x) {
    auto u16 = [&](std::size_t at) { return static_cast<std::uint32_t>(x[at] | x[at + 1] << 8); };
    auto u32 = [&](std::size_t at) { return u16(at) | u16(at + 2) << 16; };
    if (x.size() < 8 || u16(0) != 0x0003) return std::unexpected("not binary XML");
    std::vector<std::string> strings;
    std::vector<std::uint32_t> ids;
    std::string out;
    int depth = 0;
    auto s = [&](std::uint32_t i) -> std::string { return i < strings.size() ? strings[i] : std::string(); };
    for (std::size_t at = u16(2); at + 8 <= x.size();) {
        const std::uint32_t type = u16(at), header = u16(at + 2), size = u32(at + 4);
        if (size < 8 || at + size > x.size()) return std::unexpected("a broken chunk");
        if (type == 0x0001) {
            const std::uint32_t count = u32(at + 8), flags = u32(at + 16), start = u32(at + 20);
            for (std::uint32_t i = 0; i < count; ++i) {
                std::size_t p = at + start + u32(at + header + 4 * i);
                std::string text;
                if (flags & 0x100) {
                    p += (x[p] & 0x80) ? 2 : 1;
                    std::size_t n = x[p] & 0x7f;
                    if (x[p] & 0x80) n = (n << 8) | x[p + 1], ++p;
                    ++p;
                    text.assign(reinterpret_cast<const char*>(&x[p]), n);
                } else {
                    std::size_t n = u16(p);
                    p += 2;
                    for (std::size_t k = 0; k < n; ++k) {
                        const std::uint32_t c = u16(p + 2 * k);
                        if (c < 0x80) text += static_cast<char>(c);
                        else text += '?';
                    }
                }
                strings.push_back(text);
            }
        } else if (type == 0x0180) {
            for (std::size_t p = at + 8; p < at + size; p += 4) ids.push_back(u32(p));
        } else if (type == 0x0102) {
            out += std::string(2 * static_cast<std::size_t>(depth), ' ') + "E: " + s(u32(at + 20)) + "\n";
            const std::uint32_t count = u16(at + 28);
            for (std::uint32_t i = 0; i < count; ++i) {
                const std::size_t a = at + 16 + 20 + 20 * i;
                const std::uint32_t name = u32(a + 4), raw = u32(a + 8), vtype = x[a + 15], data = u32(a + 16);
                std::string v;
                if (vtype == t_string) v = "\"" + s(data) + "\"";
                else if (vtype == t_boolean) v = data ? "true" : "false";
                else if (vtype == t_reference) v = std::format("@{:#010x}", data);
                else if (vtype == t_int_dec) v = std::format("{}", static_cast<std::int32_t>(data));
                else v = std::format("(type {:#04x}){:#x}", vtype, data);
                const std::string id = name < ids.size() ? std::format("({:#010x})", ids[name]) : "";
                out += std::string(2 * static_cast<std::size_t>(depth) + 2, ' ') + "A: " +
                       (u32(a) != 0xffffffff ? "android:" : "") + s(name) + id + "=" + v +
                       (raw != 0xffffffff && vtype != t_string ? " (raw \"" + s(raw) + "\")" : "") + "\n";
            }
            ++depth;
        } else if (type == 0x0103) {
            --depth;
        }
        at += size;
    }
    return out;
}

}  // namespace apkpack
