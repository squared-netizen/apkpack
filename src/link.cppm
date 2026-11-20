// SPDX-License-Identifier: MIT
//
// apkpack.link: an unsigned APK from a manifest, a res/ folder and an
// assets/ folder, in place of aapt2 compile, aapt2 link and android.jar:
//
//   AndroidManifest.xml   binary XML, with <uses-sdk> (minSdkVersion,
//                         targetSdkVersion) and, for a debug build,
//                         android:debuggable="true" on <application>
//   resources.arsc        the app's resources (apkpack.res)
//   res/...               XML compiled, anything else as it is
//   assets/...            as they are
//
// Every entry is stored (apkpack.zip). The output is the same bytes for the
// same inputs.

export module apkpack.link;

import std;
import apkpack.crypto;
import apkpack.res;
import apkpack.zip;

export namespace apkpack {

struct LinkOptions {
    std::filesystem::path manifest, res, assets;
    int min_sdk = 28, target_sdk = 28;
    bool debuggable = false;
};

namespace linkdetail {
inline std::optional<std::string> read_text(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return std::nullopt;
    return std::string(std::istreambuf_iterator<char>(in), {});
}

/// The files under `dir`, relative, sorted, hidden ones left out (as aapt2
/// leaves them out).
inline std::vector<std::filesystem::path> files_under(const std::filesystem::path& dir) {
    std::vector<std::filesystem::path> out;
    if (dir.empty() || !std::filesystem::is_directory(dir)) return out;
    for (auto it = std::filesystem::recursive_directory_iterator(dir); it != std::filesystem::recursive_directory_iterator(); ++it) {
        const std::string name = it->path().filename().string();
        if (name.starts_with(".")) {
            if (it->is_directory()) it.disable_recursion_pending();
            continue;
        }
        if (it->is_regular_file()) out.push_back(std::filesystem::relative(it->path(), dir));
    }
    std::ranges::sort(out);
    return out;
}

/// A <string>'s text as Android reads it: surrounding quotes kept text as
/// it is; otherwise whitespace runs become one space; \n, \t, \', \", \\ and
/// \uXXXX are escapes.
inline std::string string_value(std::string_view raw) {
    std::string t(raw);
    const bool quoted = t.size() >= 2 && t.front() == '"' && t.back() == '"';
    if (quoted) {
        t = t.substr(1, t.size() - 2);
    } else {
        std::string collapsed;
        bool space = false;
        for (char c : t) {
            if (c == ' ' || c == '\n' || c == '\t' || c == '\r') {
                space = true;
                continue;
            }
            if (space && !collapsed.empty()) collapsed += ' ';
            space = false;
            collapsed += c;
        }
        t = collapsed;
    }
    std::string out;
    for (std::size_t i = 0; i < t.size(); ++i) {
        if (t[i] != '\\' || i + 1 == t.size()) {
            out += t[i];
            continue;
        }
        const char e = t[++i];
        if (e == 'n') out += '\n';
        else if (e == 't') out += '\t';
        else out += e;
    }
    return out;
}
}  // namespace linkdetail

/// The manifest's root, with what the build sets: the package, <uses-sdk>,
/// android:debuggable.
inline std::expected<XmlNode, std::string> prepare_manifest(XmlNode root, const LinkOptions& o) {
    if (root.name != "manifest") return std::unexpected("the manifest's root is not <manifest>");
    auto set = [](XmlNode& n, const std::string& k, const std::string& v) {
        for (auto& [ak, av] : n.attrs)
            if (ak == k) {
                av = v;
                return;
            }
        n.attrs.emplace_back(k, v);
    };
    auto sdk = std::ranges::find_if(root.children, [](const XmlNode& c) { return c.name == "uses-sdk"; });
    if (sdk == root.children.end()) {
        XmlNode n;
        n.name = "uses-sdk";
        n.line = root.line;
        root.children.insert(root.children.begin(), n);
        sdk = root.children.begin();
    }
    set(*sdk, "android:minSdkVersion", std::to_string(o.min_sdk));
    set(*sdk, "android:targetSdkVersion", std::to_string(o.target_sdk));
    if (o.debuggable) {
        auto app = std::ranges::find_if(root.children, [](const XmlNode& c) { return c.name == "application"; });
        if (app == root.children.end()) return std::unexpected("debuggable: the manifest has no <application>");
        set(*app, "android:debuggable", "true");
    }
    return root;
}

inline std::expected<Bytes, std::string> link(const LinkOptions& o) {
    using namespace linkdetail;
    auto manifest_text = read_text(o.manifest);
    if (!manifest_text) return std::unexpected("cannot read " + o.manifest.string());
    auto manifest_xml = parse_xml(*manifest_text);
    if (!manifest_xml) return std::unexpected(o.manifest.string() + ": " + manifest_xml.error());
    ResourceTable table;
    for (const auto& [k, v] : manifest_xml->attrs)
        if (k == "package") table.package = v;
    if (table.package.empty()) return std::unexpected(o.manifest.string() + ": <manifest> has no package");

    // res/: every resource named first (IDs come from the names), typed after.
    struct XmlFile {
        std::string path;
        XmlNode root;
    };
    std::vector<XmlFile> xml_files;
    std::vector<std::pair<std::string, std::filesystem::path>> plain_files;
    for (const auto& rel : files_under(o.res)) {
        if (rel.has_parent_path() && rel.parent_path().has_parent_path())
            return std::unexpected("res/" + rel.string() + ": res/ holds folders of files, one deep");
        const std::string folder = rel.parent_path().string(), file = rel.filename().string();
        const std::size_t dash = folder.find('-');
        const std::string type = folder.substr(0, dash);
        auto config = Config::parse(dash == std::string::npos ? "" : folder.substr(dash + 1));
        if (!config) return std::unexpected("res/" + folder + ": " + config.error());
        if (type == "values" && config->sdk == 0 && (config->ui_mode != 0 || (config->density != 0 && config->density != 0xffff)))
            config->sdk = config->ui_mode != 0 ? 8 : 4;
        if (type == "values") {
            auto text = read_text(o.res / rel);
            if (!text) return std::unexpected("cannot read res/" + rel.string());
            auto doc = parse_xml(*text);
            if (!doc) return std::unexpected("res/" + rel.string() + ": " + doc.error());
            for (const XmlNode& item : doc->children) {
                std::string kind = item.name, name;
                for (const auto& [k, v] : item.attrs)
                    if (k == "name") name = v;
                if (kind == "item")
                    for (const auto& [k, v] : item.attrs)
                        if (k == "type") kind = v;
                if (name.empty()) return std::unexpected(std::format("res/{}: line {}: <{}> without a name", rel.string(), item.line, item.name));
                static constexpr std::array<std::string_view, 6> known = {"string", "color", "bool", "integer", "dimen", "id"};
                if (std::ranges::find(known, kind) == known.end())
                    return std::unexpected(std::format("res/{}: line {}: <{}>, which apkpack does not compile yet", rel.string(), item.line, kind));
                table.types[kind][name].push_back(ResourceValue{*config, item.text, kind, {}, {}});
            }
            continue;
        }
        // As aapt2 does: a qualifier newer than Android 1.0 brings its
        // version along (a density: v4; night or notnight: v8), and the
        // file's folder in the APK says so (mipmap-hdpi-v4).
        std::string out_folder = folder;
        if (config->sdk == 0 && (config->ui_mode != 0 || (config->density != 0 && config->density != 0xffff))) {
            config->sdk = config->ui_mode != 0 ? 8 : 4;
            out_folder += std::format("-v{}", config->sdk);
        }
        const std::string entry = file.substr(0, file.find('.'));
        const std::string path = "res/" + out_folder + "/" + file;
        table.types[type][entry].push_back(ResourceValue{*config, {}, {}, path, Value{t_string, 0, path}});
        if (file.ends_with(".xml") && type != "raw") {
            auto text = read_text(o.res / rel);
            if (!text) return std::unexpected("cannot read " + path);
            auto doc = parse_xml(*text);
            if (!doc) return std::unexpected(path + ": " + doc.error());
            xml_files.push_back({path, std::move(*doc)});
        } else {
            plain_files.emplace_back(path, o.res / rel);
        }
    }
    // @+id/name anywhere declares an id.
    std::function<void(const XmlNode&)> ids = [&](const XmlNode& n) {
        for (const auto& [k, v] : n.attrs)
            if (v.starts_with("@+id/")) table.types["id"][v.substr(5)];
        for (const XmlNode& c : n.children) ids(c);
    };
    for (const XmlFile& f : xml_files) ids(f.root);
    ids(*manifest_xml);
    for (auto& [name, values] : table.types["id"])
        if (values.empty()) values.push_back(ResourceValue{Config{}, {}, "id", {}, Value{t_boolean, 0}});
    if (table.types["id"].empty()) table.types.erase("id");

    // The values, typed now that every name has its ID.
    for (auto& [type, entries] : table.types) {
        for (auto& [name, values] : entries) {
            for (ResourceValue& v : values) {
                if (v.typed) continue;
                const std::string where = std::format("@{}/{}", type, name);
                std::string text = v.raw;
                if (v.value_kind != "string") {
                    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) text.pop_back();
                    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) text.erase(0, 1);
                }
                if (!text.empty() && (text[0] == '@' || text[0] == '?')) {
                    auto r = resolve_reference(text, table);
                    if (!r) return std::unexpected(where + ": " + r.error());
                    v.typed = *r;
                } else if (v.value_kind == "string") {
                    v.typed = Value{t_string, 0, string_value(v.raw)};
                } else if (v.value_kind == "color") {
                    auto c = parse_color(text);
                    if (!c) return std::unexpected(where + ": not a color: " + text);
                    v.typed = *c;
                } else if (v.value_kind == "bool") {
                    if (text != "true" && text != "false") return std::unexpected(where + ": not true or false: " + text);
                    v.typed = Value{t_boolean, text == "true" ? 0xffffffffU : 0U};
                } else if (v.value_kind == "integer") {
                    auto i = parse_integer(text);
                    if (!i) return std::unexpected(where + ": not an integer: " + text);
                    v.typed = *i;
                } else if (v.value_kind == "dimen") {
                    auto d = parse_dimension(text);
                    if (!d) return std::unexpected(where + ": not a dimension: " + text);
                    v.typed = *d;
                } else if (v.value_kind == "id") {
                    v.typed = Value{t_boolean, 0};
                }
            }
        }
    }

    auto manifest = prepare_manifest(std::move(*manifest_xml), o);
    if (!manifest) return std::unexpected(manifest.error());
    auto manifest_bin = compile_xml(*manifest, table);
    if (!manifest_bin) return std::unexpected("AndroidManifest.xml: " + manifest_bin.error());

    std::vector<ZipEntry> entries;
    entries.push_back(ZipEntry{"AndroidManifest.xml", std::move(*manifest_bin)});
    if (!table.types.empty()) entries.push_back(ZipEntry{"resources.arsc", compile_table(table)});
    std::vector<ZipEntry> res_entries;
    for (const XmlFile& f : xml_files) {
        auto bin = compile_xml(f.root, table);
        if (!bin) return std::unexpected(f.path + ": " + bin.error());
        res_entries.push_back(ZipEntry{f.path, std::move(*bin)});
    }
    for (const auto& [path, source] : plain_files) {
        auto text = read_text(source);
        if (!text) return std::unexpected("cannot read " + source.string());
        res_entries.push_back(ZipEntry{path, Bytes(text->begin(), text->end())});
    }
    std::ranges::sort(res_entries, {}, &ZipEntry::name);
    for (ZipEntry& e : res_entries) entries.push_back(std::move(e));
    for (const auto& rel : files_under(o.assets)) {
        auto data = read_text(o.assets / rel);
        if (!data) return std::unexpected("cannot read " + (o.assets / rel).string());
        entries.push_back(ZipEntry{"assets/" + rel.generic_string(), Bytes(data->begin(), data->end())});
    }
    return write_zip(entries);
}

}  // namespace apkpack
