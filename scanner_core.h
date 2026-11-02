// scanner_core.h - Bergsson Mod Scanner engine (no UI)
//
// Everything that inspects jars and talks to the outside world:
//   * zip reader + inflate, class-file constant pool parser
//   * cheat / stealer / obfuscator signatures and loader/dropper heuristics
//   * SHA-1 + CurseForge fingerprints, batch Modrinth (and CurseForge) lookups over WinHTTP
//   * running-game detection: reads javaw/java command line + working directory from the PEB
//   * plain-text reports and the command-line front end (cliMain)
//
// Included once, by bergsson.cpp.
//
// Extra signatures: put bergsson_sigs.txt next to the exe (loaded automatically)
// or pass --sigs. One per line, '#' = comment:
//   weight|kind|pattern|label      kind = cheat, malware, suspicious, obf
//   Prefix the pattern with '=' to require word/camelCase boundaries.

#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <winternl.h>
#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <richedit.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <tlhelp32.h>
#include <uxtheme.h>
#include <winhttp.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN64
#error Build Bergsson Mod Scanner as 64-bit (use the x64 Native Tools prompt) - it reads 64-bit Java process memory.
#endif

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

static uint16_t rd16(const uint8_t* p) { return uint16_t(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t* p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
static uint16_t be16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }

static std::string lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
    return s;
}

static std::wstring lowerW(std::wstring s) {
    for (auto& c : s) c = wchar_t(towlower(c));
    return s;
}

static bool endsWith(const std::string& s, const std::string& suf) {
    return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

static std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

static std::wstring toWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

static std::string pathUtf8(const fs::path& p) { return toUtf8(p.wstring()); }

static std::string printable(const std::string& s, size_t maxLen = 90) {
    std::string out;
    for (unsigned char c : s) {
        if (out.size() >= maxLen) { out += "..."; break; }
        if (c >= 0x20 && c < 0x7f) out += char(c);
        else { char buf[8]; snprintf(buf, sizeof buf, "\\x%02X", c); out += buf; }
    }
    return out;
}

static bool readFile(const fs::path& p, Bytes& out) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    auto size = f.tellg();
    if (size < 0) return false;
    f.seekg(0);
    out.resize(size_t(size));
    if (size > 0) f.read(reinterpret_cast<char*>(out.data()), size);
    return bool(f);
}

static std::string formatCount(long long n) {
    char buf[32];
    if (n >= 1000000) snprintf(buf, sizeof buf, "%.1fM", n / 1e6);
    else if (n >= 1000) snprintf(buf, sizeof buf, "%.1fk", n / 1e3);
    else snprintf(buf, sizeof buf, "%lld", n);
    return buf;
}

// ---------------------------------------------------------------------------
// Inflate (RFC 1951), modeled after zlib's "puff" reference decoder
// ---------------------------------------------------------------------------

class Inflater {
public:
    // truncate: stop quietly after `limit` bytes instead of failing (used to peek at a file's header)
    Inflater(const uint8_t* in, size_t len, size_t limit, bool truncate = false)
        : in_(in), len_(len), limit_(limit), truncate_(truncate) {}

    Bytes run() {
        try {
            int last;
            do {
                last = bits(1);
                int type = bits(2);
                if (type == 0) stored();
                else if (type == 1) fixed();
                else if (type == 2) dynamic();
                else throw std::runtime_error("bad deflate block type");
            } while (!last);
        } catch (const Truncated&) {
        }
        return std::move(out_);
    }

private:
    struct Huffman { short count[16]; short symbol[320]; };
    struct FixedTables { Huffman lencode, distcode; };
    struct Truncated {};

    const uint8_t* in_;
    size_t len_, pos_ = 0, limit_;
    bool truncate_;
    uint32_t bitbuf_ = 0;
    int bitcnt_ = 0;
    Bytes out_;

    int bits(int need) {
        uint32_t val = bitbuf_;
        while (bitcnt_ < need) {
            if (pos_ >= len_) throw std::runtime_error("deflate input exhausted");
            val |= uint32_t(in_[pos_++]) << bitcnt_;
            bitcnt_ += 8;
        }
        bitbuf_ = val >> need;
        bitcnt_ -= need;
        return int(val & ((1u << need) - 1));
    }

    void put(uint8_t b) {
        if (out_.size() >= limit_) {
            if (truncate_) throw Truncated{};
            throw std::runtime_error("entry exceeds size limit (zip bomb?)");
        }
        out_.push_back(b);
    }

    void stored() {
        bitbuf_ = 0; bitcnt_ = 0;
        if (pos_ + 4 > len_) throw std::runtime_error("truncated stored block");
        unsigned len = in_[pos_] | (in_[pos_ + 1] << 8);
        unsigned nlen = in_[pos_ + 2] | (in_[pos_ + 3] << 8);
        pos_ += 4;
        if (len != (~nlen & 0xffff)) throw std::runtime_error("stored block length mismatch");
        if (pos_ + len > len_) throw std::runtime_error("truncated stored block");
        while (len--) put(in_[pos_++]);
    }

    static void construct(Huffman& h, const short* length, int n) {
        short offs[16];
        std::memset(h.count, 0, sizeof h.count);
        for (int s = 0; s < n; s++) h.count[length[s]]++;
        offs[1] = 0;
        for (int len = 1; len < 15; len++) offs[len + 1] = short(offs[len] + h.count[len]);
        for (int s = 0; s < n; s++)
            if (length[s] != 0) h.symbol[offs[length[s]]++] = short(s);
    }

    int decode(const Huffman& h) {
        int code = 0, first = 0, index = 0;
        for (int len = 1; len < 16; len++) {
            code |= bits(1);
            int count = h.count[len];
            if (code - count < first) return h.symbol[index + (code - first)];
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        throw std::runtime_error("bad huffman code");
    }

    void codes(const Huffman& lencode, const Huffman& distcode) {
        static const short lbase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
        static const short lext[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
        static const short dbase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
        static const short dext[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
        for (;;) {
            int symbol = decode(lencode);
            if (symbol < 256) { put(uint8_t(symbol)); continue; }
            if (symbol == 256) return;
            symbol -= 257;
            if (symbol >= 29) throw std::runtime_error("bad length symbol");
            int len = lbase[symbol] + bits(lext[symbol]);
            symbol = decode(distcode);
            if (symbol >= 30) throw std::runtime_error("bad distance symbol");
            size_t dist = size_t(dbase[symbol] + bits(dext[symbol]));
            if (dist > out_.size()) throw std::runtime_error("distance too far back");
            while (len--) put(out_[out_.size() - dist]);
        }
    }

    void fixed() {
        static const FixedTables tables = [] {
            FixedTables t;
            short lengths[288];
            int s = 0;
            for (; s < 144; s++) lengths[s] = 8;
            for (; s < 256; s++) lengths[s] = 9;
            for (; s < 280; s++) lengths[s] = 7;
            for (; s < 288; s++) lengths[s] = 8;
            construct(t.lencode, lengths, 288);
            for (s = 0; s < 30; s++) lengths[s] = 5;
            construct(t.distcode, lengths, 30);
            return t;
        }();
        codes(tables.lencode, tables.distcode);
    }

    void dynamic() {
        static const short order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
        short lengths[320] = {0};
        int nlen = bits(5) + 257, ndist = bits(5) + 1, ncode = bits(4) + 4;
        if (nlen > 286 || ndist > 30) throw std::runtime_error("bad dynamic block counts");
        for (int i = 0; i < ncode; i++) lengths[order[i]] = short(bits(3));
        Huffman lencode, distcode;
        construct(lencode, lengths, 19);
        int index = 0;
        while (index < nlen + ndist) {
            int symbol = decode(lencode);
            if (symbol < 16) { lengths[index++] = short(symbol); continue; }
            short len = 0;
            if (symbol == 16) {
                if (index == 0) throw std::runtime_error("repeat with no previous length");
                len = lengths[index - 1];
                symbol = 3 + bits(2);
            } else if (symbol == 17) symbol = 3 + bits(3);
            else symbol = 11 + bits(7);
            if (index + symbol > nlen + ndist) throw std::runtime_error("too many lengths");
            while (symbol--) lengths[index++] = len;
        }
        construct(lencode, lengths, nlen);
        construct(distcode, lengths + nlen, ndist);
        codes(lencode, distcode);
    }
};

// ---------------------------------------------------------------------------
// Minimal zip reader
// ---------------------------------------------------------------------------

struct ZipEntry {
    std::string name;
    uint16_t flags = 0, method = 0;
    uint32_t csize = 0, usize = 0, localOffset = 0;
    uint32_t crc = 0;
    uint32_t dosTime = 0;  // (date << 16) | time, as stored in the central directory
};

class Zip {
public:
    std::vector<ZipEntry> entries;
    std::string error;

    bool open(const Bytes* data) {
        data_ = data;
        const Bytes& d = *data;
        if (d.size() < 22) { error = "file too small to be a jar"; return false; }
        size_t stop = d.size() > 22 + 65535 ? d.size() - 22 - 65535 : 0;
        size_t eocd = SIZE_MAX;
        for (size_t p = d.size() - 22 + 1; p-- > stop;)
            if (rd32(&d[p]) == 0x06054b50) { eocd = p; break; }
        if (eocd == SIZE_MAX) { error = "no zip central directory (not a jar?)"; return false; }
        uint16_t count = rd16(&d[eocd + 10]);
        uint32_t cdOffset = rd32(&d[eocd + 16]);
        if (cdOffset == 0xFFFFFFFF || count == 0xFFFF) { error = "zip64 jars are not supported"; return false; }
        size_t q = cdOffset;
        for (unsigned i = 0; i < count; i++) {
            if (q + 46 > d.size() || rd32(&d[q]) != 0x02014b50) { error = "corrupt central directory"; return !entries.empty(); }
            ZipEntry e;
            e.flags = rd16(&d[q + 8]);
            e.method = rd16(&d[q + 10]);
            e.dosTime = (uint32_t(rd16(&d[q + 14])) << 16) | rd16(&d[q + 12]);
            e.crc = rd32(&d[q + 16]);
            e.csize = rd32(&d[q + 20]);
            e.usize = rd32(&d[q + 24]);
            uint16_t n = rd16(&d[q + 28]), x = rd16(&d[q + 30]), c = rd16(&d[q + 32]);
            e.localOffset = rd32(&d[q + 42]);
            if (q + 46 + n > d.size()) { error = "corrupt central directory"; return !entries.empty(); }
            e.name.assign(reinterpret_cast<const char*>(&d[q + 46]), n);
            entries.push_back(std::move(e));
            q += 46 + size_t(n) + x + c;
        }
        return true;
    }

    Bytes extract(const ZipEntry& e, size_t limit) const {
        const Bytes& d = *data_;
        size_t lo = e.localOffset;
        if (lo + 30 > d.size() || rd32(&d[lo]) != 0x04034b50) throw std::runtime_error("bad local header");
        if (e.flags & 1) throw std::runtime_error("entry is encrypted");
        size_t start = lo + 30 + rd16(&d[lo + 26]) + rd16(&d[lo + 28]);
        if (start + e.csize > d.size()) throw std::runtime_error("entry data out of bounds");
        if (e.method == 0) {
            if (e.csize > limit) throw std::runtime_error("entry exceeds size limit");
            return Bytes(d.begin() + start, d.begin() + start + e.csize);
        }
        if (e.method == 8) return Inflater(&d[start], e.csize, limit).run();
        throw std::runtime_error("unsupported compression method " + std::to_string(e.method));
    }

    // First `n` bytes of an entry, without decompressing the rest.
    Bytes extractPrefix(const ZipEntry& e, size_t n) const {
        const Bytes& d = *data_;
        size_t lo = e.localOffset;
        if (lo + 30 > d.size() || rd32(&d[lo]) != 0x04034b50 || (e.flags & 1)) return {};
        size_t start = lo + 30 + rd16(&d[lo + 26]) + rd16(&d[lo + 28]);
        if (start + e.csize > d.size()) return {};
        if (e.method == 0) return Bytes(d.begin() + start, d.begin() + start + std::min<size_t>(n, e.csize));
        if (e.method != 8) return {};
        try { return Inflater(&d[start], e.csize, n, true).run(); } catch (...) { return {}; }
    }

private:
    const Bytes* data_ = nullptr;
};

// ---------------------------------------------------------------------------
// Hashes: SHA-1 (Modrinth) and CurseForge's whitespace-stripped MurmurHash2
// ---------------------------------------------------------------------------

static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static std::string sha1Hex(const Bytes& data) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    Bytes msg(data);
    uint64_t bitlen = uint64_t(data.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0);
    for (int i = 7; i >= 0; --i) msg.push_back(uint8_t(bitlen >> (i * 8)));
    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t(msg[off + 4 * i]) << 24) | (uint32_t(msg[off + 4 * i + 1]) << 16) |
                   (uint32_t(msg[off + 4 * i + 2]) << 8) | uint32_t(msg[off + 4 * i + 3]);
        for (int i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ d; k = 0xCA62C1D6; }
            uint32_t t = rotl(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl(b, 30); b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    char buf[41];
    for (int i = 0; i < 5; i++) snprintf(buf + i * 8, 9, "%08x", h[i]);
    return buf;
}

static uint32_t curseForgeFingerprint(const Bytes& data) {
    Bytes f;
    f.reserve(data.size());
    for (uint8_t b : data) if (b != 9 && b != 10 && b != 13 && b != 32) f.push_back(b);
    const uint32_t m = 0x5bd1e995;
    uint32_t len = uint32_t(f.size());
    uint32_t h = 1u ^ len;
    size_t i = 0;
    for (; i + 4 <= f.size(); i += 4) {
        uint32_t k = rd32(&f[i]);
        k *= m; k ^= k >> 24; k *= m;
        h *= m; h ^= k;
    }
    switch (len & 3) {
        case 3: h ^= uint32_t(f[i + 2]) << 16; [[fallthrough]];
        case 2: h ^= uint32_t(f[i + 1]) << 8; [[fallthrough]];
        case 1: h ^= f[i]; h *= m;
    }
    h ^= h >> 13; h *= m; h ^= h >> 15;
    return h;
}

// ---------------------------------------------------------------------------
// Java class file constant pool parsing
// ---------------------------------------------------------------------------

struct ClassInfo {
    bool validMagic = false;
    bool cpError = false;
    std::vector<std::string> utf8;      // every CONSTANT_Utf8 (names, descriptors, literals)
    std::vector<std::string> literals;  // only those referenced by CONSTANT_String (string literals)
    std::vector<std::string> classRefs;   // CONSTANT_Class names this class uses
    std::vector<std::string> memberRefs;  // "owner.name" for every field/method it calls or reads
    std::string thisName;
    int major = 0;                        // class file major version (52 = Java 8, 65 = Java 21, ...)
};

static ClassInfo parseClass(const Bytes& d) {
    ClassInfo ci;
    if (d.size() < 10 || !(d[0] == 0xCA && d[1] == 0xFE && d[2] == 0xBA && d[3] == 0xBE)) return ci;
    ci.validMagic = true;
    ci.major = be16(&d[6]);
    uint16_t count = be16(&d[8]);
    std::vector<int> utf8At(count, -1);
    std::vector<uint16_t> stringRefs, classRefs(count, 0);
    std::vector<std::pair<uint16_t, uint16_t>> members;  // (class index, name-and-type index)
    std::vector<uint16_t> natName(count, 0);
    size_t p = 10;
    try {
        for (uint16_t i = 1; i < count; i++) {
            if (p >= d.size()) throw 0;
            uint8_t tag = d[p++];
            auto need = [&](size_t n) { if (p + n > d.size()) throw 0; };
            switch (tag) {
                case 1: {
                    need(2);
                    uint16_t len = be16(&d[p]);
                    need(2 + size_t(len));
                    utf8At[i] = int(ci.utf8.size());
                    ci.utf8.emplace_back(reinterpret_cast<const char*>(&d[p + 2]), len);
                    p += 2 + size_t(len);
                    break;
                }
                case 7: need(2); classRefs[i] = be16(&d[p]); p += 2; break;
                case 8: need(2); stringRefs.push_back(be16(&d[p])); p += 2; break;
                case 16: case 19: case 20: need(2); p += 2; break;
                case 15: need(3); p += 3; break;
                case 9: case 10: case 11: need(4); members.push_back({be16(&d[p]), be16(&d[p + 2])}); p += 4; break;
                case 12: need(4); natName[i] = be16(&d[p]); p += 4; break;
                case 3: case 4: case 17: case 18: need(4); p += 4; break;
                case 5: case 6: need(8); p += 8; i++; break;
                default: throw 0;
            }
        }
        if (p + 6 <= d.size()) {
            uint16_t thisIdx = be16(&d[p + 2]);
            if (thisIdx < count && classRefs[thisIdx] < count && utf8At[classRefs[thisIdx]] >= 0)
                ci.thisName = ci.utf8[size_t(utf8At[classRefs[thisIdx]])];
        }
    } catch (...) {
        ci.cpError = true;
    }
    for (uint16_t r : stringRefs)
        if (r < count && utf8At[r] >= 0) ci.literals.push_back(ci.utf8[size_t(utf8At[r])]);
    auto utf = [&](uint16_t idx) -> const std::string* {
        return idx < count && utf8At[idx] >= 0 ? &ci.utf8[size_t(utf8At[idx])] : nullptr;
    };
    auto className = [&](uint16_t idx) -> const std::string* { return idx < count ? utf(classRefs[idx]) : nullptr; };
    for (uint16_t i = 1; i < count; i++)
        if (classRefs[i]) if (auto n = utf(classRefs[i])) ci.classRefs.push_back(*n);
    for (auto& [cls, nat] : members) {
        const std::string* owner = className(cls);
        const std::string* name = nat < count ? utf(natName[nat]) : nullptr;
        if (owner && name) ci.memberRefs.push_back(*owner + "." + *name);
    }
    return ci;
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

enum class Kind { Cheat, Malware, Suspicious, Obf };

static const char* kindName(Kind k) {
    switch (k) {
        case Kind::Cheat: return "cheat";
        case Kind::Malware: return "malware";
        case Kind::Suspicious: return "suspicious";
        default: return "obf";
    }
}

struct Signature {
    std::string pattern;  // lowercase
    int weight;
    Kind kind;
    std::string label;
    bool boundary;        // require word / camelCase boundaries around the match
};

// pattern, weight, kind, label, boundary
static std::vector<Signature> defaultSignatures() {
    using K = Kind;
    return {
        // Known hacked clients / cheat frameworks
        {"wurstclient", 60, K::Cheat, "Wurst client", false},
        {"meteordevelopment", 60, K::Cheat, "Meteor client", false},
        {"meteorclient", 60, K::Cheat, "Meteor client", false},
        {"liquidbounce", 60, K::Cheat, "LiquidBounce", false},
        {"net/ccbluex", 60, K::Cheat, "LiquidBounce (ccbluex)", false},
        {"aristois", 60, K::Cheat, "Aristois client", false},
        {"impactclient", 60, K::Cheat, "Impact client", false},
        {"rusherhack", 60, K::Cheat, "RusherHack", false},
        {"futureclient", 60, K::Cheat, "Future client", false},
        {"thunderhack", 60, K::Cheat, "ThunderHack", false},
        {"bleachhack", 60, K::Cheat, "BleachHack", false},
        {"salhack", 60, K::Cheat, "SalHack", false},
        {"kamiblue", 60, K::Cheat, "KAMI Blue", false},
        {"3arthh4ck", 60, K::Cheat, "3arthh4ck", false},
        {"konasclient", 60, K::Cheat, "Konas", false},
        {"doomsdayclient", 60, K::Cheat, "Doomsday client", false},
        {"vape.gg", 60, K::Cheat, "Vape client", false},
        {"vapeclient", 60, K::Cheat, "Vape client", false},
        {"novoline", 60, K::Cheat, "Novoline", false},
        {"ghostclient", 40, K::Cheat, "Ghost client wording", false},
        {"hackedclient", 40, K::Cheat, "Hacked client wording", false},
        {"selfdestruct", 40, K::Cheat, "Self-destruct (hide client) feature", false},
        {"self destruct", 40, K::Cheat, "Self-destruct (hide client) feature", false},
        {"clickgui", 20, K::Cheat, "ClickGUI (typical cheat menu)", false},
        {"click gui", 20, K::Cheat, "ClickGUI (typical cheat menu)", false},
        {"module/combat", 30, K::Cheat, "Combat module package", false},
        {"modules/combat", 30, K::Cheat, "Combat module package", false},
        {"module/movement", 20, K::Cheat, "Movement module package", false},
        {"modules/movement", 20, K::Cheat, "Movement module package", false},
        {"modules/exploit", 25, K::Cheat, "Exploit module package", false},
        {"module/exploit", 25, K::Cheat, "Exploit module package", false},

        // Combat
        {"killaura", 30, K::Cheat, "KillAura", false},
        {"kill aura", 30, K::Cheat, "KillAura", false},
        {"aimbot", 30, K::Cheat, "Aimbot", false},
        {"aimassist", 20, K::Cheat, "Aim assist", false},
        {"triggerbot", 30, K::Cheat, "TriggerBot", false},
        {"autoclicker", 25, K::Cheat, "Autoclicker", false},
        {"auto clicker", 25, K::Cheat, "Autoclicker", false},
        {"crystalaura", 30, K::Cheat, "CrystalAura", false},
        {"anchoraura", 30, K::Cheat, "AnchorAura", false},
        {"bedaura", 30, K::Cheat, "BedAura", false},
        {"autocrystal", 25, K::Cheat, "AutoCrystal", false},
        {"antiknockback", 25, K::Cheat, "Anti-knockback", false},
        {"noknockback", 25, K::Cheat, "Anti-knockback", false},
        {"=antikb", 20, K::Cheat, "Anti-knockback", true},
        {"=criticals", 10, K::Cheat, "Criticals module", true},
        {"=hitboxes", 5, K::Cheat, "Hitbox expander", true},
        {"=reachhack", 25, K::Cheat, "Reach hack", true},
        {"autototem", 15, K::Cheat, "AutoTotem", false},
        {"autotrap", 20, K::Cheat, "AutoTrap", false},

        // Movement
        {"=scaffold", 20, K::Cheat, "Scaffold", true},
        {"=nofall", 20, K::Cheat, "NoFall", true},
        {"flyhack", 25, K::Cheat, "Fly hack", false},
        {"=packetfly", 25, K::Cheat, "PacketFly", true},
        {"speedhack", 25, K::Cheat, "Speed hack", false},
        {"=bhop", 15, K::Cheat, "BHop", true},
        {"=noslow", 20, K::Cheat, "NoSlow", true},
        {"=jesus", 10, K::Cheat, "Jesus (water walk)", true},
        {"=longjump", 5, K::Cheat, "LongJump (also a vanilla frog task)", true},
        {"fakelag", 15, K::Cheat, "FakeLag", false},
        {"=boatfly", 15, K::Cheat, "BoatFly", true},
        {"=elytrafly", 10, K::Cheat, "ElytraFly", true},
        {"=airjump", 10, K::Cheat, "AirJump", true},

        // Render / information
        {"=xray", 15, K::Cheat, "X-Ray", true},
        {"wallhack", 25, K::Cheat, "Wallhack", false},
        {"playeresp", 20, K::Cheat, "Player ESP", false},
        {"chestesp", 20, K::Cheat, "Chest ESP", false},
        {"storageesp", 20, K::Cheat, "Storage ESP", false},
        {"=tracers", 8, K::Cheat, "Tracers", true},
        {"=newchunks", 15, K::Cheat, "NewChunks", true},
        {"freecam", 8, K::Cheat, "Freecam (allowed on some servers)", false},

        // World / exploits / automation
        {"=nuker", 20, K::Cheat, "Nuker", true},
        {"=fastbreak", 10, K::Cheat, "FastBreak", true},
        {"=fastplace", 10, K::Cheat, "FastPlace", true},
        {"servercrasher", 30, K::Cheat, "Server crasher", false},
        {"=crasher", 15, K::Cheat, "Crasher", true},
        {"=dupe", 10, K::Cheat, "Dupe", true},
        {"anticheatbypass", 30, K::Cheat, "Anticheat bypass", false},
        {"grimbypass", 30, K::Cheat, "Grim bypass", false},
        {"vulcanbypass", 30, K::Cheat, "Vulcan bypass", false},
        {"watchdogbypass", 30, K::Cheat, "Watchdog bypass", false},
        {"baritone", 5, K::Cheat, "Baritone (pathing bot)", false},

        // Stealers / RATs
        {"discord.com/api/webhooks", 80, K::Malware, "Discord webhook (common exfiltration)", false},
        {"discordapp.com/api/webhooks", 80, K::Malware, "Discord webhook (common exfiltration)", false},
        {"api.telegram.org/bot", 60, K::Malware, "Telegram bot API (exfiltration)", false},
        {"launcher_accounts", 60, K::Malware, "Reads Minecraft launcher accounts", false},
        {"lunarclient/settings", 50, K::Malware, "Reads Lunar Client accounts", false},
        {"microsoft_accounts", 50, K::Malware, "Reads Essential accounts", false},
        {"feather/accounts", 50, K::Malware, "Reads Feather accounts", false},
        {"=leveldb", 40, K::Malware, "Browser/Discord LevelDB access (token grabbing)", true},
        {"login data", 40, K::Malware, "Chrome saved passwords file", false},
        {"os_crypt", 50, K::Malware, "Chrome encryption key access", false},
        {"encrypted_key", 50, K::Malware, "Chrome encryption key access", false},
        {"wallet.dat", 60, K::Malware, "Crypto wallet theft", false},
        {"metamask", 40, K::Malware, "Crypto wallet theft", false},
        {"=exodus", 30, K::Malware, "Crypto wallet theft", true},
        {"jnativehook", 50, K::Malware, "Global keyboard hook (keylogger)", false},
        {"keylogger", 50, K::Malware, "Keylogger", false},
        {"func_148254_d", 25, K::Malware, "Reads session token (1.8.9 SRG getToken)", false},
        {"api.ipify.org", 30, K::Malware, "Public IP lookup", false},
        {"checkip.amazonaws.com", 30, K::Malware, "Public IP lookup", false},
        {"ipinfo.io", 20, K::Malware, "Public IP lookup", false},

        // Suspicious capabilities (common in loaders/droppers, sometimes legit)
        {"pastebin.com/raw", 20, K::Suspicious, "Downloads from Pastebin", false},
        {"cdn.discordapp.com/attachments", 20, K::Suspicious, "Downloads from Discord CDN", false},
        {"java/net/urlclassloader", 10, K::Suspicious, "Loads classes from URLs", false},
        {"=defineclass", 10, K::Suspicious, "Defines classes at runtime", true},
        {"java/lang/processbuilder", 10, K::Suspicious, "Starts external processes", false},
        {"=getruntime", 5, K::Suspicious, "Runtime access (exec?)", true},
        {"=appdata", 10, K::Suspicious, "Touches %APPDATA%", true},

        // Obfuscator watermarks
        {"allatori", 40, K::Obf, "Allatori obfuscator", false},
        {"zelix", 40, K::Obf, "Zelix KlassMaster", false},
        {"=zkm", 30, K::Obf, "Zelix KlassMaster", true},
        {"skidfuscator", 40, K::Obf, "Skidfuscator", false},
        {"branchlock", 40, K::Obf, "Branchlock", false},
        {"paramorphism", 40, K::Obf, "Paramorphism", false},
        {"caesium", 30, K::Obf, "Caesium obfuscator", false},
        {"superblaze", 30, K::Obf, "Superblaze obfuscator", false},
        {"binscure", 40, K::Obf, "Binscure", false},
        {"=dasho", 30, K::Obf, "DashO", true},
        {"obfuscated by", 40, K::Obf, "Obfuscator watermark", false},
        {"native0/loader", 40, K::Obf, "native-obfuscator (code compiled to native)", false},
        {"proguard", 5, K::Obf, "ProGuard", false},
    };
}

static bool loadSignatureFile(const fs::path& path, std::vector<Signature>& sigs) {
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        std::vector<std::string> parts;
        std::stringstream ss(line);
        std::string part;
        while (std::getline(ss, part, '|')) parts.push_back(part);
        if (parts.size() < 3) continue;
        Signature s;
        s.weight = std::atoi(parts[0].c_str());
        std::string k = lower(parts[1]);
        s.kind = k == "malware" ? Kind::Malware : k == "suspicious" ? Kind::Suspicious : k == "obf" ? Kind::Obf : Kind::Cheat;
        s.pattern = lower(parts[2]);
        s.boundary = !s.pattern.empty() && s.pattern[0] == '=';
        s.label = parts.size() > 3 ? parts[3] : parts[2];
        sigs.push_back(s);
    }
    return true;
}

static bool isLowerC(char c) { return c >= 'a' && c <= 'z'; }
static bool isUpperC(char c) { return c >= 'A' && c <= 'Z'; }
static bool isLetterC(char c) { return isLowerC(c) || isUpperC(c); }

// Boundary = start/end of string, a non-letter, or a camelCase transition.
// So "Scaffold" matches in "ScaffoldModule" and "AutoScaffold" but not "scaffolding".
static bool boundaryOk(const std::string& orig, size_t pos, size_t len) {
    bool startOk = pos == 0 || !isLetterC(orig[pos - 1]) || (isUpperC(orig[pos]) && !isUpperC(orig[pos - 1]));
    size_t end = pos + len;
    bool endOk = end >= orig.size() || !isLetterC(orig[end]) || (isUpperC(orig[end]) && !isUpperC(orig[end - 1]));
    return startOk && endOk;
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

struct Finding {
    Kind kind;
    int weight;
    std::string text;
};

struct ModrinthInfo {
    bool checked = false, matched = false;
    std::string projectId, slug, title, version, categories;
    long long downloads = -1;
    std::string claimedTitle, claimedSlug;  // set when the jar's mod id is a Modrinth project but the file isn't
};

// Result of comparing an unverified jar with the official Modrinth file of the version it claims to be.
struct OriginalDiff {
    bool done = false;
    std::string versionLabel, fileName, note;
    std::vector<std::string> added, modified, removed;  // entry names
    size_t unchanged = 0;
};

struct ModReport {
    std::string label;
    int depth = 0;
    std::string sha1;
    uint32_t cfFingerprint = 0;
    std::string modId, modName, modVersion, loader;
    ModrinthInfo mr;
    bool cfChecked = false, cfMatched = false;
    std::string cfName, cfUrl;
    std::string lookupError;
    bool verified = false;
    std::string error;
    size_t classCount = 0, entryCount = 0;
    std::vector<Finding> findings;
    fs::path filePath;                                            // top-level jars only
    OriginalDiff diff;
    std::vector<std::pair<std::string, std::string>> behaviorHits;  // (class, cheat behavior) for cross-referencing

    int score(Kind k) const {
        int s = 0;
        for (auto& f : findings) if (f.kind == k) s += f.weight;
        return s;
    }
};

struct Options {
    bool verbose = false;
    std::vector<Signature> sigs;
};

static fs::path exeDir() {
    wchar_t buf[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(nullptr, buf, DWORD(std::size(buf)));
    return fs::path(std::wstring(buf, n)).parent_path();
}

static Options makeOptions() {
    Options opt;
    opt.sigs = defaultSignatures();
    loadSignatureFile(exeDir() / "bergsson_sigs.txt", opt.sigs);
    return opt;
}

struct SigHit { size_t count = 0; std::string firstWhere; std::string context; };

static void matchBlob(const std::string& orig, const std::string& where, const Options& opt, std::map<size_t, SigHit>& hits) {
    std::string low = lower(orig);
    for (size_t i = 0; i < opt.sigs.size(); i++) {
        const Signature& s = opt.sigs[i];
        std::string pat = s.boundary ? s.pattern.substr(1) : s.pattern;
        if (pat.empty()) continue;
        size_t pos = low.find(pat);
        while (pos != std::string::npos && s.boundary && !boundaryOk(orig, pos, pat.size()))
            pos = low.find(pat, pos + 1);
        if (pos == std::string::npos) continue;
        SigHit& h = hits[i];
        if (h.count++ == 0) {
            h.firstWhere = where;
            size_t a = orig.rfind('\n', pos), b = orig.find('\n', pos);
            a = a == std::string::npos ? 0 : a + 1;
            if (b == std::string::npos) b = orig.size();
            h.context = orig.substr(a, b - a);
        }
    }
}

// Lenient single-key lookup, used for mod metadata files that are not always valid JSON.
static std::string jsonString(const std::string& s, const std::string& key, size_t from = 0) {
    std::string needle = "\"" + key + "\"";
    size_t p = s.find(needle, from);
    while (p != std::string::npos) {
        size_t q = p + needle.size();
        while (q < s.size() && (s[q] == ' ' || s[q] == '\t' || s[q] == '\r' || s[q] == '\n')) q++;
        if (q < s.size() && s[q] == ':') {
            q++;
            while (q < s.size() && (s[q] == ' ' || s[q] == '\t' || s[q] == '\r' || s[q] == '\n')) q++;
            if (q < s.size() && s[q] == '"') {
                std::string out;
                for (q++; q < s.size() && s[q] != '"'; q++) {
                    if (s[q] == '\\' && q + 1 < s.size()) q++;
                    out += s[q];
                }
                return out;
            }
        }
        p = s.find(needle, p + 1);
    }
    return "";
}

static std::string tomlString(const std::string& s, const std::string& key) {
    size_t p = s.find(key);
    while (p != std::string::npos) {
        bool lineStart = p == 0 || s[p - 1] == '\n' || s[p - 1] == ' ' || s[p - 1] == '\t';
        size_t q = p + key.size();
        while (q < s.size() && (s[q] == ' ' || s[q] == '\t')) q++;
        if (lineStart && q < s.size() && s[q] == '=') {
            q++;
            while (q < s.size() && (s[q] == ' ' || s[q] == '\t')) q++;
            if (q < s.size() && (s[q] == '"' || s[q] == '\'')) {
                char quote = s[q];
                size_t e = s.find(quote, q + 1);
                if (e != std::string::npos) return s.substr(q + 1, e - q - 1);
            }
        }
        p = s.find(key, p + 1);
    }
    return "";
}

static double shannonEntropy(const std::string& s) {
    if (s.empty()) return 0;
    int freq[256] = {0};
    for (unsigned char c : s) freq[c]++;
    double e = 0;
    for (int f : freq)
        if (f) { double p = double(f) / s.size(); e -= p * std::log2(p); }
    return e;
}

static double byteEntropy(const Bytes& d) {
    if (d.empty()) return 0;
    size_t freq[256] = {0};
    for (uint8_t b : d) freq[b]++;
    double e = 0;
    for (size_t f : freq)
        if (f) { double p = double(f) / d.size(); e -= p * std::log2(p); }
    return e;
}

static bool looksEncrypted(const std::string& lit) {
    if (lit.size() < 16) return false;
    if (lit.find_first_of(" ./:") != std::string::npos) return false;
    bool up = false, lo = false, dig = false, sym = false;
    for (unsigned char c : lit) {
        if (c >= 'A' && c <= 'Z') up = true;
        else if (c >= 'a' && c <= 'z') lo = true;
        else if (c >= '0' && c <= '9') dig = true;
        else sym = true;
    }
    if (int(up) + int(lo) + int(dig) + int(sym) < 3) return false;
    return shannonEntropy(lit) / std::log2(double(std::min<size_t>(lit.size(), 94))) >= 0.9;
}

static bool looksGarbled(const std::string& lit) {
    // Control characters and C1 code points (0xC2 0x80-0x9F) rarely appear in real
    // strings but are common output of string-encryption obfuscators.
    size_t bad = 0;
    for (size_t i = 0; i < lit.size(); i++) {
        unsigned char c = uint8_t(lit[i]);
        // \x01 and \x02 are javac's string-concatenation recipe placeholders, not encryption
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != 1 && c != 2) bad++;
        else if (c == 0xC2 && i + 1 < lit.size() && uint8_t(lit[i + 1]) >= 0x80 && uint8_t(lit[i + 1]) <= 0x9F) bad++;
    }
    return bad >= 3 && bad * 5 >= lit.size();
}

static const std::set<std::string>& reservedNames() {
    static const std::set<std::string> names = {
        "abstract","assert","boolean","break","byte","case","catch","char","class","const","continue",
        "default","do","double","else","enum","extends","final","finally","float","for","goto","if",
        "implements","import","instanceof","int","interface","long","native","new","package","private",
        "protected","public","return","short","static","super","switch","synchronized","this","throw",
        "throws","transient","try","void","volatile","while","null","true","false",
        "con","prn","aux","nul","com1","com2","com3","lpt1","lpt2","lpt3"};
    return names;
}

// ---------------------------------------------------------------------------
// Behavior analysis: what a class does, independent of how it's named.
// Hidden cheats rename everything, but they still have to call the same game internals.
// ---------------------------------------------------------------------------

// Minecraft classes a cheat has to touch, under every naming scheme a mod jar ships with:
// Fabric intermediary (class_NNN), Mojang names (NeoForge, Forge 1.20.5+) and MCP names (Forge 1.8-1.16).
struct ClassGroup { const char* tag; std::vector<std::string> names; };

static const std::vector<ClassGroup>& sensitiveClasses() {
    static const std::vector<ClassGroup> groups = {
        {"interaction", {"net/minecraft/class_636", "net/minecraft/client/multiplayer/MultiPlayerGameMode",
                         "net/minecraft/client/multiplayer/PlayerControllerMP", "net/minecraft/client/multiplayer/PlayerController"}},
        {"attackPacket", {"net/minecraft/class_2824", "net/minecraft/network/protocol/game/ServerboundInteractPacket",
                          "net/minecraft/network/play/client/CPacketUseEntity", "net/minecraft/network/play/client/CUseEntityPacket"}},
        {"movePacket", {"net/minecraft/class_2828", "net/minecraft/network/protocol/game/ServerboundMovePlayerPacket",
                        "net/minecraft/network/play/client/CPacketPlayer", "net/minecraft/network/play/client/CPlayerPacket"}},
        {"velocityPacket", {"net/minecraft/class_2743", "net/minecraft/class_2664",
                            "net/minecraft/network/protocol/game/ClientboundSetEntityMotionPacket",
                            "net/minecraft/network/protocol/game/ClientboundExplodePacket",
                            "net/minecraft/network/play/server/SPacketEntityVelocity", "net/minecraft/network/play/server/SPacketExplosion",
                            "net/minecraft/network/play/server/SEntityVelocityPacket", "net/minecraft/network/play/server/SExplosionPacket"}},
        {"connection", {"net/minecraft/class_2535", "net/minecraft/class_634", "net/minecraft/network/Connection",
                        "net/minecraft/client/multiplayer/ClientPacketListener", "net/minecraft/network/NetworkManager",
                        "net/minecraft/client/network/NetHandlerPlayClient", "net/minecraft/client/network/play/ClientPlayNetHandler"}},
        {"input", {"net/minecraft/class_312", "net/minecraft/class_304", "net/minecraft/client/MouseHandler",
                   "net/minecraft/client/KeyMapping", "net/minecraft/client/MouseHelper", "net/minecraft/client/settings/KeyBinding"}},
        {"keybind", {"net/minecraft/class_304", "net/minecraft/client/KeyMapping", "net/minecraft/client/settings/KeyBinding"}},
    };
    return groups;
}

// True if `cls` (or one of its inner classes) belongs to the named group.
static bool inGroup(const std::string& cls, const char* tag) {
    for (const auto& g : sensitiveClasses()) {
        if (std::strcmp(g.tag, tag) != 0) continue;
        for (const auto& n : g.names)
            if (cls.compare(0, n.size(), n) == 0 && (cls.size() == n.size() || cls[n.size()] == '$')) return true;
    }
    return false;
}

struct Behavior {
    bool osInput = false, gameInput = false, random = false, timing = false, attack = false, moveForge = false;
    bool connection = false, cancel = false, mixin = false, velocity = false, rawKeys = false, keybindReg = false;
    bool selfLocate = false, fileDelete = false, loaderHook = false, modListEdit = false, loadsByName = false;
};

static Behavior analyzeBehavior(const ClassInfo& ci) {
    Behavior b;
    for (const auto& c : ci.classRefs) {
        if (c == "java/awt/Robot") b.osInput = true;
        else if (c == "java/util/Random" || c == "java/util/concurrent/ThreadLocalRandom" || c == "java/security/SecureRandom") b.random = true;
        else if (c.rfind("net/fabricmc/loader/impl/", 0) == 0 || c.find("/fml/loading/moddiscovery/") != std::string::npos ||
                 c == "com/terraformersmc/modmenu/ModMenu" || c.rfind("com/terraformersmc/modmenu/gui/", 0) == 0) {
            // ...unless it's the loader / Mod Menu itself
            if (ci.thisName.rfind("net/fabricmc/loader/", 0) != 0 && ci.thisName.rfind("com/terraformersmc/modmenu/", 0) != 0)
                b.loaderHook = true;
        }
        if (inGroup(c, "attackPacket")) b.attack = true;
        if (inGroup(c, "connection")) b.connection = true;
        if (inGroup(c, "velocityPacket")) b.velocity = true;
    }
    // Library bindings (LWJGL's User32, JNA) declare SendInput & co. without using them.
    bool binding = ci.thisName.rfind("org/lwjgl/", 0) == 0 || ci.thisName.rfind("com/sun/jna/", 0) == 0;
    for (const auto& s : ci.utf8) {
        if (s == "Lorg/spongepowered/asm/mixin/Mixin;") b.mixin = true;
        else if (!binding && (s == "SendInput" || s == "mouse_event" || s == "keybd_event")) b.osInput = true;
    }
    static const std::set<std::string> inputPress = {
        "setPressed", "setDown", "set", "click", "onKeyPressed", "onMouseButton", "setKeyPressed", "setKeyBindState", "onTick",
        "method_23481", "method_1416", "method_1420", "method_1601", "func_74510_a", "func_74507_a"};
    static const std::set<std::string> attackCalls = {"attackEntity", "attack", "method_2918", "func_78764_a"};
    bool listsMods = false, removes = false;
    for (const auto& m : ci.memberRefs) {
        size_t dot = m.rfind('.');
        std::string owner = m.substr(0, dot), name = m.substr(dot + 1);
        if (owner == "java/lang/System" && (name == "nanoTime" || name == "currentTimeMillis")) b.timing = true;
        else if (owner.rfind("org/spongepowered/asm/mixin/injection/callback/CallbackInfo", 0) == 0 && name == "cancel") b.cancel = true;
        else if ((owner == "org/lwjgl/glfw/GLFW" && (name == "glfwGetKey" || name == "glfwGetMouseButton")) ||
                 (owner == "org/lwjgl/input/Keyboard" && name == "isKeyDown") || (owner == "org/lwjgl/input/Mouse" && name == "isButtonDown"))
            b.rawKeys = true;
        else if (name == "registerKeyBinding" || name == "registerKeyMapping" || (inGroup(owner, "keybind") && name == "<init>") ||
                 owner.find("RegisterKeyMappingsEvent") != std::string::npos)
            b.keybindReg = true;
        else if (name == "getCodeSource") b.selfLocate = true;
        else if ((owner == "java/io/File" && (name == "delete" || name == "deleteOnExit")) ||
                 (owner == "java/nio/file/Files" && (name == "delete" || name == "deleteIfExists")))
            b.fileDelete = true;
        else if (owner == "java/lang/Class" && name == "forName") b.loadsByName = true;
        else if (name == "loadClass") b.loadsByName = true;
        if (name == "getAllMods" || name == "getMods") listsMods = true;
        if (name == "remove" || name == "removeIf") removes = true;
        if (inGroup(owner, "input") && inputPress.count(name)) b.gameInput = true;
        if (inGroup(owner, "interaction") && attackCalls.count(name)) b.attack = true;
        if (inGroup(owner, "movePacket") && name == "<init>") b.moveForge = true;
    }
    b.modListEdit = listsMods && removes;
    return b;
}

// One cheat-behavior rule matched by a class.
struct BehaviorRule { Kind kind; int weight; std::string label; };

static std::vector<BehaviorRule> behaviorRules(const Behavior& b) {
    std::vector<BehaviorRule> r;
    bool timed = b.random || b.timing;
    if (b.osInput) r.push_back({Kind::Cheat, 35, std::string("Simulates OS-level mouse/keyboard input (autoclicker)") + (timed ? " with randomized timing" : "")});
    // Plain timing is everywhere (GUIs, animations); randomized delays are what cheats use to look human.
    if (b.gameInput && b.random) r.push_back({Kind::Cheat, 30, "Presses game keys / mouse buttons from code with randomized delays (autoclicker)"});
    else if (b.gameInput) r.push_back({Kind::Suspicious, 10, "Presses game keys from code (also done by toggle-sprint style mods)"});
    if (b.attack && b.random) r.push_back({Kind::Cheat, 35, "Attacks entities from code with randomized delays (KillAura / TriggerBot pattern)"});
    else if (b.attack && b.timing) r.push_back({Kind::Suspicious, 15, "Attacks entities from code on a timer"});
    else if (b.attack && !b.mixin) r.push_back({Kind::Suspicious, 10, "Sends attack / interact actions from code"});
    if (b.moveForge) r.push_back({Kind::Cheat, 25, "Builds its own movement packets (Fly / NoFall / Blink pattern)"});
    if (b.mixin && b.velocity && b.cancel) r.push_back({Kind::Cheat, 35, "Cancels knockback / velocity packets (Anti-Knockback pattern)"});
    else if (b.mixin && b.velocity) r.push_back({Kind::Suspicious, 15, "Hooks knockback / velocity packet handling"});
    if (b.mixin && b.cancel && b.connection)
        r.push_back({Kind::Suspicious, 10, "Cancels packets inside the network connection (Blink / FakeLag pattern; chat-privacy mods do this too)"});
    if (b.selfLocate && b.fileDelete) r.push_back({Kind::Suspicious, 20, "Locates its own jar and deletes files (self-destruct; auto-updaters also do this)"});
    // Reading the mod list or loader internals is normal; patching them (mixins) is how cheats hide from it.
    if (b.mixin && (b.loaderHook || b.modListEdit))
        r.push_back({Kind::Cheat, 40, "Patches the mod loader / mod list (can hide mods from Mod Menu or the loader)"});
    return r;
}

static std::string javaVersionName(int major) { return major >= 45 ? "Java " + std::to_string(major - 44) : "unknown"; }

static std::string listSome(const std::vector<std::string>& items, size_t max = 3) {
    std::string out;
    for (size_t i = 0; i < items.size() && i < max; i++) out += (i ? ", " : "") + printable(items[i], 70);
    if (items.size() > max) out += " +" + std::to_string(items.size() - max) + " more";
    return out;
}

static const size_t kEntryLimit = 64u << 20;  // max decompressed size per entry

static void scanJar(const Bytes& data, const std::string& label, int depth, const Options& opt, std::vector<ModReport>& out) {
    size_t myIndex = out.size();
    out.emplace_back();
    out[myIndex].label = label;
    out[myIndex].depth = depth;
    out[myIndex].sha1 = sha1Hex(data);
    out[myIndex].cfFingerprint = curseForgeFingerprint(data);

    Zip zip;
    if (!zip.open(&data)) { out[myIndex].error = zip.error; return; }
    if (!zip.error.empty()) out[myIndex].findings.push_back({Kind::Obf, 15, "Zip structure damaged: " + zip.error});

    std::map<size_t, SigHit> hits;
    std::set<std::string> seen;
    size_t classes = 0, shortN = 0, confusableN = 0, nonAsciiN = 0, reservedN = 0, mismatchN = 0;
    size_t badMagicN = 0, cpErrN = 0, classDirN = 0, encryptedN = 0, dupN = 0, nativeN = 0, extractErrN = 0;
    size_t literalsN = 0, encryptedLitN = 0, garbledN = 0;
    std::string exampleShort, exampleConfusable, exampleNonAscii, exampleReserved, exampleEncLit;
    std::vector<std::pair<std::string, Bytes>> nested;
    // Loader / dropper indicators
    size_t blobN = 0, blobBytes = 0, jdkMimicN = 0;
    std::string exampleBlob, exampleMimic;
    bool definesClasses = false, rawSocket = false, hardcodedIp = false, usesJna = false, bundlesJna = false, javaAgent = false;
    std::set<std::string> entrypointKinds;
    // Behavior + injected-code indicators
    struct ClassMeta { std::string name, pkg; int major; uint32_t time; };
    std::vector<ClassMeta> classMeta;
    std::map<std::string, std::vector<std::string>> ruleClasses;  // behavior label -> classes showing it
    std::map<std::string, BehaviorRule> ruleInfo;
    std::vector<std::string> multiBehavior, rawKeyClasses, disguisedClass, disguisedZip;
    std::vector<std::pair<std::string, std::vector<std::string>>> byNameLoads;  // class -> class-name-like literals
    std::set<std::string> jarClassNames;
    bool anyKeybindReg = false;

    static const std::vector<std::string> textExt = {".json", ".toml", ".txt", ".properties", ".cfg", ".yml",
                                                     ".yaml", ".mcmeta", ".lang", ".info", ".mf", ".js"};

    for (const ZipEntry& e : zip.entries) {
        if (!seen.insert(e.name).second) dupN++;
        if (e.flags & 1) encryptedN++;
        std::string lname = lower(e.name);
        if (endsWith(lname, ".class/")) classDirN++;
        if (!e.name.empty() && e.name.back() == '/') continue;

        for (unsigned char c : e.name) if (c >= 0x80) { nonAsciiN++; if (exampleNonAscii.empty()) exampleNonAscii = e.name; break; }
        if (endsWith(lname, ".dll") || endsWith(lname, ".so") || endsWith(lname, ".dylib") || endsWith(lname, ".jnilib")) nativeN++;

        std::string blob = e.name + "\n";

        if (endsWith(lname, ".class")) {
            classes++;
            if (lname.rfind("com/sun/jna/", 0) == 0) bundlesJna = true;
            static const char* jdkPrefixes[] = {"java/", "javax/", "jdk/", "sun/", "net/java/", "com/sun/"};
            for (const char* pre : jdkPrefixes)
                if (lname.rfind(pre, 0) == 0 && lname.rfind("com/sun/jna/", 0) != 0) {
                    jdkMimicN++; if (exampleMimic.empty()) exampleMimic = e.name; break;
                }
            if (lname == "mod_d.class" || (lname.rfind("mod_", 0) == 0 && lname.find('/') == std::string::npos)) entrypointKinds.insert("ModLoader");
            std::string simple = e.name.substr(e.name.rfind('/') == std::string::npos ? 0 : e.name.rfind('/') + 1);
            simple = simple.substr(0, simple.size() - 6);
            std::string outer = simple.substr(0, simple.find('$'));
            if (outer != "package-info" && outer != "module-info" && !outer.empty()) {
                if (outer.size() <= 2) { shortN++; if (exampleShort.empty()) exampleShort = e.name; }
                if (outer.size() >= 4 && outer.find_first_not_of("Il1") == std::string::npos) {
                    confusableN++; if (exampleConfusable.empty()) exampleConfusable = e.name;
                }
                // Keywords only count in their exact (lowercase) form - "Synchronized" is a legit name, "if" isn't.
                // Device names (CON, AUX...) are reserved in any case on Windows.
                static const std::set<std::string> devices = {"con", "prn", "aux", "nul", "com1", "com2", "com3", "lpt1", "lpt2", "lpt3"};
                if (reservedNames().count(outer) || devices.count(lower(outer))) { reservedN++; if (exampleReserved.empty()) exampleReserved = e.name; }
            }
            Bytes cls;
            try { cls = zip.extract(e, kEntryLimit); } catch (...) { extractErrN++; continue; }
            ClassInfo ci = parseClass(cls);
            if (!ci.validMagic) { badMagicN++; continue; }
            if (ci.cpError) cpErrN++;
            if (!ci.thisName.empty()) {
                std::string path = e.name;
                if (path.rfind("META-INF/versions/", 0) == 0) {
                    size_t slash = path.find('/', 18);
                    if (slash != std::string::npos) path = path.substr(slash + 1);
                }
                if (ci.thisName + ".class" != path) mismatchN++;
            }
            for (const auto& s : ci.utf8) {
                blob += s; blob += '\n';
                if (s == "defineClass") definesClasses = true;
                else if (s == "java/nio/channels/SocketChannel" || s == "java/net/Socket") rawSocket = true;
                else if (s == "getByAddress") hardcodedIp = true;
                else if (s.rfind("com/sun/jna/", 0) == 0) usesJna = true;
            }
            for (const auto& lit : ci.literals) {
                literalsN++;
                if (looksEncrypted(lit)) { encryptedLitN++; if (exampleEncLit.empty()) exampleEncLit = lit; }
                if (looksGarbled(lit)) garbledN++;
            }

            std::string cname = ci.thisName.empty() ? e.name.substr(0, e.name.size() - 6) : ci.thisName;
            jarClassNames.insert(e.name.substr(0, e.name.size() - 6));
            if (e.name.rfind("META-INF/", 0) != 0) {
                size_t slash = e.name.rfind('/');
                classMeta.push_back({cname, slash == std::string::npos ? "" : e.name.substr(0, slash), ci.major, e.dosTime});
            }
            Behavior b = analyzeBehavior(ci);
            if (b.rawKeys) rawKeyClasses.push_back(cname);
            if (b.keybindReg) anyKeybindReg = true;
            int cheatRules = 0;
            for (const auto& rule : behaviorRules(b)) {
                ruleClasses[rule.label].push_back(cname);
                ruleInfo.emplace(rule.label, rule);
                if (rule.kind == Kind::Cheat) {
                    cheatRules++;
                    out[myIndex].behaviorHits.push_back({cname, rule.label});
                }
            }
            if (cheatRules >= 2) multiBehavior.push_back(cname);
            if (b.loadsByName) {
                std::vector<std::string> names;
                for (const auto& lit : ci.literals)
                    if (lit.find('.') != std::string::npos && lit.find(' ') == std::string::npos && lit.size() < 200) names.push_back(lit);
                if (!names.empty()) byNameLoads.push_back({cname, names});
            }
        } else if (endsWith(lname, ".jar")) {
            if (depth < 3) {
                try { nested.emplace_back(e.name, zip.extract(e, kEntryLimit)); } catch (...) { extractErrN++; }
            }
        } else {
            // Code smuggled in as a "resource": a class file or a jar renamed to .png/.json/...
            if (e.usize >= 4 && !endsWith(lname, ".zip")) {
                Bytes head = zip.extractPrefix(e, 4);
                // kotlinx-coroutines ships its debug probes as DebugProbesKt.bin on purpose
                if (head.size() == 4 && head[0] == 0xCA && head[1] == 0xFE && head[2] == 0xBA && head[3] == 0xBE && !endsWith(e.name, "DebugProbesKt.bin"))
                    disguisedClass.push_back(e.name);
                else if (head.size() == 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4) disguisedZip.push_back(e.name);
            }
            // Extension-less, high-entropy files outside META-INF are typically encrypted payloads.
            std::string base = lname.substr(lname.rfind('/') == std::string::npos ? 0 : lname.rfind('/') + 1);
            if (base.find('.') == std::string::npos && lname.rfind("meta-inf/", 0) != 0 && e.usize >= 4096) {
                try {
                    Bytes raw = zip.extract(e, kEntryLimit);
                    if (byteEntropy(raw) >= 7.2) {
                        blobN++;
                        blobBytes += raw.size();
                        if (exampleBlob.empty()) exampleBlob = e.name;
                    }
                } catch (...) { extractErrN++; }
            }
            bool isText = false;
            for (auto& ext : textExt) if (endsWith(lname, ext)) { isText = true; break; }
            if (isText && e.usize <= (2u << 20)) {
                Bytes txt;
                try { txt = zip.extract(e, 2u << 20); } catch (...) { extractErrN++; continue; }
                std::string s(txt.begin(), txt.end());
                std::string ls = lower(s);
                ModReport& r = out[myIndex];
                if (lname == "fabric.mod.json") entrypointKinds.insert("Fabric");
                if (lname == "quilt.mod.json") entrypointKinds.insert("Quilt");
                if (lname == "meta-inf/mods.toml") entrypointKinds.insert("Forge");
                if (lname == "meta-inf/neoforge.mods.toml") entrypointKinds.insert("NeoForge");
                if (lname == "mcmod.info") entrypointKinds.insert("Forge (legacy)");
                if (endsWith(lname, ".json") && lname.find('/') == std::string::npos && ls.find("\"mainclass\"") != std::string::npos)
                    entrypointKinds.insert("LabyMod");
                if (lname == "meta-inf/manifest.mf") {
                    if ((ls.find("premain-class:") != std::string::npos || ls.find("agent-class:") != std::string::npos) &&
                        ls.find("kotlinx.coroutines.debug.") == std::string::npos)  // the coroutines debug agent is benign
                        javaAgent = true;
                    if (ls.find("main-class:") != std::string::npos && ls.find("\nmain-class:") != std::string::npos) entrypointKinds.insert("standalone Main-Class");
                }
                if (lname == "fabric.mod.json") {
                    r.loader = "fabric"; r.modId = jsonString(s, "id"); r.modName = jsonString(s, "name"); r.modVersion = jsonString(s, "version");
                } else if (lname == "quilt.mod.json" && r.modId.empty()) {
                    r.loader = "quilt"; r.modId = jsonString(s, "id"); r.modName = jsonString(s, "name"); r.modVersion = jsonString(s, "version");
                } else if ((lname == "meta-inf/mods.toml" || lname == "meta-inf/neoforge.mods.toml") && r.modId.empty()) {
                    r.loader = lname == "meta-inf/mods.toml" ? "forge" : "neoforge";
                    r.modId = tomlString(s, "modId"); r.modName = tomlString(s, "displayName"); r.modVersion = tomlString(s, "version");
                } else if (lname == "mcmod.info" && r.modId.empty()) {
                    r.loader = "forge (legacy)"; r.modId = jsonString(s, "modid"); r.modName = jsonString(s, "name"); r.modVersion = jsonString(s, "version");
                }
                blob += s;
            }
        }
        matchBlob(blob, e.name, opt, hits);
    }

    ModReport& r = out[myIndex];
    r.classCount = classes;
    r.entryCount = zip.entries.size();

    for (auto& [idx, h] : hits) {
        const Signature& s = opt.sigs[idx];
        std::string text = s.label + " - matched \"" + (s.boundary ? s.pattern.substr(1) : s.pattern) + "\" in " +
                           std::to_string(h.count) + " entr" + (h.count == 1 ? "y" : "ies") + ", e.g. " + printable(h.firstWhere, 70);
        if (opt.verbose) text += "\n          context: " + printable(h.context, 120);
        r.findings.push_back({s.kind, s.weight, text});
    }

    auto add = [&](int w, const std::string& t) { r.findings.push_back({Kind::Obf, w, t}); };
    if (classes >= 10 && shortN * 2 >= classes)
        add(35, std::to_string(shortN) + "/" + std::to_string(classes) + " classes have 1-2 character names, e.g. " + printable(exampleShort));
    if (confusableN >= 3)
        add(45, std::to_string(confusableN) + " classes named with confusable I/l/1 characters, e.g. " + printable(exampleConfusable));
    if (nonAsciiN)
        add(40, std::to_string(nonAsciiN) + " entries with non-ASCII names, e.g. " + printable(exampleNonAscii));
    if (reservedN)
        add(40, std::to_string(reservedN) + " classes named after Java keywords / reserved device names, e.g. " + printable(exampleReserved));
    if (mismatchN)
        add(20, std::to_string(mismatchN) + " classes whose internal name doesn't match their path");
    if (badMagicN)
        add(20, std::to_string(badMagicN) + " .class entries that aren't valid class files (decoys or corruption)");
    if (cpErrN)
        add(15, std::to_string(cpErrN) + " classes with malformed constant pools");
    if (classDirN)
        add(30, std::to_string(classDirN) + " directories named *.class/ (anti-decompiler trick)");
    if (encryptedN)
        add(25, std::to_string(encryptedN) + " password-encrypted zip entries");
    if (dupN)
        add(20, std::to_string(dupN) + " duplicate zip entries (anti-analysis trick)");
    if (extractErrN)
        add(10, std::to_string(extractErrN) + " entries that fail to decompress");
    if (literalsN >= 20 && encryptedLitN >= 10 && encryptedLitN * 4 >= literalsN)
        add(30, std::to_string(encryptedLitN) + "/" + std::to_string(literalsN) + " string constants look encrypted, e.g. " + printable(exampleEncLit, 40));
    if (garbledN >= 5)
        add(30, std::to_string(garbledN) + " string constants contain control characters (string encryption)");
    if (nativeN)
        add(10, std::to_string(nativeN) + " native libraries bundled (code hidden from Java analysis; also used legitimately)");

    auto flag = [&](Kind k, int w, const std::string& t) { r.findings.push_back({k, w, t}); };
    if (blobN)
        flag(Kind::Suspicious, 25, std::to_string(blobN) + " extension-less encrypted data files (" + std::to_string(blobBytes / 1024) +
                                   " KB) - hidden payload, e.g. " + printable(exampleBlob));
    if (blobN && definesClasses)
        flag(Kind::Malware, 60, "Decrypts hidden classes from inside the jar and loads them in memory with defineClass (malware loader)");
    if (javaAgent)
        flag(Kind::Suspicious, 25, "Manifest declares a Java agent (Premain-Class/Agent-Class) - can rewrite the game's code at load time");
    if (entrypointKinds.size() >= 3) {
        std::string kinds;
        for (auto& k : entrypointKinds) kinds += (kinds.empty() ? "" : ", ") + k;
        flag(Kind::Suspicious, 30, "Entry points for " + std::to_string(entrypointKinds.size()) + " different loaders (" + kinds +
                                   ") - droppers do this to run under any launcher");
    }
    if (rawSocket && hardcodedIp)
        flag(Kind::Suspicious, 20, "Opens raw sockets to a hard-coded IP address (InetAddress.getByAddress)");
    if (usesJna && !bundlesJna)
        flag(Kind::Suspicious, 10, "Calls native Windows/OS functions through JNA");
    if (jdkMimicN)
        flag(Kind::Suspicious, 20, std::to_string(jdkMimicN) + " classes in a package that imitates the JDK, e.g. " + printable(exampleMimic));
    if (depth == 0 && r.modId.size() <= 2 && !r.modId.empty() && r.modName.size() <= 2)
        flag(Kind::Suspicious, 10, "Meaningless mod id/name ('" + r.modId + "') - real mods identify themselves");

    // What the code does, whatever it's called
    for (const auto& [label, list] : ruleClasses) {
        const BehaviorRule& info = ruleInfo.at(label);
        flag(info.kind, info.weight, label + " - in " + listSome(list));
    }
    if (!multiBehavior.empty())
        flag(Kind::Cheat, 20, "A single class combines several cheat behaviors: " + listSome(multiBehavior));
    if (!rawKeyClasses.empty() && !anyKeybindReg)
        flag(Kind::Suspicious, 10, "Reads raw keyboard/mouse state but registers no keybinds (hidden hotkeys) - in " + listSome(rawKeyClasses));
    std::vector<std::string> hiddenLoads;
    for (const auto& [cls, names] : byNameLoads)
        for (const auto& n : names) {
            std::string slash = n;
            std::replace(slash.begin(), slash.end(), '.', '/');
            if (jarClassNames.count(slash) && slash != cls) hiddenLoads.push_back(cls + " -> " + n);
        }
    if (!hiddenLoads.empty())
        flag(Kind::Suspicious, 5, "Loads its own classes by name at runtime (common in mixin plugins; also used to hide code): " + listSome(hiddenLoads, 2));
    if (!disguisedClass.empty())
        flag(Kind::Suspicious, 35, std::to_string(disguisedClass.size()) + " class file(s) disguised as resources: " + listSome(disguisedClass));
    if (!disguisedZip.empty())
        flag(Kind::Suspicious, 30, std::to_string(disguisedZip.size()) + " zip/jar archive(s) disguised as resources: " + listSome(disguisedZip));

    // Classes that don't match the rest of the jar were usually added to it afterwards.
    if (classMeta.size() >= 8) {
        auto dominant = [&](auto key) {
            std::map<uint64_t, size_t> counts;
            for (const auto& m : classMeta) counts[key(m)]++;
            auto best = std::max_element(counts.begin(), counts.end(), [](auto& x, auto& y) { return x.second < y.second; });
            return std::make_pair(best->first, best->second);
        };
        auto [major, majorN] = dominant([](const ClassMeta& m) { return uint64_t(m.major); });
        if (majorN * 10 >= classMeta.size() * 8) {
            std::set<std::string> pkgs;
            for (const auto& m : classMeta) if (uint64_t(m.major) == major) pkgs.insert(m.pkg);
            std::vector<std::string> odd;
            int oddMajor = 0;
            for (const auto& m : classMeta)
                if (uint64_t(m.major) != major && pkgs.count(m.pkg)) { odd.push_back(m.name); oddMajor = m.major; }
            if (!odd.empty() && odd.size() <= 5)
                flag(Kind::Suspicious, 15, std::to_string(odd.size()) + " class(es) compiled for " + javaVersionName(oddMajor) +
                                           " while the rest of their package targets " + javaVersionName(int(major)) +
                                           " - typical of code added to an existing jar: " + listSome(odd));
        }
        auto [stamp, stampN] = dominant([](const ClassMeta& m) { return uint64_t(m.time); });
        if (stampN * 100 >= classMeta.size() * 85) {
            std::vector<std::string> odd;
            for (const auto& m : classMeta) if (uint64_t(m.time) != stamp) odd.push_back(m.name);
            if (!odd.empty() && odd.size() <= 5)
                flag(Kind::Suspicious, 10, std::to_string(odd.size()) + " class(es) carry a different timestamp than the rest of the jar "
                                           "(added or replaced later): " + listSome(odd));
        }
    }

    for (auto& [name, bytes] : nested) scanJar(bytes, label + "!/" + name, depth + 1, opt, out);
}

// Reads and scans one jar file; the top-level report is reports[0].
static void scanFile(const fs::path& jar, const std::string& label, const Options& opt, std::vector<ModReport>& reports) {
    Bytes data;
    std::error_code ec;
    auto size = fs::file_size(jar, ec);
    if (ec || size > (512ull << 20) || !readFile(jar, data)) {
        ModReport r;
        r.label = label;
        r.error = !ec && size > (512ull << 20) ? "file larger than 512 MB, skipped" : "could not read file";
        reports.push_back(r);
        return;
    }
    scanJar(data, label, 0, opt, reports);
    reports[0].filePath = jar;
}

static std::vector<fs::path> collectJars(const std::vector<fs::path>& roots, std::vector<std::string>* missing = nullptr) {
    std::vector<fs::path> jars;
    for (const auto& in : roots) {
        std::error_code ec;
        if (fs::is_directory(in, ec)) {
            for (auto it = fs::recursive_directory_iterator(in, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) break;
                if (it->is_regular_file(ec) && lowerW(it->path().extension().wstring()) == L".jar") jars.push_back(it->path());
            }
        } else if (fs::is_regular_file(in, ec)) {
            jars.push_back(in);
        } else if (missing) {
            missing->push_back(pathUtf8(in));
        }
    }
    std::sort(jars.begin(), jars.end());
    jars.erase(std::unique(jars.begin(), jars.end()), jars.end());
    return jars;
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

static std::string verdict(const ModReport& r) {
    if (!r.error.empty()) return "ERROR";
    int cheat = r.score(Kind::Cheat), mal = r.score(Kind::Malware), sus = r.score(Kind::Suspicious), obf = r.score(Kind::Obf);
    if (mal >= 50) return "MALWARE INDICATORS";
    if (cheat >= 50) return "LIKELY CHEAT";
    // A byte-for-byte Modrinth file with no cheat *behavior* isn't flagged on name matches alone.
    bool trusted = r.verified && r.behaviorHits.empty() && mal == 0;
    if (!trusted && (cheat >= 20 || mal >= 20 || sus >= 30)) return "SUSPICIOUS";
    if (obf >= 40 && !r.verified) return "OBFUSCATED";
    return "OK";
}

static int rankOf(const std::string& v) {
    static const std::vector<std::string> rank = {"OK", "OBFUSCATED", "ERROR", "SUSPICIOUS", "LIKELY CHEAT", "MALWARE INDICATORS"};
    auto it = std::find(rank.begin(), rank.end(), v);
    return it == rank.end() ? -1 : int(it - rank.begin());
}

// Worst verdict of a jar and everything nested inside it, so a clean wrapper can't hide a payload.
static std::string worstVerdict(const std::vector<ModReport>& reports) {
    std::string worst = "OK";
    for (const auto& r : reports) if (rankOf(verdict(r)) > rankOf(worst)) worst = verdict(r);
    return worst;
}

// ---------------------------------------------------------------------------
// JSON (for API responses)
// ---------------------------------------------------------------------------

struct JVal {
    enum Type { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool b = false;
    double n = 0;
    std::string s;
    std::vector<JVal> arr;
    std::vector<std::pair<std::string, JVal>> obj;

    static const JVal& none() { static const JVal v; return v; }
    const JVal& operator[](const std::string& k) const {
        for (auto& kv : obj) if (kv.first == k) return kv.second;
        return none();
    }
    const JVal& operator[](size_t i) const { return i < arr.size() ? arr[i] : none(); }
    std::string str() const {
        if (type == Str) return s;
        if (type == Num) { char buf[32]; snprintf(buf, sizeof buf, "%.0f", n); return buf; }
        return "";
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::string& s) : s_(s) {}
    JVal parse() { return value(); }

private:
    const std::string& s_;
    size_t p_ = 0;

    [[noreturn]] void fail() { throw std::runtime_error("bad json"); }
    void ws() { while (p_ < s_.size() && std::isspace(uint8_t(s_[p_]))) p_++; }
    bool peek(char c) { return p_ < s_.size() && s_[p_] == c; }
    void expect(char c) { if (!peek(c)) fail(); p_++; }

    JVal value() {
        ws();
        if (p_ >= s_.size()) fail();
        JVal v;
        char c = s_[p_];
        if (c == '{') {
            v.type = JVal::Obj;
            p_++; ws();
            if (peek('}')) { p_++; return v; }
            for (;;) {
                ws();
                std::string k = parseString();
                ws(); expect(':');
                v.obj.emplace_back(std::move(k), value());
                ws();
                if (peek(',')) { p_++; continue; }
                expect('}');
                return v;
            }
        }
        if (c == '[') {
            v.type = JVal::Arr;
            p_++; ws();
            if (peek(']')) { p_++; return v; }
            for (;;) {
                v.arr.push_back(value());
                ws();
                if (peek(',')) { p_++; continue; }
                expect(']');
                return v;
            }
        }
        if (c == '"') { v.type = JVal::Str; v.s = parseString(); return v; }
        if (s_.compare(p_, 4, "true") == 0) { p_ += 4; v.type = JVal::Bool; v.b = true; return v; }
        if (s_.compare(p_, 5, "false") == 0) { p_ += 5; v.type = JVal::Bool; return v; }
        if (s_.compare(p_, 4, "null") == 0) { p_ += 4; return v; }
        size_t start = p_;
        while (p_ < s_.size() && std::strchr("+-0123456789.eE", s_[p_])) p_++;
        if (start == p_) fail();
        v.type = JVal::Num;
        v.n = std::strtod(s_.substr(start, p_ - start).c_str(), nullptr);
        return v;
    }

    unsigned hex4() {
        if (p_ + 4 > s_.size()) fail();
        unsigned v = unsigned(std::strtoul(s_.substr(p_, 4).c_str(), nullptr, 16));
        p_ += 4;
        return v;
    }

    static void appendUtf8(std::string& out, unsigned cp) {
        if (cp < 0x80) out += char(cp);
        else if (cp < 0x800) { out += char(0xC0 | (cp >> 6)); out += char(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { out += char(0xE0 | (cp >> 12)); out += char(0x80 | ((cp >> 6) & 0x3F)); out += char(0x80 | (cp & 0x3F)); }
        else { out += char(0xF0 | (cp >> 18)); out += char(0x80 | ((cp >> 12) & 0x3F)); out += char(0x80 | ((cp >> 6) & 0x3F)); out += char(0x80 | (cp & 0x3F)); }
    }

    std::string parseString() {
        expect('"');
        std::string out;
        while (p_ < s_.size()) {
            char c = s_[p_++];
            if (c == '"') return out;
            if (c != '\\') { out += c; continue; }
            if (p_ >= s_.size()) fail();
            char e = s_[p_++];
            switch (e) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'u': {
                    unsigned cp = hex4();
                    if (cp >= 0xD800 && cp < 0xDC00 && s_.compare(p_, 2, "\\u") == 0) {
                        p_ += 2;
                        unsigned lo = hex4();
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    appendUtf8(out, cp);
                    break;
                }
                default: out += e;
            }
        }
        fail();
    }
};

static JVal parseJson(const std::string& s) {
    try { return JsonParser(s).parse(); } catch (...) { return JVal(); }
}

static std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (uint8_t(c) < 0x20) { char buf[8]; snprintf(buf, sizeof buf, "\\u%04x", c); out += buf; }
        else out += c;
    }
    return out;
}

static std::string jsonStringArray(const std::vector<std::string>& items) {
    std::string out = "[";
    for (size_t i = 0; i < items.size(); i++) out += (i ? ",\"" : "\"") + jsonEscape(items[i]) + "\"";
    return out + "]";
}

static std::string urlEncode(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += char(c);
        else { char buf[4]; snprintf(buf, sizeof buf, "%%%02X", c); out += buf; }
    }
    return out;
}

// ---------------------------------------------------------------------------
// HTTPS (WinHTTP)
// ---------------------------------------------------------------------------

struct HttpResult { int code = 0; std::string body; std::string error; };

static HttpResult httpRequest(const wchar_t* host, const std::string& path, const wchar_t* method,
                              const std::string& body = "", const std::wstring& headers = L"", size_t maxBytes = 16u << 20) {
    HttpResult res;
    HINTERNET session = WinHttpOpen(L"BergssonModScanner/3.0 (Minecraft mod audit tool)", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { res.error = "WinHTTP unavailable"; return res; }
    WinHttpSetTimeouts(session, 10000, 10000, 20000, 30000);
    HINTERNET conn = WinHttpConnect(session, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET req = conn ? WinHttpOpenRequest(conn, method, toWide(path).c_str(), nullptr, WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    bool ok = req && WinHttpSendRequest(req, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(), DWORD(-1L),
                                        body.empty() ? WINHTTP_NO_REQUEST_DATA : LPVOID(body.data()), DWORD(body.size()),
                                        DWORD(body.size()), 0) &&
              WinHttpReceiveResponse(req, nullptr);
    if (ok) {
        DWORD code = 0, len = sizeof code;
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &code, &len, WINHTTP_NO_HEADER_INDEX);
        res.code = int(code);
        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0) break;
            size_t old = res.body.size();
            res.body.resize(old + avail);
            DWORD got = 0;
            if (!WinHttpReadData(req, &res.body[old], avail, &got)) { res.body.resize(old); break; }
            res.body.resize(old + got);
            if (res.body.size() > maxBytes) { res.code = 0; res.error = "response too large"; res.body.clear(); break; }
        }
    } else {
        res.error = "network error " + std::to_string(GetLastError());
    }
    if (req) WinHttpCloseHandle(req);
    if (conn) WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return res;
}

// ---------------------------------------------------------------------------
// Modrinth / CurseForge batch lookups
// ---------------------------------------------------------------------------

static std::string sanitizeId(const std::string& s) {
    std::string out;
    for (char c : s) if (std::isalnum(uint8_t(c)) || c == '-' || c == '_') out += c;
    return out;
}

// Looks up every top-level jar by SHA-1 with POST /v2/version_files, then fetches the matched
// projects - plus the projects named by unmatched jars' mod ids - with GET /v2/projects.
static void modrinthLookup(const std::vector<ModReport*>& tops, std::string& err) {
    std::vector<std::string> hashes;
    for (auto* t : tops) hashes.push_back(t->sha1);
    std::sort(hashes.begin(), hashes.end());
    hashes.erase(std::unique(hashes.begin(), hashes.end()), hashes.end());

    std::map<std::string, std::pair<std::string, std::string>> byHash;  // sha1 -> (project id, version number)
    for (size_t i = 0; i < hashes.size(); i += 200) {
        std::vector<std::string> chunk(hashes.begin() + i, hashes.begin() + std::min(hashes.size(), i + 200));
        std::string body = "{\"hashes\":" + jsonStringArray(chunk) + ",\"algorithm\":\"sha1\"}";
        HttpResult r = httpRequest(L"api.modrinth.com", "/v2/version_files", L"POST", body, L"Content-Type: application/json\r\n");
        if (r.code != 200) { err = "Modrinth lookup failed: " + (r.error.empty() ? "HTTP " + std::to_string(r.code) : r.error); return; }
        JVal j = parseJson(r.body);
        for (auto& [hash, version] : j.obj) byHash[hash] = {version["project_id"].str(), version["version_number"].str()};
    }

    std::set<std::string> ids;
    for (auto& [hash, pv] : byHash) ids.insert(pv.first);
    for (auto* t : tops)
        if (!byHash.count(t->sha1) && !sanitizeId(t->modId).empty()) ids.insert(sanitizeId(t->modId));

    std::map<std::string, JVal> projects;  // keyed by "id:<id>" and "slug:<slug>"
    std::vector<std::string> idList(ids.begin(), ids.end());
    for (size_t i = 0; i < idList.size(); i += 100) {
        std::vector<std::string> chunk(idList.begin() + i, idList.begin() + std::min(idList.size(), i + 100));
        HttpResult r = httpRequest(L"api.modrinth.com", "/v2/projects?ids=" + urlEncode(jsonStringArray(chunk)), L"GET");
        if (r.code != 200) { err = "Modrinth project lookup failed: " + (r.error.empty() ? "HTTP " + std::to_string(r.code) : r.error); break; }
        JVal j = parseJson(r.body);
        for (auto& p : j.arr) {
            projects["id:" + p["id"].str()] = p;
            projects["slug:" + lower(p["slug"].str())] = p;
        }
    }

    for (auto* t : tops) {
        t->mr.checked = true;
        auto h = byHash.find(t->sha1);
        if (h != byHash.end()) {
            t->mr.matched = true;
            t->verified = true;
            t->mr.projectId = h->second.first;
            t->mr.version = h->second.second;
            t->mr.title = t->mr.projectId;
            auto p = projects.find("id:" + t->mr.projectId);
            if (p != projects.end()) {
                t->mr.title = p->second["title"].str();
                t->mr.slug = p->second["slug"].str();
                t->mr.downloads = (long long)p->second["downloads"].n;
                for (auto& c : p->second["categories"].arr) t->mr.categories += (t->mr.categories.empty() ? "" : ", ") + c.str();
            }
            continue;
        }
        std::string id = lower(sanitizeId(t->modId));
        auto p = id.empty() ? projects.end() : projects.find("slug:" + id);
        if (p != projects.end()) {
            t->mr.claimedTitle = p->second["title"].str();
            t->mr.claimedSlug = p->second["slug"].str();
            t->findings.push_back({Kind::Suspicious, 25,
                "Claims mod id '" + t->modId + "' which is the Modrinth project \"" + t->mr.claimedTitle +
                "\", but this exact file is not published there (modified/repackaged, dev build, or from another site)"});
        }
    }
}

static void curseForgeLookup(const std::vector<ModReport*>& tops, const std::string& key, std::string& err) {
    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\nx-api-key: " + toWide(key) + L"\r\n";
    std::string fps;
    for (auto* t : tops) fps += (fps.empty() ? "" : ",") + std::to_string(t->cfFingerprint);
    HttpResult r = httpRequest(L"api.curseforge.com", "/v1/fingerprints/432", L"POST", "{\"fingerprints\":[" + fps + "]}", headers);
    if (r.code != 200) { err += (err.empty() ? "" : "; ") + std::string("CurseForge lookup failed: HTTP ") + std::to_string(r.code); return; }
    JVal j = parseJson(r.body);
    std::map<uint32_t, std::pair<std::string, std::string>> byFp;  // fingerprint -> (mod id, file name)
    std::string modIds;
    for (auto& m : j["data"]["exactMatches"].arr) {
        const JVal& f = m["file"];
        byFp[uint32_t(f["fileFingerprint"].n)] = {f["modId"].str(), f["displayName"].str()};
        modIds += (modIds.empty() ? "" : ",") + f["modId"].str();
    }
    std::map<std::string, std::pair<std::string, std::string>> mods;  // mod id -> (name, url)
    if (!modIds.empty()) {
        HttpResult m = httpRequest(L"api.curseforge.com", "/v1/mods", L"POST", "{\"modIds\":[" + modIds + "]}", headers);
        for (auto& mod : parseJson(m.body)["data"].arr) mods[mod["id"].str()] = {mod["name"].str(), mod["links"]["websiteUrl"].str()};
    }
    for (auto* t : tops) {
        t->cfChecked = true;
        auto it = byFp.find(t->cfFingerprint);
        if (it == byFp.end()) continue;
        t->cfMatched = true;
        t->verified = true;
        auto mod = mods.find(it->second.first);
        t->cfName = mod != mods.end() ? mod->second.first : "mod #" + it->second.first;
        t->cfUrl = mod != mods.end() ? mod->second.second : "";
    }
}

static std::string cfKeyFromEnv() {
    const char* k = std::getenv("CF_API_KEY");
    return k ? k : "";
}

// For a jar that claims to be a Modrinth project but isn't one of its files: download the official file of the
// version it claims (into memory, SHA-1 checked) and compare entry by entry. A cheat injected into a real mod
// shows up as the exact classes that were added or changed.
static void compareWithOriginal(ModReport& t) {
    OriginalDiff& d = t.diff;
    std::string slug = sanitizeId(t.mr.claimedSlug);
    if (t.filePath.empty() || slug.empty()) return;
    if (t.modVersion.empty() || t.modVersion.find("${") != std::string::npos) {
        d.done = true;
        d.note = "the jar doesn't state a usable version, so there is nothing to compare against";
        return;
    }
    HttpResult v = httpRequest(L"api.modrinth.com", "/v2/project/" + slug + "/version/" + urlEncode(t.modVersion), L"GET");
    if (v.code == 404) {
        d.done = true;
        d.note = "Modrinth has no version " + t.modVersion + " of " + t.mr.claimedTitle;
        t.findings.push_back({Kind::Suspicious, 10, "Claims to be " + t.mr.claimedTitle + " " + t.modVersion + ", a version Modrinth doesn't have"});
        return;
    }
    if (v.code != 200) return;
    JVal ver = parseJson(v.body);
    const JVal* file = nullptr;
    for (const auto& f : ver["files"].arr) if (f["primary"].b || !file) file = &f;
    if (!file) return;
    std::string url = (*file)["url"].str(), expect = (*file)["hashes"]["sha1"].str();
    const std::string prefix = "https://cdn.modrinth.com/";
    if (url.rfind(prefix, 0) != 0) return;
    d.versionLabel = t.mr.claimedTitle + " " + ver["version_number"].str();
    d.fileName = (*file)["filename"].str();
    HttpResult dl = httpRequest(L"cdn.modrinth.com", url.substr(prefix.size() - 1), L"GET", "", L"", 256u << 20);
    if (dl.code != 200) { d.done = true; d.note = "couldn't download the official file"; return; }
    Bytes official(dl.body.begin(), dl.body.end()), mine;
    if (sha1Hex(official) != expect) { d.done = true; d.note = "the downloaded official file failed its SHA-1 check"; return; }
    if (!readFile(t.filePath, mine)) return;

    Zip zo, zm;
    if (!zo.open(&official) || !zm.open(&mine)) return;
    std::map<std::string, std::pair<uint32_t, uint32_t>> ref;  // name -> (crc, size)
    for (const auto& e : zo.entries) if (e.name.empty() || e.name.back() != '/') ref[e.name] = {e.crc, e.usize};
    std::set<std::string> seen;
    for (const auto& e : zm.entries) {
        if (e.name.empty() || e.name.back() == '/' || !seen.insert(e.name).second) continue;
        auto it = ref.find(e.name);
        if (it == ref.end()) d.added.push_back(e.name);
        else if (it->second != std::make_pair(e.crc, e.usize)) d.modified.push_back(e.name);
        else d.unchanged++;
    }
    for (const auto& [name, v2] : ref) if (!seen.count(name)) d.removed.push_back(name);
    d.done = true;

    auto classesIn = [](const std::vector<std::string>& v) {
        std::vector<std::string> out;
        for (const auto& n : v) if (endsWith(lower(n), ".class") || endsWith(lower(n), ".jar")) out.push_back(n);
        return out;
    };
    std::vector<std::string> addedCode = classesIn(d.added), changedCode = classesIn(d.modified);
    size_t codeTotal = 0;
    for (const auto& e : zm.entries) if (endsWith(lower(e.name), ".class") || endsWith(lower(e.name), ".jar")) codeTotal++;

    if (d.added.empty() && d.modified.empty() && d.removed.empty()) {
        d.note = "same contents as the official file (only the packaging differs)";
        return;
    }
    if ((addedCode.size() + changedCode.size()) * 2 > std::max<size_t>(codeTotal, 1)) {
        d.note = "most of the code differs - a different build, so changes can't be pinpointed";
        t.findings.push_back({Kind::Suspicious, 10, "Most code differs from the official " + d.versionLabel + " (rebuilt or a different version)"});
        return;
    }
    if (!addedCode.empty())
        t.findings.push_back({Kind::Suspicious, 45, std::to_string(addedCode.size()) + " class(es)/jar(s) added that aren't in the official " +
                                                    d.versionLabel + ": " + listSome(addedCode)});
    if (!changedCode.empty())
        t.findings.push_back({Kind::Suspicious, 35, std::to_string(changedCode.size()) + " class(es)/jar(s) modified compared to the official " +
                                                    d.versionLabel + ": " + listSome(changedCode)});
    size_t otherChanged = d.added.size() + d.modified.size() - addedCode.size() - changedCode.size();
    if (otherChanged)
        t.findings.push_back({Kind::Suspicious, 10, std::to_string(otherChanged) + " resource(s) differ from the official file"});

    // Cheat behavior inside the code that was added or changed is the smoking gun.
    std::set<std::string> touched;
    for (const auto& n : addedCode) touched.insert(n.substr(0, n.size() - 6));
    for (const auto& n : changedCode) touched.insert(n.substr(0, n.size() - 6));
    std::vector<std::string> injected;
    for (const auto& [cls, rule] : t.behaviorHits)
        if (touched.count(cls)) injected.push_back(cls + " (" + rule + ")");
    if (!injected.empty())
        t.findings.push_back({Kind::Cheat, 40, "Code injected into " + d.versionLabel + " has cheat behavior: " + listSome(injected, 2)});
}

static void onlineLookup(const std::vector<ModReport*>& tops, std::string& err) {
    if (tops.empty()) return;
    modrinthLookup(tops, err);
    for (auto* t : tops)
        if (!t->mr.matched && !t->mr.claimedSlug.empty()) compareWithOriginal(*t);
    std::string key = cfKeyFromEnv();
    if (!key.empty()) curseForgeLookup(tops, key, err);
    for (auto* t : tops) t->lookupError = err;
}

static std::string sourceText(const ModReport& r) {
    std::string s;
    if (!r.mr.checked) s = "not checked";
    else if (r.mr.matched)
        s = "Modrinth: exact file match - " + r.mr.title + (r.mr.slug.empty() ? "" : " (modrinth.com/mod/" + r.mr.slug + ")") + " v" + r.mr.version;
    else s = "not found on Modrinth";
    if (r.cfChecked) s += r.cfMatched ? " | CurseForge: exact file match - " + r.cfName : " | not found on CurseForge";
    if (!r.lookupError.empty()) s += " (" + r.lookupError + ")";
    return s;
}

// ---------------------------------------------------------------------------
// Running-game detection: read javaw/java command line + working directory from the PEB
// ---------------------------------------------------------------------------

struct GameInstance {
    DWORD pid = 0;
    std::wstring exeName, exePath, cmdline, cwd;
    fs::path modsDir;
    std::string loader, mcVersion, launcher, note;

    std::string describe() const {
        std::string d = loader.empty() ? "Minecraft" : loader;
        if (!mcVersion.empty()) d = lower(mcVersion).find(lower(d)) != std::string::npos ? mcVersion : d + " " + mcVersion;
        if (!launcher.empty()) d += " - " + launcher;
        return d + " (PID " + std::to_string(pid) + ")";
    }
};

static bool readRemoteWString(HANDLE h, uint64_t addr, size_t bytes, std::wstring& out) {
    if (!addr || bytes == 0 || bytes > 65534) return false;
    out.assign(bytes / 2, L'\0');
    SIZE_T got = 0;
    return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), out.data(), bytes, &got) && got == bytes;
}

static bool readProcessParams(DWORD pid, GameInstance& gi) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        gi.note = GetLastError() == ERROR_ACCESS_DENIED ? "access denied - the game is running elevated; run Bergsson Mod Scanner as administrator"
                                                        : "cannot open process";
        return false;
    }
    wchar_t exe[MAX_PATH * 2];
    DWORD exeLen = DWORD(std::size(exe));
    if (QueryFullProcessImageNameW(h, 0, exe, &exeLen)) gi.exePath.assign(exe, exeLen);

    using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto ntQuery = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    BOOL wow = FALSE;
    IsWow64Process(h, &wow);
    bool ok = false;
    SIZE_T got = 0;
    ULONG len = 0;
    if (ntQuery && !wow) {
        // 64-bit: PEB+0x20 -> RTL_USER_PROCESS_PARAMETERS; CurrentDirectory.DosPath @0x38, CommandLine @0x70
        PROCESS_BASIC_INFORMATION pbi{};
        uint64_t params = 0;
        uint8_t buf[0x80];
        if (ntQuery(h, 0 /*ProcessBasicInformation*/, &pbi, sizeof pbi, &len) >= 0 &&
            ReadProcessMemory(h, reinterpret_cast<const uint8_t*>(pbi.PebBaseAddress) + 0x20, &params, sizeof params, &got) &&
            ReadProcessMemory(h, reinterpret_cast<LPCVOID>(params), buf, sizeof buf, &got)) {
            auto us = [&](size_t off, std::wstring& o) {
                uint16_t n; uint64_t p;
                std::memcpy(&n, buf + off, 2); std::memcpy(&p, buf + off + 8, 8);
                return readRemoteWString(h, p, n, o);
            };
            ok = us(0x70, gi.cmdline);
            us(0x38, gi.cwd);
        }
    } else if (ntQuery) {
        // 32-bit Java under WOW64: PEB32+0x10 -> params32; CurrentDirectory @0x24, CommandLine @0x40
        ULONG_PTR peb32 = 0;
        uint32_t params = 0;
        uint8_t buf[0x48];
        if (ntQuery(h, 26 /*ProcessWow64Information*/, &peb32, sizeof peb32, &len) >= 0 && peb32 &&
            ReadProcessMemory(h, reinterpret_cast<LPCVOID>(peb32 + 0x10), &params, sizeof params, &got) &&
            ReadProcessMemory(h, reinterpret_cast<LPCVOID>(uintptr_t(params)), buf, sizeof buf, &got)) {
            auto us = [&](size_t off, std::wstring& o) {
                uint16_t n; uint32_t p;
                std::memcpy(&n, buf + off, 2); std::memcpy(&p, buf + off + 4, 4);
                return readRemoteWString(h, p, n, o);
            };
            ok = us(0x40, gi.cmdline);
            us(0x24, gi.cwd);
        }
    }
    CloseHandle(h);
    if (!ok) gi.note = "could not read process memory";
    return ok;
}

static void resolveInstance(GameInstance& gi) {
    std::wstring low = lowerW(gi.cmdline + L" " + gi.exePath);
    if (low.find(L"neoforge") != std::wstring::npos) gi.loader = "NeoForge";
    else if (low.find(L"quilt") != std::wstring::npos) gi.loader = "Quilt";
    else if (low.find(L"fabric") != std::wstring::npos) gi.loader = "Fabric";
    else if (low.find(L"forge") != std::wstring::npos || low.find(L"cpw.mods") != std::wstring::npos) gi.loader = "Forge";
    else gi.loader = "Minecraft";

    static const std::pair<const wchar_t*, const char*> launchers[] = {
        {L"prismlauncher", "Prism Launcher"}, {L"multimc", "MultiMC"}, {L"polymc", "PolyMC"},
        {L"atlauncher", "ATLauncher"}, {L"gdlauncher", "GDLauncher"}, {L"curseforge", "CurseForge"},
        {L"modrinthapp", "Modrinth App"}, {L"com.modrinth", "Modrinth App"}, {L"lunarclient", "Lunar Client"},
        {L"feather", "Feather"}, {L"tlauncher", "TLauncher"}, {L"badlion", "Badlion"}, {L"technic", "Technic"},
        {L"sklauncher", "SKLauncher"}, {L".minecraft\\runtime", "Minecraft Launcher"},
        {L"microsoft.4297127d64ec6", "Minecraft Launcher"}};
    for (auto& [needle, name] : launchers)
        if (low.find(needle) != std::wstring::npos) { gi.launcher = name; break; }

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(gi.cmdline.c_str(), &argc);
    fs::path cwd(gi.cwd), gameDir;
    std::vector<fs::path> jarDirs;
    for (int i = 0; argv && i < argc; i++) {
        std::wstring a = argv[i];
        if (lowerW(a) == L"--gamedir" && i + 1 < argc) gameDir = argv[i + 1];
        if (a == L"--version" && i + 1 < argc) gi.mcVersion = toUtf8(argv[i + 1]);
        // Jars passed by path (e.g. -Dfabric.addMods=..., launcher-specific lists) reveal a mods folder too.
        size_t eq = a.find(L'=');
        std::wstring list = eq == std::wstring::npos ? a : a.substr(eq + 1);
        std::wstringstream ss(list);
        std::wstring piece;
        while (std::getline(ss, piece, L';')) {
            std::wstringstream ss2(piece);
            std::wstring part;
            while (std::getline(ss2, part, L',')) {
                fs::path p(part);
                if (lowerW(p.extension().wstring()) == L".jar" && lowerW(p.parent_path().filename().wstring()) == L"mods")
                    jarDirs.push_back(p.parent_path());
            }
        }
    }
    if (argv) LocalFree(argv);
    if (!gameDir.empty() && gameDir.is_relative()) gameDir = cwd / gameDir;

    std::vector<fs::path> candidates;
    if (!gameDir.empty()) candidates.push_back(gameDir / "mods");
    candidates.insert(candidates.end(), jarDirs.begin(), jarDirs.end());
    if (!gi.cwd.empty()) candidates.push_back(cwd / "mods");
    for (auto& c : candidates) {
        std::error_code ec;
        if (fs::is_directory(c, ec)) { gi.modsDir = c.lexically_normal(); return; }
    }
    if (gi.note.empty()) gi.note = "no mods folder found (vanilla or unsupported launcher)";
}

static std::vector<GameInstance> findGameProcesses() {
    std::vector<GameInstance> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return found;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof pe;
    for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe)) {
        std::wstring name = lowerW(pe.szExeFile);
        if (name != L"javaw.exe" && name != L"java.exe") continue;
        GameInstance gi;
        gi.pid = pe.th32ProcessID;
        gi.exeName = pe.szExeFile;
        if (readProcessParams(gi.pid, gi)) {
            std::wstring low = lowerW(gi.cmdline);
            bool isMinecraft = low.find(L"minecraft") != std::wstring::npos || low.find(L"--gamedir") != std::wstring::npos ||
                               low.find(L"net.fabricmc") != std::wstring::npos || low.find(L"cpw.mods") != std::wstring::npos ||
                               low.find(L"prismlauncher") != std::wstring::npos || low.find(L"multimc") != std::wstring::npos;
            if (!isMinecraft) continue;
            resolveInstance(gi);
            // Launcher shims (e.g. Oracle's javapath) leave a second process with the same arguments.
            bool dup = !gi.modsDir.empty() &&
                       std::any_of(found.begin(), found.end(), [&](const GameInstance& o) { return o.modsDir == gi.modsDir; });
            if (dup) continue;
        }
        found.push_back(std::move(gi));
    }
    CloseHandle(snap);
    return found;
}

static fs::path defaultModsDir() {
    if (const char* a = std::getenv("APPDATA")) return fs::path(toWide(a)) / ".minecraft" / "mods";
    return "mods";
}

// ---------------------------------------------------------------------------
// Text reports (CLI output and GUI export)
// ---------------------------------------------------------------------------

struct Colors { const char *red, *yellow, *green, *cyan, *magenta, *dim, *bold, *reset; };
static const Colors kNoColors{"", "", "", "", "", "", "", ""};

static const char* verdictAnsi(const std::string& v, const Colors& c) {
    if (v == "MALWARE INDICATORS" || v == "LIKELY CHEAT") return c.red;
    if (v == "SUSPICIOUS" || v == "OBFUSCATED" || v == "ERROR") return c.yellow;
    return c.green;
}

static void printReport(std::ostream& os, const ModReport& r, bool verbose, const Colors& c) {
    std::string v = verdict(r);
    std::string ind(size_t(r.depth) * 4, ' ');
    os << ind << verdictAnsi(v, c) << c.bold << "[" << v << "]" << c.reset << " " << c.bold << r.label << c.reset << "\n";
    if (!r.error.empty()) { os << ind << "    " << r.error << "\n\n"; return; }
    if (!r.modId.empty() || !r.modName.empty())
        os << ind << "    Mod:     " << r.modName << " (" << r.modId << ") " << r.modVersion << "  [" << r.loader << "]\n";
    os << ind << "    SHA-1:   " << r.sha1 << "   CF fingerprint: " << r.cfFingerprint << "\n";
    if (r.depth == 0) os << ind << "    Source:  " << (r.verified ? c.green : c.dim) << sourceText(r) << c.reset << "\n";
    if (r.diff.done) {
        os << ind << "    Diff:    ";
        if (!r.diff.versionLabel.empty())
            os << "vs official " << r.diff.versionLabel << ": +" << r.diff.added.size() << " added, ~" << r.diff.modified.size()
               << " modified, -" << r.diff.removed.size() << " removed, " << r.diff.unchanged << " identical";
        if (!r.diff.note.empty()) os << (r.diff.versionLabel.empty() ? "" : " - ") << r.diff.note;
        os << "\n";
    }
    os << ind << "    Scores:  cheat " << r.score(Kind::Cheat) << " | malware " << r.score(Kind::Malware)
       << " | suspicious " << r.score(Kind::Suspicious) << " | obfuscation " << r.score(Kind::Obf)
       << "   (" << r.classCount << " classes, " << r.entryCount << " entries)\n";

    std::vector<Finding> fs = r.findings;
    std::stable_sort(fs.begin(), fs.end(), [](const Finding& a, const Finding& b) { return a.weight > b.weight; });
    for (const Finding& f : fs) {
        if (!verbose && f.weight < 10) continue;
        const char* col = f.kind == Kind::Malware ? c.red : f.kind == Kind::Cheat ? c.magenta : f.kind == Kind::Obf ? c.cyan : c.yellow;
        os << ind << "      " << col << "[" << kindName(f.kind) << " +" << f.weight << "]" << c.reset << " " << f.text << "\n";
    }
    os << "\n";
}

// ---------------------------------------------------------------------------
// Command-line mode
// ---------------------------------------------------------------------------

static void usage() {
    std::cout <<
        "Bergsson Mod Scanner - audit Minecraft mod jars for cheats, malware and obfuscation\n\n"
        "usage: bergsson [paths...] [options]      (no arguments opens the GUI)\n"
        "  paths            .jar files or folders (searched recursively). Default: .minecraft/mods\n"
        "  --detect         scan the mods folder of the running Minecraft instance(s)\n"
        "  --offline        skip Modrinth / CurseForge lookups\n"
        "  --sigs FILE      extra signatures: weight|kind|pattern|label  (kind: cheat/malware/suspicious/obf)\n"
        "  --verbose        show low-weight findings, matched context and clean nested jars\n"
        "  --no-color       plain output\n"
        "  Set CF_API_KEY to also check CurseForge.\n";
}

static int cliMain(const std::vector<std::wstring>& args, bool colorAvailable) {
    Options opt = makeOptions();
    bool offline = false, detect = false, color = colorAvailable;
    std::vector<fs::path> inputs;
    for (size_t i = 0; i < args.size(); i++) {
        const std::wstring& a = args[i];
        if (a == L"--offline") offline = true;
        else if (a == L"--detect") detect = true;
        else if (a == L"--verbose" || a == L"-v") opt.verbose = true;
        else if (a == L"--no-color") color = false;
        else if (a == L"--sigs" && i + 1 < args.size()) {
            if (!loadSignatureFile(args[++i], opt.sigs)) { std::cerr << "cannot read signature file " << toUtf8(args[i]) << "\n"; return 2; }
        } else if (a == L"--help" || a == L"-h" || a == L"/?") { usage(); return 0; }
        else if (!a.empty() && a[0] == L'-') { std::cerr << "unknown option " << toUtf8(a) << "\n"; usage(); return 2; }
        else inputs.emplace_back(a);
    }
    Colors c = color ? Colors{"\x1b[31m", "\x1b[33m", "\x1b[32m", "\x1b[36m", "\x1b[35m", "\x1b[2m", "\x1b[1m", "\x1b[0m"} : kNoColors;

    if (detect) {
        auto instances = findGameProcesses();
        for (auto& gi : instances) {
            std::cout << "Detected " << gi.describe() << ": ";
            if (!gi.modsDir.empty()) { std::cout << pathUtf8(gi.modsDir) << "\n"; inputs.push_back(gi.modsDir); }
            else std::cout << gi.note << "\n";
        }
        if (instances.empty()) std::cout << "No running Minecraft (java/javaw) process found.\n";
        std::cout << "\n";
        if (inputs.empty()) return 2;
    }
    if (inputs.empty()) inputs.push_back(defaultModsDir());

    std::vector<std::string> missing;
    std::vector<fs::path> jars = collectJars(inputs, &missing);
    for (auto& m : missing) std::cerr << "not found: " << m << "\n";
    if (jars.empty()) { std::cerr << "no .jar files to scan\n"; return 2; }

    std::vector<std::vector<ModReport>> all(jars.size());
    for (size_t i = 0; i < jars.size(); i++) scanFile(jars[i], pathUtf8(jars[i]), opt, all[i]);

    if (!offline) {
        std::vector<ModReport*> tops;
        for (auto& reps : all) if (reps[0].error.empty()) tops.push_back(&reps[0]);
        std::string err;
        onlineLookup(tops, err);
        if (!err.empty()) std::cerr << err << "\n";
    }

    std::map<std::string, int> tally;
    bool anyFlagged = false;
    for (auto& reps : all) {
        for (const auto& r : reps)
            if (r.depth == 0 || opt.verbose || verdict(r) != "OK") printReport(std::cout, r, opt.verbose, c);
        std::string worst = worstVerdict(reps);
        if (worst != "OK") anyFlagged = true;
        tally[worst]++;
    }
    std::cout << c.bold << "Summary: " << jars.size() << " jar(s) scanned" << c.reset << "\n";
    for (auto& [v, n] : tally) std::cout << "  " << verdictAnsi(v, c) << v << c.reset << ": " << n << "\n";
    std::cout << c.dim << "Heuristic results - review flagged files manually before taking action." << c.reset << "\n";
    return anyFlagged ? 1 : 0;
}

