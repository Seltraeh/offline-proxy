/**
* @file cp_core.cpp
* @brief Pure building blocks of the content provider (see cp_core.h).
*/
#include "cp_core.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <sstream>

namespace cp {

namespace {

bool EndsWith(const std::string& s, const char* suffix)
{
    const size_t n = strlen(suffix);
    return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}

bool StartsWith(const std::string& s, const char* prefix)
{
    const size_t n = strlen(prefix);
    return s.size() >= n && s.compare(0, n, prefix) == 0;
}

char FoldChar(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool ParseU64(const std::string& s, uint64_t& out)
{
    if (s.empty() || s.size() > 20)
        return false;
    uint64_t v = 0;
    for (size_t i = 0; i < s.size(); ++i)
    {
        const char c = s[i];
        if (c < '0' || c > '9')
            return false;
        const uint64_t next = v * 10 + static_cast<uint64_t>(c - '0');
        if (next < v)
            return false;
        v = next;
    }
    out = v;
    return true;
}

std::vector<std::string> SplitTabs(const std::string& line)
{
    std::vector<std::string> parts;
    size_t start = 0;
    for (;;)
    {
        const size_t tab = line.find('\t', start);
        if (tab == std::string::npos)
        {
            parts.push_back(line.substr(start));
            return parts;
        }
        parts.push_back(line.substr(start, tab - start));
        start = tab + 1;
    }
}

std::vector<std::string> SplitLines(const std::string& text)
{
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < text.size())
    {
        size_t nl = text.find('\n', start);
        if (nl == std::string::npos)
            nl = text.size();
        std::string line = text.substr(start, nl - start);
        if (!line.empty() && line[line.size() - 1] == '\r')
            line.erase(line.size() - 1);
        lines.push_back(line);
        start = nl + 1;
    }
    return lines;
}

//! A broker relative path: '/'-separated, no empty / "." / ".." segments, no backslash or control chars.
bool IsSafeRelPath(const std::string& rel)
{
    if (rel.empty() || rel.size() > 1024 || rel[0] == '/')
        return false;
    size_t start = 0;
    for (;;)
    {
        const size_t slash = rel.find('/', start);
        const std::string seg = rel.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (seg.empty() || seg == "." || seg == "..")
            return false;
        for (size_t i = 0; i < seg.size(); ++i)
        {
            const unsigned char c = static_cast<unsigned char>(seg[i]);
            if (c < 0x20 || c == 0x7f || c == '\\' || c == ':')
                return false;
        }
        if (slash == std::string::npos)
            return true;
        start = slash + 1;
    }
}

std::string BaseName(const std::string& rel)
{
    const size_t slash = rel.find_last_of('/');
    return slash == std::string::npos ? rel : rel.substr(slash + 1);
}

int HexValue(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

const char kProtocol[] = "bfcp 2";

} // namespace

std::string Fold(const std::string& s)
{
    std::string out(s);
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = FoldChar(out[i]);
    return out;
}

std::string FoldPath(const std::string& path)
{
    std::string out(path);
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = out[i] == '/' ? '\\' : FoldChar(out[i]);
    return out;
}

bool IsSafeFlatName(const char* s, size_t n)
{
    if (!s || n == 0 || n > 255)
        return false;
    if ((n == 1 && s[0] == '.') || (n == 2 && s[0] == '.' && s[1] == '.'))
        return false;
    for (size_t i = 0; i < n; ++i)
    {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x20 || c == 0x7f || c == '/' || c == '\\' || c == ':' || c == '*' || c == '?'
            || c == '"' || c == '<' || c == '>' || c == '|')
            return false;
    }
    return s[n - 1] != '.' && s[n - 1] != ' ';
}

bool IsProtectedStateName(const std::string& folded)
{
    return folded == "userdefault.xml" || folded == "xmlfileprocessor.xml" || folded == "thumbs.db"
        || StartsWith(folded, ".ds_")
        || EndsWith(folded, ".dat") || EndsWith(folded, ".xml") || EndsWith(folded, ".ini")
        || EndsWith(folded, ".tmp") || EndsWith(folded, ".json") || EndsWith(folded, ".zip");
}

bool SplitLocalStatePath(const char* path, const std::string& prefixFolded, std::string& name)
{
    if (!path || prefixFolded.empty())
        return false;
    size_t i = 0;
    for (; i < prefixFolded.size(); ++i)
    {
        char c = path[i];
        if (c == 0)
            return false;
        c = c == '/' ? '\\' : FoldChar(c);
        if (c != prefixFolded[i])
            return false;
    }
    const char* rest = path + i;
    const size_t n = strlen(rest);
    if (!IsSafeFlatName(rest, n))
        return false;
    name.assign(rest, n);
    return true;
}

size_t MsvcTextModeTranslate(const uint8_t* in, size_t n, uint8_t* out)
{
    size_t o = 0;
    for (size_t i = 0; i < n; ++i)
    {
        const uint8_t c = in[i];
        if (c == 0x1A)
            break;                              // CTRL+Z: end of file in text mode
        if (c == '\r' && i + 1 < n && in[i + 1] == '\n')
            continue;                           // CR LF -> LF (the LF is written next)
        out[o++] = c;
    }
    return o;
}

void FileCryptEncode(uint8_t* data, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        data[i] = static_cast<uint8_t>(data[i] + static_cast<uint8_t>(i * i));
}

void FileCryptDecode(uint8_t* data, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        data[i] = static_cast<uint8_t>(data[i] - static_cast<uint8_t>(i * i));
}

namespace {

BCRYPT_ALG_HANDLE g_sha256 = nullptr;
INIT_ONCE g_sha256Once = INIT_ONCE_STATIC_INIT;

BOOL CALLBACK OpenSha256(PINIT_ONCE, PVOID, PVOID*)
{
    return BCryptOpenAlgorithmProvider(&g_sha256, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0;
}

} // namespace

std::string Sha256Tag(const uint8_t* data, size_t n)
{
    InitOnceExecuteOnce(&g_sha256Once, OpenSha256, nullptr, nullptr);
    BCRYPT_ALG_HANDLE s_alg = g_sha256;
    if (!s_alg)
        return std::string();
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(s_alg, &h, nullptr, 0, nullptr, 0, 0) < 0)
        return std::string();
    UCHAR digest[32];
    bool ok = true;
    size_t off = 0;
    while (ok && off < n)
    {
        const ULONG chunk = static_cast<ULONG>(std::min<size_t>(n - off, 1u << 30));
        ok = BCryptHashData(h, const_cast<PUCHAR>(data + off), chunk, 0) >= 0;
        off += chunk;
    }
    ok = ok && BCryptFinishHash(h, digest, sizeof digest, 0) >= 0;
    BCryptDestroyHash(h);
    if (!ok)
        return std::string();
    static const char* hex = "0123456789abcdef";
    std::string out("sha256:");
    for (size_t i = 0; i < sizeof digest; ++i)
    {
        out.push_back(hex[digest[i] >> 4]);
        out.push_back(hex[digest[i] & 15]);
    }
    return out;
}

bool IsDigestTag(const std::string& s)
{
    if (s.size() != 7 + 64 || s.compare(0, 7, "sha256:") != 0)
        return false;
    for (size_t i = 7; i < s.size(); ++i)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

bool ParseStatus(const std::string& text, StatusInfo& out, std::string& error)
{
    out = StatusInfo();
    const std::vector<std::string> lines = SplitLines(text);
    if (lines.empty() || lines[0] != kProtocol)
    {
        error = std::string("not a ") + kProtocol + " status";
        return false;
    }
    if (lines.back() != "end")
    {
        error = "status truncated";
        return false;
    }
    for (size_t i = 1; i + 1 < lines.size(); ++i)
    {
        const std::string& line = lines[i];
        const size_t sp = line.find(' ');
        const std::string key = line.substr(0, sp);
        const std::string value = sp == std::string::npos ? std::string() : line.substr(sp + 1);
        if (key == "enabled") out.enabled = value == "1";
        else if (key == "ready") out.ready = value == "1";
        else if (key == "epoch") out.epoch = value;
        else if (key == "generation") ParseU64(value, out.generation);
        else if (key == "reason") out.reason = value;
    }
    out.parsed = true;
    return true;
}

bool ParseIndex(const std::string& text, IndexSnapshot& out, std::string& error)
{
    out = IndexSnapshot();
    const std::vector<std::string> lines = SplitLines(text);
    if (lines.empty() || lines[0] != kProtocol)
    {
        error = std::string("not a ") + kProtocol + " index";
        return false;
    }
    if (lines.back() != "end")
    {
        error = "index truncated (no end line)";
        return false;
    }
    bool haveEpoch = false, haveGen = false, haveFull = false;
    for (size_t i = 1; i + 1 < lines.size(); ++i)
    {
        const std::string& line = lines[i];
        if (line.empty())
            continue;
        if (line[0] == 'F' && line.size() > 1 && line[1] == '\t')
        {
            // F <gen> <size> <name> <rel> <digest>
            const std::vector<std::string> p = SplitTabs(line);
            IndexEntry e;
            if (p.size() != 6 || !ParseU64(p[1], e.gen) || !ParseU64(p[2], e.size) || !IsDigestTag(p[5]))
            {
                error = "bad F row: " + line;
                return false;
            }
            e.name = p[3];
            e.rel = p[4];
            e.digest = p[5];
            // The flat name must be exactly the served file's basename: a broker
            // cannot make one cached name read another file's bytes.
            if (!IsSafeFlatName(e.name.c_str(), e.name.size()) || !IsSafeRelPath(e.rel)
                || Fold(BaseName(e.rel)) != Fold(e.name))
            {
                error = "unsafe F row: " + line;
                return false;
            }
            out.files[Fold(e.name)] = e;
        }
        else if (line[0] == 'D' && line.size() > 1 && line[1] == '\t')
        {
            const std::vector<std::string> p = SplitTabs(line);
            uint64_t gen = 0;
            if (p.size() != 3 || !ParseU64(p[1], gen) || !IsSafeFlatName(p[2].c_str(), p[2].size()))
            {
                error = "bad D row: " + line;
                return false;
            }
            out.removed[Fold(p[2])] = gen;
        }
        else if (line[0] == 'X' && line.size() > 1 && line[1] == '\t')
        {
            // X <gen> <name> <reason>: owned but not servable (an incomplete bundle).
            const std::vector<std::string> p = SplitTabs(line);
            uint64_t gen = 0;
            if (p.size() < 3 || !ParseU64(p[1], gen) || !IsSafeFlatName(p[2].c_str(), p[2].size()))
            {
                error = "bad X row: " + line;
                return false;
            }
            out.unavailable[Fold(p[2])] = gen;
        }
        else if (line[0] == 'C' && line.size() > 1 && line[1] == '\t')
        {
            const std::vector<std::string> p = SplitTabs(line);
            if (p.size() < 2 || !IsSafeFlatName(p[1].c_str(), p[1].size()))
            {
                error = "bad C row: " + line;
                return false;
            }
            out.collisions.insert(Fold(p[1]));
        }
        else
        {
            const size_t sp = line.find(' ');
            const std::string key = line.substr(0, sp);
            const std::string value = sp == std::string::npos ? std::string() : line.substr(sp + 1);
            if (key == "epoch") { out.epoch = value; haveEpoch = !value.empty(); }
            else if (key == "generation") haveGen = ParseU64(value, out.generation);
            else if (key == "full") { out.full = value == "1"; haveFull = value == "0" || value == "1"; }
            else
            {
                error = "unknown index row: " + line;
                return false;
            }
        }
    }
    if (!haveEpoch || !haveGen || !haveFull)
    {
        error = "index header incomplete";
        return false;
    }
    return true;
}

namespace {

//! A path an I row may name: a flat LocalState name, or '/'-separated flat names inside the package.
bool SafeInputPath(const std::string& root, const std::string& path)
{
    if (path.empty() || path.size() > 260)
        return false;
    if (root == "localstate")
        return IsSafeFlatName(path.c_str(), path.size());
    size_t start = 0;
    for (;;)
    {
        const size_t slash = path.find('/', start);
        const size_t end = slash == std::string::npos ? path.size() : slash;
        if (!IsSafeFlatName(path.c_str() + start, end - start))
            return false;
        if (slash == std::string::npos)
            return true;
        start = slash + 1;
    }
}

//! Ver<v>_<key>[_<n>].dat, in any case (the file system's lookup ignores it): a master table file the
//! client keeps in LocalState, and its 8-character key, folded.
bool MasterTableKey(const std::string& original, std::string& key)
{
    const std::string name = Fold(original);
    if (name.size() < 3 + 1 + 1 + 8 + 4 || name.compare(0, 3, "ver") != 0 || !EndsWith(name, ".dat"))
        return false;
    size_t i = 3;
    while (i < name.size() && name[i] >= '0' && name[i] <= '9')
        ++i;
    if (i == 3 || i + 1 + 8 + 4 > name.size() || name[i] != '_')
        return false;
    ++i;
    for (size_t k = i; k < i + 8; ++k)
    {
        const char c = name[k];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
            return false;
    }
    const std::string part = name.substr(i + 8, name.size() - 4 - (i + 8));   // "" or "_<n>"
    if (!part.empty())
    {
        if (part.size() < 2 || part[0] != '_')
            return false;
        for (size_t k = 1; k < part.size(); ++k)
            if (part[k] < '0' || part[k] > '9')
                return false;
    }
    key = name.substr(i, 8);
    return true;
}

std::wstring Widen(const std::string& utf8)
{
    if (utf8.empty())
        return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.c_str(), static_cast<int>(utf8.size()),
                                      nullptr, 0);
    if (n <= 0)
        return std::wstring();
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.c_str(), static_cast<int>(utf8.size()), &out[0], n);
    return out;
}

//! dir + '\\' + rel, '/' turned into '\\'.
std::string JoinDir(const std::string& dir, const std::string& rel)
{
    std::string out(dir);
    if (!out.empty() && out[out.size() - 1] != '\\' && out[out.size() - 1] != '/')
        out.push_back('\\');
    for (size_t i = 0; i < rel.size(); ++i)
        out.push_back(rel[i] == '/' ? '\\' : rel[i]);
    return out;
}

bool ReadWholeFile(const std::string& path, std::vector<uint8_t>& out)
{
    const std::wstring wide = Widen(path);
    if (wide.empty())
        return false;
    HANDLE h = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    LARGE_INTEGER size;
    bool ok = GetFileSizeEx(h, &size) != 0 && size.QuadPart >= 0 && size.QuadPart < (1LL << 31);
    if (ok)
    {
        out.resize(static_cast<size_t>(size.QuadPart));
        DWORD got = 0;
        ok = out.empty() || (ReadFile(h, &out[0], static_cast<DWORD>(out.size()), &got, nullptr) != 0
                             && got == out.size());
    }
    CloseHandle(h);
    return ok;
}

std::string Narrow(const wchar_t* wide)
{
    const int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1)
        return std::string();
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &out[0], n, nullptr, nullptr);
    return out;
}

} // namespace

bool VerifyClientInputs(const std::vector<ClientInput>& inputs, const std::string& localStateDir,
                        const std::string& packageDir, std::string& why)
{
    if (inputs.empty())
    {
        why = "the report names no client input to check";
        return false;
    }
    std::map<std::string, std::set<std::string> > tables;   // folded key -> folded names the report names
    for (size_t i = 0; i < inputs.size(); ++i)
    {
        const ClientInput& in = inputs[i];
        const std::string& dir = in.root == "localstate" ? localStateDir : packageDir;
        if (dir.empty())
        {
            why = "the client's " + in.root + " folder is not known yet";
            return false;
        }
        std::vector<uint8_t> bytes;
        if (!ReadWholeFile(JoinDir(dir, in.path), bytes))
        {
            why = "the client's " + in.root + " file " + in.path + " cannot be read";
            return false;
        }
        const std::string digest = Sha256Tag(bytes.empty() ? nullptr : &bytes[0], bytes.size());
        if (digest != in.digest)
        {
            why = "the client's " + in.root + " file " + in.path + " is not the one the manifest was derived from ("
                + digest.substr(0, 7 + 12) + "..., the manifest's " + in.digest.substr(0, 7 + 12) + "...)";
            return false;
        }
        std::string key;
        if (in.root == "localstate" && MasterTableKey(in.path, key))
            tables[Fold(key)].insert(Fold(in.path));
    }
    // LocalState holds one copy of a table the game reads: any other version or part of a named
    // table means the report may describe tables this client does not use.
    for (std::map<std::string, std::set<std::string> >::const_iterator t = tables.begin(); t != tables.end(); ++t)
    {
        WIN32_FIND_DATAW fd;
        const std::wstring pattern = Widen(JoinDir(localStateDir, "Ver*_" + t->first + "*.dat"));
        HANDLE h = pattern.empty() ? INVALID_HANDLE_VALUE : FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE)
        {
            why = "LocalState cannot be listed for the table " + t->first;
            return false;
        }
        bool other = false;
        std::string name;
        do
        {
            std::string key;
            name = Narrow(fd.cFileName);
            other = !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && MasterTableKey(name, key)
                && Fold(key) == t->first && !t->second.count(Fold(name));
        } while (!other && FindNextFileW(h, &fd));
        FindClose(h);
        if (other)
        {
            why = "LocalState also holds " + name + ", another version or part of the table " + t->first
                + " than the manifest names";
            return false;
        }
    }
    return true;
}

bool ParseCoverage(const std::string& text, CoverageInfo& out, std::string& error, const std::string& expectBuild)
{
    out = CoverageInfo();
    const std::vector<std::string> lines = SplitLines(text);
    if (lines.size() < 3 || lines[0] != kProtocol || lines[1] != "coverage 1")
    {
        error = std::string("not a ") + kProtocol + " coverage report";
        return false;
    }
    if (lines.back() != "end")
    {
        error = "coverage report truncated (no end line)";
        return false;
    }
    static const char* const kClasses[] = { "absent", "unowned", "missing", "ambiguous", "unavailable" };
    std::set<std::string> seen;                                   // header fields: each exactly once
    std::map<std::pair<std::string, std::string>, uint64_t> rows; // (set, class) -> P rows
    const auto flag = [](const std::string& v, bool& f) { f = v == "1"; return v == "0" || v == "1"; };
    for (size_t i = 2; i + 1 < lines.size(); ++i)
    {
        const std::string& line = lines[i];
        if (line.compare(0, 2, "P\t") == 0)
        {
            const std::vector<std::string> p = SplitTabs(line);
            bool known = false;
            for (const char* cls : kClasses)
                known = known || (p.size() == 4 && p[2] == cls);
            if (!known || p[1].empty() || p[3].empty())
            {
                error = "malformed coverage problem row: " + line;
                return false;
            }
            ++rows[std::make_pair(p[1], p[2])];
            ++out.problemRows;
            continue;
        }
        if (line.compare(0, 2, "U\t") == 0)
        {
            ++out.unknownRows;
            continue;
        }
        if (line.compare(0, 2, "I\t") == 0)
        {
            // I <root> <path> sha256:<hex>: a client file the manifest was derived from
            const std::vector<std::string> p = SplitTabs(line);
            bool good = p.size() == 4 && (p[1] == "localstate" || p[1] == "package") && SafeInputPath(p[1], p[2])
                && IsDigestTag(p[3]);
            for (size_t k = 0; good && k < out.inputs.size(); ++k)
                good = !(out.inputs[k].root == p[1] && Fold(out.inputs[k].path) == Fold(p[2]));
            if (!good)
            {
                error = "malformed or repeated coverage input row: " + line;
                return false;
            }
            ClientInput input;
            input.root = p[1];
            input.path = p[2];
            input.digest = p[3];
            out.inputs.push_back(input);
            continue;
        }
        if (line.compare(0, 4, "set ") == 0)
        {
            // set <name> required N ok N absent N unowned N missing N ambiguous N unavailable N
            std::vector<std::string> w;
            std::istringstream ss(line);
            for (std::string t; ss >> t;)
                w.push_back(t);
            static const char* const kOrder[] = { "required", "ok", "absent", "unowned", "missing", "ambiguous",
                                                  "unavailable" };
            CoverageSet s;
            uint64_t* const fields[] = { &s.required, &s.ok, &s.absent, &s.unowned, &s.missing, &s.ambiguous,
                                         &s.unavailable };
            bool good = w.size() == 2 + 2 * 7 && !w[1].empty();
            for (size_t k = 0; good && k < 7; ++k)
                good = w[2 + 2 * k] == kOrder[k] && ParseU64(w[3 + 2 * k], *fields[k]);
            if (!good || out.sets.count(w[1]))
            {
                error = "malformed or repeated coverage set line: " + line;
                return false;
            }
            out.sets[w[1]] = s;
            continue;
        }
        const size_t sp = line.find(' ');
        const std::string key = line.substr(0, sp);
        const std::string value = sp == std::string::npos ? std::string() : line.substr(sp + 1);
        if (!seen.insert(key).second)
        {
            error = "repeated coverage field: " + key;
            return false;
        }
        bool good = true;
        if (key == "complete") good = flag(value, out.claimed);
        else if (key == "enabled") good = flag(value, out.enabled);
        else if (key == "ready") good = flag(value, out.ready);
        else if (key == "build_match") good = flag(value, out.buildMatch);
        else if (key == "epoch") { out.epoch = value; good = !value.empty(); }
        else if (key == "generation") good = ParseU64(value, out.generation);
        else if (key == "unknown") good = ParseU64(value, out.unknown);
        else if (key == "excluded") good = ParseU64(value, out.excluded);
        else if (key == "inputs") good = ParseU64(value, out.inputCount);
        else if (key == "policy") out.policy = value;
        else if (key == "manifest") out.manifest = value;
        else if (key == "manifest_build") out.manifestBuild = value;
        else if (key == "client_build") out.clientBuild = value;
        else if (key == "manifest_error") out.manifestError = true;
        else if (key == "reason") out.reason = value;
        else
        {
            error = "unknown coverage field: " + line;   // an A row of the first Session 16 broker lands here
            return false;
        }
        if (!good)
        {
            error = "bad coverage field: " + line;
            return false;
        }
    }
    static const char* const kHeader[] = { "complete", "enabled", "ready", "epoch", "generation", "policy",
                                           "manifest", "manifest_build", "client_build", "build_match", "unknown",
                                           "excluded", "inputs" };
    for (const char* key : kHeader)
    {
        if (!seen.count(key))
        {
            error = std::string("coverage report header incomplete (no ") + key + ")";
            return false;
        }
    }
    out.parsed = true;
    for (std::map<std::string, CoverageSet>::const_iterator it = out.sets.begin(); it != out.sets.end(); ++it)
        out.absent += it->second.absent;

    // Whatever it claims, a report that contradicts itself proves nothing.
    std::string contradiction;
    for (std::map<std::string, CoverageSet>::const_iterator it = out.sets.begin(); it != out.sets.end(); ++it)
    {
        const CoverageSet& s = it->second;
        if (s.ok + s.absent + s.unowned + s.missing + s.ambiguous + s.unavailable != s.required)
            contradiction = "set " + it->first + " counts do not add up to its required names";
    }
    for (std::map<std::pair<std::string, std::string>, uint64_t>::const_iterator it = rows.begin(); it != rows.end(); ++it)
    {
        const std::map<std::string, CoverageSet>::const_iterator s = out.sets.find(it->first.first);
        const std::string& cls = it->first.second;
        const uint64_t count = s == out.sets.end() ? 0
            : cls == "absent" ? s->second.absent : cls == "unowned" ? s->second.unowned
            : cls == "missing" ? s->second.missing : cls == "ambiguous" ? s->second.ambiguous : s->second.unavailable;
        if (it->second > count)
            contradiction = "problem rows for set " + it->first.first + " " + cls + " exceed its count";
    }
    if (out.unknownRows != out.unknown)
        contradiction = "the unknown count and its rows disagree";
    if (out.inputs.size() != out.inputCount)
        contradiction = "the inputs count and its rows disagree";

    // Completeness has to be shown, field by field.
    std::string missing;
    if (!contradiction.empty()) missing = "the report contradicts itself: " + contradiction;
    else if (!out.claimed) missing = out.reason.empty() ? "the report says incomplete" : out.reason;
    else if (!out.enabled || !out.ready) missing = "the report says complete but the broker is not enabled and ready";
    else if (!out.buildMatch) missing = "the report says complete but not for this client build";
    else if (out.manifestError || out.manifest.compare(0, 7, "sha256:") != 0 || out.policy.compare(0, 7, "sha256:") != 0)
        missing = "the report says complete without a loaded manifest and policy";
    else if (out.unknown != 0 || out.unknownRows != 0) missing = "the report says complete with unknown startup lists";
    else if (out.sets.size() != 2 || !out.sets.count("login") || !out.sets.count("background"))
        missing = "the report says complete without exactly the login and background sets";
    else if (out.problemRows != 0) missing = "the report says complete with problem rows";
    else if (out.inputs.empty())
        missing = "the report says complete without naming the client files its manifest was derived from";
    else if (!out.reason.empty()) missing = "the report says complete and gives a reason";
    else if (!expectBuild.empty() && (out.clientBuild != expectBuild || out.manifestBuild != expectBuild))
        missing = "the report says complete for another client build";
    else
    {
        for (std::map<std::string, CoverageSet>::const_iterator it = out.sets.begin(); it != out.sets.end(); ++it)
        {
            const CoverageSet& s = it->second;
            if (s.required == 0 || s.ok != s.required)
                missing = "the report says complete but set " + it->first + " is empty or not fully owned";
        }
    }
    out.complete = missing.empty();
    if (!out.complete)
        out.reason = missing;
    return true;
}

std::string BuildIdentity(const ModuleIdentity& id)
{
    char buf[32];
    sprintf_s(buf, "%08X-%08X-%08X", id.timeDateStamp, id.sizeOfImage, id.entryPoint);
    return buf;
}

Ownership ContentIndex::Lookup(const std::string& folded, IndexEntry* entry) const
{
    std::map<std::string, IndexEntry>::const_iterator it = m_present.find(folded);
    if (it != m_present.end())
    {
        if (entry)
            *entry = it->second;
        return Ownership::Present;
    }
    return m_absent.count(folded) ? Ownership::Absent : Ownership::NotOwned;
}

std::vector<std::string> ContentIndex::Apply(const IndexSnapshot& snap)
{
    std::vector<std::string> changed;
    const bool replace = snap.full || snap.epoch != m_epoch;
    if (replace)
    {
        std::map<std::string, IndexEntry> next;
        for (std::map<std::string, IndexEntry>::const_iterator it = snap.files.begin(); it != snap.files.end(); ++it)
            if (!IsProtectedStateName(it->first) && !snap.collisions.count(it->first))
                next.insert(*it);
        for (std::map<std::string, IndexEntry>::const_iterator it = m_present.begin(); it != m_present.end(); ++it)
        {
            std::map<std::string, IndexEntry>::const_iterator n = next.find(it->first);
            // A new epoch means the broker restarted: generations are not
            // comparable, so everything served before is treated as changed.
            if (n == next.end() || snap.epoch != m_epoch || n->second.rel != it->second.rel
                || n->second.gen != it->second.gen || n->second.size != it->second.size
                || n->second.digest != it->second.digest)
                changed.push_back(it->first);
            if (n == next.end() && !snap.collisions.count(it->first))
                m_absent.insert(it->first);
        }
        for (std::map<std::string, IndexEntry>::const_iterator it = next.begin(); it != next.end(); ++it)
            m_absent.erase(it->first);
        m_present.swap(next);
    }
    else
    {
        for (std::map<std::string, IndexEntry>::const_iterator it = snap.files.begin(); it != snap.files.end(); ++it)
        {
            if (IsProtectedStateName(it->first) || snap.collisions.count(it->first))
                continue;
            std::map<std::string, IndexEntry>::iterator cur = m_present.find(it->first);
            if (cur == m_present.end() || cur->second.rel != it->second.rel || cur->second.gen != it->second.gen
                || cur->second.size != it->second.size || cur->second.digest != it->second.digest)
                changed.push_back(it->first);
            m_present[it->first] = it->second;
            m_absent.erase(it->first);
        }
        for (std::map<std::string, uint64_t>::const_iterator it = snap.removed.begin(); it != snap.removed.end(); ++it)
        {
            if (snap.files.count(it->first))
                continue;
            if (m_present.erase(it->first))
                changed.push_back(it->first);
            if (!snap.collisions.count(it->first))
                m_absent.insert(it->first);
        }
    }
    // Unavailable names (members of an incomplete bundle) are reported missing:
    // the game must take its own missing-asset path rather than read half a
    // bundle from the provider and the rest from a stale cache.
    for (std::map<std::string, uint64_t>::const_iterator it = snap.unavailable.begin(); it != snap.unavailable.end(); ++it)
    {
        if (m_present.erase(it->first))
            changed.push_back(it->first);
        m_absent.insert(it->first);
    }
    // Collisions are always the complete current set: an ambiguous name is
    // neither served nor reported missing -- the provider declines it.
    for (std::set<std::string>::const_iterator it = snap.collisions.begin(); it != snap.collisions.end(); ++it)
    {
        if (m_present.erase(*it))
            changed.push_back(*it);
        m_absent.erase(*it);
    }
    m_collisions = snap.collisions;
    m_epoch = snap.epoch;
    m_generation = snap.generation;
    std::sort(changed.begin(), changed.end());
    changed.erase(std::unique(changed.begin(), changed.end()), changed.end());
    return changed;
}

ByteCache::ByteCache(size_t maxBytes, size_t maxEntryBytes)
    : m_maxBytes(maxBytes), m_maxEntryBytes(maxEntryBytes)
{
}

BlobPtr ByteCache::Get(const std::string& key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::unordered_map<std::string, Slot>::iterator it = m_slots.find(key);
    if (it == m_slots.end())
        return BlobPtr();
    m_lru.splice(m_lru.begin(), m_lru, it->second.pos);
    return it->second.blob;
}

void ByteCache::PutLocked(const std::string& key, BlobPtr blob)
{
    std::unordered_map<std::string, Slot>::iterator it = m_slots.find(key);
    if (it != m_slots.end())
    {
        m_bytes -= it->second.blob->bytes.size();
        m_lru.erase(it->second.pos);
        m_slots.erase(it);
    }
    if (!blob || blob->bytes.size() > m_maxEntryBytes)
        return;
    m_lru.push_front(key);
    Slot slot;
    slot.blob = blob;
    slot.pos = m_lru.begin();
    m_slots[key] = slot;
    m_bytes += blob->bytes.size();
    while (m_bytes > m_maxBytes && !m_lru.empty())
    {
        const std::string victim = m_lru.back();
        std::unordered_map<std::string, Slot>::iterator v = m_slots.find(victim);
        m_bytes -= v->second.blob->bytes.size();
        m_slots.erase(v);
        m_lru.pop_back();
        ++m_evictions;
    }
}

void ByteCache::Put(const std::string& key, BlobPtr blob)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    PutLocked(key, blob);
}

void ByteCache::Evict(const std::string& key)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::unordered_map<std::string, Slot>::iterator it = m_slots.find(key);
    if (it == m_slots.end())
        return;
    m_bytes -= it->second.blob->bytes.size();
    m_lru.erase(it->second.pos);
    m_slots.erase(it);
    ++m_evictions;
}

void ByteCache::Clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_evictions += m_slots.size();
    m_slots.clear();
    m_lru.clear();
    m_bytes = 0;
}

void ByteCache::SetToken(uint64_t token)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (token > m_token)
        m_token = token;
}

BlobPtr ByteCache::GetOrFetch(const std::string& key, const std::function<BlobPtr(std::string&)>& fetch,
                              std::string& error, bool* hit, uint64_t token)
{
    std::shared_ptr<Flight> flight;
    bool leader = false;
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        std::unordered_map<std::string, Slot>::iterator it = m_slots.find(key);
        if (it != m_slots.end())
        {
            m_lru.splice(m_lru.begin(), m_lru, it->second.pos);
            ++m_hits;
            if (hit)
                *hit = true;
            return it->second.blob;
        }
        std::unordered_map<std::string, std::shared_ptr<Flight> >::iterator f = m_flights.find(key);
        if (f != m_flights.end())
        {
            // Same key = same content identity: sharing the bytes is safe
            // whichever scene the leader started in.
            flight = f->second;
            ++m_coalesced;
        }
        else
        {
            flight = std::make_shared<Flight>();
            flight->token = token;
            m_flights[key] = flight;
            leader = true;
            ++m_misses;
        }
        if (!leader)
        {
            m_cv.wait(lock, [&] { return flight->done; });
            error = flight->error;
            if (hit)
                *hit = false;
            return flight->result;
        }
    }
    std::string fetchError;
    BlobPtr result = fetch(fetchError);
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (result)
        {
            // A scene change while this fetch was outstanding: deliver, don't cache.
            if (flight->token == kAnyToken || flight->token == m_token)
                PutLocked(key, result);
            else
                ++m_dropped;
        }
        flight->done = true;
        flight->result = result;
        flight->error = fetchError;
        m_flights.erase(key);
    }
    m_cv.notify_all();
    error = fetchError;
    if (hit)
        *hit = false;
    return result;
}

size_t ByteCache::Bytes() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_bytes;
}

size_t ByteCache::Entries() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_slots.size();
}

bool MatchSignature(const SiteSignature& sig, const uint8_t* image, size_t available, std::string& why)
{
    const size_t n = strlen(sig.mask);
    if (strlen(sig.bytes) != n * 2)
    {
        why = std::string(sig.name) + ": malformed signature";
        return false;
    }
    if (!image || available < n)
    {
        why = std::string(sig.name) + ": site not readable";
        return false;
    }
    for (size_t i = 0; i < n; ++i)
    {
        if (sig.mask[i] != 'x')
            continue;
        const int hi = HexValue(sig.bytes[i * 2]), lo = HexValue(sig.bytes[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            why = std::string(sig.name) + ": malformed signature";
            return false;
        }
        if (image[i] != static_cast<uint8_t>(hi * 16 + lo))
        {
            char buf[160];
            sprintf_s(buf, "%s: byte +%u is %02X, expected %02X", sig.name, static_cast<unsigned>(i),
                      image[i], hi * 16 + lo);
            why = buf;
            return false;
        }
    }
    return true;
}

bool MatchIdentity(const ModuleIdentity& id, const uint8_t* headers, size_t available, std::string& why)
{
    if (!headers || available < sizeof(IMAGE_DOS_HEADER))
    {
        why = std::string(id.file) + ": no image";
        return false;
    }
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0
        || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > available)
    {
        why = std::string(id.file) + ": not a PE image";
        return false;
    }
    const IMAGE_NT_HEADERS32* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(headers + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        why = std::string(id.file) + ": not an x86 PE image";
        return false;
    }
    if (nt->FileHeader.TimeDateStamp != id.timeDateStamp || nt->OptionalHeader.SizeOfImage != id.sizeOfImage
        || nt->OptionalHeader.AddressOfEntryPoint != id.entryPoint)
    {
        char buf[256];
        sprintf_s(buf, "%s: build mismatch (TimeDateStamp %08X SizeOfImage %08X entry %08X; supported %08X %08X %08X)",
                  id.file, nt->FileHeader.TimeDateStamp, nt->OptionalHeader.SizeOfImage,
                  nt->OptionalHeader.AddressOfEntryPoint, id.timeDateStamp, id.sizeOfImage, id.entryPoint);
        why = buf;
        return false;
    }
    return true;
}

// ------------------------------------------- sites another component patches ----

namespace {

//! Committed executable memory at @p p (the protections the hooks' own checks accept).
bool ExecutableAt(const void* p)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    return VirtualQuery(p, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT
        && (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool ExecutableRange(const void* p, size_t n)
{
    return n && ExecutableAt(p) && ExecutableAt(static_cast<const uint8_t*>(p) + n - 1);
}

//! Where the `E9 rel32` at @p jmp leads (wrapping like the CPU).
uintptr_t JumpTarget(const uint8_t* jmp)
{
    int32_t rel = 0;
    memcpy(&rel, jmp + 1, sizeof rel);
    return reinterpret_cast<uintptr_t>(jmp) + 5u + static_cast<uintptr_t>(static_cast<intptr_t>(rel));
}

} // namespace

bool SnapshotSites(uintptr_t base, const SiteSignature* sigs, size_t count, std::vector<SiteSnapshot>& out,
                   std::string& why)
{
    out.clear();
    for (size_t i = 0; i < count; ++i)
    {
        const SiteSignature& sig = sigs[i];
        const size_t n = strlen(sig.mask);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(base + sig.rva);
        if (sig.module != 0)
        {
            why = std::string(sig.name) + ": not a game-EXE site";
            return false;
        }
        if (!ExecutableRange(p, n))
        {
            why = std::string(sig.name) + ": site is not in executable memory";
            return false;
        }
        if (!MatchSignature(sig, p, n, why))
            return false;
        SiteSnapshot s;
        s.sig = &sig;
        s.address = base + sig.rva;
        s.bytes.assign(p, p + n);
        out.push_back(std::move(s));
    }
    return true;
}

bool VerifySitesSince(const std::vector<SiteSnapshot>& snapshots, const CodeDetour* detours, size_t detourCount,
                      const SharedSite* shared, size_t sharedCount, std::string& why)
{
    char buf[320];
    for (const SiteSnapshot& s : snapshots)
    {
        const std::string name = s.sig ? s.sig->name : "?";
        const size_t n = s.bytes.size();
        const uint8_t* live = reinterpret_cast<const uint8_t*>(s.address);
        if (!ExecutableRange(live, n))
        {
            why = name + ": site is not in executable memory";
            return false;
        }
        const char* expected = nullptr;
        for (size_t i = 0; i < sharedCount; ++i)
            if (strcmp(shared[i].site, name.c_str()) == 0)
                expected = shared[i].detourSite;
        // The bytes the expected detour may have changed: none unless one is expected here.
        size_t patchFrom = n, patchTo = n;
        if (expected)
        {
            const CodeDetour* d = nullptr;
            for (size_t i = 0; i < detourCount; ++i)
                if (detours[i].site && strcmp(detours[i].site, expected) == 0)
                    d = &detours[i];
            if (!d)
            {
                why = name + ": the " + expected + " detour expected on it is not recorded";
                return false;
            }
            const std::string owner = d->owner ? d->owner : "another component";
            if (d->target < s.address || d->target - s.address + 5u > n)
            {
                sprintf_s(buf, "%s: the %s's %s detour at %08X is not inside the verified bytes", name.c_str(),
                          owner.c_str(), expected, static_cast<unsigned>(d->target));
                why = buf;
                return false;
            }
            const size_t off = d->target - s.address;
            // How many bytes the jump displaced: the trampoline holds exactly those original bytes,
            // then E9 back to the first instruction left in place (Detours x86).
            size_t k = 0;
            if (d->trampoline && ExecutableAt(d->trampoline))
            {
                for (size_t c = 5; c <= 25 && off + c <= n && !k; ++c)
                {
                    const uint8_t* back = d->trampoline + c;
                    if (ExecutableRange(d->trampoline, c + 5) && back[0] == 0xE9 && JumpTarget(back) == d->target + c
                        && memcmp(d->trampoline, &s.bytes[off], c) == 0)
                        k = c;
                }
            }
            if (!k)
            {
                why = name + ": the " + owner + "'s " + expected
                    + " trampoline does not hold the displaced original instructions and a jump back to the rest";
                return false;
            }
            if (live[off] != 0xE9 || JumpTarget(live + off) != d->detour)
            {
                if (live[off] == 0xE9)
                    sprintf_s(buf, "%s: byte +%u is a jump to %08X, not the %s's %s detour (%08X)", name.c_str(),
                              static_cast<unsigned>(off), static_cast<unsigned>(JumpTarget(live + off)), owner.c_str(),
                              expected, static_cast<unsigned>(d->detour));
                else
                    sprintf_s(buf, "%s: byte +%u is %02X, not the %s's %s detour (E9 to %08X)", name.c_str(),
                              static_cast<unsigned>(off), live[off], owner.c_str(), expected,
                              static_cast<unsigned>(d->detour));
                why = buf;
                return false;
            }
            for (size_t i = off + 5; i < off + k; ++i)
            {
                if (live[i] != 0xCC)
                {
                    sprintf_s(buf, "%s: byte +%u is %02X, not the CC the %s detour leaves after its jump", name.c_str(),
                              static_cast<unsigned>(i), live[i], expected);
                    why = buf;
                    return false;
                }
            }
            patchFrom = off;
            patchTo = off + k;
        }
        for (size_t i = 0; i < n; ++i)
        {
            if (i >= patchFrom && i < patchTo)
                continue;
            if (live[i] != s.bytes[i])
            {
                sprintf_s(buf, "%s: byte +%u is %02X, was %02X on the untouched image%s", name.c_str(),
                          static_cast<unsigned>(i), live[i], s.bytes[i],
                          expected ? "" : " (no detour of another component is expected on this site)");
                why = buf;
                return false;
            }
        }
    }
    return true;
}

} // namespace cp
