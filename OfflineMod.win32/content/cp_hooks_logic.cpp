/**
* @file cp_hooks_logic.cpp
* @brief Hook bodies of the content provider (DLL and tests share them).
*
* Every hook first asks whether the provider is active and whether the name
* is one it owns; everything else falls straight through to the game's own
* function, so an unowned name behaves exactly as without the proxy.
*/
#include "cp_hooks_internal.h"
#include "cp_log.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <intrin.h>
#include <psapi.h>

#include <algorithm>
#include <errno.h>
#include <string.h>
#include <vector>

#pragma intrinsic(_ReturnAddress)

extern "C" void* g_cpTrueGetTexture = nullptr;

namespace cp {
namespace hooks {

Env& env()
{
    static Env* e = new Env();   // leaked on purpose: hooks may run during process exit
    return *e;
}

namespace {

bool ProviderActive()
{
    Env& e = env();
    if (!e.provider)
        return false;
    e.provider->EnsureStarted();
    return e.provider->Active();
}

struct DecisionLabel
{
    const char* kind;
    const char* verdict;
    const char* summary;   //!< short form for the totals line
};

const DecisionLabel kDecisionLabels[kDecisionSlots] = {
    { "existsLocalFile", "present (provider)", "existsLocalFile present" },
    { "existsLocalFile", "absent (provider)", "existsLocalFile absent" },
    { "downloaded?", "yes (provider)", "downloaded? yes" },
    { "downloaded?", "no (provider)", "downloaded? no" },
    { "isFileExist", "present (provider)", "isFileExist present" },
    { "isFileExist", "absent (provider)", "isFileExist absent" },
    { "getTexture", "raw provider bytes: FileCrypt force-decode cleared", "getTexture raw" },
    { "addLoadFile", "not queued (provider serves it)", "not queued main" },
    { "addLoadFilePriority", "not queued (provider serves it)", "not queued priority" },
    { "addLoadFile", "QUEUED for the game's downloader (main list)", "QUEUED main" },
    { "addLoadFilePriority", "QUEUED for the game's downloader (priority list)", "QUEUED priority" },
};

//! Names actually passed to the game's downloader are what startup coverage
//! must drive to zero: every one is listed (up to this many per list and
//! process), not only a sample.
const unsigned kQueuedNamesListed = 4000;

bool IsQueuedSlot(DecisionSlot slot)
{
    return slot == kDecisionQueuedMain || slot == kDecisionQueuedPriority;
}

void RememberPath(const std::string& flat, const char* path)
{
    Env& e = env();
    const std::string folded = Fold(flat);
    std::lock_guard<std::mutex> lock(e.seenLock);
    std::pair<std::multimap<std::string, std::string>::iterator, std::multimap<std::string, std::string>::iterator>
        range = e.seenPaths.equal_range(folded);
    for (std::multimap<std::string, std::string>::iterator it = range.first; it != range.second; ++it)
        if (it->second == path)
            return;
    e.seenPaths.insert(std::make_pair(folded, std::string(path)));
}

//! The provider's ownership, except that sound names stay the game's own while
//! their reader (which bypasses getFileData) is not hooked.
Ownership HookClassify(const std::string& flat)
{
    Env& e = env();
    if (!e.audioHooked && IsAudioName(flat))
        return Ownership::NotOwned;
    return e.provider->Classify(flat);
}

//! Owned LocalState path -> flat name + ownership; false for anything the provider does not own.
bool OwnedLocalPath(const char* path, std::string& flat, Ownership& own)
{
    if (!path || !EnsurePrefix())
        return false;
    if (!SplitLocalStatePath(path, env().prefixFolded, flat))
        return false;
    own = HookClassify(flat);
    return own != Ownership::NotOwned;
}

//! Owned flat name (as the game's name strings carry it) -> ownership.
bool OwnedName(const MsvcString* name, std::string& flat, Ownership& own)
{
    if (!name || name->size == 0 || name->size > 255)
        return false;
    const char* s = StrData(name);
    if (!s || !IsSafeFlatName(s, name->size))
        return false;
    flat.assign(s, name->size);
    own = HookClassify(flat);
    return own != Ownership::NotOwned;
}

//! The flat basename a FileLoader queue entry names (callers may prefix a folder, "/unit/img/...").
bool QueuedFlatName(const MsvcString* name, std::string& flat)
{
    if (!name || name->size == 0 || name->size > 1024)
        return false;
    const char* s = StrData(name);
    if (!s)
        return false;
    size_t start = 0;
    for (size_t i = 0; i < name->size; ++i)
        if (s[i] == '/' || s[i] == '\\')
            start = i + 1;
    if (start >= name->size || !IsSafeFlatName(s + start, name->size - start))
        return false;
    flat.assign(s + start, name->size - start);
    return true;
}

//! True when the queue entry must not reach the game's downloader: the provider is
//! active and owns the name with a version present (it serves the bytes itself).
//! Anything else is counted (and listed) as a real download.
bool SuppressQueued(bool priority, const MsvcString* name)
{
    std::string flat;
    const bool named = QueuedFlatName(name, flat);
    if (named && ProviderActive() && HookClassify(flat) == Ownership::Present)
    {
        InterlockedIncrement(&env().suppressedEnqueues);
        RecordDecision(priority ? kDecisionSuppressedPriority : kDecisionSuppressedMain, flat);
        return true;
    }
    if (!named && name && name->size && name->size <= 1024 && StrData(name))
        flat.assign(StrData(name), name->size);   // an unusual path: listed as given
    if (!priority)
    {
        if (IsProtectedStateName(Fold(flat)))
            InterlockedIncrement(&env().mainQueuedState);
        else
            InterlockedIncrement(&env().mainQueuedAssets);
    }
    RecordDecision(priority ? kDecisionQueuedPriority : kDecisionQueuedMain, flat);
    return false;
}

//! The registered RAM file behind a FILE* (nullptr for a real CRT stream).
MemFile* FindMemFile(const FILE* stream, bool take)
{
    Env& e = env();
    std::lock_guard<std::mutex> lock(e.memFilesLock);
    std::set<const void*>::iterator it = e.memFiles.find(stream);
    if (it == e.memFiles.end())
        return nullptr;
    if (take)
        e.memFiles.erase(it);
    return const_cast<MemFile*>(reinterpret_cast<const MemFile*>(stream));
}

//! fopen_s of an owned LocalState name: a RAM file of the provider's bytes, or ENOENT.
int OpenOwned(FILE** stream, const std::string& flat, const char* path, const char* mode, Ownership own,
              uintptr_t returnAddress)
{
    Env& e = env();
    const unsigned rva = static_cast<unsigned>(e.exeBase && returnAddress > e.exeBase ? returnAddress - e.exeBase
                                                                                        : returnAddress);
    *stream = nullptr;
    if (own == Ownership::Absent)
    {
        InterlockedIncrement(&e.audioMissing);
        CP_LOG_WARN("open %s: removed from game_content; not falling back to the client cache [caller +%06X]", path, rva);
        return ENOENT;
    }
    MemFile* m = new MemFile();
    std::string error;
    IndexEntry used;
    bool hit = false;
    LARGE_INTEGER t0, t1, f;
    QueryPerformanceCounter(&t0);
    const ReadStatus st = e.provider->Read(flat, m->bytes, error, &used, &hit);
    QueryPerformanceCounter(&t1);
    QueryPerformanceFrequency(&f);
    if (st != ReadStatus::Ok)
    {
        delete m;
        if (st == ReadStatus::Absent)
            InterlockedIncrement(&e.audioMissing);
        if (st == ReadStatus::Superseded)
            CP_LOG_WARN("open %s: %s; failing it until the next scene change [caller +%06X]", path, error.c_str(), rva);
        else
            CP_LOG_WARN("open %s failed: %s (%s) [caller +%06X]", path, error.c_str(),
                        st == ReadStatus::Absent ? "missing" : "error", rva);
        return st == ReadStatus::Error ? EIO : ENOENT;
    }
    if (!strchr(mode, 'b') && !m->bytes.empty())
        m->bytes.resize(MsvcTextModeTranslate(&m->bytes[0], m->bytes.size(), &m->bytes[0]));
    m->name = flat;
    {
        std::lock_guard<std::mutex> lock(e.memFilesLock);
        e.memFiles.insert(m);
    }
    InterlockedIncrement(&e.audioServed);
    *stream = reinterpret_cast<FILE*>(m);
    const double ms = 1000.0 * static_cast<double>(t1.QuadPart - t0.QuadPart) / static_cast<double>(f.QuadPart ? f.QuadPart : 1);
    CP_LOG_INFO("served %s <- %s gen %llu, %u bytes to the audio reader as a RAM file, %s %.2f ms [caller +%06X]",
                flat.c_str(), used.rel.c_str(), static_cast<unsigned long long>(used.gen),
                static_cast<unsigned>(m->bytes.size()), hit ? "ram" : "fetched", ms, rva);
    return 0;
}

//! Frees a by-value std::string the original would have destroyed (game CRT heap).
void FreeByValue(const MsvcString& s)
{
    if (s.capacity >= 16 && env().msvcrDelete)
        env().msvcrDelete(s.bx.ptr);
}

} // namespace

bool IsAudioName(const std::string& flat)
{
    const std::string f = Fold(flat);
    return f.size() > 4 && (f.compare(f.size() - 4, 4, ".mp3") == 0 || f.compare(f.size() - 4, 4, ".wav") == 0);
}

size_t OpenMemFiles()
{
    Env& e = env();
    std::lock_guard<std::mutex> lock(e.memFilesLock);
    return e.memFiles.size();
}

bool EnsurePrefix()
{
    Env& e = env();
    std::lock_guard<std::mutex> lock(e.prefixLock);
    if (e.prefixKnown)
        return true;
    if (!e.sharedFileUtils || !e.getWritablePath)
        return false;
    if (!e.anyThreadMayResolve && GetCurrentThreadId() != e.renderThreadId)
        return false;
    void* fu = e.sharedFileUtils();
    if (!fu)
        return false;
    MsvcString result;
    memset(&result, 0, sizeof result);
    result.capacity = 15;
    e.getWritablePath(fu, nullptr, &result);
    std::string raw(StrData(&result), result.size);
    // The string was allocated by the game's CRT: free it there, never here.
    if (result.capacity >= 16 && e.msvcrDelete)
        e.msvcrDelete(result.bx.ptr);
    if (raw.empty())
        return false;
    if (raw[raw.size() - 1] != '\\' && raw[raw.size() - 1] != '/')
        raw.push_back('\\');
    e.prefixRaw = raw;
    e.prefixFolded = FoldPath(raw);
    e.prefixKnown = true;
    CP_LOG_INFO("LocalState prefix: %s", raw.c_str());
    return true;
}

unsigned char* ServeOwned(const std::string& flat, const char* path, const char* mode,
                          unsigned long* pSize, uintptr_t returnAddress)
{
    Env& e = env();
    *pSize = 0;
    const uintptr_t rva = e.exeBase && returnAddress > e.exeBase ? returnAddress - e.exeBase : returnAddress;
    std::vector<uint8_t> bytes;
    std::string error;
    IndexEntry used;
    bool hit = false;
    LARGE_INTEGER t0, t1, f;
    QueryPerformanceCounter(&t0);
    const ReadStatus st = e.provider->Read(flat, bytes, error, &used, &hit);
    QueryPerformanceCounter(&t1);
    QueryPerformanceFrequency(&f);
    const double ms = 1000.0 * static_cast<double>(t1.QuadPart - t0.QuadPart) / static_cast<double>(f.QuadPart ? f.QuadPart : 1);
    if (st == ReadStatus::Absent)
    {
        CP_LOG_WARN("read %s: missing (%s); reported to the game as absent [caller +%06X]", path, error.c_str(),
                    static_cast<unsigned>(rva));
        return nullptr;
    }
    if (st == ReadStatus::Superseded)
    {
        // Never another version inside this scene: the game takes its
        // missing-file path now and gets the new version after the next
        // scene change adopts it.
        CP_LOG_WARN("read %s: %s; failing it until the next scene change [caller +%06X]", path, error.c_str(),
                    static_cast<unsigned>(rva));
        return nullptr;
    }
    if (st != ReadStatus::Ok)
    {
        CP_LOG_ERROR("read %s failed: %s [caller +%06X]", path, error.c_str(), static_cast<unsigned>(rva));
        return nullptr;
    }
    RememberPath(flat, path);

    const bool text = !mode || !strchr(mode, 'b');
    const bool encoded = returnAddress && (returnAddress == e.encodedReaderReturn[0] || returnAddress == e.encodedReaderReturn[1]);
    size_t n = bytes.size();
    if (text)
        n = MsvcTextModeTranslate(bytes.empty() ? nullptr : &bytes[0], bytes.size(), bytes.empty() ? nullptr : &bytes[0]);
    if (encoded)
        FileCryptEncode(bytes.empty() ? nullptr : &bytes[0], n);

    // operator new(0) returns a unique pointer, and so does fopen+fread of an
    // empty file in the original: never hand back NULL for a present file.
    unsigned char* out = static_cast<unsigned char*>(e.msvcrNew ? e.msvcrNew(n ? n : 1) : nullptr);
    if (!out)
    {
        CP_LOG_ERROR("read %s: allocation of %u bytes failed", path, static_cast<unsigned>(n));
        return nullptr;
    }
    if (n)
        memcpy(out, &bytes[0], n);
    *pSize = static_cast<unsigned long>(n);
    CP_LOG_INFO("served %s <- %s gen %llu, %u bytes%s%s, %s %.2f ms [caller +%06X]", flat.c_str(), used.rel.c_str(),
                static_cast<unsigned long long>(used.gen), static_cast<unsigned>(n),
                text ? " text-mode" : "", encoded ? " FileCrypt-encoded" : "", hit ? "ram" : "fetched", ms,
                static_cast<unsigned>(rva));
    return out;
}

unsigned char* __fastcall Hook_GetFileData(void* self, void* edx, const char* name, const char* mode, unsigned long* pSize)
{
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    if (name && mode && pSize && ProviderActive())
    {
        std::string flat;
        Ownership own;
        if (OwnedLocalPath(name, flat, own))
        {
            if (own == Ownership::Absent)
            {
                *pSize = 0;
                CP_LOG_WARN("read %s: removed from game_content; not falling back to the client cache", name);
                return nullptr;
            }
            return ServeOwned(flat, name, mode, pSize, ret);
        }
    }
    return env().trueGetFileData(self, edx, name, mode, pSize);
}

bool __fastcall Hook_IsFileExist(void* self, void* edx, const char* path)
{
    if (path && ProviderActive())
    {
        std::string flat;
        Ownership own;
        if (OwnedLocalPath(path, flat, own))
        {
            RecordDecision(own == Ownership::Present ? kDecisionFileExistPresent : kDecisionFileExistAbsent, flat);
            return own == Ownership::Present;
        }
    }
    return env().trueIsFileExist(self, edx, path);
}

bool __fastcall Hook_ExistsLocalFile(const MsvcString* name, void* edx)
{
    if (ProviderActive())
    {
        std::string flat;
        Ownership own;
        if (OwnedName(name, flat, own))
        {
            RecordDecision(own == Ownership::Present ? kDecisionExistsPresent : kDecisionExistsAbsent, flat);
            return own == Ownership::Present;
        }
    }
    return env().trueExistsLocalFile(name, edx);
}

bool __fastcall Hook_IsFileAlreadyDownloaded(const MsvcString* name, void* edx)
{
    if (ProviderActive())
    {
        std::string flat;
        Ownership own;
        if (OwnedName(name, flat, own))
        {
            RecordDecision(own == Ownership::Present ? kDecisionDownloadedYes : kDecisionDownloadedNo, flat);
            return own == Ownership::Present;
        }
    }
    return env().trueIsFileAlreadyDownloaded(name, edx);
}

extern "C" int __stdcall CP_TextureFromProvider(const MsvcString* path)
{
    if (!path || !ProviderActive())
        return 0;
    const char* s = StrData(path);
    if (!s || path->size == 0 || path->size > 2048)
        return 0;
    std::string flat;
    Ownership own;
    std::string copy(s, path->size);
    if (!OwnedLocalPath(copy.c_str(), flat, own) || own != Ownership::Present)
        return 0;
    RecordDecision(kDecisionTextureRaw, flat);
    return 1;
}

/*!
* CommonUtils::getTexture takes the path in ECX, "force FileCrypt decode" in
* DL and one bool on the stack, and the caller pops that bool.  Provider
* bytes are raw, so for an owned path DL is cleared; the original then takes
* its own magic-number branch (PNG 89 50 4E / JPEG FF D8 -> no decode) and
* nothing is decoded twice.  Stack and callee-saved registers are untouched.
*/
extern "C" __declspec(naked) void GetTextureThunk()
{
    __asm {
        push ecx
        push edx
        push ecx
        call CP_TextureFromProvider
        pop edx
        pop ecx
        test eax, eax
        jz passthrough
        xor dl, dl
    passthrough:
        jmp dword ptr [g_cpTrueGetTexture]
    }
}

void SafePoint(const char* why)
{
    Env& e = env();
    if (!e.provider || !e.provider->Active())
        return;
    const std::vector<std::string> changed = e.provider->SafePoint(why);
    if (changed.empty())
        return;
    // Release the game's decoded copies of changed files so the next scene
    // reloads them (through the provider) instead of reusing old textures.
    std::vector<std::string> keys;
    {
        std::lock_guard<std::mutex> lock(e.seenLock);
        for (size_t i = 0; i < changed.size(); ++i)
        {
            std::pair<std::multimap<std::string, std::string>::iterator, std::multimap<std::string, std::string>::iterator>
                range = e.seenPaths.equal_range(changed[i]);
            for (std::multimap<std::string, std::string>::iterator it = range.first; it != range.second; ++it)
                keys.push_back(it->second);
        }
    }
    void* cache = e.sharedTextureCache ? e.sharedTextureCache() : nullptr;
    for (size_t i = 0; i < keys.size(); ++i)
    {
        if (cache && e.removeTextureForKey)
            e.removeTextureForKey(cache, nullptr, keys[i].c_str());
        CP_LOG_INFO("  released decoded copy: %s", keys[i].c_str());
    }
}

namespace {

bool ReadRttiName(const void* object, char* out, size_t cap)
{
    __try
    {
        // x86 MSVC: vtable[-1] -> CompleteObjectLocator; +12 -> TypeDescriptor; +8 -> ".?AVName@ns@@"
        const uintptr_t* vtable = *reinterpret_cast<const uintptr_t* const*>(object);
        const uintptr_t locator = vtable[-1];
        const uintptr_t type = *reinterpret_cast<const uintptr_t*>(locator + 12);
        strncpy_s(out, cap, reinterpret_cast<const char*>(type + 8), _TRUNCATE);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

void SceneChange(const char* kind, const void* scene)
{
    static volatile long s_changes = 0;
    const long n = InterlockedIncrement(&s_changes);
    CP_LOG_INFO("scene change #%ld: %s(%s)", n, kind, scene ? ClassNameOf(scene).c_str() : "-");
    LogPerformanceWindow(kind);
    LogDecisionTotals(kind);
    SafePoint(kind);
}

} // namespace

std::string ClassNameOf(const void* object)
{
    char raw[256] = { 0 };
    if (!object || !ReadRttiName(object, raw, sizeof raw))
        return "?";
    std::string name(raw);
    if (name.compare(0, 4, ".?AV") == 0 || name.compare(0, 4, ".?AU") == 0)
        name = name.substr(4);
    const size_t at = name.find("@@");
    if (at != std::string::npos)
        name = name.substr(0, at);
    return name;
}

void LogPerformanceWindow(const char* why)
{
    Env& e = env();
    const unsigned n = (std::min)(e.frameCount, Env::kFrameSamples);
    std::vector<float> v(e.frameMs, e.frameMs + n);
    std::sort(v.begin(), v.end());
    const float p50 = n ? v[n / 2] : 0.f;
    const float p95 = n ? v[(std::min)(n - 1, static_cast<unsigned>(n * 0.95))] : 0.f;
    const float p99 = n ? v[(std::min)(n - 1, static_cast<unsigned>(n * 0.99))] : 0.f;
    const float mx = n ? v[n - 1] : 0.f;
    PROCESS_MEMORY_COUNTERS_EX mem;
    memset(&mem, 0, sizeof mem);
    mem.cb = sizeof mem;
    GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&mem), sizeof mem);
    char provider[512] = "provider off";   // sprintf_s aborts on overflow: room for every counter at 20 digits
    if (e.provider)
    {
        const ProviderStats st = e.provider->Stats();
        sprintf_s(provider, "provider %s: reads %llu (ram %llu), fetched %llu KB in %llu fetches %.1f ms, failures %llu (superseded %llu), owned lookups %llu, cache %u KB",
                  e.provider->Active() ? "active" : "inactive", st.reads, st.cacheHits, st.bytesFetched / 1024, st.fetches,
                  st.fetchMicros / 1000.0, st.readFailures, st.superseded, st.ownedLookups,
                  static_cast<unsigned>(e.provider->CacheBytes() / 1024));
    }
    CP_LOG_INFO("perf (%s): %u frame(s) ms p50 %.2f p95 %.2f p99 %.2f max %.2f | working set %u MB peak %u MB private %u MB | %s | tripwire writes %ld, refused removes %ld, suppressed downloads %ld",
                why, e.frameCount, p50, p95, p99, mx, static_cast<unsigned>(mem.WorkingSetSize >> 20),
                static_cast<unsigned>(mem.PeakWorkingSetSize >> 20), static_cast<unsigned>(mem.PrivateUsage >> 20), provider,
                e.persistentWrites, e.refusedRemoves, e.suppressedEnqueues);
    e.frameCount = 0;
}

void __fastcall Hook_DrawScene(void* self, void* edx)
{
    Env& e = env();
    if (!e.renderThreadId)
        e.renderThreadId = GetCurrentThreadId();
    if (!e.prefixKnown && e.provider && e.provider->Active())
        EnsurePrefix();
    static LARGE_INTEGER freq = {};
    if (!freq.QuadPart)
        QueryPerformanceFrequency(&freq);
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    if (e.lastFrameQpc)
    {
        e.frameMs[e.frameCount % Env::kFrameSamples] =
            static_cast<float>(1000.0 * static_cast<double>(now.QuadPart - e.lastFrameQpc) / static_cast<double>(freq.QuadPart));
        ++e.frameCount;
        ++e.totalFrames;
    }
    else
        e.windowStartQpc = now.QuadPart;
    e.lastFrameQpc = now.QuadPart;
    if (now.QuadPart - e.windowStartQpc > 30 * freq.QuadPart)
    {
        LogPerformanceWindow("periodic");
        e.windowStartQpc = now.QuadPart;
    }
    e.trueDrawScene(self, edx);
}

void __fastcall Hook_ReplaceScene(void* self, void* edx, void* scene)
{
    SceneChange("replaceScene", scene);
    env().trueReplaceScene(self, edx, scene);
}

void __fastcall Hook_PushScene(void* self, void* edx, void* scene)
{
    SceneChange("pushScene", scene);
    env().truePushScene(self, edx, scene);
}

void __fastcall Hook_RunWithScene(void* self, void* edx, void* scene)
{
    SceneChange("runWithScene", scene);
    env().trueRunWithScene(self, edx, scene);
}

void __fastcall Hook_PopScene(void* self, void* edx)
{
    SceneChange("popScene", nullptr);
    env().truePopScene(self, edx);
}

FILE* __cdecl Hook_Fopen(const char* path, const char* mode)
{
    if (path && mode && (strchr(mode, 'w') || strchr(mode, 'a') || strchr(mode, '+')) && ProviderActive())
    {
        std::string flat;
        Ownership own;
        if (OwnedLocalPath(path, flat, own))
        {
            const long n = InterlockedIncrement(&env().persistentWrites);
            const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
            CP_LOG_WARN("TRIPWIRE persistent write #%ld to an owned asset: %s (mode %s) [caller +%06X]", n, path, mode,
                        static_cast<unsigned>(env().exeBase && ret > env().exeBase ? ret - env().exeBase : ret));
        }
    }
    return env().trueFopen(path, mode);
}

int __cdecl Hook_Remove(const char* path)
{
    if (path && ProviderActive())
    {
        std::string flat;
        Ownership own;
        if (OwnedLocalPath(path, flat, own))
        {
            // The provider owns this name, so a cached copy is never read; the
            // game deleting it (e.g. SuperAnim's "corrupted file" handler) would
            // only churn LocalState.  Refused and logged instead.
            const long n = InterlockedIncrement(&env().refusedRemoves);
            CP_LOG_WARN("refused remove #%ld of an owned asset's cached copy: %s", n, path);
            return -1;
        }
    }
    return env().trueRemove(path);
}

int __cdecl Hook_FopenS(FILE** stream, const char* path, const char* mode)
{
    if (stream && path && mode && ProviderActive())
    {
        std::string flat;
        Ownership own;
        if (OwnedLocalPath(path, flat, own))
        {
            const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
            if (!strchr(mode, 'w') && !strchr(mode, 'a') && !strchr(mode, '+'))
                return OpenOwned(stream, flat, path, mode, own, ret);
            const long n = InterlockedIncrement(&env().persistentWrites);
            CP_LOG_WARN("TRIPWIRE persistent write #%ld to an owned asset: %s (mode %s, fopen_s) [caller +%06X]", n, path,
                        mode, static_cast<unsigned>(env().exeBase && ret > env().exeBase ? ret - env().exeBase : ret));
        }
    }
    return env().trueFopenS(stream, path, mode);
}

size_t __cdecl Hook_Fread(void* buffer, size_t size, size_t count, FILE* stream)
{
    MemFile* m = FindMemFile(stream, false);
    if (!m)
        return env().trueFread(buffer, size, count, stream);
    if (!buffer || size == 0 || count == 0)
        return 0;
    const size_t left = m->bytes.size() - m->pos;
    const size_t want = count > left / size ? left : size * count;
    if (want)
        memcpy(buffer, &m->bytes[m->pos], want);
    m->pos += want;
    // Like the CRT: complete items only; a trailing partial item is consumed.
    return want / size;
}

int __cdecl Hook_Fclose(FILE* stream)
{
    MemFile* m = FindMemFile(stream, true);
    if (!m)
        return env().trueFclose(stream);
    delete m;
    return 0;
}

void __fastcall Hook_AddLoadFile(void* self, void* edx, int encode, MsvcString name)
{
    if (SuppressQueued(false, &name))
    {
        FreeByValue(name);
        return;
    }
    env().trueAddLoadFile(self, edx, encode, name);
}

void __fastcall Hook_AddLoadFilePriority(void* self, void* edx, int encode, int flag, MsvcString name)
{
    if (SuppressQueued(true, &name))
    {
        FreeByValue(name);
        return;
    }
    env().trueAddLoadFilePriority(self, edx, encode, flag, name);
}

void RecordDecision(DecisionSlot slot, const std::string& name)
{
    Env& e = env();
    InterlockedIncrement(&e.decisions[slot]);
    const unsigned limit = IsQueuedSlot(slot) ? kQueuedNamesListed : kDecisionSampleNames;
    if (static_cast<unsigned>(e.decisionsSampled[slot]) >= limit)
        return;
    long listed = 0;
    {
        const std::string key = std::to_string(static_cast<int>(slot)) + "|" + Fold(name);
        std::lock_guard<std::mutex> lock(e.seenLock);
        if (static_cast<unsigned>(e.decisionsSampled[slot]) >= limit || !e.loggedDecisions.insert(key).second)
            return;
        listed = InterlockedIncrement(&e.decisionsSampled[slot]);
    }
    const DecisionLabel& l = kDecisionLabels[slot];
    CP_LOG_INFO("%s %s -> %s", l.kind, name.c_str(), l.verdict);
    if (static_cast<unsigned>(listed) == limit)
        CP_LOG_INFO("%s -> %s: %u names listed; further ones are only counted (decision totals at each scene change)",
                    l.kind, l.verdict, limit);
}

void LogDecisionTotals(const char* why)
{
    Env& e = env();
    std::string line;
    for (int i = 0; i < kDecisionSlots; ++i)
    {
        const long total = e.decisions[i];
        const long window = total - e.decisionsAtSummary[i];
        e.decisionsAtSummary[i] = total;
        if (!total)
            continue;
        char part[160];
        sprintf_s(part, "%s%s %ld (total %ld)", line.empty() ? "" : ", ", kDecisionLabels[i].summary, window, total);
        line += part;
    }
    char tail[160];
    sprintf_s(tail, "; main list assets %ld, client state %ld since start", e.mainQueuedAssets, e.mainQueuedState);
    CP_LOG_INFO("decisions (%s): %s%s", why, line.empty() ? "none" : line.c_str(), tail);
}

} // namespace hooks
} // namespace cp
