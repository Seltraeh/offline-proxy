/**
* @file cp_startup.cpp
* @brief Installs the startup edits (cp_startup_internal.h) after the content provider.
*
* census  Detours on the census builder 0xE415D0 (its own transaction).
* prompt  The rel32 of LoginScene::updateEvent's `call SaveUtils::loadUserDefaults` at
*         0x8E51A8 is pointed at Hook_PromptFlagRead (same __cdecl ABI, the key string by
*         value); the original target is kept and written back on detach.  No other caller
*         of loadUserDefaults is affected.
*
* Two steps, because the content provider detours one of the sites the edits rely on (the
* downloaded-name lookup 0xE417E0) and the edits need the provider:
*   Startup_Prepare  before ContentProvider_Attach: the EXE identity and every kStartupSignatures
*                    site on the untouched image, their bytes kept;
*   Startup_Attach   after it: every site again, exactly as kept except the provider's own
*                    recorded lookup detour (kSharedSites, cp_core.h VerifySitesSince), then both
*                    edits.
* tests/fixtures/make_signatures.py STARTUP_SITES; tests/fixtures/check_startup_sites.py proves on
* the binary what the edits rely on, check_attach_overlap.py which sites the DLL's own patches
* reach before each check.  Otherwise one DECLINED line and the game keeps both.
*/
#include "../pch.h"
#include "cp_startup.h"

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER

#include <detours/detours.h>
#include <wchar.h>

#include "cp_hooks_internal.h"
#include "cp_log.h"
#include "cp_signatures.h"
#include "cp_startup_internal.h"

namespace {

using namespace cp;

const uint32_t kCensusRva = 0xE415D0;
const uint32_t kCensusMapRva = 0x1597E20;      // the downloaded-name map global (VA 0x1997E20)
const uint32_t kPromptCallRva = 0x8E51A8;      // E8 rel32 -> SaveUtils::loadUserDefaults
const uint32_t kLoadUserDefaultsRva = 0x240300;

void* g_fCensus = nullptr;
bool g_censusHooked = false;
uint8_t* g_promptCall = nullptr;
int32_t g_promptRel = 0;

// Startup_Prepare's result: the startup sites as the untouched image held them.
std::vector<SiteSnapshot> g_untouched;
bool g_prepared = false;
std::string g_prepareWhy = "the startup sites were not checked before the content provider attached";

bool WriteRel32(uint8_t* call, int32_t rel)
{
    DWORD old = 0;
    if (!VirtualProtect(call + 1, 4, PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(call + 1, &rel, 4);
    FlushInstructionCache(GetCurrentProcess(), call, 5);
    DWORD unused = 0;
    if (!VirtualProtect(call + 1, 4, old, &unused))
        CP_LOG_WARN("startup coverage path: protection restore failed (%lu)", GetLastError());
    return true;
}

void Declined(const std::string& why)
{
    CP_LOG_WARN("startup coverage path DECLINED: %s. The LocalState census and the background-download prompt stay "
                "the game's own.", why.c_str());
}

} // namespace

namespace cp {
namespace startup {

// The one startup site another component of this DLL patches before Startup_Attach: the content
// provider detours the downloaded-name lookup.  Hook_IsFileAlreadyDownloaded answers an owned name
// itself and hands every other name to the original through its trampoline, so the lookup's
// null-map path -- what a left-out census relies on -- still decides those names.
// tests/fixtures/check_attach_overlap.py proves it is the only overlap.
const SharedSite kSharedSites[] = { { "censusLookup", "isFileAlreadyDownloaded" } };
const size_t kSharedSiteCount = sizeof kSharedSites / sizeof kSharedSites[0];

bool PrepareImage(uintptr_t base, std::vector<SiteSnapshot>& untouched, std::string& why)
{
    untouched.clear();
    if (!MatchIdentity(kSupportedModules[0], reinterpret_cast<const uint8_t*>(base), 4096, why))
        return false;
    return SnapshotSites(base, kStartupSignatures, sizeof kStartupSignatures / sizeof kStartupSignatures[0],
                         untouched, why);
}

bool AttachImage(uintptr_t base, Provider* provider, const std::vector<SiteSnapshot>& untouched,
                 const CodeDetour* detours, size_t detourCount, std::string& why)
{
    Env& e = env();
    if (e.provider || g_censusHooked)
    {
        why = "the startup edits are already installed";
        return false;
    }
    if (!provider)
    {
        why = "the content provider is not installed";
        return false;
    }
    if (untouched.size() != sizeof kStartupSignatures / sizeof kStartupSignatures[0])
    {
        why = "the startup sites were not checked on the untouched image";
        return false;
    }
    if (!VerifySitesSince(untouched, detours, detourCount, kSharedSites, kSharedSiteCount, why))
        return false;
    uint8_t* call = reinterpret_cast<uint8_t*>(base + kPromptCallRva);
    int32_t rel = 0;
    memcpy(&rel, call + 1, 4);
    if (call[0] != 0xE8 || reinterpret_cast<uintptr_t>(call + 5 + rel) != base + kLoadUserDefaultsRva)
    {
        why = "the prompt's flag read is not a call to SaveUtils::loadUserDefaults";
        return false;
    }

    e.exeBase = base;
    e.build = BuildIdentity(kSupportedModules[0]);
    e.censusMap = reinterpret_cast<void* const*>(base + kCensusMapRva);
    e.trueLoadUserDefaults = reinterpret_cast<LoadUserDefaults_t>(base + kLoadUserDefaultsRva);

    g_fCensus = reinterpret_cast<void*>(base + kCensusRva);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&g_fCensus, reinterpret_cast<PVOID>(Hook_Census));
    const LONG err = DetourTransactionCommit();
    if (err != NO_ERROR)
    {
        g_fCensus = nullptr;
        why = "Detours could not hook the census (error " + std::to_string(err) + ")";
        return false;
    }
    e.trueCensus = reinterpret_cast<Census_t>(g_fCensus);
    g_censusHooked = true;

    const int32_t redirected = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&Hook_PromptFlagRead)
                                                    - reinterpret_cast<uintptr_t>(call + 5));
    if (!WriteRel32(call, redirected))
    {
        DetachImage();
        why = "the prompt's flag read could not be redirected";
        return false;
    }
    g_promptCall = call;
    g_promptRel = rel;
    e.provider = provider;    // last: decisions are taken only with both edits in place
    return true;
}

void DetachImage()
{
    Env& e = env();
    e.provider = nullptr;
    if (g_promptCall)
    {
        WriteRel32(g_promptCall, g_promptRel);
        g_promptCall = nullptr;
    }
    if (g_censusHooked)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&g_fCensus, reinterpret_cast<PVOID>(Hook_Census));
        DetourTransactionCommit();
        g_censusHooked = false;
        g_fCensus = nullptr;
    }
}

} // namespace startup
} // namespace cp

void Startup_Prepare()
{
    g_prepared = startup::PrepareImage(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)), g_untouched,
                                       g_prepareWhy);
}

void Startup_Attach()
{
    if (startup::env().provider)
        return;
    if (!g_prepared)
    {
        Declined(g_prepareWhy);
        return;
    }
    const hooks::Env& provider = hooks::env();
    std::string why;
    // Where the report's package inputs are checked (VerifyClientInputs); set before the decisions
    // are bound.  Unknown, every check fails and the game keeps its census and prompt.
    wchar_t exePath[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (length > 0 && length < MAX_PATH)
    {
        wchar_t* slash = wcsrchr(exePath, L'\\');
        if (slash)
            *slash = L'\0';
        char utf8[MAX_PATH * 3] = {};
        if (WideCharToMultiByte(CP_UTF8, 0, exePath, -1, utf8, sizeof utf8, nullptr, nullptr) > 0)
            startup::env().packageDir = utf8;
    }
    if (!startup::AttachImage(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)), provider.provider, g_untouched,
                              provider.detours, provider.detourCount, why))
    {
        Declined(why);
        return;
    }
    CP_LOG_INFO("startup coverage path installed for build %s: the LocalState census (0xE415D0) is left out per call "
                "only while the broker reports startup coverage complete for the generation the provider serves; "
                "the background-download prompt's flag read (0x8E51A8) answers \"No\" for the session only when "
                "covered and nothing is queued for background download.  Its %u sites matched the untouched image "
                "before the content provider attached and again after it, the downloaded-name lookup (0xE417E0) "
                "carrying exactly the provider's own detour", startup::env().build.c_str(),
                static_cast<unsigned>(g_untouched.size()));
}

void Startup_Detach()
{
    startup::DetachImage();
}

#endif // CONTENT_PROVIDER
