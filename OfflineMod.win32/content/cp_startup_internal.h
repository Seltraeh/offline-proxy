/**
* @file cp_startup_internal.h
* @brief Startup decisions taken from the broker's coverage report (Session 16); shared
* by the DLL and the tests.
*
* Two narrow edits of the supported Windows build (x86 RVAs of BraveFrontier.Windows.exe
* fb4f3c25; BF-WorkingDirRust/docs/OFFLINE_STARTUP_TRANSITION_PLAN.md section 8):
*
*   census   0xE415D0 builds the "downloaded-name map" (a CCDictionary of every file in
*            LocalState, global 0x1597E20) for the login check list.  Its three callers --
*            AppDelegate::applicationDidFinishLaunching via 0xE427B0, LoginScene::updateEvent
*            0x8E32DF, MissionStartScene 0xA03CA1 -- each call it only when the global is null,
*            and every reader of the global treats null as "no map": existsLocalFile 0x237EB0
*            then checks the file itself (_stat64i32 + a non-empty fopen), which is what a
*            first launch with an empty LocalState does.  So leaving the map unbuilt changes
*            no answer, only the cost: it is left out only when the provider is ACTIVE on the
*            generation a coverage report proves complete (ParseCoverage: every field agrees),
*            and built (and timed) otherwise -- a provider still starting included.
*   prompt   0x8E51A8 is LoginScene::updateEvent's only read of DLC_WARNING_MENU_FLG
*            (SaveUtils::loadUserDefaults 0x240300: __cdecl, the key std::string by value,
*            the callee destroys it; "" when unset).  The call is redirected here: a stored
*            answer is always the game's; an unset one stays "" (the game asks) unless startup
*            coverage is complete for the generation the provider serves AND nothing but client
*            state was queued for background download -- then the read answers "false", the
*            documented "No" value, for this session only: nothing is stored, so the provider
*            switched off or incomplete brings the question back.
*/
#pragma once

#include "cp_core.h"
#include "cp_hooks_internal.h"
#include "cp_provider.h"

#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace cp {
namespace startup {

//! The census builder (x86 0xE415D0): no arguments, and none of its callers reads a result.
typedef void (__cdecl* Census_t)();
//! SaveUtils::loadUserDefaults (x86 0x240300).
typedef const char* (__cdecl* LoadUserDefaults_t)(hooks::MsvcString key);

//! The value the prompt's read answers when it is left out: what LoginScene::confirmAnswerNo stores.
extern const char kAnswerNo[];
//! The only key the redirected call site reads.
extern const char kPromptKey[];

struct Decision
{
    bool skip = false;
    std::string why;
    CoverageInfo coverage;
};

struct Env
{
    Provider* provider = nullptr;
    std::string build;                  //!< BuildIdentity(kSupportedModules[0])
    uintptr_t exeBase = 0;
    //! The folder holding the client EXE (UTF-8): where the report's "package" inputs are checked.
    //! The "localstate" ones are checked under the game's own writable path (hooks EnsurePrefix).
    std::string packageDir;
    Census_t trueCensus = nullptr;
    LoadUserDefaults_t trueLoadUserDefaults = nullptr;
    void* const* censusMap = nullptr;   //!< the global the census writes (exe + 0x1597E20)

    volatile long censusCalls = 0, censusSkipped = 0, censusBuilt = 0;
    volatile long promptReads = 0, promptLeftOut = 0, promptAsked = 0;

    std::mutex lock;
    bool haveCoverage = false;
    CoverageInfo lastCoverage;          //!< reused only for the generation it names
};

Env& env();

//! Whether this census call may be left out (see the file comment); never fails open.
Decision DecideCensus();
//! Whether an unset prompt answer may read as "No" for this session; never fails open.
Decision DecidePrompt();

void __cdecl Hook_Census();
const char* __cdecl Hook_PromptFlagRead(hooks::MsvcString key);

//! Entries in the downloaded-name map now (0 when there is none or it cannot be read).
long CensusEntries();

//! The startup sites a detour of another component may patch before AttachImage (cp_startup.cpp:
//! the content provider's downloaded-name lookup detour on censusLookup, nothing else).
extern const SharedSite kSharedSites[];
extern const size_t kSharedSiteCount;

//! Startup_Prepare on an image: the EXE identity and every startup site on the untouched bytes,
//! which are kept in @p untouched.
bool PrepareImage(uintptr_t base, std::vector<SiteSnapshot>& untouched, std::string& why);
//! Startup_Attach on a prepared image: every site exactly as kept except the detours kSharedSites
//! expects (VerifySitesSince), then the census detour and the prompt-read redirect, the decisions
//! bound to @p provider last.  False with the reason and nothing changed otherwise.
bool AttachImage(uintptr_t base, Provider* provider, const std::vector<SiteSnapshot>& untouched,
                 const CodeDetour* detours, size_t detourCount, std::string& why);
//! Undoes AttachImage: decisions unbound first, then the redirect and the census detour.
void DetachImage();

} // namespace startup
} // namespace cp
