/**
* @file cp_startup_logic.cpp
* @brief Startup decisions from the broker's coverage report (see cp_startup_internal.h).
*
* Every path that cannot prove coverage -- no provider, a provider not (or no longer) ACTIVE
* (starting, failed to start, dormant, switched off), an older broker without the report, an
* unreadable, incomplete or self-contradicting report, a report for another build or for another
* generation than the one the provider has adopted, anything queued for background download --
* leaves the game's own behaviour: the census is built, the prompt is asked.
*/
#include "cp_startup_internal.h"
#include "cp_log.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)

namespace cp {
namespace startup {

const char kAnswerNo[] = "false";
const char kPromptKey[] = "DLC_WARNING_MENU_FLG";

Env& env()
{
    static Env* e = new Env();   // leaked on purpose, like the hooks' environment
    return *e;
}

namespace {

std::string Describe(const CoverageInfo& c)
{
    const std::map<std::string, CoverageSet>::const_iterator login = c.sets.find("login");
    const std::map<std::string, CoverageSet>::const_iterator background = c.sets.find("background");
    char buf[240];
    sprintf_s(buf, "epoch %s generation %llu, login %llu and background %llu name(s) owned, %llu client input file(s) "
              "matched", c.epoch.c_str(), static_cast<unsigned long long>(c.generation),
              static_cast<unsigned long long>(login == c.sets.end() ? 0 : login->second.ok),
              static_cast<unsigned long long>(background == c.sets.end() ? 0 : background->second.ok),
              static_cast<unsigned long long>(c.inputs.size()));
    return buf;
}

//! The provider's index and the report describe the same generation of the same broker.
bool SameGeneration(const Provider& p, const CoverageInfo& c, std::string& why)
{
    if (p.HasPending())
    {
        why = "the broker has published a newer generation the provider has not adopted yet";
        return false;
    }
    if (c.epoch != p.Epoch() || c.generation != p.PinnedGeneration())
    {
        char buf[200];
        sprintf_s(buf, "the report describes epoch %s generation %llu, the provider serves epoch %s generation %llu",
                  c.epoch.c_str(), static_cast<unsigned long long>(c.generation), p.Epoch().c_str(),
                  static_cast<unsigned long long>(p.PinnedGeneration()));
        why = buf;
        return false;
    }
    return true;
}

//! The report's manifest was derived from this client's own files: its master tables in LocalState
//! (the game's writable path) and its package files (Session 18, VerifyClientInputs).
bool ClientHoldsInputs(const CoverageInfo& c, std::string& why)
{
    std::string localState;
    if (hooks::EnsurePrefix())
    {
        hooks::Env& h = hooks::env();
        std::lock_guard<std::mutex> lock(h.prefixLock);
        localState = h.prefixRaw;
    }
    std::string mismatch;
    if (VerifyClientInputs(c.inputs, localState, env().packageDir, mismatch))
        return true;
    why = "the report's manifest was not derived from this client's own files: " + mismatch;
    return false;
}

bool FreshCoverage(CoverageInfo& out, std::string& why)
{
    Env& e = env();
    if (!e.provider->FetchCoverage(e.build, out, why))
        return false;
    std::lock_guard<std::mutex> lock(e.lock);
    e.lastCoverage = out;
    e.haveCoverage = true;
    return true;
}

unsigned CallerRva(uintptr_t ret)
{
    const uintptr_t base = env().exeBase;
    return static_cast<unsigned>(base && ret > base ? ret - base : ret);
}

} // namespace

Decision DecideCensus()
{
    Decision d;
    Env& e = env();
    if (!e.provider)
    {
        d.why = "no content provider (the client build was declined)";
        return d;
    }
    e.provider->EnsureStarted();
    const ProviderState state = e.provider->State();
    if (state == ProviderState::Dormant)
    {
        d.why = "the provider is dormant (broker switched off)";
        return d;
    }
    // Stock until the provider is ACTIVE: a complete report is the broker's claim about its own
    // generation, not proof that this process adopted it (QC 2026-10-20).  A provider still
    // starting, or one whose start failed, keeps the game's census.
    if (state != ProviderState::Active)
    {
        d.why = "the provider has not adopted an index yet (starting, or its start failed)";
        return d;
    }
    // A report already fetched for the generation the provider serves is reused (a mission
    // start asks again); anything else is fetched now.
    bool cached = false;
    {
        std::lock_guard<std::mutex> lock(e.lock);
        std::string ignored;
        if (e.haveCoverage && SameGeneration(*e.provider, e.lastCoverage, ignored))
        {
            d.coverage = e.lastCoverage;
            cached = true;
        }
    }
    std::string why;
    if (!cached && !FreshCoverage(d.coverage, why))
    {
        d.why = why;
        return d;
    }
    if (!d.coverage.complete)
    {
        d.why = "startup coverage incomplete: " + (d.coverage.reason.empty() ? std::string("(no reason)") : d.coverage.reason);
        return d;
    }
    // Checked after the fetch: the provider may have adopted another generation, or gone
    // dormant, while the report was on its way.
    if (!e.provider->Active())
    {
        d.why = "the provider stopped being active while the report was fetched";
        return d;
    }
    if (!SameGeneration(*e.provider, d.coverage, why))
    {
        d.why = why;
        return d;
    }
    if (!ClientHoldsInputs(d.coverage, why))
    {
        d.why = why;
        return d;
    }
    d.skip = true;
    d.why = "startup coverage complete (" + Describe(d.coverage) + ")";
    return d;
}

Decision DecidePrompt()
{
    Decision d;
    Env& e = env();
    if (!e.provider || !e.provider->Active())
    {
        d.why = "the content provider is not active";
        return d;
    }
    std::string why;
    if (!FreshCoverage(d.coverage, why))
    {
        d.why = why;
        return d;
    }
    if (!d.coverage.complete)
    {
        d.why = "startup coverage incomplete: " + d.coverage.reason;
        return d;
    }
    if (!e.provider->Active())
    {
        d.why = "the provider stopped being active while the report was fetched";
        return d;
    }
    if (!SameGeneration(*e.provider, d.coverage, why))
    {
        d.why = why;
        return d;
    }
    if (!ClientHoldsInputs(d.coverage, why))
    {
        d.why = why;
        return d;
    }
    const long assets = hooks::env().mainQueuedAssets;
    if (assets > 0)
    {
        d.why = std::to_string(assets) + " asset name(s) were queued for background download (listed as "
            "\"QUEUED for the game's downloader (main list)\"): the question stays the player's";
        return d;
    }
    d.skip = true;
    d.why = "startup coverage complete (" + Describe(d.coverage) + ") and no asset queued for background download ("
        + std::to_string(hooks::env().mainQueuedState) + " client-state name(s) queued, e.g. text dictionaries)";
    return d;
}

long CensusEntries()
{
    Env& e = env();
    if (!e.censusMap)
        return 0;
    __try
    {
        const uint8_t* map = static_cast<const uint8_t*>(*e.censusMap);
        // CCDictionary-like object: element count at +0x18 (0xE427EF: cmp [eax+18h], 0).
        return map ? *reinterpret_cast<const long*>(map + 0x18) : 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return -1;
    }
}

void __cdecl Hook_Census()
{
    Env& e = env();
    const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
    const long n = InterlockedIncrement(&e.censusCalls);
    const Decision d = DecideCensus();
    if (d.skip)
    {
        InterlockedIncrement(&e.censusSkipped);
        CP_LOG_INFO("LocalState census #%ld LEFT OUT [caller +%06X]: %s; existsLocalFile checks files the provider "
                    "does not own itself", n, CallerRva(ret), d.why.c_str());
        return;
    }
    LARGE_INTEGER t0, t1, f;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    e.trueCensus();
    QueryPerformanceCounter(&t1);
    InterlockedIncrement(&e.censusBuilt);
    CP_LOG_INFO("LocalState census #%ld built [caller +%06X]: %ld name(s) in %.1f ms (%s)", n, CallerRva(ret),
                CensusEntries(), 1000.0 * static_cast<double>(t1.QuadPart - t0.QuadPart) / static_cast<double>(f.QuadPart),
                d.why.c_str());
}

const char* __cdecl Hook_PromptFlagRead(hooks::MsvcString key)
{
    Env& e = env();
    // The key is the callee's: read it before the original destroys its copy.
    const std::string name(hooks::StrData(&key), key.size <= 64 ? key.size : 0);
    const char* value = e.trueLoadUserDefaults(key);
    InterlockedIncrement(&e.promptReads);
    if (name != kPromptKey)
        return value;
    if (value && *value)
    {
        CP_LOG_INFO("background-download prompt: the player's stored answer \"%s\" stands", value);
        return value;
    }
    const Decision d = DecidePrompt();
    if (!d.skip)
    {
        InterlockedIncrement(&e.promptAsked);
        CP_LOG_INFO("background-download prompt left to the player: %s", d.why.c_str());
        return value;
    }
    InterlockedIncrement(&e.promptLeftOut);
    CP_LOG_INFO("background-download prompt LEFT OUT: %s; read as \"%s\" (No) for this session, nothing stored",
                d.why.c_str(), kAnswerNo);
    return kAnswerNo;
}

} // namespace startup
} // namespace cp
