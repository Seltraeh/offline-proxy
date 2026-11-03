/**
* @file cp_gate_flash.cpp
* @brief Installs the summon gate flash fix (#24) after verifying the client build.
*
* One patch, in SummonsAnimeScene2::updateEvent (gumi.BraveFrontier 2.19.6.0
* x86): the 5-byte `call SuperAnimList::shared` at RVA 0x8760EF that opens the
* stock white-screen decision becomes `jmp GateFlashThunk`.  The thunk decides
* (cp_gate_flash_logic.cpp) and continues at one of the two places the stock
* decision itself ends at: 0x8761C3 (create the overlay) or 0x876238 (the fade
* step).  tests/fixtures/check_gate_flash_site.py proves from the binary that
* nothing after the skipped block depends on it (stack, exception state,
* registers, locals).
*
* Not a Detours hook: the target is a branch in the middle of a function, and
* nothing of the replaced block is ever executed, so no trampoline is needed.
* The DLL is attached before the game runs any code, and the stock bytes are
* kept and written back on detach or on a fault.
*/
#include "../pch.h"
#include "cp_gate_flash.h"

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER

#include <string>

#include "cp_gate_flash_internal.h"
#include "cp_log.h"
#include "cp_signatures.h"

namespace {

using namespace cp;
using namespace cp::gateflash;

const char* const kExeName = "BraveFrontier.Windows.exe";
const uint32_t kSiteRva = 0x8760EF;            // call SuperAnimList::shared
const uint32_t kYesRva = 0x8761C3;             // create the white overlay
const uint32_t kNoRva = 0x876238;              // the overlay fade step
const uint32_t kSharedRva = 0x631390;          // SuperAnimList::shared
const uint8_t kStockSite[5] = { 0xE8, 0x9C, 0xB2, 0xDB, 0xFF };

bool EndsWithI(const char* s, const char* suffix)
{
    const size_t a = strlen(s), b = strlen(suffix);
    return a >= b && _stricmp(s + a - b, suffix) == 0;
}

//! Verifies the game EXE and the three gate flash sites; false (with a reason) declines.
bool VerifyGateSites(uintptr_t& base, std::string& why)
{
    char exePath[MAX_PATH] = { 0 };
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    if (!EndsWithI(exePath, kExeName))
    {
        why = std::string("host process is not ") + kExeName + " (" + exePath + ")";
        return false;
    }
    base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    if (!MatchIdentity(kSupportedModules[0], reinterpret_cast<const uint8_t*>(base), 4096, why))
        return false;
    for (size_t i = 0; i < sizeof kGateFlashSignatures / sizeof kGateFlashSignatures[0]; ++i)
    {
        const SiteSignature& s = kGateFlashSignatures[i];
        const uint8_t* p = reinterpret_cast<const uint8_t*>(base + s.rva);
        MEMORY_BASIC_INFORMATION mbi;
        if (s.module != 0 || !VirtualQuery(p, &mbi, sizeof mbi)
            || !(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            why = std::string(s.name) + ": site is not in the game's executable memory";
            return false;
        }
        if (!MatchSignature(s, p, strlen(s.mask), why))
            return false;
    }
    if (memcmp(reinterpret_cast<const void*>(base + kSiteRva), kStockSite, sizeof kStockSite) != 0)
    {
        why = "the trigger's call SuperAnimList::shared is not where the signature put it";
        return false;
    }
    return true;
}

} // namespace

void GateFlash_Attach(void)
{
    uintptr_t base = 0;
    std::string why;
    if (!VerifyGateSites(base, why))
    {
        CP_LOG_WARN("gate flash fix DECLINED: %s. Summons keep the stock white-screen trigger. Supported: "
                    "gumi.BraveFrontier 2.19.6.0 x86 (tests/fixtures/make_signatures.py, check_gate_flash_site.py).",
                    why.c_str());
        return;
    }
    GateEnv& g = genv();
    g.sharedList = reinterpret_cast<SharedList_t>(base + kSharedRva);
    g_cpGateFlashYes = base + kYesRva;
    g_cpGateFlashNo = base + kNoRva;
    g.site = reinterpret_cast<uint8_t*>(base + kSiteRva);
    memcpy(g.original, g.site, sizeof g.original);
    g.protection = ProtectionOf(g.site);

    uint8_t jmp[5] = { 0xE9, 0, 0, 0, 0 };
    const int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&GateFlashThunk)
                                             - reinterpret_cast<uintptr_t>(g.site + sizeof jmp));
    memcpy(jmp + 1, &rel, sizeof rel);
    const WriteResult w = g.write(g.site, jmp, sizeof jmp, g.protection);
    g.patched = w.copied;                  // the jump is in place once copied, whatever failed after it
    if (!w.Complete())
    {
        if (!w.copied)
        {
            CP_LOG_WARN("gate flash fix DECLINED: could not write the patch (%s failed, error %lu); the stock trigger "
                        "is unchanged", FailedStep(w), w.error);
            return;
        }
        // The jump was copied but the page protection or the cache flush failed: put the stock call back.
        const WriteResult back = RestoreSite(g);
        if (back.copied)
            CP_LOG_WARN("gate flash fix NOT installed: %s failed after the jump was written (error %lu); the stock "
                        "trigger is back%s", FailedStep(w), w.error,
                        back.Complete() ? "" : " (its own protection/flush step failed too)");
        else
            CP_LOG_ERROR("gate flash fix PARTIAL: %s failed after the jump was written (error %lu) and the stock "
                         "bytes could not be written back (error %lu); the fix stays in place and runs, detach "
                         "retries the stock bytes", FailedStep(w), w.error, back.error);
        return;
    }
    CP_LOG_INFO("gate flash fix installed at exe %08X + %06X: the summon's white screen now follows the final "
                "gate's opening (GachaGateOpen*, frame %d) instead of the count of animations on screen",
                static_cast<unsigned>(base), static_cast<unsigned>(kSiteRva), kFlashFrame);
}

void GateFlash_Detach(void)
{
    GateEnv& g = genv();
    if (!g.patched)
        return;
    const WriteResult w = RestoreSite(g);
    if (!w.Complete())
        CP_LOG_ERROR("gate flash: the stock trigger %s at detach (%s failed, error %lu)",
                     w.copied ? "is back but not cleanly" : "could not be written back", FailedStep(w), w.error);
}

#endif // CONTENT_PROVIDER
