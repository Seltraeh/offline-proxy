/**
* @file cp_name_fit.cpp
* @brief Installs the unit-info title name fit (#22-2) after verifying the client build.
*
* One patch, in UnitDetailUserUnitScene's header build (gumi.BraveFrontier 2.19.6.0 x86): the
* 5-byte `call 0x387100` at RVA 0xCA71A5 that creates the unit-name label becomes `call
* NameFitThunk`.  The call's arguments, as the site builds them (proved by
* tests/fixtures/check_name_fit_site.py):
*
*     ecx, edx            two ints (0x3A, 7)            xmm1..xmm3  three floats (xmm3 = the width)
*     [esp+4]  float      [esp+8]  colour (3 bytes)     [esp+0Ch] int (0Ch)
*     [esp+10h] std::string by value (18h bytes; the callee owns and frees it)
*     caller-cleaned: the site's `add esp, 24h` follows the call
*
* 0x387100 forwards them unchanged through 0x3871E0, 0x3872C0 and 0x3873B0 to 0x3874A0, each layer
* appending one default before the string: 1, 1 (wrap, read at [ebp+18h]), 1, 0 (shrink, read at
* [ebp+20h]).  0x3874A0 calls the shrink-to-fit 0x2370B0 only when wrap is 0 and shrink is not.
* NameFitThunk calls 0x3874A0 directly with the same arguments and 1, 0, 1, 1: no wrap, shrink to
* xmm3.  The string's 18h bytes are MOVED into the new argument slot (0x3874A0 frees it, as 0x387100
* would have), the registers ecx, edx and xmm1..xmm3 are passed through untouched, and the thunk
* cleans its own 34h bytes, so the site sees exactly what 0x387100 returns: the label in eax.
*/
#include "../pch.h"
#include "cp_name_fit.h"

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER

#include <string>

#include "cp_gate_flash_internal.h"     // cp::gateflash::WriteCode (protect, write, flush)
#include "cp_name_fit_internal.h"      // per-site install/restore with rollback
#include "cp_log.h"
#include "cp_signatures.h"

extern "C" uintptr_t g_cpNameFitFull = 0;   // absolute address of the label helper's full overload

// The skill popup's description width (Evan, round 5).  The unit-info touch popup (0xCB6750) creates its BB, SBB
// and UBB descriptions with the label helper at x 26 and wrap width 274.0 (`movss xmm3, [0x16E56B0]` at
// 0xCB988D / 0xCB9920 / 0xCB9981).  Drawn, a wrapped line runs past the frame's right border ("...raises normal
// hi", run b1_bursts); the frame rows sit at x 24, width 272.  The three loads are pointed at this narrower width
// so the right margin matches the left; 274.0 itself is shared with other code and stays untouched.
static const float kPopupDescWidth = 258.0f;

extern "C" __declspec(naked) void NameFitThunk()
{
    __asm {
        sub     esp, 18h                    ; slot for the moved std::string
        mov     eax, [esp + 28h]            ; caller's string at entry+10h = esp+28h now
        mov     [esp], eax
        mov     eax, [esp + 2Ch]
        mov     [esp + 4], eax
        mov     eax, [esp + 30h]
        mov     [esp + 8], eax
        mov     eax, [esp + 34h]
        mov     [esp + 0Ch], eax
        mov     eax, [esp + 38h]
        mov     [esp + 10h], eax
        mov     eax, [esp + 3Ch]
        mov     [esp + 14h], eax
        push    1                           ; [ebp+20h] shrink to fit: on
        push    1                           ; [ebp+1Ch] as 0x3872C0 passes it
        push    0                           ; [ebp+18h] wrap: off
        push    1                           ; [ebp+14h] as 0x387100 passes it
        push    dword ptr [esp + 34h]       ; [ebp+10h] the site's int (entry+0Ch)
        push    dword ptr [esp + 34h]       ; [ebp+0Ch] colour (entry+8)
        push    dword ptr [esp + 34h]       ; [ebp+8]   float (entry+4)
        call    dword ptr [g_cpNameFitFull]
        add     esp, 34h                    ; 7 dwords + the 18h-byte string
        ret                                 ; the site cleans its own 24h bytes
    }
}


// Skill popup vertical fit (round 7, Evan: "Fix vertical too"; failure policy round 8).  The three description
// labels (BB/SBB/UBB, 0xCB98C7 / 0xCB993E / 0xCB99B7) keep their call to the label helper 0x387100, but through
// PopupDescThunk: it parks its return address, calls 0x387100 with the untouched registers and stack arguments (the
// caller cleans them: `add esp, 24h` follows each site), then lets CP_FitPopupDesc scale the returned label so its
// lines fit the frame (3 lines; label+168h is the line count 0x38C3B0 builds), and returns the label in eax.
// The popup is built on the UI thread only, so one parked return address is enough.
//
// The label is gumi's text block (vtable 0x18E8CE0, a CCNode).  Its lines are separate CCLabelTTF nodes, children
// of the layer, not of the label, kept in the list at +100h (outline copies included); the label places them
// itself in its setPosition(x, y) override 0x38CDC0 (vtable +48h; x, y kept at +0F4h/+0F8h): every line's centre
// is scaled about the block's centre by the label's scale, and align 4 (these labels) keeps the left edge.  A
// plain setScale on the label moves nothing (run v3: each line shrank in place).  So the fit does what the client
// does, in three steps:
//   1. wrap again, wider: +114h (the wrap width) = width / sqrt(3 / lines), then the label's own setString
//      0x38C3B0(force 1, a copy of its text at +14Ch made by the client's string assign 0xDE250; the callee
//      frees it, as every caller's copy).  It removes and releases the old lines and lays the text out again.
//   2. scale: setScale on the label and the same scale on every line (as 0x38C3B0 / 0x38C9B0 do), then the
//      label's setPosition, so the block fits both the frame's width and its 3 lines.
//   3. keep the first line where the client put it: the top of the first line node (position, anchor, height,
//      scale) is measured before and after, the y slope by a second layout, and y moved by the difference.
// The fit, its checks, its restore and its session policy are in cp_name_fit_logic.cpp (FitPopupDesc), where the
// tests run them against fake labels.

namespace {

using namespace cp;

const char* const kExeName = "BraveFrontier.Windows.exe";
const uint32_t kSiteRva = 0xCA71A5;            // call 0x387100 (the unit-name label)
const uint32_t kFullRva = 0x3874A0;            // the label helper's full overload
const uint8_t kStockSite[5] = { 0xE8, 0x56, 0xFF, 0x6D, 0xFF };
const uint32_t kPopupWidthRvas[3] = { 0xCB988D, 0xCB9920, 0xCB9981 };   // movss xmm3, [abs32]
const uint32_t kStockWidthRva = 0x12E56B0;                                 // the 274.0 they load today
const uint32_t kPopupDescCallRvas[3] = { 0xCB98C7, 0xCB993E, 0xCB99B7 };   // call 0x387100
const uint32_t kLabelHelperRva = 0x387100;
const uint32_t kLabelSetTextRva = 0x38C3B0;                                // the label's setString(force, text)
const uint32_t kStringAssignRva = 0xDE250;                                 // std::string::assign(src, pos, count)

// Two independent patches, each a set of PatchSites installed and restored with rollback
// (cp_name_fit_logic.cpp): the name label's call, and the popup's three width operands.
struct NameFitEnv {
    cp::namefit::PatchSite name[1];
    cp::namefit::PatchSite width[3];
    cp::namefit::PatchSite desc[3];       // the three description calls (vertical fit)
};

NameFitEnv& env()
{
    static NameFitEnv e;
    return e;
}

bool EndsWithI(const char* s, const char* suffix)
{
    const size_t a = strlen(s), b = strlen(suffix);
    return a >= b && _stricmp(s + a - b, suffix) == 0;
}

//! Verifies the game EXE and the three sites; false (with a reason) declines.
bool VerifyNameFitSites(uintptr_t& base, std::string& why)
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
    for (size_t i = 0; i < sizeof kNameFitSignatures / sizeof kNameFitSignatures[0]; ++i)
    {
        const SiteSignature& s = kNameFitSignatures[i];
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
        why = "the name label's call 0x387100 is not where the signature put it";
        return false;
    }
    return true;
}

//! Logs one patch set's install result as it is: installed, not installed (every write undone), or partial.
//! @p what names the patch, @p effect says what the stock behaviour is when it is not installed.
bool LogInstall(const char* what, const char* effect, cp::namefit::InstallResult res, const cp::namefit::PatchSite* s,
                size_t n, const cp::namefit::WriteResult& failure)
{
    using namespace cp::namefit;
    switch (res)
    {
    case InstallResult::Installed:
        return true;
    case InstallResult::RolledBack:
        CP_LOG_WARN("%s NOT installed: %s failed (error %lu)%s and every write was undone; %s", what,
                    cp::gateflash::FailedStep(failure), failure.error,
                    failure.copied ? " after the bytes were written" : "", effect);
        break;
    case InstallResult::RollbackFailed:
        CP_LOG_ERROR("%s PARTIAL: %s failed (error %lu) and undoing it did not complete: %u site(s) still patched, "
                     "%u with the page protection or cache step failed; detach retries them", what,
                     cp::gateflash::FailedStep(failure), failure.error, static_cast<unsigned>(InstalledCount(s, n)),
                     static_cast<unsigned>(IncompleteCount(s, n)));
        break;
    }
    return false;
}

//! Logs one patch set's restore when it did not complete.
void LogRestore(const char* what, bool ok, const cp::namefit::PatchSite* s, size_t n,
                const cp::namefit::WriteResult& failure)
{
    using namespace cp::namefit;
    if (!ok)
        CP_LOG_ERROR("%s: restore did not complete (%s failed, error %lu): %u site(s) still patched, %u with the page "
                     "protection or cache step failed", what, cp::gateflash::FailedStep(failure), failure.error,
                     static_cast<unsigned>(InstalledCount(s, n)), static_cast<unsigned>(IncompleteCount(s, n)));
}

//! The vertical fit's session policy after a fault or a failed restore (cp_name_fit_logic.cpp): the three
//! description calls go back to stock.  Runs from the thunk, after the site's call, on the UI thread.
void DisablePopupFit()
{
    using namespace cp::namefit;
    NameFitEnv& e = env();
    WriteResult failure;
    const bool ok = RestoreSites(e.desc, 3, &cp::gateflash::WriteCode, &failure);
    if (ok)
        CP_LOG_WARN("skill popup vertical fit: the three description calls are stock again; later popups keep the "
                    "client's own layout");
    else
        LogRestore("skill popup vertical fit (disable)", ok, e.desc, 3, failure);
}

} // namespace

void NameFit_Attach(void)
{
    uintptr_t base = 0;
    std::string why;
    if (!VerifyNameFitSites(base, why))
    {
        CP_LOG_WARN("unit name fit DECLINED: %s. Long unit names keep wrapping in the unit info header. "
                    "Supported: gumi.BraveFrontier 2.19.6.0 x86 (tests/fixtures/make_signatures.py, "
                    "check_name_fit_site.py).", why.c_str());
        return;
    }
    using namespace cp::namefit;
    using cp::gateflash::ProtectionOf;
    NameFitEnv& e = env();
    g_cpNameFitFull = base + kFullRva;
    PatchSite& site = e.name[0];
    site.at = reinterpret_cast<uint8_t*>(base + kSiteRva);
    site.size = 5;
    site.protection = ProtectionOf(site.at);
    memcpy(site.original, site.at, 5);
    site.patched[0] = 0xE8;
    const int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&NameFitThunk)
                                             - reinterpret_cast<uintptr_t>(site.at + 5));
    memcpy(site.patched + 1, &rel, sizeof rel);
    WriteResult failure;
    if (LogInstall("unit name fit", "names keep wrapping",
                   InstallSites(e.name, 1, &cp::gateflash::WriteCode, &failure), e.name, 1, failure))
        CP_LOG_INFO("unit name fit installed at exe %08X + %06X: the unit info header's name label is one "
                    "line that shrinks to its width instead of wrapping onto the unit number row",
                    static_cast<unsigned>(base), static_cast<unsigned>(kSiteRva));

    // Skill popup widths: each operand must still name the client's 274.0 (relocated: base + RVA).
    const uint32_t stock = static_cast<uint32_t>(base + kStockWidthRva);
    const uint32_t ours = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&kPopupDescWidth));
    bool widthOk = true;
    for (int i = 0; i < 3; ++i)
    {
        PatchSite& w = e.width[i];
        w.at = reinterpret_cast<uint8_t*>(base + kPopupWidthRvas[i] + 4);
        w.size = 4;
        w.protection = ProtectionOf(w.at);
        memcpy(w.original, w.at, 4);
        memcpy(w.patched, &ours, 4);
        uint32_t operand = 0;
        memcpy(&operand, w.original, 4);
        widthOk = widthOk && operand == stock;
    }
    if (!widthOk)
    {
        CP_LOG_WARN("skill popup width DECLINED: a description width load does not name the stock 274.0");
        return;
    }
    // Vertical fit: each description call must still be `call 0x387100` (E8 rel32).
    g_cpLabelHelper = base + kLabelHelperRva;
    PopupFitEnv& fit = popupEnv();
    fit.labelVtable = base + kLabelVtableRva;
    fit.setText = reinterpret_cast<LabelSetTextFn>(base + kLabelSetTextRva);
    fit.assign = reinterpret_cast<StringAssignFn>(base + kStringAssignRva);
    fit.disable = &DisablePopupFit;
    bool descOk = true;
    for (int i = 0; i < 3; ++i)
    {
        PatchSite& d = e.desc[i];
        d.at = reinterpret_cast<uint8_t*>(base + kPopupDescCallRvas[i]);
        d.size = 5;
        d.protection = ProtectionOf(d.at);
        memcpy(d.original, d.at, 5);
        int32_t stockRel = 0;
        memcpy(&stockRel, d.original + 1, 4);
        descOk = descOk && d.original[0] == 0xE8
                 && reinterpret_cast<uintptr_t>(d.at + 5) + stockRel == g_cpLabelHelper;
        const int32_t rel = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&PopupDescThunk)
                                                 - reinterpret_cast<uintptr_t>(d.at + 5));
        d.patched[0] = 0xE8;
        memcpy(d.patched + 1, &rel, 4);
    }
    if (!descOk)
        CP_LOG_WARN("skill popup vertical fit DECLINED: a description call is not call 0x387100");
    else if (LogInstall("skill popup vertical fit", "long descriptions keep overflowing their frame",
                        InstallSites(e.desc, 3, &cp::gateflash::WriteCode, &failure), e.desc, 3, failure))
        CP_LOG_INFO("skill popup vertical fit installed: descriptions over %d lines scale down to fit their frame",
                    kPopupDescLines);

    if (LogInstall("skill popup width", "descriptions keep the stock width",
                   InstallSites(e.width, 3, &cp::gateflash::WriteCode, &failure), e.width, 3, failure))
        CP_LOG_INFO("skill popup width installed: BB/SBB/UBB descriptions wrap at %.0f instead of 274",
                    static_cast<double>(kPopupDescWidth));
}

void NameFit_Detach(void)
{
    using namespace cp::namefit;
    NameFitEnv& e = env();
    // Each patch restores on its own: a failure in one never hides or discards the other's state, and a
    // site that could not be restored stays marked installed (or incomplete) for a later retry.
    WriteResult failure;
    LogRestore("skill popup vertical fit", RestoreSites(e.desc, 3, &cp::gateflash::WriteCode, &failure), e.desc, 3,
               failure);
    LogRestore("skill popup width", RestoreSites(e.width, 3, &cp::gateflash::WriteCode, &failure), e.width, 3,
               failure);
    LogRestore("unit name fit", RestoreSites(e.name, 1, &cp::gateflash::WriteCode, &failure), e.name, 1, failure);
}

#endif // CONTENT_PROVIDER
