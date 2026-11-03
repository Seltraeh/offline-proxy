/**
* @file cp_name_fit_logic.cpp
* @brief Per-site install/restore with rollback, and the skill popup's vertical fit (DLL and tests share them).
*/
#include "cp_name_fit_internal.h"
#include "cp_log.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>

#include <cmath>

extern "C" uintptr_t g_cpLabelHelper = 0;
extern "C" uintptr_t g_cpPopupRet = 0;

namespace cp {
namespace namefit {

namespace {

//! One write of a site, with the bookkeeping following the bytes.
WriteResult WriteSite(PatchSite& s, const uint8_t* bytes, bool ours, WriteFn write)
{
    const WriteResult r = write(s.at, bytes, s.size, s.protection);
    if (r.copied)
    {
        s.installed = ours;
        s.incomplete = !r.Complete();
    }
    return r;
}

} // namespace

InstallResult InstallSites(PatchSite* sites, size_t n, WriteFn write, WriteResult* failure)
{
    for (size_t i = 0; i < n; ++i)
    {
        if (sites[i].installed)
            continue;
        const WriteResult r = WriteSite(sites[i], sites[i].patched, true, write);
        if (r.Complete())
            continue;
        if (failure)
            *failure = r;
        // Roll back every site holding our bytes, newest first: the failed one too when its bytes were copied.
        bool allRestored = true;
        for (size_t k = i + 1; k-- > 0;)
        {
            if (!sites[k].installed)
                continue;
            if (!WriteSite(sites[k], sites[k].original, false, write).Complete())
                allRestored = false;              // installed or incomplete: RestoreSites retries it
        }
        return allRestored ? InstallResult::RolledBack : InstallResult::RollbackFailed;
    }
    return InstallResult::Installed;
}

bool RestoreSites(PatchSite* sites, size_t n, WriteFn write, WriteResult* failure)
{
    bool allRestored = true;
    for (size_t k = n; k-- > 0;)
    {
        if (!sites[k].installed && !sites[k].incomplete)
            continue;
        const WriteResult r = WriteSite(sites[k], sites[k].original, false, write);
        if (r.Complete())
            continue;
        if (failure && allRestored)
            *failure = r;
        allRestored = false;
    }
    return allRestored;
}

size_t InstalledCount(const PatchSite* sites, size_t n)
{
    size_t c = 0;
    for (size_t i = 0; i < n; ++i)
        c += sites[i].installed ? 1 : 0;
    return c;
}

size_t IncompleteCount(const PatchSite* sites, size_t n)
{
    size_t c = 0;
    for (size_t i = 0; i < n; ++i)
        c += sites[i].incomplete ? 1 : 0;
    return c;
}

float PopupFitScale(int lines, int capacity)
{
    if (lines <= 0 || capacity <= 0 || lines <= capacity)
        return 1.0f;
    return static_cast<float>(capacity) / static_cast<float>(lines);
}

float PopupRewrapScale(int lines, int capacity)
{
    if (lines <= 0 || capacity <= 0 || lines <= capacity)
        return 1.0f;
    return std::sqrt(static_cast<float>(capacity) / static_cast<float>(lines));
}

float PopupFinalScale(float rewrap, int linesAfter, int capacity)
{
    const float height = PopupFitScale(linesAfter, capacity);
    return height < rewrap ? height : rewrap;
}

float PopupTopDelta(float topBefore, float topAfter, float slope)
{
    if (!(std::fabs(slope) > 1e-4f) || !std::isfinite(slope) || !std::isfinite(topBefore - topAfter))
        return 0.0f;
    return (topBefore - topAfter) / slope;
}

// ---- Skill popup vertical fit --------------------------------------------------------------------------------

namespace {

PopupFitEnv g_popup;   // a plain global: the DLL attaches under the loader lock

typedef void(__thiscall* NodeSetFloatFn)(void*, float);
typedef float(__thiscall* NodeGetFloatFn)(void*);
typedef void(__thiscall* NodeSetXYFn)(void*, float, float);
typedef const float*(__thiscall* NodeGetPairFn)(void*);    // const CCSize& / const CCPoint&

template <typename F>
F VSlot(void* node, size_t offset)
{
    return reinterpret_cast<F>((*reinterpret_cast<void***>(node))[offset / 4]);
}

float& F32(uint8_t* p, size_t off) { return *reinterpret_cast<float*>(p + off); }
int I32(const uint8_t* p, size_t off) { return *reinterpret_cast<const int*>(p + off); }
bool Finite(float v) { return std::isfinite(v); }

//! The label's line-node list (begin) and its length, or null when absent, implausible or holding a null node.
uint8_t** LineNodes(uint8_t* label, unsigned& count)
{
    count = 0;
    uint8_t* list = *reinterpret_cast<uint8_t**>(label + kLabelLines);
    if (!list)
        return nullptr;
    uint8_t** first = *reinterpret_cast<uint8_t***>(list + 0x14);
    uint8_t** last = *reinterpret_cast<uint8_t***>(list + 0x18);
    if (!first || last <= first || last - first > 4 * kMaxPopupLines)
        return nullptr;
    for (uint8_t** p = first; p < last; ++p)
        if (!*p)
            return nullptr;
    count = static_cast<unsigned>(last - first);
    return first;
}

//! The top of a line node in its parent's coordinates: position + (1 - anchor y) * height * scale.
float LineTop(uint8_t* line)
{
    const float y = VSlot<NodeGetFloatFn>(line, kNodeGetPositionY)(line);
    const float anchorY = VSlot<NodeGetPairFn>(line, kNodeGetAnchorPoint)(line)[1];
    const float height = VSlot<NodeGetPairFn>(line, kNodeGetContentSize)(line)[1];
    const float scaleY = VSlot<NodeGetFloatFn>(line, kNodeGetScaleY)(line);
    return y + (1.0f - anchorY) * height * scaleY;
}

//! The laid-out lines a check after a change needs: a plausible count, every node present, a finite first top.
bool Usable(uint8_t* label, int& lines, unsigned& nodes, uint8_t**& list, float& top)
{
    lines = I32(label, kLabelLineCount);
    list = LineNodes(label, nodes);
    if (lines < 1 || lines > kMaxPopupLines || !list || nodes < static_cast<unsigned>(lines))
        return false;
    top = LineTop(list[0]);
    return Finite(top);
}

bool PlausibleText(const ClientString& s)
{
    return s.capacity >= 15 && s.size > 0 && s.size <= s.capacity && s.size < 0x10000;
}

//! Copies the label's text with the client's assign and hands the copy to its setString (force 1): the text is
//! laid out again at +114h, and setString frees the copy.  Nothing lies between the two calls.
void Relayout(const PopupFitEnv& e, uint8_t* label)
{
    ClientString text = {};
    text.capacity = 15;                                                 // empty, as the client builds one
    e.assign(&text, label + kLabelText, 0, static_cast<size_t>(-1));
    e.setText(label, 1, text);
}

void Decline(PopupFitResult& r, const char* why)
{
    r.outcome = PopupFit::Declined;
    r.why = why;
}

//! A check after a change failed: lay the label out as the client built it, then verify that.
void Restore(const PopupFitEnv& e, uint8_t* label, PopupFitResult& r, const char* why)
{
    r.step = "restoring";
    r.why = why;
    VSlot<NodeSetFloatFn>(label, kNodeSetScale)(label, r.scale0);      // setString gives new lines this scale
    F32(label, kLabelWrap) = r.width;
    Relayout(e, label);
    VSlot<NodeSetXYFn>(label, kLabelSetPosition)(label, r.x, r.y);
    unsigned nodes = 0;
    uint8_t** list = nullptr;
    float top = 0.0f;
    const bool usable = Usable(label, r.linesRestored, nodes, list, top);
    r.topAfter = top;
    r.outcome = usable && r.linesRestored == r.lines && std::fabs(top - r.topBuilt) <= kTopTolerance
                    ? PopupFit::Restored : PopupFit::RestoreFailed;
}

} // namespace

PopupFitEnv& popupEnv()
{
    return g_popup;
}

void FitPopupDesc(PopupFitEnv& e, uint8_t* label, PopupFitResult& r)
{
    r = PopupFitResult();
    if (e.disabled)
    {
        r.outcome = PopupFit::Disabled;
        return;
    }
    // 0. Checks; nothing changes until all of them pass.
    if (!e.setText || !e.assign || !e.labelVtable)
        return Decline(r, "setString / the string assign / the label vtable are not resolved");
    if (*reinterpret_cast<const uintptr_t*>(label) != e.labelVtable)
        return Decline(r, "the helper's result is not the client's text block (vtable)");
    r.lines = I32(label, kLabelLineCount);
    if (r.lines <= kPopupDescLines)
        return;                                                         // NotNeeded
    if (r.lines > kMaxPopupLines)
        return Decline(r, "implausible line count");
    r.width = F32(label, kLabelWrap);
    if (!(Finite(r.width) && r.width > 0.0f && r.width < 4096.0f))
        return Decline(r, "implausible wrap width");
    if (!PlausibleText(*reinterpret_cast<const ClientString*>(label + kLabelText)))
        return Decline(r, "implausible text string");
    uint8_t** list = LineNodes(label, r.nodes);
    if (!list || r.nodes < static_cast<unsigned>(r.lines))
        return Decline(r, "the line list does not hold the laid-out lines");
    r.scale0 = VSlot<NodeGetFloatFn>(label, kNodeGetScaleX)(label);
    if (!(Finite(r.scale0) && r.scale0 > 0.0f && r.scale0 == VSlot<NodeGetFloatFn>(label, kNodeGetScaleY)(label)))
        return Decline(r, "the label's scale is not one finite positive value");
    r.x = F32(label, kLabelX);
    r.y = F32(label, kLabelY);
    r.topBuilt = LineTop(list[0]);
    if (!(Finite(r.x) && Finite(r.y) && Finite(r.topBuilt)))
        return Decline(r, "the label's position or first line cannot be measured");
    r.rewrap = PopupRewrapScale(r.lines, kPopupDescLines);

    // 1. Wrap again, wider (the first change).
    r.step = "re-wrapping";
    F32(label, kLabelWrap) = r.width / r.rewrap;
    Relayout(e, label);
    if (!Usable(label, r.linesAfter, r.nodes, list, r.topBefore))
        return Restore(e, label, r, "the re-wrapped layout has no usable lines");
    // The target is where the client itself lays the re-wrapped first line out (round 7, accepted in run v5): the
    // shorter block's first line, under the skill name.  The as-built top belongs to the taller overflowing block,
    // which reaches up into the title (round 8, run v1).

    // 2. Scale the label and every line node, and lay them out again.
    r.step = "scaling";
    r.scale = PopupFinalScale(r.rewrap, r.linesAfter, kPopupDescLines);
    VSlot<NodeSetFloatFn>(label, kNodeSetScale)(label, r.scale);
    for (unsigned i = 0; i < r.nodes; ++i)
        VSlot<NodeSetFloatFn>(list[i], kNodeSetScale)(list[i], r.scale);
    VSlot<NodeSetXYFn>(label, kLabelSetPosition)(label, r.x, r.y);

    // 3. Put the first line's top back where it was, and verify it.
    r.step = "placing";
    unsigned nodes = 0;
    list = LineNodes(label, nodes);
    if (!list || nodes != r.nodes)
        return Restore(e, label, r, "the line list changed while scaling");
    const float top0 = LineTop(list[0]);
    VSlot<NodeSetXYFn>(label, kLabelSetPosition)(label, r.x, r.y + 1.0f);
    const float slope = LineTop(list[0]) - top0;
    if (!Finite(top0) || !Finite(slope) || !(std::fabs(slope) > 1e-4f))
        return Restore(e, label, r, "the scaled layout cannot be measured");
    r.y2 = r.y + PopupTopDelta(r.topBefore, top0, slope);
    VSlot<NodeSetXYFn>(label, kLabelSetPosition)(label, r.x, r.y2);
    r.topAfter = LineTop(list[0]);
    if (!(Finite(r.topAfter) && std::fabs(r.topAfter - r.topBefore) <= kTopTolerance))
        return Restore(e, label, r, "the first line did not return to its top");
    r.outcome = PopupFit::Fitted;
}

} // namespace namefit
} // namespace cp

namespace {

//! FitPopupDesc inside SEH; false on a fault.  No C++ objects in this frame.
bool FitGuarded(cp::namefit::PopupFitEnv& e, uint8_t* label, cp::namefit::PopupFitResult& r)
{
    __try
    {
        cp::namefit::FitPopupDesc(e, label, r);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

} // namespace

extern "C" void __stdcall CP_FitPopupDesc(uint8_t* label)
{
    using namespace cp::namefit;
    PopupFitEnv& e = popupEnv();
    if (!label || e.disabled)
        return;
    PopupFitResult r;
    if (!FitGuarded(e, label, r))
        r.outcome = PopupFit::Faulted;
    switch (r.outcome)
    {
    case PopupFit::NotNeeded:
    case PopupFit::Disabled:
        return;
    case PopupFit::Declined:
        CP_LOG_WARN("skill popup vertical fit: label left as built (%d lines): %s", r.lines, r.why);
        return;
    case PopupFit::Fitted:
        CP_LOG_INFO("skill popup vertical fit: %d lines; wrap %.1f -> %.1f gives %d lines; scale %.3f (%u line nodes); "
                    "first line top %.1f -> %.1f (y %.1f -> %.1f)",
                    r.lines, static_cast<double>(r.width), static_cast<double>(r.width / r.rewrap), r.linesAfter,
                    static_cast<double>(r.scale), r.nodes, static_cast<double>(r.topBefore),
                    static_cast<double>(r.topAfter), static_cast<double>(r.y), static_cast<double>(r.y2));
        return;
    case PopupFit::Restored:
        CP_LOG_WARN("skill popup vertical fit: %s; the label was laid out again as built (scale %.3f, wrap %.1f, "
                    "%d lines, first line top %.1f)", r.why, static_cast<double>(r.scale0),
                    static_cast<double>(r.width), r.linesRestored, static_cast<double>(r.topAfter));
        return;
    case PopupFit::RestoreFailed:
        CP_LOG_ERROR("skill popup vertical fit: %s, and laying the label out again as built did not verify "
                     "(%d lines, first line top %.1f; built: %d lines, %.1f); the label may differ from the client's. "
                     "Vertical fit off for this session", r.why, r.linesRestored, static_cast<double>(r.topAfter),
                     r.lines, static_cast<double>(r.topBuilt));
        break;
    case PopupFit::Faulted:
        CP_LOG_ERROR("skill popup vertical fit: access fault while %s (%d lines); the label is not touched again "
                     "and may be left partly changed. Vertical fit off for this session", r.step, r.lines);
        break;
    }
    e.disabled = true;
    if (e.disable)
        e.disable();
}

// The client is built with whole-program optimisation (0x387100 takes ecx, edx and xmm1..xmm3), so the code after
// each site is not assumed to treat any register as clobbered: everything 0x387100 returns (eax, ecx, edx,
// xmm0..xmm7) is put back as it was before CP_FitPopupDesc ran.
extern "C" __declspec(naked) void PopupDescThunk()
{
    __asm {
        pop     dword ptr [g_cpPopupRet]      ; the site's stack arguments are now on top, as 0x387100 expects
        call    dword ptr [g_cpLabelHelper]
        push    dword ptr [g_cpPopupRet]      ; the site's return address, back in place at once
        push    eax
        push    ecx
        push    edx
        sub     esp, 80h
        movdqu  [esp], xmm0
        movdqu  [esp + 10h], xmm1
        movdqu  [esp + 20h], xmm2
        movdqu  [esp + 30h], xmm3
        movdqu  [esp + 40h], xmm4
        movdqu  [esp + 50h], xmm5
        movdqu  [esp + 60h], xmm6
        movdqu  [esp + 70h], xmm7
        push    eax                           ; the label
        call    CP_FitPopupDesc               ; __stdcall: pops its argument
        movdqu  xmm0, [esp]
        movdqu  xmm1, [esp + 10h]
        movdqu  xmm2, [esp + 20h]
        movdqu  xmm3, [esp + 30h]
        movdqu  xmm4, [esp + 40h]
        movdqu  xmm5, [esp + 50h]
        movdqu  xmm6, [esp + 60h]
        movdqu  xmm7, [esp + 70h]
        add     esp, 80h
        pop     edx
        pop     ecx
        pop     eax
        ret                                   ; back to the site, which cleans its own arguments
    }
}
