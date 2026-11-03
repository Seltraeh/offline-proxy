/**
* @file cp_gate_flash_logic.cpp
* @brief The gate flash decision, its thunk and its log lines (DLL and tests share them).
*/
#include "cp_gate_flash_internal.h"
#include "cp_hooks_internal.h"
#include "cp_log.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <xmmintrin.h>

#include <string.h>

extern "C" uintptr_t g_cpGateFlashYes = 0;
extern "C" uintptr_t g_cpGateFlashNo = 0;

namespace cp {
namespace gateflash {

namespace {

// A plain global, not a function-local static: the DLL attaches under the loader lock.
GateEnv g_env;

const char kOpeningGate[] = "gachagateopen";   // GachaGateOpen2..6, GachaGateOpenAdd, GachaGateOpen6Add

bool ContainsFolded(const char* s, size_t n, const char* needle)
{
    const size_t m = strlen(needle);
    for (size_t i = 0; i + m <= n; ++i)
    {
        size_t k = 0;
        while (k < m)
        {
            char c = s[i + k];
            if (c >= 'A' && c <= 'Z')
                c = static_cast<char>(c - 'A' + 'a');
            if (c != needle[k])
                break;
            ++k;
        }
        if (k == m)
            return true;
    }
    return false;
}

bool ContainsExact(const char* s, size_t n, const char* needle)
{
    const size_t m = strlen(needle);
    for (size_t i = 0; i + m <= n; ++i)
        if (memcmp(s + i, needle, m) == 0)
            return true;
    return false;
}

bool Enabled(const uint8_t* anim)
{
    return anim[kAnimEnabledOffset] != 0;
}

const uint8_t* Overlay(const uint8_t* scene)
{
    return *reinterpret_cast<const uint8_t* const*>(scene + kSceneOverlayOffset);
}

bool IsArmed(const State& st, const void* anim)
{
    for (size_t i = 0; i < st.armedCount; ++i)
        if (st.armed[i] == anim)
            return true;
    return false;
}

//! Reads the global list and decides, inside SEH: a fault returns false.
bool DecideGuarded(GateEnv& g, const uint8_t* scene, Report& r, int& verdict)
{
    __try
    {
        const uint8_t* list = g.sharedList ? static_cast<const uint8_t*>(g.sharedList()) : nullptr;
        const uint8_t* const* begin = nullptr;
        const uint8_t* const* end = nullptr;
        if (list)
        {
            const uint8_t* arr = *reinterpret_cast<const uint8_t* const*>(list + kListArrayOffset);
            if (arr)
            {
                begin = *reinterpret_cast<const uint8_t* const* const*>(arr + kArrayBeginOffset);
                end = *reinterpret_cast<const uint8_t* const* const*>(arr + kArrayBeginOffset + 4);
            }
        }
        verdict = Decide(scene, begin, end, g.state, r) ? 1 : 0;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

} // namespace

GateEnv& genv()
{
    return g_env;
}

int FrameOf(const uint8_t* anim)
{
    return _mm_cvtt_ss2si(_mm_load_ss(reinterpret_cast<const float*>(anim + kAnimFrameOffset)));
}

bool PathOf(const uint8_t* anim, const char** data, size_t* size)
{
    const hooks::MsvcString* s = reinterpret_cast<const hooks::MsvcString*>(anim + kAnimPathOffset);
    if (s->size > s->capacity || s->size > 4096 || s->capacity < 15)
        return false;
    *data = hooks::StrData(s);
    *size = s->size;
    return *data != nullptr;
}

void NameOf(const uint8_t* anim, char* out, size_t cap)
{
    const char* p = nullptr;
    size_t n = 0;
    if (!anim || !PathOf(anim, &p, &n))
    {
        strncpy_s(out, cap, "?", _TRUNCATE);
        return;
    }
    size_t start = n;
    while (start > 0 && p[start - 1] != '\\' && p[start - 1] != '/')
        --start;
    const size_t len = n - start < cap - 1 ? n - start : cap - 1;
    memcpy(out, p + start, len);
    out[len] = 0;
}

bool IsOpeningGate(const uint8_t* anim)
{
    const char* p = nullptr;
    size_t n = 0;
    return Enabled(anim) && PathOf(anim, &p, &n) && ContainsFolded(p, n, kOpeningGate);
}

bool StockRuleWouldFlash(const uint8_t* scene, const uint8_t* const* begin, const uint8_t* const* end, Report& r)
{
    r.nativeWouldFlash = false;
    r.nativeAnim = nullptr;
    r.nativeFrame = -1;
    if (Overlay(scene) || !begin || end - begin != 3 || !begin[2])
        return false;
    const uint8_t* third = begin[2];
    const char* p = nullptr;
    size_t n = 0;
    if (!PathOf(third, &p, &n) || ContainsExact(p, n, "Touch.sam") || ContainsExact(p, n, "Hold.sam"))
        return false;
    r.nativeAnim = third;
    r.nativeFrame = FrameOf(third);
    r.nativeWouldFlash = r.nativeFrame >= kFlashFrame;
    return r.nativeWouldFlash;
}

bool Decide(const uint8_t* scene, const uint8_t* const* begin, const uint8_t* const* end, State& st, Report& r)
{
    if (scene != st.scene)
    {
        st = State();
        st.scene = scene;
    }
    r = Report();
    r.count = begin && end > begin ? static_cast<size_t>(end - begin) : 0;
    StockRuleWouldFlash(scene, begin, end, r);
    if (Overlay(scene))
    {
        st.armedCount = 0;          // already white: the game's fade step runs
        return false;
    }
    bool anyOpening = false;
    const uint8_t* fire = nullptr;
    for (const uint8_t* const* it = begin; it && it < end; ++it)
    {
        const uint8_t* anim = *it;
        if (!anim || !IsOpeningGate(anim))
            continue;
        anyOpening = true;
        const int frame = FrameOf(anim);
        const bool armed = IsArmed(st, anim);
        if (frame < kFlashFrame)
        {
            if (!armed && st.armedCount < kMaxArmed)
            {
                st.armed[st.armedCount++] = anim;
                r.armedNew = true;
                if (!r.open)
                {
                    r.open = anim;          // the first one names the opening in the log
                    r.openFrame = frame;
                }
            }
        }
        else if (armed && !fire)
        {
            fire = anim;
        }
    }
    if (fire)
    {
        r.open = fire;
        r.openFrame = FrameOf(fire);
        st.armedCount = 0;
        return true;
    }
    if (!anyOpening)
        st.armedCount = 0;
    return false;
}

namespace {

bool OsProtect(void* at, size_t n, uint32_t protection, uint32_t* previous)
{
    DWORD old = 0;
    const BOOL ok = VirtualProtect(at, n, protection, &old);
    *previous = old;
    return ok != FALSE;
}

bool OsFlush(const void* at, size_t n)
{
    return FlushInstructionCache(GetCurrentProcess(), at, n) != FALSE;
}

const CodeWriteOps kOsOps = { &OsProtect, &OsFlush };

} // namespace

const CodeWriteOps& CodeWriteOsOps()
{
    return kOsOps;
}

const char* FailedStep(const WriteResult& r)
{
    if (!r.copied)
        return "making the page writable";
    if (!r.protectRestored)
        return "restoring the page protection";
    if (!r.flushed)
        return "flushing the instruction cache";
    return "";
}

WriteResult WriteCodeWith(const CodeWriteOps& ops, uint8_t* at, const uint8_t* bytes, size_t n, uint32_t restoreTo)
{
    WriteResult r;
    if (!at)
    {
        r.error = ERROR_INVALID_ADDRESS;
        return r;
    }
    if (!ops.protect(at, n, PAGE_EXECUTE_READWRITE, &r.found))
    {
        r.error = GetLastError();
        return r;
    }
    memcpy(at, bytes, n);
    r.copied = true;
    uint32_t unused = 0;
    r.protectRestored = ops.protect(at, n, restoreTo ? restoreTo : r.found, &unused);
    if (!r.protectRestored)
        r.error = GetLastError();
    r.flushed = ops.flush(at, n);
    if (!r.flushed && r.error == 0)
        r.error = GetLastError();
    return r;
}

WriteResult WriteCode(uint8_t* at, const uint8_t* bytes, size_t n, uint32_t restoreTo)
{
    return WriteCodeWith(kOsOps, at, bytes, n, restoreTo);
}

uint32_t ProtectionOf(const void* at)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!at || VirtualQuery(at, &mbi, sizeof mbi) != sizeof mbi)
        return 0;
    return mbi.Protect;
}

WriteResult RestoreSite(GateEnv& g)
{
    if (!g.patched)
        return WriteResult();
    const WriteResult r = g.write(g.site, g.original, sizeof g.original, g.protection);
    if (r.copied)
        g.patched = false;
    return r;
}

extern "C" int __stdcall CP_GateFlashDecide(const uint8_t* scene)
{
    GateEnv& g = genv();
    if (g.faulted)
        return 0;
    Report r;
    int verdict = 0;
    if (!DecideGuarded(g, scene, r, verdict))
    {
        g.faulted = true;
        const WriteResult w = RestoreSite(g);
        if (w.Complete())
            CP_LOG_ERROR("gate flash: fault while reading the animation list; the stock white-screen trigger is "
                         "restored from the next frame");
        else if (w.copied)
            CP_LOG_ERROR("gate flash: fault while reading the animation list; the stock white-screen trigger is "
                         "restored from the next frame, but %s failed (error %lu)", FailedStep(w), w.error);
        else
            CP_LOG_ERROR("gate flash: fault while reading the animation list; the trigger stays off for this session "
                         "(stock bytes could not be written back: %s failed, error %lu)", FailedStep(w), w.error);
        return 0;
    }
    char name[64];
    if (r.armedNew && !g.state.openLogged)
    {
        g.state.openLogged = true;
        NameOf(r.open, name, sizeof name);
        CP_LOG_INFO("gate flash: the final gate is opening (%s at frame %d, %u animation(s) on screen); "
                    "white follows at frame %d", name, r.openFrame, static_cast<unsigned>(r.count), kFlashFrame);
    }
    if (r.nativeWouldFlash && !verdict && !g.state.nativeLogged)
    {
        g.state.nativeLogged = true;
        NameOf(r.nativeAnim, name, sizeof name);
        CP_LOG_INFO("gate flash: the stock trigger would turn the screen white now (3 animations, the third %s "
                    "at frame %d) -- not the final gate's opening, so no white", name, r.nativeFrame);
    }
    if (verdict)
    {
        NameOf(r.open, name, sizeof name);
        CP_LOG_INFO("gate flash: white at frame %d of %s (%u animation(s) on screen; the stock trigger %s)",
                    r.openFrame, name, static_cast<unsigned>(r.count),
                    r.nativeWouldFlash ? "fires on this frame too" : "would not have fired");
    }
    return verdict;
}

extern "C" __declspec(naked) void GateFlashThunk()
{
    __asm {
        pushad
        push edi
        call CP_GateFlashDecide
        test eax, eax
        popad
        jz no_flash
        jmp dword ptr [g_cpGateFlashYes]
    no_flash:
        jmp dword ptr [g_cpGateFlashNo]
    }
}

} // namespace gateflash
} // namespace cp
