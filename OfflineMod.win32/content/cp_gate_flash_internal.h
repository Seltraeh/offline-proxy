/**
* @file cp_gate_flash_internal.h
* @brief The gate flash decision and its thunk, shared by the DLL and the tests.
*
* The DLL fills GateEnv after the build checks; tests fill it with fake
* animation lists and call the same decision and thunk.
*/
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace cp {
namespace gateflash {

// Layout of gumi.BraveFrontier 2.19.6.0 x86 (docs/CONTENT_PROVIDER_WINDOWS_CONTRACT.md, #24).
const uint32_t kAnimFrameOffset = 0x1B0;     //!< SuperAnimEx current frame, float (stock trigger: cvttss2si [esi+1B0h])
const uint32_t kAnimPathOffset = 0x204;      //!< SuperAnimEx .sam path, MSVC std::string (path getter 0x45C670)
const uint32_t kAnimEnabledOffset = 0x21E;   //!< SuperAnimEx enabled flag; SuperAnimList::process (0x631EC0) drops 0
const uint32_t kSceneOverlayOffset = 0x238;  //!< SummonsAnimeScene2 white overlay, 0 until created (0x876109/0x876228)
const uint32_t kListArrayOffset = 0x14;      //!< SuperAnimList -> its array object
const uint32_t kArrayBeginOffset = 0x14;     //!< array object -> element vector begin (end at +4)
const int kFlashFrame = 45;                  //!< the stock trigger's frame (cmp eax, 2Dh at 0x8761BE)
const size_t kMaxArmed = 8;

/*!
* What the decision remembers between frames of one summon scene: the
* opening-gate animations it saw BEFORE frame 45.  Only those may start the
* white, so an animation first seen at or past frame 45 (one left over from
* an earlier scene, resting on its last frame) never can.
*/
struct State
{
    const void* scene = nullptr;
    const void* armed[kMaxArmed] = {};
    size_t armedCount = 0;
    bool openLogged = false;     //!< the opening was logged for this scene
    bool nativeLogged = false;   //!< the stock rule's would-be trigger was logged for this scene
};

//! What one decision saw, for the log and the tests.
struct Report
{
    size_t count = 0;                    //!< animations in the global list
    const uint8_t* open = nullptr;       //!< the opening-gate animation armed or firing this frame
    int openFrame = -1;
    bool armedNew = false;               //!< an opening-gate animation was armed this frame
    bool nativeWouldFlash = false;       //!< the stock count rule would create the overlay this frame
    const uint8_t* nativeAnim = nullptr; //!< the stock rule's index-2 animation
    int nativeFrame = -1;
};

//! The stock trigger's frame read: cvttss2si of the float (NaN / out of range -> INT_MIN).
int FrameOf(const uint8_t* anim);
//! The animation's path bytes; false for an implausible string.
bool PathOf(const uint8_t* anim, const char** data, size_t* size);
//! The basename of the path into @p out ("?" when unreadable).
void NameOf(const uint8_t* anim, char* out, size_t cap);
//! An enabled animation whose path names an opening gate (GachaGateOpen*, case-insensitive).
bool IsOpeningGate(const uint8_t* anim);

/*!
* The stock rule, for comparison only: no overlay yet, exactly three
* animations, the third not Touch.sam / Hold.sam, and its frame >= 45.
*/
bool StockRuleWouldFlash(const uint8_t* scene, const uint8_t* const* begin, const uint8_t* const* end, Report& r);

/*!
* The replacement rule: true when the white overlay should be created now --
* no overlay yet, and an opening-gate animation armed earlier in this scene
* (seen below frame 45) has reached frame 45.  Disabled animations never
* count; a scene with no opening-gate animation forgets what it armed.
*/
bool Decide(const uint8_t* scene, const uint8_t* const* begin, const uint8_t* const* end, State& st, Report& r);

/*!
* What one code write did (round-8 QC P2).  The copy is the step that changes the code, so `copied` is true from
* the moment the new bytes are in place, whatever happens after it: callers keep their bookkeeping on `copied`
* (which bytes are in memory) and report success only on Complete() (the page protection went back as it was and
* the instruction cache was flushed too).  A write that fails after the copy has still changed the code.
*/
struct WriteResult
{
    bool copied = false;            //!< the page was made writable and the bytes copied
    bool protectRestored = false;   //!< the page's protection was set back (to restoreTo, or to what it found)
    bool flushed = false;           //!< FlushInstructionCache succeeded
    uint32_t found = 0;             //!< the protection the page had before this write (valid when copied)
    unsigned long error = 0;        //!< GetLastError() of the first step that failed; 0 when complete
    bool Complete() const { return copied && protectRestored && flushed; }
};

//! The step a write failed at, for the log ("making the page writable", ...); "" when it completed.
const char* FailedStep(const WriteResult& r);

/*!
* The two OS calls a code write makes.  Production uses VirtualProtect and FlushInstructionCache (CodeWriteOsOps);
* the tests wrap them to fail any one step on real pages.  Each returns false on failure with the error in
* GetLastError(), as the OS calls do.
*/
struct CodeWriteOps
{
    bool (*protect)(void* at, size_t n, uint32_t protection, uint32_t* previous);
    bool (*flush)(const void* at, size_t n);
};
const CodeWriteOps& CodeWriteOsOps();

/*!
* Writes @p n code bytes: make writable, copy, set the protection back, flush.  Every step after the copy runs even
* when an earlier one failed (a copied write is always flushed).  @p restoreTo is the protection to leave the page
* with; 0 puts back what the write found.  Patches pass the protection the site had at attach: after a failed
* restore the page is left writable, and a later write that "put back what it found" would keep it so.
*/
WriteResult WriteCodeWith(const CodeWriteOps& ops, uint8_t* at, const uint8_t* bytes, size_t n, uint32_t restoreTo = 0);
//! WriteCodeWith(CodeWriteOsOps(), ...): the writer every patch in the DLL uses.
WriteResult WriteCode(uint8_t* at, const uint8_t* bytes, size_t n, uint32_t restoreTo = 0);
typedef WriteResult (*CodeWriter)(uint8_t* at, const uint8_t* bytes, size_t n, uint32_t restoreTo);
//! The page protection at @p at now (VirtualQuery); 0 when it cannot be read.
uint32_t ProtectionOf(const void* at);

typedef void* (__cdecl* SharedList_t)();

struct GateEnv
{
    SharedList_t sharedList = nullptr;   //!< SuperAnimList::shared (0x631390)
    CodeWriter write = &WriteCode;       //!< every write of the site (the tests make steps fail)
    uint8_t* site = nullptr;             //!< the patched call (0x8760EF)
    uint8_t original[5] = {};            //!< its stock bytes, restored on detach or fault
    uint32_t protection = 0;             //!< the site's page protection at attach; every write leaves it so
    bool patched = false;                //!< OUR bytes are at the site now (follows WriteResult::copied)
    bool faulted = false;
    State state;
};

GateEnv& genv();

/*!
* Writes the stock bytes back over the patch (the stock trigger runs again).  `patched` follows the copy: it is
* cleared once the stock bytes are back, even if the protection or flush step then failed.  Nothing patched ->
* a result with copied == false and error 0.
*/
WriteResult RestoreSite(GateEnv& g);

//! The thunk's predicate: 1 = create the overlay now, 0 = go on to the fade step.
extern "C" int __stdcall CP_GateFlashDecide(const uint8_t* scene);
/*!
* Reached by `jmp` from the patched call with the stock registers; edi = the
* scene.  Restores every register and jumps to g_cpGateFlashYes (create the
* overlay, 0x8761C3) or g_cpGateFlashNo (the fade step, 0x876238).
*/
extern "C" void GateFlashThunk();
extern "C" uintptr_t g_cpGateFlashYes;
extern "C" uintptr_t g_cpGateFlashNo;

} // namespace gateflash
} // namespace cp
