/**
* @file cp_name_fit_internal.h
* @brief The name-fit patch's per-site install/restore bookkeeping and the skill popup's vertical fit (DLL and
*        tests share them).
*
* Each code location the patch rewrites is a PatchSite: its address, the stock bytes, the bytes to write, the page
* protection it had at attach and which bytes are in place now.  Every write goes through a CodeWriter
* (cp::gateflash::WriteCode in the DLL), so the tests can make any step of any write fail.  The rules (round-7 QC
* P2, and round 8: a write can fail AFTER its bytes were copied):
*   - The bookkeeping follows the bytes: `installed` is set or cleared by every write that copied, whatever failed
*     after the copy.  A write that copied but whose protection or cache step failed marks its site `incomplete`.
*   - Install writes the sites in order; on the first write that does not complete, every site holding our bytes,
*     the failed one included, is restored, newest first.
*   - Restore rewrites the stock bytes of every site that is installed or incomplete; a site whose restore does not
*     complete stays so, and a later RestoreSites retries it.
*   - Nothing is reported installed or restored that did not complete.
*/
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "cp_gate_flash_internal.h"     // WriteResult, CodeWriter (the shared code writer)

namespace cp {
namespace namefit {

using cp::gateflash::WriteResult;
typedef cp::gateflash::CodeWriter WriteFn;

const size_t kMaxSiteBytes = 8;

struct PatchSite {
    uint8_t* at = nullptr;
    size_t size = 0;                         // bytes rewritten, <= kMaxSiteBytes
    uint8_t original[kMaxSiteBytes] = { 0 };
    uint8_t patched[kMaxSiteBytes] = { 0 };
    uint32_t protection = 0;                 // the page protection at attach (0: whatever each write finds)
    bool installed = false;                  // our bytes are in place now
    bool incomplete = false;                 // the last write copied but its protection or flush step failed
};

enum class InstallResult {
    Installed,        // every site holds the patched bytes and every write completed
    RolledBack,       // a write did not complete; every site is stock again and every rollback write completed
    RollbackFailed,   // ... and some rollback write did not complete: its site is still installed or incomplete
};

/*!
* Installs every site in order, rolling back on the first write that does not complete (see the file comment).
* @p failure, when given, receives that write's result (the step and error for the log).
*/
InstallResult InstallSites(PatchSite* sites, size_t n, WriteFn write, WriteResult* failure = nullptr);
//! Restores every installed or incomplete site; true when every one is stock with a completed write.
//! @p failure, when given, receives the first restore that did not complete.
bool RestoreSites(PatchSite* sites, size_t n, WriteFn write, WriteResult* failure = nullptr);
//! Number of sites currently marked installed.
size_t InstalledCount(const PatchSite* sites, size_t n);
//! Number of sites whose last write copied but did not complete.
size_t IncompleteCount(const PatchSite* sites, size_t n);

//! Scale for a skill-popup description of `lines` lines in a frame that holds `capacity` lines: 1 when it
//! fits, else capacity / lines (round 7, vertical overflow).  Non-positive input -> 1.
float PopupFitScale(int lines, int capacity);
//! Before scaling, the description is wrapped again at width / this: sqrt(capacity / lines), so that the scaled
//! block uses the frame's whole width (n lines at width w hold about n*s lines at w/s; n*s*s = capacity).
//! 1 when it already fits or on non-positive input.
float PopupRewrapScale(int lines, int capacity);
//! The scale for a description re-wrapped at width / `rewrap` that now has `linesAfter` lines: the smaller of
//! `rewrap` (the width fits again) and capacity / linesAfter (the height fits).
float PopupFinalScale(float rewrap, int linesAfter, int capacity);
//! How far to move the label's y so the first line's top returns to `topBefore`: the layout moved it to
//! `topAfter`, and one unit of label y moves it by `slope` (measured).  0 for a degenerate slope.
float PopupTopDelta(float topBefore, float topAfter, float slope);

// ---- Skill popup vertical fit (round 7; failure policy round 8, QC P2) ----------------------------------------
//
// The label is gumi's text block (x86 2.19.6.0; tests/fixtures/check_name_fit_site.py sections 8-11).  The client
// builds it (0xD67E20) as: constructor, its text copied by std::string::assign 0xDE250, setString 0x38C3B0 at the
// wrap width +114h (setString itself ends with setPosition +48h and 0x38C9B0), then the helper's setPosition at the
// label's own +0F4h/+0F8h.  setString gives each new line node the label's scale.
//
// Failure policy:
//   - Everything that can be checked is checked before anything changes; a failed check leaves the label as built
//     (Declined).
//   - After a change, a check that fails restores the label the way the client built it: the stock scale, the
//     stock width, setString with a copy of the (unchanged) text, and setPosition at the stock x, y.  The restore
//     is verified: the stock line count and the first line's top back where it was (Restored).  A restore that
//     does not verify is reported as such (RestoreFailed).
//   - An access fault leaves the label's state unknown: it is never touched again (Faulted).
//   - After RestoreFailed or Faulted the fit is off for the session: PopupFitEnv::disable puts the three call
//     sites back to stock and every later call does nothing.
// Ownership: the text copy is made by the client's assign immediately before setString, which frees it (as every
// client caller's copy); no check or return lies between the two calls.

//! std::string as the client's msvcr120 lays it out: 16-byte buffer (or pointer), size at +10h, capacity at +14h.
struct ClientString {
    uint8_t buf[16];
    uint32_t size;
    uint32_t capacity;
};
static_assert(sizeof(ClientString) == 0x18, "the client's std::string is 18h bytes");

typedef void*(__thiscall* StringAssignFn)(ClientString*, const void* src, size_t pos, size_t count);
typedef void(__thiscall* LabelSetTextFn)(void* label, int force, ClientString text);

const size_t kLabelX = 0xF4;               // float, stored by the label's setPosition
const size_t kLabelY = 0xF8;
const size_t kLabelLines = 0x100;          // the line-node list: begin at +14h, end at +18h (outline copies too)
const size_t kLabelWrap = 0x114;           // float wrap width
const size_t kLabelText = 0x14C;           // ClientString
const size_t kLabelLineCount = 0x168;      // int, the lines setString laid out
const uint32_t kLabelVtableRva = 0x14E8CE0;   // VA 0x18E8CE0, installed by the constructor 0x38BF60
const size_t kNodeGetScaleX = 0x30, kNodeGetScaleY = 0x38, kNodeSetScale = 0x40, kLabelSetPosition = 0x48;
const size_t kNodeGetPositionY = 0x64, kNodeGetAnchorPoint = 0x7C, kNodeGetContentSize = 0x88;
const int kPopupDescLines = 3;             // description lines one popup frame holds (round 7 observation)
const int kMaxPopupLines = 64;             // more is not a description: the label is not read further
const float kTopTolerance = 0.5f;          // first-line top agreement (layout is linear in y; v5 was exact)

struct PopupFitEnv {
    uintptr_t labelVtable = 0;             // base + kLabelVtableRva: only this text block is changed
    LabelSetTextFn setText = nullptr;      // 0x38C3B0
    StringAssignFn assign = nullptr;       // 0xDE250
    void (*disable)() = nullptr;           // after RestoreFailed / Faulted: puts the three call sites back to stock
    bool disabled = false;                 // the fit does nothing more this session
};
PopupFitEnv& popupEnv();

enum class PopupFit {
    NotNeeded,       // 3 lines or fewer: untouched
    Declined,        // a check before any change failed: untouched
    Fitted,          // re-wrapped, scaled, and the first line's top verified where the client put it
    Restored,        // a check after a change failed; the label was laid out again as built and that verified
    RestoreFailed,   // ... the restore did not verify: the label may differ from the client's (fit disabled)
    Faulted,         // an access fault while `step`: the label may be left partly changed (fit disabled)
    Disabled,        // an earlier RestoreFailed / Faulted turned the fit off
};

//! What one fit did; plain data, so the SEH frame around it holds no C++ objects.
struct PopupFitResult {
    PopupFit outcome = PopupFit::NotNeeded;
    const char* step = "checking";         // the step running (for a fault)
    const char* why = "";                  // Declined / Restored / RestoreFailed: the check that failed
    int lines = 0, linesAfter = 0, linesRestored = 0;
    float width = 0.0f, rewrap = 1.0f, scale = 1.0f, scale0 = 1.0f;
    float x = 0.0f, y = 0.0f, y2 = 0.0f;
    float topBuilt = 0.0f;                 // the first line's top as built: where a restore must put it back
    float topBefore = 0.0f;                // ... after the re-wrap, unscaled: where the fit keeps it (round 7, run v5)
    float topAfter = 0.0f;
    unsigned nodes = 0;                    // entries in the line list (outlines included)
};

//! The fit (see the policy above); no SEH of its own.
void FitPopupDesc(PopupFitEnv& e, uint8_t* label, PopupFitResult& r);

} // namespace namefit
} // namespace cp

/*!
* The thunk's call-out: runs FitPopupDesc inside SEH on popupEnv(), logs the outcome, and applies the session
* policy (disable after RestoreFailed / Faulted).
*/
extern "C" void __stdcall CP_FitPopupDesc(uint8_t* label);
/*!
* Called in place of the label helper 0x387100 at the three description sites (`call`, caller-cleaned): parks its
* return address, calls g_cpLabelHelper with the untouched registers and stack, runs CP_FitPopupDesc(eax) and
* returns the label in eax with eax, ecx, edx and xmm0..xmm7 as the helper left them.  UI thread only.
*/
extern "C" void PopupDescThunk();
extern "C" uintptr_t g_cpLabelHelper;      // absolute address of 0x387100
extern "C" uintptr_t g_cpPopupRet;         // the site's return address while the helper runs
