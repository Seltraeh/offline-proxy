/**
* @file cp_hooks_internal.h
* @brief Hook functions and their environment, shared by the DLL and the tests.
*
* The DLL fills Env with the game's real functions after the build checks;
* tests fill it with fakes and call the same hook functions, so the ABI
* thunk, the byte forms and the ownership decisions are exercised without
* the UWP client.
*/
#pragma once

#include "cp_core.h"
#include "cp_provider.h"

#include <stdio.h>

#include <map>
#include <mutex>
#include <set>
#include <string>

namespace cp {
namespace hooks {

//! MSVC 2013 x86 std::string as compiled into the game and cocos2d (24 bytes).
struct MsvcString
{
    union { char buf[16]; char* ptr; } bx;
    uint32_t size;
    uint32_t capacity;
};
inline const char* StrData(const MsvcString* s) { return s->capacity >= 16 ? s->bx.ptr : s->bx.buf; }

typedef unsigned char* (__fastcall* GetFileData_t)(void* self, void* edx, const char* name, const char* mode, unsigned long* size);
typedef bool (__fastcall* IsFileExist_t)(void* self, void* edx, const char* path);
typedef void* (__fastcall* GetWritablePath_t)(void* self, void* edx, MsvcString* result);
typedef void (__fastcall* SceneArg_t)(void* self, void* edx, void* scene);
typedef void (__fastcall* SceneNoArg_t)(void* self, void* edx);
typedef bool (__fastcall* NameCheck_t)(const MsvcString* name, void* edx);
typedef void* (__cdecl* Singleton_t)();
//! FileLoader::addLoadFile: this, bool encode, std::string BY VALUE (the callee frees it); ret 1Ch.
typedef void (__fastcall* AddLoadFile_t)(void* self, void* edx, int encode, MsvcString name);
//! FileLoader::addLoadFilePriority: this, bool encode, bool, std::string BY VALUE; ret 20h.
typedef void (__fastcall* AddLoadFilePriority_t)(void* self, void* edx, int encode, int flag, MsvcString name);
typedef void (__fastcall* RemoveTextureForKey_t)(void* self, void* edx, const char* key);
typedef void* (__cdecl* OperatorNew_t)(size_t);
typedef void (__cdecl* OperatorDelete_t)(void*);
typedef FILE* (__cdecl* Fopen_t)(const char*, const char*);
typedef int (__cdecl* Remove_t)(const char*);
typedef int (__cdecl* FopenS_t)(FILE** stream, const char* path, const char* mode);
typedef size_t (__cdecl* Fread_t)(void* buffer, size_t size, size_t count, FILE* stream);
typedef int (__cdecl* Fclose_t)(FILE* stream);

/*!
* An owned sound opened by the audio reader (x86 0xEC0030, the EXE's only
* fopen_s caller: fopen_s(&f, path, "rb"), fread(buf, 1, 210, f) until it
* returns 0, fclose(f); nothing else ever sees f).  The FILE* the game holds
* is this object's address: Hook_Fread / Hook_Fclose recognise it by the
* registry and serve it from RAM, so it never reaches the CRT.
*/
struct MemFile
{
    std::vector<uint8_t> bytes;
    size_t pos = 0;
    std::string name;
};

/*!
* The provider's per-name decisions, counted (Session 16).  The login check
* list asks about every owned name (about 58,000 decisions on the C6 policy);
* writing one log line for each -- the log reopens its file per line, under
* one lock shared by the check list's ten worker threads -- held the warm
* FILE_CHECK screen for about 20 s.  Each slot now logs its first
* kDecisionSampleNames names in the old format, then only counts; the totals
* are logged at every scene change.
*/
enum DecisionSlot
{
    kDecisionExistsPresent, kDecisionExistsAbsent,           // CommonUtils::existsLocalFile
    kDecisionDownloadedYes, kDecisionDownloadedNo,           // the downloaded-name map lookup
    kDecisionFileExistPresent, kDecisionFileExistAbsent,     // CCFileUtils::isFileExist
    kDecisionTextureRaw,                                     // getTexture force-decode cleared
    kDecisionSuppressedMain, kDecisionSuppressedPriority,    // owned, present: not queued
    kDecisionQueuedMain, kDecisionQueuedPriority,            // passed to the game's downloader
    kDecisionSlots
};
const unsigned kDecisionSampleNames = 20;

struct Env
{
    Provider* provider = nullptr;

    GetFileData_t trueGetFileData = nullptr;
    IsFileExist_t trueIsFileExist = nullptr;
    NameCheck_t trueExistsLocalFile = nullptr;
    NameCheck_t trueIsFileAlreadyDownloaded = nullptr;
    SceneArg_t trueReplaceScene = nullptr;
    SceneArg_t truePushScene = nullptr;
    SceneArg_t trueRunWithScene = nullptr;
    SceneNoArg_t truePopScene = nullptr;
    SceneNoArg_t trueDrawScene = nullptr;
    Fopen_t trueFopen = nullptr;
    Remove_t trueRemove = nullptr;
    FopenS_t trueFopenS = nullptr;
    Fread_t trueFread = nullptr;
    Fclose_t trueFclose = nullptr;
    /*!
    * The audio reader's three CRT imports are patched (all or none).  Only
    * then may sound names (.mp3, .wav) be owned: their reader bypasses
    * getFileData, so unhooked they stay the game's own files whatever the
    * index says (owning them would stop their download with nothing to read).
    */
    bool audioHooked = false;
    std::mutex memFilesLock;
    std::set<const void*> memFiles;
    AddLoadFile_t trueAddLoadFile = nullptr;
    AddLoadFilePriority_t trueAddLoadFilePriority = nullptr;
    /*!
    * Every detour ContentProvider_Attach placed, recorded once its transaction committed.  The
    * startup path verifies its sites before this attach and again after it, and accepts a change
    * at one of them only where it is exactly one of these (cp_startup.cpp, cp_core.h
    * VerifySitesSince).
    */
    CodeDetour detours[16];
    size_t detourCount = 0;

    Singleton_t sharedFileUtils = nullptr;
    GetWritablePath_t getWritablePath = nullptr;
    Singleton_t sharedTextureCache = nullptr;
    RemoveTextureForKey_t removeTextureForKey = nullptr;
    OperatorNew_t msvcrNew = nullptr;          //!< msvcr120_app operator new: the heap the game frees from
    OperatorDelete_t msvcrDelete = nullptr;

    //! Return addresses right after the two getFileData calls of the
    //! two-image texture loader, which decodes FileCrypt unconditionally.
    uintptr_t encodedReaderReturn[2] = { 0, 0 };
    uintptr_t exeBase = 0;

    //! Folded writable path with a trailing '\\' (LocalState); resolved lazily.
    std::string prefixFolded;
    std::string prefixRaw;
    bool prefixKnown = false;
    //! The render thread (first drawScene caller).  getWritablePath goes through
    //! WinRT ApplicationData, so the prefix is only resolved on the thread the game
    //! itself uses it from; other threads pass through until it is known.
    unsigned long renderThreadId = 0;
    //! Tests resolve the prefix on their own thread.
    bool anyThreadMayResolve = false;
    std::mutex prefixLock;

    //! Exact path strings the game used for owned names (texture cache keys).
    std::mutex seenLock;
    std::multimap<std::string, std::string> seenPaths;   //!< folded name -> exact path
    std::set<std::string> loggedDecisions;               //!< the sampled names, per slot (bounded)

    //! Decisions per slot since the process started, and at the last summary.
    volatile long decisions[kDecisionSlots] = {};
    long decisionsAtSummary[kDecisionSlots] = {};
    volatile long decisionsSampled[kDecisionSlots] = {};
    //! Names passed to the game's MAIN (background) list that are assets, and
    //! those that are client state the provider never owns (sgtext zips): the
    //! background-download prompt is only left out when no asset was queued.
    volatile long mainQueuedAssets = 0;
    volatile long mainQueuedState = 0;

    // tripwire counters
    volatile long persistentWrites = 0;
    volatile long refusedRemoves = 0;
    //! Downloads of owned, present names kept out of the FileLoader queues:
    //! the direct addLoadFilePriority callers (Town, gates, Home...) that do
    //! not ask existsLocalFile first.  Sessions 10-15 saw up to a few hundred
    //! per process; requestFileWithEncode's entries never reach the hook.
    volatile long suppressedEnqueues = 0;
    //! Sounds the audio reader opened from provider RAM, and owned sounds it was told are missing.
    volatile long audioServed = 0;
    volatile long audioMissing = 0;

    // frame pacing (render thread only): intervals between drawScene calls
    static const unsigned kFrameSamples = 4096;
    float frameMs[kFrameSamples];
    unsigned frameCount = 0;
    long long lastFrameQpc = 0;
    long long windowStartQpc = 0;
    unsigned long long totalFrames = 0;
};

Env& env();

//! The texture loader's FileCrypt flag thunk calls the original through this.
extern "C" void* g_cpTrueGetTexture;

bool EnsurePrefix();

/*!
* Bytes for an owned LocalState read, in the form the reader expects: raw,
* MSVC text-mode translated for "r" reads, or FileCrypt-encoded for the one
* reader that always decodes.  Allocated with the game's operator new.
*/
unsigned char* ServeOwned(const std::string& flatName, const char* path, const char* mode,
                          unsigned long* pSize, uintptr_t returnAddress);

unsigned char* __fastcall Hook_GetFileData(void* self, void* edx, const char* name, const char* mode, unsigned long* pSize);
bool __fastcall Hook_IsFileExist(void* self, void* edx, const char* path);
bool __fastcall Hook_ExistsLocalFile(const MsvcString* name, void* edx);
bool __fastcall Hook_IsFileAlreadyDownloaded(const MsvcString* name, void* edx);
void __fastcall Hook_ReplaceScene(void* self, void* edx, void* scene);
void __fastcall Hook_PushScene(void* self, void* edx, void* scene);
void __fastcall Hook_RunWithScene(void* self, void* edx, void* scene);
void __fastcall Hook_PopScene(void* self, void* edx);
void __fastcall Hook_DrawScene(void* self, void* edx);
//! Logs frame-time percentiles, memory and provider counters for the window so far.
void LogPerformanceWindow(const char* why);
/*!
* Counts one decision; logs the name in the old per-name format while the
* slot has logged fewer than kDecisionSampleNames distinct names.
*/
void RecordDecision(DecisionSlot slot, const std::string& name);
//! One line with every slot's count since the last summary and since start (resets the window).
void LogDecisionTotals(const char* why);
//! RTTI class name of a polymorphic object ("?" when unreadable).
std::string ClassNameOf(const void* object);
FILE* __cdecl Hook_Fopen(const char* path, const char* mode);
int __cdecl Hook_Remove(const char* path);
/*!
* The FileLoader queue entries (Phase C1).  While the provider is active, a
* name it owns and has present is never queued for download: the provider
* serves it.  Anything else -- the provider idle, starting or dormant, a name
* it does not own, an owned name it reports absent -- goes to the original, so
* suppression can never strand a load the provider cannot replace.  The
* by-value std::string belongs to the callee: freed here (with the game's
* operator delete) when suppressed, handed to the original otherwise.
*/
void __fastcall Hook_AddLoadFile(void* self, void* edx, int encode, MsvcString name);
void __fastcall Hook_AddLoadFilePriority(void* self, void* edx, int encode, int flag, MsvcString name);

//! True for names only the audio reader opens (.mp3; .wav is what cocos asks for before the reader renames it).
bool IsAudioName(const std::string& flat);
/*!
* The audio reader's file calls (EXE IAT, module-scoped).  fopen_s of an
* owned, present LocalState name returns a RAM file of the provider's bytes;
* an owned name the provider reports absent fails with ENOENT (never the
* stale cached copy); anything else -- provider idle or dormant, a name it
* does not own -- is the CRT's.  fread / fclose serve RAM files and pass
* every real FILE* through untouched.
*/
int __cdecl Hook_FopenS(FILE** stream, const char* path, const char* mode);
size_t __cdecl Hook_Fread(void* buffer, size_t size, size_t count, FILE* stream);
int __cdecl Hook_Fclose(FILE* stream);
//! Live RAM files (tests: none may leak).
size_t OpenMemFiles();

//! Custom-ABI thunk for CommonUtils::getTexture (ecx = path, dl = force-decode, [esp+4] = bool).
extern "C" void GetTextureThunk();
//! The thunk's predicate: 1 when the path is an owned, present LocalState file.
extern "C" int __stdcall CP_TextureFromProvider(const MsvcString* path);

void SafePoint(const char* why);

} // namespace hooks
} // namespace cp
