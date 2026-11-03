/**
* @file cp_hooks.cpp
* @brief Installs the content provider hooks after verifying the client build.
*
* Hook sites (gumi.BraveFrontier 2.19.6.0 x86; RVAs and masked signatures in
* cp_signatures.h, contract in docs/CONTENT_PROVIDER_WINDOWS_CONTRACT.md):
*
*   cocos2d  CCFileUtils::getFileData        every asset read (vtable slot 12)
*   cocos2d  CCFileUtilsWinRT::isFileExist   cocos-level existence (slot 2)
*   cocos2d  CCDirector replace/push/pop/runWithScene   safe points
*   game     CommonUtils::existsLocalFile    "is it downloaded?" for every scene
*   game     downloaded-name map lookup      the download-list builders' check
*   game     CommonUtils::getTexture         clears FileCrypt force-decode for provider bytes
*   game IAT msvcr120_app fopen / remove     tripwire for writes/deletes of owned names
*   game IAT msvcr120_app fopen_s / fread / fclose   the audio reader (0xEC0030, the only
*                                            fopen_s caller): owned sounds become RAM files
*   game     FileLoader::addLoadFile / addLoadFilePriority   the download queues (owned,
*                                            present names are never queued; Phase C1)
*
* The hooks go in their OWN Detours transaction: a failed attach aborts the
* whole transaction it is part of, and must never take main.cpp's connection
* hooks or the FPS cap down with it.
*/
#include "../pch.h"
#include "cp_hooks.h"

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER

#include <detours/detours.h>

#include "cp_hooks_internal.h"
#include "cp_log.h"
#include "cp_signatures.h"

namespace {

using namespace cp;
using namespace cp::hooks;

const char* const kExeName = "BraveFrontier.Windows.exe";
const char* const kCocosName = "libcocos2d_v2.2.5_Windows_8.1.dll";
const size_t kCacheBytes = 48u * 1024u * 1024u;
const size_t kMaxEntryBytes = 16u * 1024u * 1024u;

bool g_installed = false;
// Plain globals (no function-local statics: attach runs under the loader lock).
// Never freed -- hooks may still run while the process exits.
WinInetBroker* g_broker = nullptr;
Provider* g_provider = nullptr;
void** g_iatFopen = nullptr;
void** g_iatRemove = nullptr;
void** g_iatFopenS = nullptr;
void** g_iatFread = nullptr;
void** g_iatFclose = nullptr;

void* g_fGetFileData = nullptr;
void* g_fIsFileExist = nullptr;
void* g_fExistsLocalFile = nullptr;
void* g_fIsFileAlreadyDownloaded = nullptr;
void* g_fReplaceScene = nullptr;
void* g_fPushScene = nullptr;
void* g_fPopScene = nullptr;
void* g_fRunWithScene = nullptr;
void* g_fDrawScene = nullptr;
void* g_fAddLoadFile = nullptr;
void* g_fAddLoadFilePriority = nullptr;

const SiteSignature* FindSite(const char* name)
{
    for (size_t i = 0; i < sizeof kSiteSignatures / sizeof kSiteSignatures[0]; ++i)
        if (strcmp(kSiteSignatures[i].name, name) == 0)
            return &kSiteSignatures[i];
    return nullptr;
}

uintptr_t SiteAddress(const uintptr_t bases[2], const char* name)
{
    const SiteSignature* s = FindSite(name);
    return s ? bases[s->module] + s->rva : 0;
}

bool EndsWithI(const char* s, const char* suffix)
{
    const size_t a = strlen(s), b = strlen(suffix);
    return a >= b && _stricmp(s + a - b, suffix) == 0;
}

//! Verifies both modules and every hook site; false (with a reason) declines everything.
bool VerifyClient(uintptr_t bases[2], std::string& why)
{
    char exePath[MAX_PATH] = { 0 };
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    if (!EndsWithI(exePath, kExeName))
    {
        why = std::string("host process is not ") + kExeName + " (" + exePath + ")";
        return false;
    }
    bases[0] = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    bases[1] = reinterpret_cast<uintptr_t>(GetModuleHandleA(kCocosName));
    if (!bases[1])
    {
        why = std::string(kCocosName) + " is not loaded";
        return false;
    }
    for (int m = 0; m < 2; ++m)
    {
        if (!MatchIdentity(kSupportedModules[m], reinterpret_cast<const uint8_t*>(bases[m]), 4096, why))
            return false;
    }
    for (size_t i = 0; i < sizeof kSiteSignatures / sizeof kSiteSignatures[0]; ++i)
    {
        const SiteSignature& s = kSiteSignatures[i];
        const uint8_t* p = reinterpret_cast<const uint8_t*>(bases[s.module] + s.rva);
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(p, &mbi, sizeof mbi) || !(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        {
            why = std::string(s.name) + ": site is not in executable memory";
            return false;
        }
        if (!MatchSignature(s, p, strlen(s.mask), why))
            return false;
    }
    return true;
}

//! The game EXE's own IAT slot for an msvcr120_app import (module-scoped, not process-wide).
void** FindIatSlot(uintptr_t base, const char* dll, const char* func)
{
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const IMAGE_NT_HEADERS32* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress)
        return nullptr;
    for (const IMAGE_IMPORT_DESCRIPTOR* d = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
         d->Name; ++d)
    {
        if (_stricmp(reinterpret_cast<const char*>(base + d->Name), dll) != 0 || !d->OriginalFirstThunk)
            continue;
        const IMAGE_THUNK_DATA32* names = reinterpret_cast<const IMAGE_THUNK_DATA32*>(base + d->OriginalFirstThunk);
        IMAGE_THUNK_DATA32* slots = reinterpret_cast<IMAGE_THUNK_DATA32*>(base + d->FirstThunk);
        for (size_t i = 0; names[i].u1.AddressOfData; ++i)
        {
            if (IMAGE_SNAP_BY_ORDINAL32(names[i].u1.Ordinal))
                continue;
            const IMAGE_IMPORT_BY_NAME* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + names[i].u1.AddressOfData);
            if (strcmp(reinterpret_cast<const char*>(ibn->Name), func) == 0)
                return reinterpret_cast<void**>(&slots[i].u1.Function);
        }
    }
    return nullptr;
}

bool PatchSlot(void** slot, void* value, void** previous)
{
    DWORD old = 0;
    if (!slot || !VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old))
        return false;
    if (previous)
        *previous = *slot;
    *slot = value;
    VirtualProtect(slot, sizeof(void*), old, &old);
    return true;
}

template <typename T>
T Export(HMODULE m, const char* name)
{
    return reinterpret_cast<T>(GetProcAddress(m, name));
}

} // namespace

void ContentProvider_Attach(void)
{
    uintptr_t bases[2] = { 0, 0 };
    std::string why;
    if (!VerifyClient(bases, why))
    {
        CP_LOG_WARN("content provider DECLINED: %s. The game keeps its own LocalState cache. "
                    "Supported: gumi.BraveFrontier 2.19.6.0 x86; for another client build re-derive the sites "
                    "(docs/CONTENT_PROVIDER_WINDOWS_CONTRACT.md, tests/fixtures/make_signatures.py).", why.c_str());
        return;
    }

    HMODULE cocos = reinterpret_cast<HMODULE>(bases[1]);
    HMODULE crt = GetModuleHandleA("msvcr120_app.dll");
    Env& e = env();
    e.exeBase = bases[0];
    e.sharedFileUtils = Export<Singleton_t>(cocos, "?sharedFileUtils@CCFileUtils@cocos2d@@SAPAV12@XZ");
    e.getWritablePath = Export<GetWritablePath_t>(cocos,
        "?getWritablePath@CCFileUtilsWinRT@cocos2d@@UAE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ");
    e.sharedTextureCache = Export<Singleton_t>(cocos, "?sharedTextureCache@CCTextureCache@cocos2d@@SAPAV12@XZ");
    e.removeTextureForKey = Export<RemoveTextureForKey_t>(cocos, "?removeTextureForKey@CCTextureCache@cocos2d@@QAEXPBD@Z");
    e.msvcrNew = crt ? Export<OperatorNew_t>(crt, "??2@YAPAXI@Z") : nullptr;
    e.msvcrDelete = crt ? Export<OperatorDelete_t>(crt, "??3@YAXPAX@Z") : nullptr;
    const uintptr_t getWritableSite = SiteAddress(bases, "getWritablePath");
    if (!e.sharedFileUtils || !e.getWritablePath || !e.sharedTextureCache || !e.removeTextureForKey
        || !e.msvcrNew || !e.msvcrDelete || reinterpret_cast<uintptr_t>(e.getWritablePath) != getWritableSite)
    {
        CP_LOG_WARN("content provider DECLINED: a required cocos2d/CRT export is missing or moved");
        return;
    }
    // The two-image texture loader decodes both of its reads unconditionally;
    // its getFileData calls return to "<site> + 33" (after `call [edi+30h]`).
    e.encodedReaderReturn[0] = SiteAddress(bases, "pairTexture_read1") + 33;
    e.encodedReaderReturn[1] = SiteAddress(bases, "pairTexture_read2") + 33;

    g_fGetFileData = reinterpret_cast<void*>(SiteAddress(bases, "getFileData"));
    g_fIsFileExist = reinterpret_cast<void*>(SiteAddress(bases, "isFileExist"));
    g_fExistsLocalFile = reinterpret_cast<void*>(SiteAddress(bases, "existsLocalFile"));
    g_fIsFileAlreadyDownloaded = reinterpret_cast<void*>(SiteAddress(bases, "isFileAlreadyDownloaded"));
    g_cpTrueGetTexture = reinterpret_cast<void*>(SiteAddress(bases, "getTexture"));
    g_fReplaceScene = reinterpret_cast<void*>(SiteAddress(bases, "replaceScene"));
    g_fPushScene = reinterpret_cast<void*>(SiteAddress(bases, "pushScene"));
    g_fPopScene = reinterpret_cast<void*>(SiteAddress(bases, "popScene"));
    g_fRunWithScene = reinterpret_cast<void*>(SiteAddress(bases, "runWithScene"));
    g_fDrawScene = reinterpret_cast<void*>(SiteAddress(bases, "drawScene"));
    g_fAddLoadFile = reinterpret_cast<void*>(SiteAddress(bases, "addLoadFile"));
    g_fAddLoadFilePriority = reinterpret_cast<void*>(SiteAddress(bases, "addLoadFilePriority"));

    g_broker = new WinInetBroker(SERVICE_IP, static_cast<unsigned short>(SERVICE_PORT));
    g_provider = new Provider(g_broker, kCacheBytes, kMaxEntryBytes);
    e.provider = g_provider;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&g_fGetFileData, reinterpret_cast<PVOID>(Hook_GetFileData));
    DetourAttach(&g_fIsFileExist, reinterpret_cast<PVOID>(Hook_IsFileExist));
    DetourAttach(&g_fExistsLocalFile, reinterpret_cast<PVOID>(Hook_ExistsLocalFile));
    DetourAttach(&g_fIsFileAlreadyDownloaded, reinterpret_cast<PVOID>(Hook_IsFileAlreadyDownloaded));
    DetourAttach(&g_cpTrueGetTexture, reinterpret_cast<PVOID>(GetTextureThunk));
    DetourAttach(&g_fReplaceScene, reinterpret_cast<PVOID>(Hook_ReplaceScene));
    DetourAttach(&g_fPushScene, reinterpret_cast<PVOID>(Hook_PushScene));
    DetourAttach(&g_fPopScene, reinterpret_cast<PVOID>(Hook_PopScene));
    DetourAttach(&g_fRunWithScene, reinterpret_cast<PVOID>(Hook_RunWithScene));
    DetourAttach(&g_fDrawScene, reinterpret_cast<PVOID>(Hook_DrawScene));
    DetourAttach(&g_fAddLoadFile, reinterpret_cast<PVOID>(Hook_AddLoadFile));
    DetourAttach(&g_fAddLoadFilePriority, reinterpret_cast<PVOID>(Hook_AddLoadFilePriority));
    PVOID* failed = nullptr;
    const LONG err = DetourTransactionCommitEx(&failed);
    if (err != NO_ERROR)
    {
        e.provider = nullptr;
        CP_LOG_WARN("content provider DECLINED: Detours could not hook site %p (error %ld); nothing was changed",
                    failed ? *failed : nullptr, err);
        return;
    }
    // Trampolines: the hooks call the originals through these.
    e.trueGetFileData = reinterpret_cast<GetFileData_t>(g_fGetFileData);
    e.trueIsFileExist = reinterpret_cast<IsFileExist_t>(g_fIsFileExist);
    e.trueExistsLocalFile = reinterpret_cast<NameCheck_t>(g_fExistsLocalFile);
    e.trueIsFileAlreadyDownloaded = reinterpret_cast<NameCheck_t>(g_fIsFileAlreadyDownloaded);
    e.trueReplaceScene = reinterpret_cast<SceneArg_t>(g_fReplaceScene);
    e.truePushScene = reinterpret_cast<SceneArg_t>(g_fPushScene);
    e.truePopScene = reinterpret_cast<SceneNoArg_t>(g_fPopScene);
    e.trueRunWithScene = reinterpret_cast<SceneArg_t>(g_fRunWithScene);
    e.trueDrawScene = reinterpret_cast<SceneNoArg_t>(g_fDrawScene);
    e.trueAddLoadFile = reinterpret_cast<AddLoadFile_t>(g_fAddLoadFile);
    e.trueAddLoadFilePriority = reinterpret_cast<AddLoadFilePriority_t>(g_fAddLoadFilePriority);

    // Where each detour went.  The startup path verifies its sites before this attach and again
    // after it; it accepts a change only where it is exactly one of these (cp_startup.cpp).
    const struct { const char* site; PVOID hook; void* trampoline; } placed[] = {
        { "getFileData", reinterpret_cast<PVOID>(Hook_GetFileData), g_fGetFileData },
        { "isFileExist", reinterpret_cast<PVOID>(Hook_IsFileExist), g_fIsFileExist },
        { "existsLocalFile", reinterpret_cast<PVOID>(Hook_ExistsLocalFile), g_fExistsLocalFile },
        { "isFileAlreadyDownloaded", reinterpret_cast<PVOID>(Hook_IsFileAlreadyDownloaded), g_fIsFileAlreadyDownloaded },
        { "getTexture", reinterpret_cast<PVOID>(GetTextureThunk), g_cpTrueGetTexture },
        { "replaceScene", reinterpret_cast<PVOID>(Hook_ReplaceScene), g_fReplaceScene },
        { "pushScene", reinterpret_cast<PVOID>(Hook_PushScene), g_fPushScene },
        { "popScene", reinterpret_cast<PVOID>(Hook_PopScene), g_fPopScene },
        { "runWithScene", reinterpret_cast<PVOID>(Hook_RunWithScene), g_fRunWithScene },
        { "drawScene", reinterpret_cast<PVOID>(Hook_DrawScene), g_fDrawScene },
        { "addLoadFile", reinterpret_cast<PVOID>(Hook_AddLoadFile), g_fAddLoadFile },
        { "addLoadFilePriority", reinterpret_cast<PVOID>(Hook_AddLoadFilePriority), g_fAddLoadFilePriority },
    };
    static_assert(sizeof placed / sizeof placed[0] <= sizeof e.detours / sizeof e.detours[0], "Env::detours too small");
    e.detourCount = 0;
    for (size_t i = 0; i < sizeof placed / sizeof placed[0]; ++i)
    {
        CodeDetour& d = e.detours[e.detourCount++];
        d.owner = "content provider";
        d.site = placed[i].site;
        d.target = SiteAddress(bases, placed[i].site);
        d.detour = reinterpret_cast<uintptr_t>(DetourCodeFromPointer(placed[i].hook, nullptr));
        d.trampoline = static_cast<const uint8_t*>(placed[i].trampoline);
    }

    g_iatFopen = FindIatSlot(bases[0], "msvcr120_app.dll", "fopen");
    g_iatRemove = FindIatSlot(bases[0], "msvcr120_app.dll", "remove");
    void* prev = nullptr;
    if (PatchSlot(g_iatFopen, reinterpret_cast<void*>(Hook_Fopen), &prev))
        e.trueFopen = reinterpret_cast<Fopen_t>(prev);
    else
        g_iatFopen = nullptr;
    if (PatchSlot(g_iatRemove, reinterpret_cast<void*>(Hook_Remove), &prev))
        e.trueRemove = reinterpret_cast<Remove_t>(prev);
    else
        g_iatRemove = nullptr;

    // The audio reader: all three slots or none.  fread and fclose first (they
    // pass every real FILE* through), fopen_s last (it starts handing out RAM
    // files); each original is stored before its slot points at the hook.
    g_iatFopenS = FindIatSlot(bases[0], "msvcr120_app.dll", "fopen_s");
    g_iatFread = FindIatSlot(bases[0], "msvcr120_app.dll", "fread");
    g_iatFclose = FindIatSlot(bases[0], "msvcr120_app.dll", "fclose");
    if (g_iatFopenS && g_iatFread && g_iatFclose)
    {
        e.trueFread = reinterpret_cast<Fread_t>(*g_iatFread);
        e.trueFclose = reinterpret_cast<Fclose_t>(*g_iatFclose);
        e.trueFopenS = reinterpret_cast<FopenS_t>(*g_iatFopenS);
        if (PatchSlot(g_iatFread, reinterpret_cast<void*>(Hook_Fread), nullptr))
        {
            if (PatchSlot(g_iatFclose, reinterpret_cast<void*>(Hook_Fclose), nullptr))
            {
                if (PatchSlot(g_iatFopenS, reinterpret_cast<void*>(Hook_FopenS), nullptr))
                    e.audioHooked = true;
                else
                    PatchSlot(g_iatFclose, reinterpret_cast<void*>(e.trueFclose), nullptr);
            }
            if (!e.audioHooked)
                PatchSlot(g_iatFread, reinterpret_cast<void*>(e.trueFread), nullptr);
        }
    }

    g_installed = true;
    CP_LOG_INFO("content provider hooks installed (exe base %08X, cocos base %08X; tripwires fopen %s remove %s; "
                "audio reader %s); waiting for the server's broker at %s:%u", static_cast<unsigned>(bases[0]),
                static_cast<unsigned>(bases[1]), g_iatFopen ? "on" : "off", g_iatRemove ? "on" : "off",
                e.audioHooked ? "on (sounds may be owned)" : "OFF (sound names stay the game's own)", SERVICE_IP,
                static_cast<unsigned>(SERVICE_PORT));
}

void ContentProvider_Detach(void)
{
    if (!g_installed)
        return;
    Env& e = env();
    if (e.provider)
        e.provider->Stop();
    if (g_iatFopen && e.trueFopen)
        PatchSlot(g_iatFopen, reinterpret_cast<void*>(e.trueFopen), nullptr);
    if (g_iatRemove && e.trueRemove)
        PatchSlot(g_iatRemove, reinterpret_cast<void*>(e.trueRemove), nullptr);
    if (e.audioHooked)
    {
        // fopen_s first: no new RAM files; fread / fclose keep serving any still open.
        PatchSlot(g_iatFopenS, reinterpret_cast<void*>(e.trueFopenS), nullptr);
        if (!OpenMemFiles())
        {
            PatchSlot(g_iatFclose, reinterpret_cast<void*>(e.trueFclose), nullptr);
            PatchSlot(g_iatFread, reinterpret_cast<void*>(e.trueFread), nullptr);
        }
    }
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&g_fGetFileData, reinterpret_cast<PVOID>(Hook_GetFileData));
    DetourDetach(&g_fIsFileExist, reinterpret_cast<PVOID>(Hook_IsFileExist));
    DetourDetach(&g_fExistsLocalFile, reinterpret_cast<PVOID>(Hook_ExistsLocalFile));
    DetourDetach(&g_fIsFileAlreadyDownloaded, reinterpret_cast<PVOID>(Hook_IsFileAlreadyDownloaded));
    DetourDetach(&g_cpTrueGetTexture, reinterpret_cast<PVOID>(GetTextureThunk));
    DetourDetach(&g_fReplaceScene, reinterpret_cast<PVOID>(Hook_ReplaceScene));
    DetourDetach(&g_fPushScene, reinterpret_cast<PVOID>(Hook_PushScene));
    DetourDetach(&g_fPopScene, reinterpret_cast<PVOID>(Hook_PopScene));
    DetourDetach(&g_fRunWithScene, reinterpret_cast<PVOID>(Hook_RunWithScene));
    DetourDetach(&g_fDrawScene, reinterpret_cast<PVOID>(Hook_DrawScene));
    DetourDetach(&g_fAddLoadFile, reinterpret_cast<PVOID>(Hook_AddLoadFile));
    DetourDetach(&g_fAddLoadFilePriority, reinterpret_cast<PVOID>(Hook_AddLoadFilePriority));
    DetourTransactionCommit();
    e.detourCount = 0;
    g_installed = false;
}

#endif // CONTENT_PROVIDER
