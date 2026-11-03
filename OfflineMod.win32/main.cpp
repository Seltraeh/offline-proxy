/**
* @file main.cpp
* @author Arves100
* @date 30/10/2024
* @brief Entrypoint for Brave Frontier Windows offline mod
*/
#include "pch.h"
#include <detours/detours.h>
#include <serverconfig.h>
#include "fps_cap.h"
#include "console_log.h"
#include "content/cp_gate_flash.h"
#include "content/cp_name_fit.h"
#include "content/cp_post_quest.h"
#include "content/cp_hooks.h"
#include "content/cp_startup.h"

typedef HINTERNET(WINAPI* InternetConnectW_t)(
    _In_ HINTERNET     hInternet,
    _In_ LPCWSTR       lpszServerName,
    _In_ INTERNET_PORT nServerPort,
    _In_ LPCWSTR       lpszUserName,
    _In_ LPCWSTR       lpszPassword,
    _In_ DWORD         dwService,
    _In_ DWORD         dwFlags,
    _In_ DWORD_PTR     dwContext
);

typedef HINTERNET(WINAPI* InternetConnectA_t)(
    _In_ HINTERNET     hInternet,
    _In_ LPCSTR        lpszServerName,
    _In_ INTERNET_PORT nServerPort,
    _In_ LPCSTR        lpszUserName,
    _In_ LPCSTR        lpszPassword,
    _In_ DWORD         dwService,
    _In_ DWORD         dwFlags,
    _In_ DWORD_PTR     dwContext
);

typedef HINTERNET(WINAPI* HttpOpenRequestA_t)(
    _In_ HINTERNET hConnect,
    _In_ LPCSTR    lpszVerb,
    _In_ LPCSTR    lpszObjectName,
    _In_ LPCSTR    lpszVersion,
    _In_ LPCSTR    lpszReferrer,
    _In_ LPCSTR* lplpszAcceptTypes,
    _In_ DWORD     dwFlags,
    _In_ DWORD_PTR dwContext
);

typedef HINTERNET(WINAPI* HttpOpenRequestW_t)(
    _In_ HINTERNET hConnect,
    _In_ LPCWSTR   lpszVerb,
    _In_ LPCWSTR   lpszObjectName,
    _In_ LPCWSTR   lpszVersion,
    _In_ LPCWSTR   lpszReferrer,
    _In_ LPCWSTR* lplpszAcceptTypes,
    _In_ DWORD     dwFlags,
    _In_ DWORD_PTR dwContext
);

#ifdef OFFLINE_DEPLOY
typedef void (WINAPI* OfflineModStartup_t)(void);
static HMODULE g_ofmLib = nullptr;
static OfflineModStartup_t g_ofmStartup = nullptr;
#endif

static InternetConnectW_t TrueInternetConnectW = InternetConnectW;
static InternetConnectA_t TrueInternetConnectA = InternetConnectA;
static HttpOpenRequestA_t TrueHttpOpenRequestA = HttpOpenRequestA;
static HttpOpenRequestW_t TrueHttpOpenRequestW = HttpOpenRequestW;

static HINTERNET WINAPI MyInternetConnectA(
    _In_ HINTERNET     hInternet,
    _In_ LPCSTR        lpszServerName,
    _In_ INTERNET_PORT nServerPort,
    _In_ LPCSTR        lpszUserName,
    _In_ LPCSTR        lpszPassword,
    _In_ DWORD         dwService,
    _In_ DWORD         dwFlags,
    _In_ DWORD_PTR     dwContext
)
{
#ifndef OFFLINE_DEPLOY
    ConsoleLog("InternetConnectA: %s:%u (SVC:%x)\n", lpszServerName, nServerPort, dwService);
#endif

    if (strstr(lpszServerName, "microsoft.com") != nullptr || strstr(lpszServerName, "wikia.com") != nullptr || strstr(lpszServerName, "fandom.com") != nullptr)
        return TrueInternetConnectA(hInternet, lpszServerName, INTERNET_DEFAULT_HTTP_PORT, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

    return TrueInternetConnectA(hInternet, SERVICE_IP, SERVICE_PORT, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

static HINTERNET WINAPI MyInternetConnectW(
    _In_ HINTERNET     hInternet,
    _In_ LPCWSTR        lpszServerName,
    _In_ INTERNET_PORT nServerPort,
    _In_ LPCWSTR        lpszUserName,
    _In_ LPCWSTR        lpszPassword,
    _In_ DWORD         dwService,
    _In_ DWORD         dwFlags,
    _In_ DWORD_PTR     dwContext
)
{
#ifndef OFFLINE_DEPLOY
    ConsoleLogW(L"InternetConnectW: %s:%u (SVC:%x)\n", lpszServerName, nServerPort, dwService);
#endif

    if (wcswcs(lpszServerName, L"microsoft.com") != nullptr || wcswcs(lpszServerName, L"wikia.com") != nullptr || wcswcs(lpszServerName, L"fandom.com") != nullptr)
        return TrueInternetConnectW(hInternet, lpszServerName, INTERNET_DEFAULT_HTTP_PORT, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);

    return TrueInternetConnectW(hInternet, SERVICE_IP_W, SERVICE_PORT, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

static void PatchSecurityOptions(HINTERNET hInternet)
{
    DWORD dwFlags2;
    DWORD dwBuffLen = sizeof(dwFlags2);

    if (InternetQueryOption(hInternet, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags2, &dwBuffLen))
    {
#ifndef OFFLINE_DEPLOY
        ConsoleLog("patched options...\n");
#endif
        dwFlags2 |= SECURITY_SET_MASK;
        InternetSetOption(hInternet, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags2, sizeof(dwFlags2));
    }
}

static HINTERNET WINAPI MyHttpOpenRequestA(
    _In_ HINTERNET hConnect,
    _In_ LPCSTR    lpszVerb,
    _In_ LPCSTR    lpszObjectName,
    _In_ LPCSTR    lpszVersion,
    _In_ LPCSTR    lpszReferrer,
    _In_ LPCSTR* lplpszAcceptTypes,
    _In_ DWORD     dwFlags,
    _In_ DWORD_PTR dwContext
)
{
    dwFlags &= ~INTERNET_FLAG_SECURE;
    dwFlags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    auto ret = TrueHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

    if (!ret)
        return nullptr;

    PatchSecurityOptions(ret);
    return ret;
}

#if SERVICE_DISABLE_HTTPS
HINTERNET WINAPI MyHttpOpenRequestW(
    _In_ HINTERNET hConnect,
    _In_ LPCWSTR   lpszVerb,
    _In_ LPCWSTR   lpszObjectName,
    _In_ LPCWSTR   lpszVersion,
    _In_ LPCWSTR   lpszReferrer,
    _In_ LPCWSTR* lplpszAcceptTypes,
    _In_ DWORD     dwFlags,
    _In_ DWORD_PTR dwContext
)
{
    dwFlags &= ~INTERNET_FLAG_SECURE;
    dwFlags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    auto ret = TrueHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);

    if (!ret)
        return nullptr;

    PatchSecurityOptions(ret);
    return ret;
}
#endif

static void DetourDetach()
{
    // Its own transaction, like its attach (see DetourAttach below).
    Startup_Detach();
    ContentProvider_Detach();
    GateFlash_Detach();
    NameFit_Detach();
    PostQuest_Detach();

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueInternetConnectA, (PVOID)MyInternetConnectA);
    DetourDetach(&(PVOID&)TrueInternetConnectW, (PVOID)MyInternetConnectW);
#if SERVICE_DISABLE_HTTPS
    DetourDetach(&(PVOID&)TrueHttpOpenRequestA, (PVOID)MyHttpOpenRequestA);
    DetourDetach(&(PVOID&)TrueHttpOpenRequestW, (PVOID)MyHttpOpenRequestW);
#endif
    FpsCap_Detach();
    DetourTransactionCommit();
}

static void DetourAttach()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueInternetConnectA, (PVOID)MyInternetConnectA);
    DetourAttach(&(PVOID&)TrueInternetConnectW, (PVOID)MyInternetConnectW);
#if SERVICE_DISABLE_HTTPS
    DetourAttach(&(PVOID&)TrueHttpOpenRequestA, (PVOID)MyHttpOpenRequestA);
    DetourAttach(&(PVOID&)TrueHttpOpenRequestW, (PVOID)MyHttpOpenRequestW);
#endif
    FpsCap_Attach();
    DetourTransactionCommit();

    // Startup work replaced on the strength of the broker's coverage report: its
    // sites are checked here, on the untouched image, because the content provider
    // below detours one of them (the downloaded-name lookup).
    Startup_Prepare();

    // Separate transaction: Detours aborts a whole transaction when one attach
    // fails, and the content provider must never take the connection hooks or
    // the FPS cap down with it.  It verifies the client build first and
    // declines (logging why) on anything it does not recognise.
    ContentProvider_Attach();

    // The startup edits need the provider above: they go in only if every site
    // still holds the bytes Startup_Prepare saw, except exactly the provider's own
    // recorded detour, and decline on their own (logging why) otherwise.
    Startup_Attach();

    // The summon gate white-screen fix (#24): one verified code patch of its
    // own, independent of the provider's hooks and of its broker.
    GateFlash_Attach();
    // The unit info title name fit (#22-2): one verified call retarget of its own.
    NameFit_Attach();
    PostQuest_Attach();
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    (void)hinstDLL;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_DETACH)
    {
#ifdef OFFLINE_DEPLOY
        if (g_ofmLib)
        {
            FreeLibrary(g_ofmLib);
        }
#endif
        DetourDetach();
    }
    else if (fdwReason == DLL_PROCESS_ATTACH)
    {
#ifndef OFFLINE_DEPLOY
        // Hooks print through console_log.h, never straight to this console: a
        // console that is selecting text or paused blocks every write to it.
        if (!AllocConsole())
        {
            MessageBoxA(nullptr, "ALLOC_CONSOLE_FAILED", "DEBUG", MB_OK | MB_ICONERROR);
        }
        FILE* dummy;
        freopen_s(&dummy, "CONOUT$", "w", stdout);
        freopen_s(&dummy, "CONOUT$", "w", stderr);
#else
        g_ofmLib = LoadLibraryW(L"offlinemod.dll");
        if (!g_ofmLib)
        {
            MessageBoxA(nullptr, "Unable to find the offline mod component, the application will now exit!", "Fatal Error", MB_OK | MB_ICONERROR);
            return FALSE;
        }
        g_ofmStartup = (OfflineModStartup_t)GetProcAddress(g_ofmLib, "OfflineMod_startup");
        if (!g_ofmStartup)
        {
            MessageBoxA(nullptr, "The offline mod component is corrupted, the application will now exit!", "Fatal Error", MB_OK | MB_ICONERROR);
            FreeLibrary(g_ofmLib);
            return FALSE;
        }

        g_ofmStartup();
#endif

        DetourAttach();
    }

    return TRUE;
}
