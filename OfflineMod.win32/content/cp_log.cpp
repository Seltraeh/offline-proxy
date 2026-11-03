/**
* @file cp_log.cpp
* @brief Content provider diagnostics (see cp_log.h).
*/
#include "cp_log.h"

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>

namespace cp {

namespace {

const DWORD kMaxLogBytes = 8u * 1024u * 1024u;

CRITICAL_SECTION g_lock;
INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
char g_dir[MAX_PATH] = { 0 };
char g_path[MAX_PATH] = { 0 };
LARGE_INTEGER g_qpcStart = {};
LARGE_INTEGER g_qpcFreq = {};

BOOL CALLBACK InitLog(PINIT_ONCE, PVOID, PVOID*)
{
    InitializeCriticalSection(&g_lock);
    QueryPerformanceFrequency(&g_qpcFreq);
    QueryPerformanceCounter(&g_qpcStart);
    return TRUE;
}

const char* kLevel[] = { "DEBUG", "INFO ", "WARN ", "ERROR" };

} // namespace

void SetLogDirectoryForTests(const char* dir)
{
    InitOnceExecuteOnce(&g_once, InitLog, nullptr, nullptr);
    EnterCriticalSection(&g_lock);
    strncpy_s(g_dir, dir, _TRUNCATE);
    g_path[0] = 0;
    LeaveCriticalSection(&g_lock);
}

const char* LogPath()
{
    return g_path;
}

void Log(LogLevel level, const char* fmt, ...)
{
    InitOnceExecuteOnce(&g_once, InitLog, nullptr, nullptr);

    char msg[1024];
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    const double ms = g_qpcFreq.QuadPart
        ? 1000.0 * static_cast<double>(now.QuadPart - g_qpcStart.QuadPart) / static_cast<double>(g_qpcFreq.QuadPart)
        : 0.0;
    int n = sprintf_s(msg, "%10.1f %5lu %s ", ms, GetCurrentThreadId(), kLevel[level & 3]);
    if (n < 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    const int m = vsnprintf_s(msg + n, sizeof msg - n - 2, _TRUNCATE, fmt, ap);
    va_end(ap);
    n = m < 0 ? static_cast<int>(strlen(msg)) : n + m;
    msg[n++] = '\n';
    msg[n] = 0;

    OutputDebugStringA(msg);

    EnterCriticalSection(&g_lock);
    if (!g_path[0])
    {
        if (!g_dir[0])
        {
            const DWORD len = GetTempPathA(MAX_PATH, g_dir);
            if (len == 0 || len >= MAX_PATH)
                g_dir[0] = 0;
        }
        if (g_dir[0])
        {
            strcpy_s(g_path, g_dir);
            const size_t l = strlen(g_path);
            if (l && g_path[l - 1] != '\\' && g_path[l - 1] != '/')
                strcat_s(g_path, "\\");
            strcat_s(g_path, "offlinemod_content.log");
        }
    }
    if (g_path[0])
    {
        HANDLE h = CreateFileA(g_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE)
        {
            LARGE_INTEGER size = {};
            GetFileSizeEx(h, &size);
            if (size.QuadPart > kMaxLogBytes)
            {
                CloseHandle(h);
                char rotated[MAX_PATH + 4];
                sprintf_s(rotated, "%s.1", g_path);
                MoveFileExA(g_path, rotated, MOVEFILE_REPLACE_EXISTING);
                h = CreateFileA(g_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            }
            if (h != INVALID_HANDLE_VALUE)
            {
                DWORD written = 0;
                WriteFile(h, msg, static_cast<DWORD>(n), &written, nullptr);
                CloseHandle(h);
            }
        }
    }
    LeaveCriticalSection(&g_lock);
}

} // namespace cp
