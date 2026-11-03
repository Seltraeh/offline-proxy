/**
* @file console_log.cpp
* @brief Queued console output (see console_log.h).
*/
#include "pch.h"
#include "console_log.h"

#include <deque>
#include <string>

namespace {

//! Lines kept while the console is held. Past this the oldest are dropped and counted.
const size_t kMaxQueued = 1000;

INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
HANDLE g_out = INVALID_HANDLE_VALUE;
SRWLOCK g_lock = SRWLOCK_INIT;
CONDITION_VARIABLE g_queued = CONDITION_VARIABLE_INIT;
std::deque<std::wstring>* g_lines = nullptr;    // never freed: the writer lives until the process ends
unsigned long g_dropped = 0;

// WriteConsoleW on a handle of our own, not the CRT's stdout: when the
// process exits while the console is held, the writer dies mid-write, and it
// must not leave a CRT stream lock taken for the CRT's exit flush to wait on.
void Write(const wchar_t* text, size_t length)
{
    DWORD written = 0;
    WriteConsoleW(g_out, text, static_cast<DWORD>(length), &written, nullptr);
}

DWORD WINAPI WriterMain(void*)
{
    for (;;)
    {
        std::wstring line;
        unsigned long dropped;
        AcquireSRWLockExclusive(&g_lock);
        while (g_lines->empty())
            SleepConditionVariableSRW(&g_queued, &g_lock, INFINITE, 0);
        line.swap(g_lines->front());
        g_lines->pop_front();
        dropped = g_dropped;
        g_dropped = 0;
        ReleaseSRWLockExclusive(&g_lock);
        if (dropped)
        {
            wchar_t note[80];
            const int n = swprintf(note, 80, L"(%lu line(s) dropped while the console was held)\n", dropped);
            if (n > 0)
                Write(note, static_cast<size_t>(n));
        }
        Write(line.data(), line.size());
    }
}

BOOL CALLBACK Start(PINIT_ONCE, PVOID, PVOID*)
{
    // CONOUT$ exists only when DllMain's AllocConsole worked (never with OFFLINE_DEPLOY).
    g_out = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_out == INVALID_HANDLE_VALUE)
        return TRUE;
    g_lines = new std::deque<std::wstring>();
    HANDLE thread = CreateThread(nullptr, 0, WriterMain, nullptr, 0, nullptr);
    if (thread)
        CloseHandle(thread);
    else
    {
        delete g_lines;
        g_lines = nullptr;
    }
    return TRUE;
}

void Queue(std::wstring&& line)
{
    InitOnceExecuteOnce(&g_once, Start, nullptr, nullptr);
    if (!g_lines)
        return;
    AcquireSRWLockExclusive(&g_lock);
    if (g_lines->size() >= kMaxQueued)
    {
        g_lines->pop_front();
        ++g_dropped;
    }
    g_lines->push_back(std::move(line));
    ReleaseSRWLockExclusive(&g_lock);
    WakeConditionVariable(&g_queued);
}

} // namespace

void ConsoleLog(const char* fmt, ...)
{
    char text[1024];
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(text, sizeof text, fmt, ap);   // truncates, always terminated
    va_end(ap);
    if (n < 0)
        return;
    wchar_t wide[1024];
    const int w = MultiByteToWideChar(CP_ACP, 0, text, -1, wide, 1024);
    if (w > 1)
        Queue(std::wstring(wide, static_cast<size_t>(w - 1)));
}

void ConsoleLogW(const wchar_t* fmt, ...)
{
    wchar_t text[1024];
    text[0] = L'\0';
    va_list ap;
    va_start(ap, fmt);
    const int n = vswprintf(text, 1024, fmt, ap);
    va_end(ap);
    if (n < 0)
        text[1023] = L'\0';   // too long: keep what fits
    if (text[0])
        Queue(std::wstring(text));
}
