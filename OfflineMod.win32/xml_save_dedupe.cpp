/**
* @file xml_save_dedupe.cpp
* @brief See xml_save_dedupe.h.
*
* Everything the hook calls is an export of libcocos2d_v2.2.5_Windows_8.1.dll (tinyxml2 is linked into it), so
* nothing depends on an address inside the game's own EXE:
*   ?SaveFile@XMLDocument@tinyxml2@@QAE?AW4XMLError@2@PBD_N@Z   the hooked call: fopen_s(path, "w"), print, fclose
*   ??0XMLPrinter@tinyxml2@@QAE@PAU_iobuf@@_N@Z                 XMLPrinter(FILE* = 0, bool compact): 0 = memory
*   ?Print@XMLDocument@tinyxml2@@QAEXPAVXMLPrinter@2@@Z         prints the whole document into the printer
*   ?CStr@XMLPrinter@tinyxml2@@QBEPBDXZ / ?CStrSize@...          the printed text and its size (with the NUL)
*   ??1XMLPrinter@tinyxml2@@UAE@XZ                               frees the printer's buffers
* The printer lives in a stack buffer far larger than the class (its last field is near +0x100).
*/
#include "pch.h"
#include "xml_save_dedupe.h"
#include "xml_save_dedupe_logic.h"

#include <detours/detours.h>
#include <serverconfig.h>
#include <stdarg.h>
#include <stdio.h>

#if CONTENT_PROVIDER
#include "content/cp_log.h"
#else
#include "console_log.h"
#endif

namespace {

const char* const kCocosDll = "libcocos2d_v2.2.5_Windows_8.1.dll";
const char* const kSaveFile = "?SaveFile@XMLDocument@tinyxml2@@QAE?AW4XMLError@2@PBD_N@Z";
const char* const kPrinterCtor = "??0XMLPrinter@tinyxml2@@QAE@PAU_iobuf@@_N@Z";
const char* const kDocPrint = "?Print@XMLDocument@tinyxml2@@QAEXPAVXMLPrinter@2@@Z";
const char* const kCStr = "?CStr@XMLPrinter@tinyxml2@@QBEPBDXZ";
const char* const kCStrSize = "?CStrSize@XMLPrinter@tinyxml2@@QBEHXZ";
const char* const kPrinterDtor = "??1XMLPrinter@tinyxml2@@UAE@XZ";
const size_t kPrinterStorage = 4096;

// __thiscall members called through __fastcall with a dummy EDX (this in ECX, the rest on the stack, callee pops).
typedef int (__fastcall* SaveFile_t)(void* doc, void* edx, const char* filename, bool compact);
typedef void* (__fastcall* PrinterCtor_t)(void* self, void* edx, FILE* fp, bool compact);
typedef void (__fastcall* DocPrint_t)(void* doc, void* edx, void* printer);
typedef const char* (__fastcall* CStr_t)(const void* self, void* edx);
typedef int (__fastcall* CStrSize_t)(const void* self, void* edx);
typedef void (__fastcall* PrinterDtor_t)(void* self, void* edx);

SaveFile_t g_trueSaveFile = nullptr;
PrinterCtor_t g_printerCtor = nullptr;
DocPrint_t g_docPrint = nullptr;
CStr_t g_cstr = nullptr;
CStrSize_t g_cstrSize = nullptr;
PrinterDtor_t g_printerDtor = nullptr;
xmlsave::Deduper* g_deduper = nullptr;    // never freed: the hook may run until the process ends

void LogLine(const char* fmt, ...)
{
    char text[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
#if CONTENT_PROVIDER
    CP_LOG_INFO("%s", text);
#else
    ConsoleLog("%s\n", text);
#endif
}

bool StatFile(const std::string& path, unsigned long long* size)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data)
        || (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        return false;
    *size = (static_cast<unsigned long long>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    return true;
}

// No C++ objects with destructors here: __try needs a frame without unwinding.
bool RenderDocument(void* doc, bool compact, unsigned char* storage, const char** text, int* size)
{
    __try
    {
        g_printerCtor(storage, nullptr, nullptr, compact);
        g_docPrint(doc, nullptr, storage);
        *text = g_cstr(storage, nullptr);
        *size = g_cstrSize(storage, nullptr);
        return *text != nullptr && *size >= 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

void DestroyPrinter(unsigned char* storage)
{
    __try
    {
        g_printerDtor(storage, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
}

int __fastcall MySaveFile(void* doc, void* edx, const char* filename, bool compact)
{
    if (!filename || !g_deduper)
        return g_trueSaveFile(doc, edx, filename, compact);

    alignas(16) unsigned char storage[kPrinterStorage];
    const char* text = nullptr;
    int size = 0;
    if (!RenderDocument(doc, compact, storage, &text, &size))
    {
        // A half-built printer is left alone rather than destroyed; the save itself is untouched.
        LogLine("xml-save: could not print %s in memory; saving it normally", filename);
        return g_trueSaveFile(doc, edx, filename, compact);
    }
    std::string printed(text, static_cast<size_t>(size));
    DestroyPrinter(storage);

    bool skipped = false;
    const unsigned long long writtenBefore = g_deduper->Written();
    const int result = g_deduper->Save(filename, printed,
        [&]() { return g_trueSaveFile(doc, edx, filename, compact); }, &skipped);
    // The provider's log appends synchronously (open, write, close per line) on this, the main thread, so the
    // hook logs only its first writes, the first skip and every 1000th skip: the game saves thousands of times.
    if (!skipped && writtenBefore < 8)
        LogLine("xml-save: wrote %s (%d bytes printed, result %d)", filename, size, result);
    else if (skipped && g_deduper->Skipped() % 1000 == 1)
        LogLine("xml-save: %llu identical save(s) skipped, %llu written (latest skip: %s)",
                g_deduper->Skipped(), g_deduper->Written(), filename);
    return result;
}

} // namespace

void XmlSaveDedupe_Attach(void)
{
    HMODULE cocos = GetModuleHandleA(kCocosDll);
    if (!cocos)
    {
        LogLine("xml-save: DECLINED: %s is not loaded", kCocosDll);
        return;
    }
    PVOID save = (PVOID)GetProcAddress(cocos, kSaveFile);
    g_printerCtor = (PrinterCtor_t)GetProcAddress(cocos, kPrinterCtor);
    g_docPrint = (DocPrint_t)GetProcAddress(cocos, kDocPrint);
    g_cstr = (CStr_t)GetProcAddress(cocos, kCStr);
    g_cstrSize = (CStrSize_t)GetProcAddress(cocos, kCStrSize);
    g_printerDtor = (PrinterDtor_t)GetProcAddress(cocos, kPrinterDtor);
    if (!save || !g_printerCtor || !g_docPrint || !g_cstr || !g_cstrSize || !g_printerDtor)
    {
        LogLine("xml-save: DECLINED: missing tinyxml2 export(s) save=%p ctor=%p print=%p cstr=%p size=%p dtor=%p",
                save, g_printerCtor, g_docPrint, g_cstr, g_cstrSize, g_printerDtor);
        return;
    }
    g_deduper = new xmlsave::Deduper(StatFile);
    g_trueSaveFile = (SaveFile_t)save;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG err = DetourAttach(&(PVOID&)g_trueSaveFile, (PVOID)MySaveFile);
    LONG commit = (err == NO_ERROR) ? DetourTransactionCommit() : (DetourTransactionAbort(), err);
    if (err != NO_ERROR || commit != NO_ERROR)
    {
        LogLine("xml-save: DECLINED: DetourAttach %ld, commit %ld", err, commit);
        g_trueSaveFile = (SaveFile_t)save;
        g_deduper = nullptr;    // the hook is not in place; nothing will call it
        return;
    }
    LogLine("xml-save: OK: XMLDocument::SaveFile at %p skips writes identical to the last one", save);
}

void XmlSaveDedupe_Detach(void)
{
    if (!g_deduper)
        return;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)g_trueSaveFile, (PVOID)MySaveFile);
    DetourTransactionCommit();
    LogLine("xml-save: detached: %llu written, %llu skipped", g_deduper->Written(), g_deduper->Skipped());
}
