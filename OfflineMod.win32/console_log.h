/**
* @file console_log.h
* @brief Lines for the debug console that never make the caller wait.
*
* Without OFFLINE_DEPLOY the proxy opens a console (DllMain) and prints each
* redirected connection to it. A console stops taking output while text is
* selected in it (one click with QuickEdit on, or Edit > Mark) or while it is
* paused, and every write then waits until it resumes. These prints run on the
* game's own threads -- the GumiLive login's InternetConnectW runs on the main
* thread -- so one stray click on the console, which opens over the title,
* froze the title at its first touch with no login request sent. A line is
* queued here instead and written by a thread of the proxy's own: a held
* console only delays the console.
*/
#pragma once

//! printf-style console line; returns at once. Does nothing without a console.
void ConsoleLog(const char* fmt, ...);

//! The wide twin of ConsoleLog.
void ConsoleLogW(const wchar_t* fmt, ...);
