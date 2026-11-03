/**
* @file cp_log.h
* @brief Content provider diagnostics: %TEMP%\offlinemod_content.log + OutputDebugString.
*
* Inside the AppContainer %TEMP% is the package's AC\Temp folder, never
* LocalState, so the log is not mistaken for (or mixed with) cached assets.
* The file is capped and rotated once (offlinemod_content.log.1).
*/
#pragma once

namespace cp {

enum LogLevel { LogDebug = 0, LogInfo = 1, LogWarn = 2, LogError = 3 };

void Log(LogLevel level, const char* fmt, ...);

//! Full path of the current log file (empty until the first write).
const char* LogPath();

//! Tests redirect the log into their own folder.
void SetLogDirectoryForTests(const char* dir);

} // namespace cp

#define CP_LOG_DEBUG(...) ::cp::Log(::cp::LogDebug, __VA_ARGS__)
#define CP_LOG_INFO(...)  ::cp::Log(::cp::LogInfo, __VA_ARGS__)
#define CP_LOG_WARN(...)  ::cp::Log(::cp::LogWarn, __VA_ARGS__)
#define CP_LOG_ERROR(...) ::cp::Log(::cp::LogError, __VA_ARGS__)
