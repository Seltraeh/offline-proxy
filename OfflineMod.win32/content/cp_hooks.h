/**
* @file cp_hooks.h
* @brief Game-side hooks of the authoritative content provider.
*
* Compiled only with OFFLINEMOD_CONTENT_PROVIDER=1, and active at runtime
* only when (1) the client is the exact supported build -- module identity
* plus every hook site's masked byte signature -- and (2) the server's
* content broker reports itself enabled.  Anything else leaves the game on
* its own LocalState cache, unchanged, with one diagnostic line in
* %TEMP%\offlinemod_content.log.
*
* Recovered Windows contract: docs/CONTENT_PROVIDER_WINDOWS_CONTRACT.md.
*/
#pragma once

#include <serverconfig.h>

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER

//! Verifies the client build and installs the hooks in their own Detours transaction.
void ContentProvider_Attach(void);
//! Removes the hooks and IAT patches (DLL_PROCESS_DETACH).
void ContentProvider_Detach(void);

#else

static inline void ContentProvider_Attach(void) {}
static inline void ContentProvider_Detach(void) {}

#endif
