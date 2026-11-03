/**
* @file cp_startup.h
* @brief Startup work replaced on the strength of the broker's coverage report (Session 16):
* the LocalState census and the background-download prompt (cp_startup_internal.h).
*
* Startup_Prepare checks every startup site's masked signature on the untouched image, before
* the content provider attaches (it detours one of them); Startup_Attach installs the edits after
* the provider, only if every site still holds those bytes except the provider's own recorded
* detour.  Anything else logs one DECLINED line and the game keeps both.  Each decision is taken
* per call from the live report.
*/
#pragma once

#include <serverconfig.h>

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER
void Startup_Prepare();
void Startup_Attach();
void Startup_Detach();
#else
static inline void Startup_Prepare() {}
static inline void Startup_Attach() {}
static inline void Startup_Detach() {}
#endif
