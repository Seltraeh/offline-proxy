#pragma once
#include <serverconfig.h>

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER
void PostQuest_Attach();
void PostQuest_Detach();
#else
static inline void PostQuest_Attach() {}
static inline void PostQuest_Detach() {}
#endif
