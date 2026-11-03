/**
* @file cp_name_fit.h
* @brief Unit-info title name fit (#22-2): a long unit name shrinks to one line instead of wrapping.
*
* UnitDetailUserUnitScene's header (x86 0xCA5E70) creates the unit-name label through the label
* helper's shortest overload (0x387100), whose defaults reach the full overload (0x3874A0) as
* "wrap at the given width, never shrink".  A name too wide for that width -- "Intact Champion
* Amadream" -- therefore breaks onto a second line that grows up over the "Unit No."/rarity/element
* row.  The helper already has a single-line shrink-to-fit (0x2370B0: scale * text width > width ->
* scale down); this patch retargets only that one call so the full overload is reached with wrap off
* and shrink on, and the same text, colour, size, position and width.  Names that fit are drawn at
* scale 1, exactly as before.
*
* Compiled with the content provider (OFFLINEMOD_CONTENT_PROVIDER=1) for its build verification and
* log, installed on its own, and declined (one line in %TEMP%\offlinemod_content.log) unless the
* client is the exact supported build and every site matches its signature byte for byte.
*/
#pragma once

#include <serverconfig.h>

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER

//! Verifies the client build and retargets the unit-info title's name label call.
void NameFit_Attach(void);
//! Restores the stock call bytes (DLL_PROCESS_DETACH).
void NameFit_Detach(void);

#else

static inline void NameFit_Attach(void) {}
static inline void NameFit_Detach(void) {}

#endif
