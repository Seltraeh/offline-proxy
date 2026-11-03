/**
* @file cp_gate_flash.h
* @brief Summon gate white-screen fix (#24): the reveal flash follows the final gate's opening.
*
* SummonsAnimeScene2::updateEvent turns the screen white when the GLOBAL
* SuperAnimList holds exactly three animations and the third has reached
* frame 45 (x86 0x8760EF..0x8761C1).  Any unrelated animation on screen (the
* header's energy-overflow glow, a download icon) shifts that count, so the
* white either covers a gate still waiting for its tap or never comes at all.
* This patch replaces only that decision: white starts when an opening-gate
* animation (GachaGateOpen*) that was seen starting in this scene reaches
* frame 45 -- the frame the stock rule uses -- whatever else is on screen.
* The overlay itself, its fade, input, the script and the reveal stay the
* game's own code.
*
* Compiled with the content provider (OFFLINEMOD_CONTENT_PROVIDER=1) because it
* shares its build verification and log, but installed on its own: it needs no
* broker, and it declines (keeping the stock trigger, with one line in
* %TEMP%\offlinemod_content.log) unless the client is the exact supported
* build and the patched code matches its signature byte for byte.
*/
#pragma once

#include <serverconfig.h>

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER

//! Verifies the client build and patches the white-screen trigger.
void GateFlash_Attach(void);
//! Restores the stock trigger bytes (DLL_PROCESS_DETACH).
void GateFlash_Detach(void);

#else

static inline void GateFlash_Attach(void) {}
static inline void GateFlash_Detach(void) {}

#endif
