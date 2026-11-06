/**
* @file xml_save_dedupe.h
* @brief Skip tinyxml2 saves that would rewrite a file with the bytes it already holds.
*
* The client rewrites LocalState\XMLFileProcessor.xml (11 KB) through tinyxml2's XMLDocument::SaveFile every
* time it sets one of the file's keys -- and it sets them on every screen change, mostly to the values they
* already have.  Each rewrite is a create + write + close in the app's LocalState: 160-180 ms of main-thread time
* per screen change, measured on 2026-11-05 (docs/MENU_STUTTER_FINDINGS_2026-11-05.md).  The hook prints the
* document in memory first and writes only when the text changed or the file is not what the last write left.
*/
#pragma once

//! Detours XMLDocument::SaveFile(const char*, bool) in the cocos2d DLL, in its own transaction.  Declines
//! (logging why) when an export is missing; the game then saves exactly as before.
void XmlSaveDedupe_Attach(void);
void XmlSaveDedupe_Detach(void);
