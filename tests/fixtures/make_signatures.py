"""Regenerate the content-provider hook signatures from a Brave Frontier Windows build.

    python tests/fixtures/make_signatures.py <extracted Appx folder>

Writes OfflineMod.win32/content/cp_signatures.h and
tests/fixtures/bf_2.19.6.0_signatures.json.  Every byte covered by an
IMAGE_REL_BASED_HIGHLOW base relocation is masked ('?'), because ASLR rewrites
it at load; the remaining bytes must match the running image exactly or the
provider declines to hook (see cp_hooks.cpp).  Needs `pip install pefile`.

The sites are the x86 functions recovered for docs/CONTENT_PROVIDER_WINDOWS_CONTRACT.md;
changing a client build means re-deriving them, not just re-running this.
"""
import hashlib
import json
import sys
from pathlib import Path

import pefile

SITES = [
    # name, module (0 exe / 1 cocos), rva, length
    ('getFileData', 1, 0x135EB0, 32),
    ('isFileExist', 1, 0x141F50, 32),
    ('getWritablePath', 1, 0x141DC0, 24),
    ('replaceScene', 1, 0x0FC8A0, 16),
    ('pushScene', 1, 0x0FC960, 16),
    ('popScene', 1, 0x0FC9B0, 16),
    ('runWithScene', 1, 0x0FC850, 16),
    ('drawScene', 1, 0x0FBB70, 16),
    ('existsLocalFile', 0, 0x237EB0, 48),
    ('isFileAlreadyDownloaded', 0, 0xE417E0, 40),
    ('getTexture', 0, 0x2353D0, 48),
    ('getTexture_readsite', 0, 0x2354D1, 32),
    ('pairTexture_read1', 0, 0x65FD29, 36),
    ('pairTexture_read2', 0, 0x65FDD6, 36),
    ('downloadWrite', 0, 0x223090, 32),
    # Phase C1 enqueue filter: FileLoader::addLoadFile (this, bool encode, std::string
    # by value; ret 1Ch, callee frees) and FileLoader::addLoadFilePriority (this, bool,
    # bool, std::string by value; ret 20h) -- their only queue entries
    # (docs/CONTENT_PROVIDER_WINDOWS_CONTRACT.md section 2).
    ('addLoadFile', 0, 0x634FA0, 48),
    ('addLoadFilePriority', 0, 0x1049A0, 48),
    # Session 15 audio reader (SGAudioHandler override, vtable 0x1961B04 slot 0):
    # the EXE's only fopen_s caller; owned sounds become RAM files through the
    # fopen_s / fread / fclose IAT slots.  Its prologue and the open + first
    # read (fopen_s(&f, path, "rb"), fread(buf, 1, 210, f)) --
    # tests/fixtures/check_audio_reader.py proves f reaches nothing but fread / fclose.
    ('audioReader', 0, 0xEC0030, 48),
    ('audioReaderOpen', 0, 0xEC01B1, 0xEC0204 - 0xEC01B1),
]
# Summon gate flash fix (#24, OfflineMod.win32/content/cp_gate_flash.cpp), verified
# separately from SITES so that neither feature can decline the other.  The
# trigger signature spans SummonsAnimeScene2::updateEvent from the patched call
# to its ret: the stock decision block, the overlay creation and the fade step
# the replacement jumps to.  tests/fixtures/check_gate_flash_site.py proves the
# jump is equivalent; changing a client build means re-running both.
GATE_FLASH_SITES = [
    ('summonsUpdateEvent', 0, 0x875F20, 48),            # SummonsAnimeScene2::updateEvent prologue
    ('gateFlashTrigger', 0, 0x8760EF, 0x87628E - 0x8760EF),
    ('superAnimListShared', 0, 0x631390, 48),           # SuperAnimList::shared, which the replacement calls
]
MODULES = ['BraveFrontier.Windows.exe', 'libcocos2d_v2.2.5_Windows_8.1.dll']
POST_QUEST_SITES = [
    ('resultRatingBranch', 0, 0xA25CCF, 0xA25CE2 - 0xA25CCF),
    ('friendFacebookBranch', 0, 0xA1F927, 0xA1F99C - 0xA1F927),
]
# Session 16 startup edits (OfflineMod.win32/content/cp_startup.cpp), verified on their own
# table so that they can never decline the provider: the census builder and each of its three
# null-guarded calls, the two null-safe readers that answer without it (the map lookup and
# existsLocalFile's own stat fallback), and the background-download prompt's flag read with the
# callee it redirects (SaveUtils::loadUserDefaults: entry and its callee-frees / "" exit).
# tests/fixtures/check_startup_sites.py proves what the edits rely on.
STARTUP_SITES = [
    ('census', 0, 0xE415D0, 48),                                   # downloaded-name map builder
    ('censusCallStartup', 0, 0xE427D8, 0xE427F5 - 0xE427D8),         # via applicationDidFinishLaunching
    ('censusCallLogin', 0, 0x8E32C4, 0x8E32E4 - 0x8E32C4),           # LoginScene::updateEvent FILE_CHECK
    ('censusCallMission', 0, 0xA03C98, 0xA03CA6 - 0xA03C98),         # MissionStartScene
    ('censusLookup', 0, 0xE417E0, 0xE417F2 - 0xE417E0),              # null map -> "not downloaded"
    ('censusExistsFallback', 0, 0x237EF5, 0x237F41 - 0x237EF5),      # null map -> _stat64i32 + fopen
    ('promptFlagRead', 0, 0x8E5199, 0x8E51F8 - 0x8E5199),            # loadUserDefaults("DLC_WARNING_MENU_FLG")
    ('loadUserDefaults', 0, 0x240300, 0x240346 - 0x240300),
    ('loadUserDefaultsExit', 0, 0x2405A2, 0x2405FF - 0x2405A2),
]
# Unit-info title name fit (#22-2, OfflineMod.win32/content/cp_name_fit.cpp): the one call in
# UnitDetailUserUnitScene's header build (0xCA5E70) that creates the unit-name label through the
# label helper's shortest overload, the full overload it is retargeted to, and the shrink-to-fit it
# enables there.  tests/fixtures/check_name_fit_site.py proves the argument layout the thunk relies on.
NAME_FIT_SITES = [
    ('unitTitleNameCall', 0, 0xCA718C, 0xCA71AD - 0xCA718C),       # push 0Ch ... call 0x387100; add esp,24h
    ('labelCreateFull', 0, 0x3874A0, 0x38758C - 0x3874A0),         # flags @+18h/@+20h, then 0x2370B0
    ('labelShrinkToFit', 0, 0x2370B0, 0x23717C - 0x2370B0),        # scale * width > max -> setScale
    # The unit-info skill popup's three description labels (BB/SBB/UBB, 0xCB6750): each loads its wrap width
    # with movss xmm3, [274.0]; the patch points those three operands at a narrower width (Evan, round 5).
    ('popupDescWidthBB', 0, 0xCB988D, 8),
    ('popupDescWidthEx', 0, 0xCB9920, 8),
    ('popupDescWidthUl', 0, 0xCB9981, 8),
    # Vertical fit: the three description calls themselves (call 0x387100), retargeted to PopupDescThunk.
    ('popupDescCallBB', 0, 0xCB98C7, 0xCB98D0 - 0xCB98C7),
    ('popupDescCallEx', 0, 0xCB993E, 0xCB9947 - 0xCB993E),
    ('popupDescCallUl', 0, 0xCB99B7, 0xCB99C0 - 0xCB99B7),
    # What the vertical fit calls: the label's setString (force flag, stored text +14Ch, wrap width +114h),
    # its setPosition(x, y) layout, and the client's std::string::assign used to copy the text.
    ('labelSetText', 0, 0x38C3B0, 0x38C427 - 0x38C3B0),
    ('labelSetTextWidth', 0, 0x38C72C, 0x38C746 - 0x38C72C),
    ('labelLayout', 0, 0x38CDC0, 0x38CE2A - 0x38CDC0),
    ('stringAssign', 0, 0xDE250, 0xDE278 - 0xDE250),
]


def load(path: Path):
    pe = pefile.PE(str(path), fast_load=False)
    relocs = set()
    for blk in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', []):
        for e in blk.entries:
            if e.type == 3:
                relocs.add(e.rva)
    return pe, relocs


def main() -> int:
    appx = Path(sys.argv[1])
    repo = Path(__file__).resolve().parents[2]
    images = [load(appx / m) for m in MODULES]
    out = {'modules': [], 'sites': []}
    for name, (pe, _) in zip(MODULES, images):
        raw = (appx / name).read_bytes()
        out['modules'].append({
            'file': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
            'timeDateStamp': pe.FILE_HEADER.TimeDateStamp,
            'sizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
            'entryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        })
    def signature(name, mod, rva, n):
        pe, relocs = images[mod]
        data = pe.get_data(rva, n)
        mask = ['x'] * n
        for r in relocs:
            for k in range(4):
                p = r + k - rva
                if 0 <= p < n:
                    mask[p] = '?'
        return {'name': name, 'module': mod, 'rva': rva, 'bytes': data.hex().upper(), 'mask': ''.join(mask)}

    out['sites'] = [signature(*site) for site in SITES]
    out['gate_flash_sites'] = [signature(*site) for site in GATE_FLASH_SITES]
    out['post_quest_sites'] = [signature(*site) for site in POST_QUEST_SITES]
    out['startup_sites'] = [signature(*site) for site in STARTUP_SITES]
    out['name_fit_sites'] = [signature(*site) for site in NAME_FIT_SITES]

    fixture = repo / 'tests' / 'fixtures' / 'bf_2.19.6.0_signatures.json'
    fixture.write_text(json.dumps(out, indent=1) + '\n', encoding='utf-8')

    lines = [
        '/**',
        ' * @file cp_signatures.h',
        ' * @brief GENERATED by tests/fixtures/make_signatures.py -- do not edit by hand.',
        ' *',
        ' * Supported client: gumi.BraveFrontier 2.19.6.0 x86 (Windows).',
    ]
    for m in out['modules']:
        lines.append(f" *   {m['file']}  sha256 {m['sha256']}  {m['size']} bytes")
    lines += [' */', '#pragma once', '', '#include "cp_core.h"', '', 'namespace cp {', '',
              'static const ModuleIdentity kSupportedModules[2] = {']
    for m in out['modules']:
        lines.append(f"    {{ \"{m['file']}\", 0x{m['timeDateStamp']:08X}u, 0x{m['sizeOfImage']:08X}u, 0x{m['entryPoint']:08X}u }},")
    lines.append('};')
    for table, key in (('kSiteSignatures', 'sites'), ('kGateFlashSignatures', 'gate_flash_sites'),
                       ('kPostQuestSignatures', 'post_quest_sites'), ('kStartupSignatures', 'startup_sites'),
                       ('kNameFitSignatures', 'name_fit_sites')):
        lines += ['', f"static const SiteSignature {table}[{len(out[key])}] = {{"]
        for s in out[key]:
            lines.append(f"    {{ \"{s['name']}\", {s['module']}u, 0x{s['rva']:06X}u,")
            lines.append(f"      \"{s['bytes']}\",")
            lines.append(f"      \"{s['mask']}\" }},")
        lines.append('};')
    lines += ['', '} // namespace cp', '']
    header = repo / 'OfflineMod.win32' / 'content' / 'cp_signatures.h'
    header.write_text('\n'.join(lines), encoding='utf-8')
    print(f'wrote {header} and {fixture}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
