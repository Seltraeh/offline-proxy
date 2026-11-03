"""Static proof of the audio reader's file contract, which the provider's RAM files emulate.

    python tests/fixtures/check_audio_reader.py [<extracted Appx folder>]

The provider serves owned sounds to the EXE's audio reader (x86 0xEC0030, the
override of SGAudioHandler::InitializeMediaStreamer, vtable 0x1961B04 slot 0)
by patching the EXE's msvcr120_app fopen_s / fread / fclose import slots
(OfflineMod.win32/content/cp_hooks*.cpp).  A RAM file only implements what the
reader does with its FILE*, so this checks, on the real EXE with capstone:

  1. fopen_s has exactly one call site in the whole EXE, inside the reader;
  2. the handler installed at startup (0xEB0BD0 -> ctor 0xEBFF60) has the
     vtable whose slot 0 is the reader;
  3. the reader opens with mode "rb", and the FILE* it receives (the slot whose
     address fopen_s gets) is read only as the stream argument of fread (both
     calls: size 1, count 210) and of fclose -- never passed to any other CRT
     stream function, never copied elsewhere;
  4. the reader calls no CRT stream function other than fopen_s, fread, fclose.

Exit status 0 when every check holds.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_ESP

BASE = 0x400000
READER, READER_END = 0xEC0030, 0xEC03D4
HANDLER_INSTALL, HANDLER_CTOR, HANDLER_VTABLE = 0xEB0BD0, 0xEBFF60, 0x1561B04
STREAM_FUNCS = {'fopen', 'fopen_s', 'fread', 'fwrite', 'fclose', 'fseek', 'ftell', '_fseeki64', '_ftelli64', 'feof',
                'ferror', 'fgetc', 'fgets', 'fputc', 'fputs', 'fflush', 'rewind', 'fgetpos', 'fsetpos', 'setvbuf',
                'fprintf', 'fscanf', '_fileno', 'clearerr', 'ungetc', 'getc', 'freopen', 'freopen_s', '_wfopen',
                '_wfopen_s'}
DEFAULT_APPX = r'C:\Users\Evan\BF\BraveFrontierAppxClient'
failures: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"{'ok  ' if ok else 'FAIL'}  {what}")
    if not ok:
        failures.append(what)


def main() -> int:
    appx = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_APPX)
    pe = pefile.PE(str(appx / 'BraveFrontier.Windows.exe'))
    mem = pe.get_memory_mapped_image()
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    iat = {}
    for d in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in d.imports:
            if imp.name:
                iat[imp.address] = f'{d.dll.decode()}!{imp.name.decode()}'
    crt = {va: name.split('!', 1)[1] for va, name in iat.items() if name.lower().startswith('msvcr120_app.dll!')}
    fopen_s = next(va for va, n in crt.items() if n == 'fopen_s')

    def iat_target(ins):
        if ins.mnemonic in ('call', 'jmp') and ins.operands and ins.operands[0].type == X86_OP_MEM \
                and ins.operands[0].mem.base == 0 and ins.operands[0].mem.index == 0:
            return ins.operands[0].mem.disp & 0xFFFFFFFF
        return None

    # 1. every reference to fopen_s's import slot in the whole EXE.  A linear
    # disassembly of .text stops at the first undecodable byte (under 10% of this
    # EXE), so this is a byte scan: any instruction using the slot (call [slot],
    # jmp [slot], mov reg, [slot]) contains its 4-byte VA; so does any stored copy.
    needle = struct.pack('<I', fopen_s)
    refs = []
    for sec in pe.sections:
        data = bytes(mem[sec.VirtualAddress:sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData)])
        at = data.find(needle)
        while at >= 0:
            refs.append(sec.VirtualAddress + at)
            at = data.find(needle, at + 1)
    in_reader = [r for r in refs if READER <= r < READER_END]
    check(len(refs) == 1 and len(in_reader) == 1,
          f'the fopen_s import slot (VA {fopen_s:#x}) is referenced once in the whole image, by the audio reader '
          f'({[hex(r) for r in refs]})')
    names = sum(bytes(mem).count(n) for n in (b'fopen_s\0',))
    check(names == 1, f'the name "fopen_s" occurs once in the image (its import entry: no GetProcAddress lookup) ({names})')

    # 2. the installed handler's vtable
    slot0 = struct.unpack_from('<I', mem, HANDLER_VTABLE)[0] - BASE
    ctor = list(md.disasm(bytes(mem[HANDLER_CTOR:HANDLER_CTOR + 0x40]), HANDLER_CTOR))
    sets_vtable = any(i.mnemonic == 'mov' and i.operands[1].type == X86_OP_IMM
                      and (i.operands[1].imm & 0xFFFFFFFF) == HANDLER_VTABLE + BASE for i in ctor)
    install = list(md.disasm(bytes(mem[HANDLER_INSTALL:HANDLER_INSTALL + 0xA8]), HANDLER_INSTALL))
    calls_ctor = any(i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM and i.operands[0].imm == HANDLER_CTOR
                     for i in install)
    sets_handler = any('setAudioHandler' in iat.get(iat_target(i) or 0, '') for i in install)
    check(slot0 == READER and sets_vtable and calls_ctor and sets_handler,
          'the handler installed at startup (setAudioHandler) has vtable 0x1961B04 whose slot 0 is the reader')

    # 3./4. the reader's FILE*
    insns = list(md.disasm(bytes(mem[READER:READER_END]), READER))
    # esp delta per instruction (linear: the reader keeps one stack depth per address)
    delta, d = {}, 0
    for i in insns:
        delta[i.address] = d
        if i.mnemonic == 'push':
            d -= 4
        elif i.mnemonic == 'pop':
            d += 4
        elif i.mnemonic in ('sub', 'add') and i.operands[0].type == X86_OP_REG and i.operands[0].reg == X86_REG_ESP \
                and i.operands[1].type == X86_OP_IMM:
            d += -i.operands[1].imm if i.mnemonic == 'sub' else i.operands[1].imm
        elif i.mnemonic == 'call' and i.operands[0].type == X86_OP_IMM:
            for r in md.disasm(bytes(mem[i.operands[0].imm:i.operands[0].imm + 0x600]), i.operands[0].imm):
                if r.mnemonic == 'ret':
                    d += r.operands[0].imm if r.operands else 0
                    break
        elif i.mnemonic in ('jmp',) and i.operands[0].type == X86_OP_IMM:
            pass
    by_addr = {i.address: i for i in insns}
    order = [i.address for i in insns]
    open_at = next(a for a in order if iat_target(by_addr[a]) == fopen_s)
    k = order.index(open_at)
    pushes = [by_addr[a] for a in order[max(0, k - 12):k] if by_addr[a].mnemonic == 'push']
    # cdecl right-to-left: the last three pushes are mode, path, &f
    mode_push, _path_push, slot_push = pushes[-3], pushes[-2], pushes[-1]
    mode_va = mode_push.operands[0].imm & 0xFFFFFFFF if mode_push.operands[0].type == X86_OP_IMM else 0
    mode = bytes(mem[mode_va - BASE:mode_va - BASE + 3]).split(b'\0')[0] if mode_va else b''
    check(mode == b'rb', f'the reader opens with mode "rb" ({mode!r})')
    lea = next(by_addr[a] for a in reversed(order[:order.index(slot_push.address)])
               if by_addr[a].mnemonic == 'lea' and by_addr[a].operands[0].type == X86_OP_REG
               and by_addr[a].operands[0].reg == slot_push.operands[0].reg)
    slot = delta[lea.address] + lea.operands[1].mem.disp      # frame offset of f
    uses, bad = [], []
    for idx, a in enumerate(order):
        i = by_addr[a]
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP and op.mem.index == 0 \
                    and delta[a] + op.mem.disp == slot and a != lea.address:
                if i.mnemonic != 'push':
                    bad.append((hex(a), i.mnemonic, i.op_str))
                    continue
                # the next call after this push consumes it
                nxt = next(by_addr[b] for b in order[idx + 1:] if by_addr[b].mnemonic == 'call')
                name = crt.get(iat_target(nxt) or 0, '?')
                uses.append((hex(a), name))
    stream_uses = sorted({n for _a, n in uses})
    check(not bad and stream_uses == ['fclose', 'fread'] and len(uses) == 3,
          f'the FILE* is only pushed to fread (twice) and fclose (once): {uses}{"; other uses " + str(bad) if bad else ""}')
    reads = []
    for idx, a in enumerate(order):
        if crt.get(iat_target(by_addr[a]) or 0) == 'fread':
            args = [by_addr[b] for b in order[max(0, idx - 8):idx] if by_addr[b].mnemonic == 'push'][-4:]
            size = args[2].operands[0].imm if args[2].operands[0].type == X86_OP_IMM else None
            count = args[1].operands[0].imm if args[1].operands[0].type == X86_OP_IMM else None
            reads.append((hex(a), size, count))
    check(len(reads) == 2 and all(r[1:] == (1, 0xD2) for r in reads), f'both freads read 210 single bytes: {reads}')
    called = sorted({crt[t] for t in (iat_target(i) for i in insns) if t in crt})
    check(set(called) & STREAM_FUNCS == {'fopen_s', 'fread', 'fclose'},
          f'the reader calls no other CRT stream function (CRT calls: {called})')

    print(f'\n{"PASS" if not failures else "FAIL"}: {len(failures)} failure(s)')
    for f in failures:
        print('  ', f)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
