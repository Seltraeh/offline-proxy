"""Prove on the supported x86 executable what the Session 16 startup edits rely on.

Run: python tests/fixtures/check_startup_sites.py [<extracted Appx folder>] [--negative]

Reads BraveFrontier.Windows.exe without modifying it (OfflineMod.win32/content/cp_startup.cpp,
cp_startup_logic.cpp).  The client run is still required for the behaviour itself.

census   0xE415D0 builds the downloaded-name map (global VA 0x1997E20, its value CCInteger at
         0x1997E24).  The edit leaves a call out, so the global stays null:
         - it takes no argument and none of its callers reads a result;
         - every direct reference to it in the image is one of three calls, each made only when
           the global is null; nothing else (no absolute pointer, no other branch) reaches it;
         - every reference to the global is a write by the builder, a release, or a read that
           tests for null first; existsLocalFile's null path is the real file check
           (_stat64i32 + fopen), the map lookup's null path answers "not downloaded";
         - with a null map nothing is inserted into the FileLoader's complete list (0xE427B0),
           so the parallel check-list filter, whose workers use that lookup, does not run
           (0xE413A0 returns at once on an empty list) -- the check list is then decided by
           existsLocalFile on the main thread.
prompt   0x8E51A8 is `call SaveUtils::loadUserDefaults` for "DLC_WARNING_MENU_FLG":
         - the callee is __cdecl (plain ret, the caller pops 18h), takes the key string by value
           and destroys it on every exit, and returns a C string -- "" (0x168987D) when unset;
         - the caller only tests and byte-compares the result: null or "" -> the prompt
           (0x8E51F8, BG_DLC_PROMPT_MSG / _TITLE), anything else -> state 10, no prompt;
         - it is LoginScene::updateEvent's only read of that key.

--negative runs the same proof on copies with one changed byte each and requires that every
copy fails (a census call without its null test, a reader without a null test, a callee-frees
exit removed, the prompt branch inverted, the call retargeted).
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

CENSUS = 0xE415D0
GLOBAL_VA = 0x1997E20
INTEGER_VA = 0x1997E24
PROMPT_CALL = 0x8E51A8
LOAD_USER_DEFAULTS = 0x240300
EMPTY_VA = 0x168987D
KEY_VA = 0x1689734


class Proof:
    def __init__(self, image: bytearray, pe: pefile.PE):
        self.mem = image
        self.pe = pe
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.failures = []
        self.text = [(s.VirtualAddress, s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData))
                     for s in pe.sections if s.Characteristics & 0x20000000]

    def check(self, ok: bool, what: str, detail=''):
        print(('PASS  ' if ok else 'FAIL  ') + what + (f'  -- {detail}' if not ok and detail else ''))
        if not ok:
            self.failures.append(what)

    def ins(self, rva: int, count: int = 30):
        return list(self.md.disasm(bytes(self.mem[rva:rva + 16 * count]), self.base + rva, count))

    def cstr(self, va: int) -> bytes:
        rva = va - self.base
        end = self.mem.index(0, rva)
        return bytes(self.mem[rva:end])

    def branch_refs(self, target: int) -> list[tuple[int, str]]:
        """Every offset in the executable sections that decodes as a direct call/jmp/jcc rel32 to target."""
        out = []
        for lo, hi in self.text:
            data = bytes(self.mem[lo:hi])
            for i in range(len(data) - 5):
                op = data[i]
                if op in (0xE8, 0xE9) and lo + i + 5 + struct.unpack_from('<i', data, i + 1)[0] == target:
                    out.append((lo + i, 'call' if op == 0xE8 else 'jmp'))
                elif op == 0x0F and 0x80 <= data[i + 1] <= 0x8F and i + 6 <= len(data) \
                        and lo + i + 6 + struct.unpack_from('<i', data, i + 2)[0] == target:
                    out.append((lo + i, 'jcc'))
        return out

    def dword_refs(self, value: int) -> list[int]:
        pat = struct.pack('<I', value)
        out, i = [], self.mem.find(pat)
        while i != -1:
            out.append(i)
            i = self.mem.find(pat, i + 1)
        return out


def prove(p: Proof) -> None:
    b = p.base
    # ---------------------------------------------------------------- census ----
    body = p.ins(CENSUS, 160)
    rets = [i for i in body if i.mnemonic == 'ret']
    p.check(bool(rets) and rets[0].op_str == '' and rets[0].address - b == 0xE417D2,
            'census 0xE415D0 ends in a plain ret at 0xE417D2 (no stack arguments)')
    early = body[:24]
    reads_args = [i for i in early[:20] if ('ecx' in i.op_str.split(',')[-1] or 'edx' in i.op_str.split(',')[-1])
                  and not i.mnemonic.startswith('call') and i.address - b < 0xE4161A]
    p.check(not reads_args, 'census reads no register argument before writing ecx/edx',
            [f'{i.address - b:X} {i.mnemonic} {i.op_str}' for i in reads_args])
    writes = [i.address - b for i in body if i.mnemonic == 'mov' and f'[{GLOBAL_VA:#x}]' in i.op_str.split(',')[0]]
    p.check(writes == [0xE4166A], 'census writes the map global once (0xE4166A)', [hex(w) for w in writes])

    refs = p.branch_refs(CENSUS)
    p.check(sorted(r for r, _ in refs) == [0x8E32DF, 0xA03CA1, 0xE427E1] and all(k == 'call' for _, k in refs),
            'exactly three direct references to the census, all calls (byte scan of every executable offset)',
            [(hex(r), k) for r, k in refs])
    p.check(not p.dword_refs(b + CENSUS), 'no absolute pointer to the census anywhere in the image (tables, vtables)')
    guards = {
        0x8E32DF: (0x8E32C4, 'cmp', 0x8E32DD, 'jne', 0x8E32E4),     # cmp [g],0 ... jne over the call
        0xA03CA1: (0xA03C98, 'cmp', 0xA03C9F, 'jne', 0xA03CA6),
        0xE427E1: (0xE427D8, 'mov', 0xE427DF, 'jne', 0xE427EF),     # mov eax,[g]; test eax,eax; jne
    }
    for call, (test_at, test_kind, branch_at, branch, skip_to) in guards.items():
        seq = p.ins(test_at, 8)
        t = next((i for i in seq if i.address - b == test_at), None)
        j = next((i for i in seq if i.address - b == branch_at), None)
        ok = (t is not None and t.mnemonic == test_kind and f'{GLOBAL_VA:#x}' in t.op_str
              and j is not None and j.mnemonic == branch and j.operands[0].imm - b == skip_to)
        if test_kind == 'mov':
            ok = ok and any(i.mnemonic == 'test' and i.op_str == 'eax, eax' for i in seq if test_at < i.address - b < branch_at)
        p.check(ok, f'census call {call:X} runs only when the map global is null (test {test_at:X}, {branch} over the call)')
        after = p.ins(call + 5, 1)[0]
        p.check('eax' not in after.op_str or after.op_str.startswith('eax,') and after.mnemonic == 'mov',
                f'census call {call:X}: the next instruction does not read eax ({after.mnemonic} {after.op_str})')

    expected_global = {
        0x237EF5: 'cmp-null', 0x8E32C4: 'cmp-null', 0x8E490D: 'read-null', 0x8E4926: 'guarded', 0x8E493A: 'clear',
        0xA03C98: 'cmp-null', 0xA04684: 'read-null', 0xA04693: 'guarded', 0xA046A7: 'clear',
        0xE4166A: 'write', 0xE4177D: 'guarded-builder', 0xE417E5: 'read-null', 0xE427D8: 'read-null', 0xE427E6: 'read-null',
    }
    seen = set()
    for lo, hi in p.text:
        for ins in p.md.disasm(bytes(p.mem[lo:hi]), b + lo):
            if f'{GLOBAL_VA:#x}' in ins.op_str or f'{INTEGER_VA:#x}' in ins.op_str:
                seen.add((ins.address - b, ins.mnemonic, ins.op_str))
    refs_global = sorted({a for a, _, s in seen if f'{GLOBAL_VA:#x}' in s})
    raw_refs = sorted(r - 1 for r in p.dword_refs(GLOBAL_VA))
    # A linear decode stops at the first undecodable byte (most of .text): the raw dword scan is authoritative.
    covered = all(any(0 <= r - a <= 6 for a in expected_global) for r in raw_refs)
    p.check(covered and len(raw_refs) == 14, 'every raw occurrence of the global VA is one of the 14 known references',
            [hex(r) for r in raw_refs])
    for at, kind in expected_global.items():
        seq = p.ins(at, 6)
        first = seq[0]
        if kind == 'cmp-null':
            ok = first.mnemonic == 'cmp' and first.op_str.endswith(', 0') and seq[1].mnemonic in ('je', 'jne') \
                or first.mnemonic == 'cmp' and first.op_str.endswith(', 0') and any(i.mnemonic in ('je', 'jne') for i in seq[1:6])
        elif kind == 'read-null':
            reg = first.op_str.split(',')[0]
            ok = first.mnemonic == 'mov' and any(i.mnemonic == 'test' and i.op_str == f'{reg}, {reg}' for i in seq[1:5]) \
                and not any(f'[{reg}' in i.op_str for i in seq[1:next(k for k, i in enumerate(seq) if i.mnemonic == 'test')])
        elif kind == 'guarded':
            ok = first.mnemonic == 'mov'                               # inside a block entered only when non-null
        elif kind == 'clear':
            ok = first.mnemonic == 'mov' and first.op_str.endswith(', 0')
        elif kind == 'write':
            ok = first.mnemonic == 'mov' and first.op_str.startswith(f'dword ptr [{GLOBAL_VA:#x}]')
        else:                                                         # guarded-builder: its own fresh map
            ok = first.mnemonic == 'mov' and 'ecx' in first.op_str
        p.check(ok, f'{at:X} uses the map global safely when it is null ({kind}: {first.mnemonic} {first.op_str})')
    # The guarded reads sit behind the read-null tests just before them.
    for guard, guarded in ((0x8E490D, 0x8E4926), (0xA04684, 0xA04693)):
        seq = p.ins(guard, 5)
        je = next((i for i in seq if i.mnemonic == 'je'), None)
        p.check(je is not None and je.operands[0].imm - b > guarded, f'{guarded:X} runs only after {guard:X} found the map non-null')
    # existsLocalFile 0x237EB0: null map -> its own file check.
    seq = p.ins(0x237EF5, 45)
    je = seq[1]
    stat = [i for i in seq if i.mnemonic == 'call' and 'dword ptr [' in i.op_str]
    stat_slot = int(stat[0].op_str.split('[')[1].rstrip(']'), 16) - b if stat else 0
    stat_name = next((imp.name.decode() for d in p.pe.DIRECTORY_ENTRY_IMPORT for imp in d.imports
                      if imp.address - b == stat_slot and imp.name), '')
    p.check(je.mnemonic == 'je' and je.operands[0].imm - b == 0x237F08 and stat_name == '_stat64i32',
            f'existsLocalFile: a null map goes to {stat_name or "?"} on the LocalState path (0x237F08)')
    fopen_check = [i for i in seq if i.mnemonic == 'call' and i.op_str.startswith('0x') and int(i.op_str, 16) - b == 0x237E50]
    p.check(bool(fopen_check), 'existsLocalFile: then the non-empty fopen check 0x237E50')
    seq = p.ins(0xE417E5, 6)
    tst = next((k for k, i in enumerate(seq) if i.mnemonic == 'test' and i.op_str == 'esi, esi'), None)
    p.check(seq[0].mnemonic == 'mov' and tst is not None and seq[tst + 1].mnemonic == 'je'
            and seq[tst + 1].operands[0].imm - b == 0xE4183D and not any('[esi' in i.op_str for i in seq[1:tst]),
            'map lookup 0xE417E0: null -> 0xE4183D, nothing read through it first')
    tail = p.ins(0xE4183D, 2)
    p.check(tail[1].mnemonic == 'xor' and tail[1].op_str == 'al, al', 'map lookup: ...which answers false')
    seq = p.ins(0xE427E6, 4)
    p.check(seq[0].mnemonic == 'mov' and seq[1].mnemonic == 'test' and seq[2].mnemonic == 'je'
            and seq[2].operands[0].imm - b == 0xE4286A,
            '0xE427B0: no map -> nothing inserted into the FileLoader complete list (jumps to its epilogue)')
    seq = p.ins(0xE413DB, 2)
    p.check(seq[0].mnemonic == 'cmp' and seq[0].op_str == 'dword ptr [ebx + 4], 0' and seq[1].mnemonic == 'jbe'
            and seq[1].operands[0].imm - b == 0xE4159F,
            'parallel check-list filter 0xE413A0: an empty complete list returns without starting its workers')
    # ---------------------------------------------------------------- prompt ----
    seq = p.ins(0x8E5199, 12)
    names = [(i.address - b, i.mnemonic, i.op_str) for i in seq]
    push = next((i for i in seq if i.mnemonic == 'push'), None)
    p.check(push is not None and push.operands[0].imm == KEY_VA and p.cstr(KEY_VA) == b'DLC_WARNING_MENU_FLG',
            'prompt: the key built on the stack is "DLC_WARNING_MENU_FLG"')
    call = next((i for i in seq if i.address - b == PROMPT_CALL), None)
    p.check(call is not None and call.mnemonic == 'call' and call.size == 5 and call.operands[0].imm - b == LOAD_USER_DEFAULTS,
            'prompt: 0x8E51A8 is a 5-byte call rel32 to SaveUtils::loadUserDefaults 0x240300')
    after = [i for i in seq if i.address - b > PROMPT_CALL][:3]
    p.check([(i.mnemonic, i.op_str) for i in after[:2]] == [('add', 'esp, 0x18'), ('test', 'eax, eax')]
            and after[2].mnemonic == 'je' and after[2].operands[0].imm - b == 0x8E51F8,
            'prompt: the caller pops the 18h-byte key, and null goes to the prompt (0x8E51F8)', names)
    loop = p.ins(0x8E51B4, 26)
    cmp_src = loop[0]
    p.check(cmp_src.mnemonic == 'mov' and cmp_src.operands[1].imm == EMPTY_VA and p.cstr(EMPTY_VA) == b'',
            'prompt: the value is compared with "" (0x168987D)')
    stores = [i for i in loop if i.mnemonic.startswith('mov') and i.op_str.startswith('dword ptr [') and 'eax' in i.op_str.split(',')[1]]
    p.check(not stores, 'prompt: the value is only tested and compared, never stored', stores)
    state = next((i for i in loop if i.mnemonic == 'mov' and i.op_str == 'dword ptr [edi + 0x214], 0xa'), None)
    je_prompt = [i for i in loop if i.mnemonic == 'je' and i.operands[0].imm - b == 0x8E51F8]
    p.check(state is not None and state.address - b == 0x8E51E9 and je_prompt,
            'prompt: equal to "" -> the prompt; different -> state 10 (0x8E51E9), as after an answer')
    dialog = p.ins(0x8E51F8, 60)
    texts = {p.cstr(i.operands[0].imm) for i in dialog if i.mnemonic == 'push' and i.operands and i.operands[0].type == 2
             and 0x1600000 < i.operands[0].imm < 0x1700000}
    p.check({b'BG_DLC_PROMPT_MSG', b'BG_DLC_PROMPT_TITLE'} <= texts, 'prompt: 0x8E51F8 shows BG_DLC_PROMPT_TITLE / _MSG')
    refs = [r for r in p.dword_refs(KEY_VA)]
    users = sorted(r - 1 for r in refs)
    p.check(any(0x8E2960 <= u < 0x8E6100 for u in users), 'the key string is referenced by LoginScene::updateEvent')
    in_login = [u for u in users if 0x8E2960 <= u < 0x8E6100]
    p.check(in_login == [0x8E519E], 'LoginScene::updateEvent reads DLC_WARNING_MENU_FLG at exactly one place', [hex(u) for u in in_login])
    # loadUserDefaults: __cdecl, frees the by-value key on every exit, returns a C string.
    lud = p.ins(LOAD_USER_DEFAULTS, 400)
    # 0x240542's ret belongs to an EH catch funclet (mov eax, <continuation>; ret), not the function.
    ret = next((i for i in lud if i.address - b == 0x2405FE), None)
    p.check(ret is not None and ret.mnemonic == 'ret' and ret.op_str == '',
            'loadUserDefaults ends in a plain ret at 0x2405FE (cdecl: the caller pops)')
    frees = [i.address - b for i in lud if i.mnemonic == 'push' and i.op_str == 'dword ptr [ebp + 8]']
    checks = [i.address - b for i in lud if i.mnemonic == 'cmp' and i.op_str == 'dword ptr [ebp + 0x1c], 0x10']
    p.check(len(frees) >= 3 and 0x2405A4 in frees and 0x2405D6 in frees and 0x24058C in checks and 0x2405BE in checks,
            'loadUserDefaults destroys the by-value key (capacity >= 16 -> operator delete) on both exits',
            (frees, checks))
    rv = [i for i in lud if i.mnemonic == 'mov' and i.op_str.startswith('eax,')]
    p.check(any(i.op_str == f'eax, {EMPTY_VA:#x}' and i.address - b == 0x2405DE for i in rv)
            and any(i.op_str == 'eax, esi' and i.address - b == 0x2405AC for i in rv),
            'loadUserDefaults returns a stored string or "" when unset')


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    folder = Path(args[0]) if args else Path(__file__).resolve().parents[3] / 'BraveFrontierAppxClient'
    exe = folder / 'BraveFrontier.Windows.exe'
    fixture = json.loads(Path(__file__).with_name('bf_2.19.6.0_signatures.json').read_text())
    raw = exe.read_bytes()
    if hashlib.sha256(raw).hexdigest() != fixture['modules'][0]['sha256']:
        print('FAIL  unsupported executable')
        return 1
    pe = pefile.PE(data=raw)
    image = bytearray(pe.get_memory_mapped_image())
    for sig in fixture.get('startup_sites', []):
        data = bytes(image[sig['rva']:sig['rva'] + len(sig['mask'])])
        ok = all(m == '?' or a == b2 for a, b2, m in zip(data, bytes.fromhex(sig['bytes']), sig['mask']))
        print(('PASS  ' if ok else 'FAIL  ') + f'signature {sig["name"]} matches the executable')
    proof = Proof(image, pe)
    prove(proof)
    if '--negative' not in sys.argv:
        print(f'startup sites: {"PASS" if not proof.failures else "FAIL"} ({len(proof.failures)} failure(s))')
        return 1 if proof.failures else 0
    controls = [
        ('a census call without its null test (jne -> nop nop)', 0xA03C9F, b'\x90\x90'),
        ('a release site without its null test (test ecx,ecx -> mov eax,[ecx])', 0x8E491D, b'\x8B\x01'),
        ('the prompt null test inverted (je -> jne)', 0x8E51B2, b'\x75'),
        ('the call retargeted (rel32 + 1)', PROMPT_CALL + 1, None),
        ('a callee-frees exit removed (push [ebp+8] -> nops)', 0x2405D6, b'\x90\x90\x90'),
        ('an extra direct call to the census', 0x8E3290, None),
    ]
    all_failed = True
    for what, at, patch in controls:
        mutated = bytearray(image)
        if patch is None and what.startswith('the call'):
            rel = struct.unpack_from('<i', mutated, at)[0] + 1
            struct.pack_into('<i', mutated, at, rel)
        elif patch is None:
            struct.pack_into('<Bi', mutated, at, 0xE8, CENSUS - (at + 5))
        else:
            mutated[at:at + len(patch)] = patch
        control = Proof(mutated, pe)
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            prove(control)
        print(('PASS  ' if control.failures else 'FAIL  ') + f'negative control "{what}": {len(control.failures)} check(s) fail')
        all_failed = all_failed and bool(control.failures)
    print(f'startup sites (negative controls): {"PASS" if all_failed and not proof.failures else "FAIL"}')
    return 0 if all_failed and not proof.failures else 1


if __name__ == '__main__':
    raise SystemExit(main())
