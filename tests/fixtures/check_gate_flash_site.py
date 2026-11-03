"""Static proof that the summon gate flash patch (OfflineMod.win32/content/cp_gate_flash.cpp)
can replace the white-overlay trigger of SummonsAnimeScene2::updateEvent by a jump.

    python tests/fixtures/check_gate_flash_site.py [<extracted Appx folder>]

The patch overwrites the 5-byte `call SuperAnimList::shared` at x86 RVA 0x8760EF
with `jmp GateFlashThunk`.  The thunk restores every register and then jumps to
one of the two places the stock decision block itself ends at:

    0x8761C3  create the white overlay (fillRect) -- the block's "yes"
    0x876238  the overlay fade step                -- the block's "no"

so the stock instructions 0x8760EF..0x8761C2 never run.  That is only correct
if nothing after the block depends on what the block computed.  This script
reads the real EXE (read-only) and checks, with capstone:

  1. the patch site is exactly `E8 rel32` calling SuperAnimList::shared (0x631390);
  2. every edge leaving the block goes to 0x8761C3, 0x876238 or the epilogue
     0x87627B, and no jump from anywhere in the EXE lands inside the block;
  3. the stack pointer is balanced on every edge leaving the block (callee
     `ret N` read from the callees), so jumping from the block's start leaves
     esp exactly where the stock path does;
  4. the C++ exception state ([esp+58h], the frame's try level) is -1 on entry
     and on every exit, so skipping the block's temporary state 3 is invisible;
  5. from each target to the epilogue, the code reads no register value the
     block computed (sub-register precise), only edi (the scene), esp and ebp
     and registers that every path into that target leaves as call-clobbered
     garbage; and it reads no stack slot that the block writes.

Exit status 0 when every check holds; the report names any failure.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_ESP

BASE = 0x400000
FUNC = 0x875F20          # SummonsAnimeScene2::updateEvent
SITE = 0x8760EF          # call SuperAnimList::shared -> patched to jmp thunk
YES = 0x8761C3           # create the overlay
NO = 0x876238            # fade step
EPILOGUE = 0x87627B
FUNC_END = 0x87628E      # one past the final ret
SHARED = 0x631390
TRY_LEVEL = 0x58         # [esp+58h] at the block's entry (the EH frame's state)
SAVED_SLOTS = {0x0: 'cookie', 0x4: 'edi', 0x8: 'esi', 0xC: 'ebx', 0x50: 'SEH next', 0x54: 'SEH handler'}
# The one indirect call after the targets: the fade step's `call [eax+14h]` on the
# overlay's CCRGBAProtocol (setOpacity(GLubyte), thiscall: pops its one argument).
INDIRECT_RET = {0x876272: 4}

DEFAULT_APPX = r'C:\Users\Evan\BF\BraveFrontierAppxClient'

# Sub-register parts, so that `mov ax, ..` followed by a read of ax is not a read of eax.
PARTS = {}
for r in ('a', 'b', 'c', 'd'):
    full = f'e{r}x'
    PARTS[full] = {f'{full}.l', f'{full}.h', f'{full}.u'}
    PARTS[f'{r}x'] = {f'{full}.l', f'{full}.h'}
    PARTS[f'{r}l'] = {f'{full}.l'}
    PARTS[f'{r}h'] = {f'{full}.h'}
for r in ('si', 'di', 'bp', 'sp'):
    PARTS[f'e{r}'] = {f'e{r}.w', f'e{r}.u'}
    PARTS[r] = {f'e{r}.w'}
GPR = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')
CALL_READS = PARTS['ecx'] | PARTS['edx']          # thiscall / fastcall, conservatively
CALL_WRITES = PARTS['eax'] | PARTS['ecx'] | PARTS['edx']

failures: list[str] = []


def check(ok: bool, what: str) -> None:
    print(f"{'ok  ' if ok else 'FAIL'}  {what}")
    if not ok:
        failures.append(what)


class Exe:
    def __init__(self, path: Path):
        self.pe = pefile.PE(str(path))
        if self.pe.OPTIONAL_HEADER.ImageBase != BASE:
            raise SystemExit(f'unexpected image base {self.pe.OPTIONAL_HEADER.ImageBase:#x}')
        self.mem = self.pe.get_memory_mapped_image()
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        text = next(s for s in self.pe.sections if s.Name.rstrip(b'\0') == b'.text')
        self.text = (text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize)

    def insns(self, start: int, end: int) -> list:
        return list(self.md.disasm(bytes(self.mem[start:end]), start))

    def ret_imm(self, rva: int) -> int:
        """Bytes a callee pops on return: its first `ret N` (these callees have one)."""
        for ins in self.md.disasm(bytes(self.mem[rva:rva + 0x400]), rva):
            if ins.mnemonic == 'ret':
                return ins.operands[0].imm if ins.operands else 0
            if ins.mnemonic == 'int3':
                break
        raise SystemExit(f'cannot read the ret of {rva:#x}')


def target(ins) -> int | None:
    if ins.operands and ins.operands[0].type == X86_OP_IMM:
        return ins.operands[0].imm
    return None


def is_jump(ins) -> bool:
    return ins.mnemonic.startswith('j')


def successors(ins) -> list[int]:
    if ins.mnemonic == 'ret' or (ins.mnemonic == 'mov' and ins.op_str == 'esp, ebp'):
        return []                           # the frame teardown ends every walk here
    if is_jump(ins):
        out = [target(ins)]
        if ins.mnemonic != 'jmp':
            out.append(ins.address + ins.size)
        return out
    return [ins.address + ins.size]


def stack_effect(exe: Exe, ins) -> int | None:
    """esp change of one instruction (None for anything not modelled)."""
    m = ins.mnemonic
    if m == 'push':
        return -4
    if m == 'pop':
        return 4
    if m == 'call':
        t = target(ins)
        return INDIRECT_RET.get(ins.address) if t is None else exe.ret_imm(t)
    if m in ('sub', 'add') and ins.operands[0].type == X86_OP_REG and ins.operands[0].reg == X86_REG_ESP:
        if ins.operands[1].type != X86_OP_IMM:
            return None
        return -ins.operands[1].imm if m == 'sub' else ins.operands[1].imm
    if m == 'mov' and ins.op_str == 'esp, ebp':
        return 0
    _, written = ins.regs_access()
    return None if X86_REG_ESP in written else 0


def esp_slots(ins, delta: int):
    """(frame offset, size, is_write) of [esp+disp] operands, relative to esp at the block entry."""
    out = []
    for i, op in enumerate(ins.operands):
        if op.type == X86_OP_MEM and op.mem.base == X86_REG_ESP and op.mem.index == 0:
            write = i == 0 and ins.mnemonic in ('mov', 'movss', 'movd', 'movq', 'movdqu', 'movaps', 'movups')
            out.append((delta + op.mem.disp, op.size, write))
    return out


def walk(exe: Exe, entry: int, insns: dict, stop: set):
    """Forward walk: esp delta at each instruction (consistent at merges) and the leaving edges."""
    delta = {entry: 0}
    work = [entry]
    edges = []                              # (from, to, esp delta on arrival)
    while work:
        a = work.pop()
        ins = insns[a]
        eff = stack_effect(exe, ins)
        if eff is None:
            failures.append(f'unmodelled stack effect at {a:#x}: {ins.mnemonic} {ins.op_str}')
            continue
        for s in successors(ins):
            nd = delta[a] + (0 if is_jump(ins) else eff)
            if s in stop or s not in insns:
                edges.append((a, s, nd))
            elif s in delta:
                if delta[s] != nd:
                    failures.append(f'esp disagrees at {s:#x}: {delta[s]} vs {nd}')
            else:
                delta[s] = nd
                work.append(s)
    return delta, edges


def reg_access(exe: Exe, ins):
    """(parts read, parts fully defined) of one instruction."""
    r, w = ins.regs_access()
    reads, writes = set(), set()
    for x in r:
        reads |= PARTS.get(exe.md.reg_name(x), set())
    for x in w:
        writes |= PARTS.get(exe.md.reg_name(x), set())
    m = ins.mnemonic
    if m == 'call':
        reads |= CALL_READS
        writes |= CALL_WRITES
    if m in ('xor', 'sub') and len(ins.operands) == 2 and all(o.type == X86_OP_REG for o in ins.operands) \
            and ins.operands[0].reg == ins.operands[1].reg:
        reads -= PARTS.get(exe.md.reg_name(ins.operands[0].reg), set())     # zeroing idiom
    if m in ('push', 'pop', 'call', 'ret'):
        writes -= PARTS['esp']              # esp is tracked by the stack walk, never "defined" here
    return reads, writes


def liveness(exe: Exe, start: int, insns: dict, delta: dict):
    """Register parts and frame slots read before being written on any path from `start`."""
    order = sorted(a for a in insns if a in delta)
    succ = {a: [s for s in successors(insns[a]) if s in delta] for a in order}
    use, kill = {}, {}
    for a in order:
        ins = insns[a]
        reads, writes = reg_access(exe, ins)
        su, sd = set(), set()
        for off, size, write in esp_slots(ins, delta[a]):
            (sd if write else su).add(off)
        if ins.mnemonic == 'push':
            sd.add(delta[a] - 4)
        if ins.mnemonic == 'pop':
            su.add(delta[a])
        use[a], kill[a] = (reads, su), (writes, sd)
    live = {a: (set(), set()) for a in order}
    changed = True
    while changed:
        changed = False
        for a in reversed(order):
            out_r, out_s = set(), set()
            for s in succ[a]:
                out_r |= live[s][0]
                out_s |= live[s][1]
            nr = use[a][0] | (out_r - kill[a][0])
            ns = use[a][1] | (out_s - kill[a][1])
            if (nr, ns) != live[a]:
                live[a] = (nr, ns)
                changed = True
    return live[start]


def garbage_at_exits(exe: Exe, block: dict, delta: dict) -> dict:
    """For each exit: register parts whose last definition on EVERY path from the site is a
    call's clobber (eax/ecx/edx after a call) -- values nothing can meaningfully depend on."""
    # state: part -> True (garbage) / False (computed value, or unknown at entry)
    start = {p: False for g in GPR for p in PARTS[g]}
    state = {SITE: start}
    work = [SITE]
    out = {}
    while work:
        a = work.pop()
        ins = block[a]
        s = dict(state[a])
        reads, writes = reg_access(exe, ins)
        for p in writes:
            s[p] = ins.mnemonic == 'call' and p in CALL_WRITES
        for n in successors(ins):
            if n in (YES, NO, EPILOGUE):
                prev = out.get(n)
                out[n] = s if prev is None else {p: prev[p] and s[p] for p in s}
            elif n in block:
                prev = state.get(n)
                merged = s if prev is None else {p: prev[p] and s[p] for p in s}
                if merged != prev:
                    state[n] = merged
                    work.append(n)
    return {k: {p for p, g in v.items() if g} for k, v in out.items()}


def branch_targets_into(exe: Exe, lo: int, hi: int) -> list:
    """(offset, target) of every byte offset in .text that, decoded as E8/E9 rel32,
    0F 8x rel32 or EB/7x/E0-E3 rel8, would branch into [lo, hi)."""
    a0, a1 = exe.text
    code = bytes(exe.mem[a0:a1])
    out = []
    for off in range(len(code) - 5):
        b = code[off]
        va = a0 + off
        t = None
        if b in (0xE8, 0xE9):
            t = va + 5 + struct.unpack_from('<i', code, off + 1)[0]
        elif b == 0x0F and 0x80 <= code[off + 1] <= 0x8F:
            t = va + 6 + struct.unpack_from('<i', code, off + 2)[0]
        elif b == 0xEB or 0x70 <= b <= 0x7F or 0xE0 <= b <= 0xE3:
            t = va + 2 + struct.unpack_from('<b', code, off + 1)[0]
        if t is not None and lo <= t < hi:
            out.append((va, t))
    return out


def pointers_into(exe: Exe, lo: int, hi: int) -> list:
    """Every 4-byte value at any offset of any section equal to an image VA in [lo, hi)."""
    out = []
    for sec in exe.pe.sections:
        data = bytes(exe.mem[sec.VirtualAddress:sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData)])
        for off in range(len(data) - 3):
            v = struct.unpack_from('<I', data, off)[0] - BASE
            if lo <= v < hi:
                out.append((sec.Name.rstrip(b'\0').decode(), hex(sec.VirtualAddress + off), hex(v)))
    return out


def main() -> int:
    appx = Path(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_APPX)
    exe = Exe(appx / 'BraveFrontier.Windows.exe')
    func = {i.address: i for i in exe.insns(FUNC, FUNC_END)}
    check(FUNC_END - 1 in func and func[FUNC_END - 1].mnemonic == 'ret',
          'updateEvent disassembles linearly to its ret at 0x87628D')

    # 1. the site
    site = func.get(SITE)
    check(site is not None and site.mnemonic == 'call' and target(site) == SHARED and site.size == 5
          and bytes(site.bytes) == bytes.fromhex('E89CB2DBFF'),
          'patch site 0x8760EF is the 5-byte call SuperAnimList::shared (E8 9C B2 DB FF)')
    check(exe.ret_imm(SHARED) == 0, 'SuperAnimList::shared takes no stack arguments (plain ret)')

    # 2. block exits; nothing enters the block from outside
    block = {a: i for a, i in func.items() if SITE <= a < YES}
    delta, edges = walk(exe, SITE, block, {YES, NO, EPILOGUE})
    exits = {to for _, to, _ in edges}
    check(exits == {YES, NO, EPILOGUE},
          f'the block leaves only to 0x8761C3 / 0x876238 / 0x87627B (found {sorted(hex(x) for x in exits)})')
    check(all(a in delta for a in block), 'every block instruction is reachable from the site')
    # Linear disassembly of all of .text stops at the first undecodable byte (it
    # covers under 10% of this EXE), so the whole-image claims are byte scans:
    # every offset decoded as each direct branch encoding (a superset of the real
    # instructions), and every 4-byte value anywhere in the image (jump tables,
    # function pointers, EH tables) compared against the block's addresses.
    branch_hits = branch_targets_into(exe, SITE + 1, YES)
    foreign = [(hex(a), hex(t)) for a, t in branch_hits if not (FUNC <= a < FUNC_END)]
    check(not foreign, f'no direct branch encoding at any offset of .text (outside updateEvent) targets the inside of '
                       f'the block ({foreign[:5]})')
    own = set(block)
    internal = [(hex(a), hex(t)) for a, t in branch_hits
                if FUNC <= a < FUNC_END and a in func and a not in own and target(func[a]) == t]
    check(not internal, f'inside updateEvent no instruction outside the block branches into it ({internal})')
    stored = pointers_into(exe, SITE + 1, YES)
    check(not stored, f'no address inside the block is stored anywhere in the image ({stored[:5]})')

    # 3. stack balance on every exit edge
    bad = [(hex(a), hex(to), d) for a, to, d in edges if d != 0]
    check(not bad, f'esp is balanced on every exit edge ({bad})')

    # 4. try level: -1 before the block, -1 on every exit
    last_state = None
    for a, ins in sorted(func.items()):
        if FUNC < a < SITE and ins.mnemonic == 'mov' and ins.op_str.startswith('dword ptr [esp + 0x58]'):
            last_state = ins.operands[1].imm & 0xFFFFFFFF if ins.operands[1].type == X86_OP_IMM else None
    check(last_state == 0xFFFFFFFF, 'try level is -1 before the block (last write: mov [esp+58h], -1)')
    level = {SITE: -1}
    work = [SITE]
    exit_levels: dict[int, set] = {}
    while work:
        a = work.pop()
        ins = block[a]
        lv = level[a]
        for off, size, write in esp_slots(ins, delta[a]):
            if off == TRY_LEVEL and write:
                v = ins.operands[1].imm & 0xFFFFFFFF if ins.operands[1].type == X86_OP_IMM else None
                lv = -1 if v == 0xFFFFFFFF else v
        for n in successors(ins):
            if n in (YES, NO, EPILOGUE):
                exit_levels.setdefault(n, set()).add(lv)
            elif n in block and n not in level:
                level[n] = lv
                work.append(n)
    check(set(exit_levels) == {YES, NO, EPILOGUE} and all(v == {-1} for v in exit_levels.values()),
          f'try level is -1 on every exit of the block ({ {hex(k): sorted(v) for k, v in exit_levels.items()} })')

    # 5. what the code after each target reads
    garbage = garbage_at_exits(exe, block, delta)
    block_writes = set()
    for a, ins in block.items():
        for off, size, write in esp_slots(ins, delta[a]):
            if write:
                block_writes.update(range(off, off + size))
        if ins.mnemonic == 'push':
            block_writes.update(range(delta[a] - 4, delta[a]))
    tail = {a: i for a, i in func.items() if YES <= a < FUNC_END}
    keep = PARTS['edi'] | PARTS['esp'] | PARTS['ebp']
    for start in (YES, NO):
        tdelta, _ = walk(exe, start, tail, set())
        regs, slots = liveness(exe, start, tail, tdelta)
        computed = regs - keep - garbage.get(start, set())
        check(not computed, f'from {start:#x} no register value computed by the block is read '
                            f'(live-in {sorted(regs)}; call-clobbered on every path in: '
                            f'{sorted(garbage.get(start, set()) & regs)})')
        foreign = sorted(s for s in slots if s not in SAVED_SLOTS)
        check(not foreign, f'from {start:#x} every stack slot read is written first, except the prologue\'s '
                           f'saved slots ({[hex(s) for s in foreign]})')
        clobbered = sorted(s for s in slots if any(b in block_writes for b in range(s, s + 4)))
        check(not clobbered, f'from {start:#x} no slot read was written by the skipped block '
                             f'({[hex(s) for s in clobbered]})')

    print(f'\n{"PASS" if not failures else "FAIL"}: {len(failures)} failure(s)')
    for f in failures:
        print('  ', f)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
