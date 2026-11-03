"""Prove, from the client binary, what OfflineMod.win32/content/cp_name_fit.cpp's thunk relies on (#22-2).

    python tests/fixtures/check_name_fit_site.py [<extracted Appx folder>]

The patch turns the unit-info header's `call 0x387100` (the unit-name label, RVA 0xCA71A5) into a call
to NameFitThunk, which calls the label helper's full overload 0x3874A0 directly with "wrap" off and
"shrink to fit" on.  Each check below is one fact that has to hold for that to be equivalent apart from
those two flags; any mismatch prints FAIL and the script exits 1.  Needs pefile and capstone.
"""
import sys
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

APPX = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r'C:\Users\Evan\BF\BraveFrontierAppxClient')
pe = pefile.PE(str(APPX / 'BraveFrontier.Windows.exe'))
mem = pe.get_memory_mapped_image()
md = Cs(CS_ARCH_X86, CS_MODE_32)
failures = 0


def ins(rva, count):
    return [f'{i.mnemonic} {i.op_str}'.strip() for i in md.disasm(bytes(mem[rva:rva + 16 * count]), rva)][:count]


def at(rva):
    return ins(rva, 1)[0]


def check(label, cond, detail=''):
    global failures
    print(('PASS  ' if cond else 'FAIL  ') + label + ('' if cond else f'  -- {detail}'))
    failures += 0 if cond else 1


def calls(rva, n, target):
    return any(i == f'call 0x{target:x}' for i in ins(rva, n))


def push_seq_before_call(fn_rva, n, target):
    """The instructions of fn up to its call to target."""
    seq = ins(fn_rva, n)
    for k, i in enumerate(seq):
        if i == f'call 0x{target:x}':
            return seq[:k + 2]
    return []


# 1. The site: arguments as the thunk reads them, the call, and the caller's own cleanup.
site = ins(0xCA718C, 12)
check('site: push 0Ch (the int), colour slot, float slot, edx=7, ecx=edx+33h, then call 0x387100',
      site[:4] == ['push 0xc', 'push ecx', 'mov eax, esp', 'push ecx']
      and 'mov edx, 7' in site and 'lea ecx, [edx + 0x33]' in site and 'call 0x387100' in site, site)
check('site: the caller cleans 24h bytes after the call (3 dwords + the 18h-byte string)',
      at(0xCA71AA) == 'add esp, 0x24', at(0xCA71AA))
check('site: the string argument is built in the 18h bytes reserved just before (sub esp, 14h; ctor)',
      ins(0xCA7165, 4)[:2] == ['sub esp, 0x14', 'mov ecx, esp'], ins(0xCA7165, 4))

# 2. 0x387100 reads float/colour/int/string at [ebp+8]/[+0Ch]/[+10h]/[+14h] and frees the string itself.
f = ins(0x387100, 70)
check('0x387100: stack args float [ebp+8], colour [ebp+0Ch], int [ebp+10h], string [ebp+14h]',
      'movss xmm0, dword ptr [ebp + 8]' in f and 'mov edi, dword ptr [ebp + 0xc]' in f
      and 'mov esi, dword ptr [ebp + 0x10]' in f and 'lea eax, [ebp + 0x14]' in f, f[:30])
check('0x387100: callee frees the by-value string ([ebp+28h] capacity, delete [ebp+14h])',
      'cmp dword ptr [ebp + 0x28], 0x10' in f and 'push dword ptr [ebp + 0x14]' in f)
check('0x387100: passes ecx/edx/xmm1..3 on and appends 1 before calling 0x3871E0',
      'push 1' in push_seq_before_call(0x387100, 70, 0x3871E0) and calls(0x387100, 70, 0x3871E0))

# 3. The chain's appended defaults: 1 (0x3871E0), 1 (0x3872C0), 0 (0x3873B0), and its cleanup.
seq = push_seq_before_call(0x3871E0, 80, 0x3872C0)
check('0x3871E0 appends 1 (becomes [ebp+18h] of 0x3874A0) and calls 0x3872C0', 'push 1' in seq, seq[-12:])
seq = push_seq_before_call(0x3871E0, 160, 0x3873B0)
check('0x3872C0 appends 1 (becomes [ebp+1Ch]) and calls 0x3873B0', 'push 1' in seq[-14:], seq[-14:])
seq = push_seq_before_call(0x3873B0, 80, 0x3874A0)
check('0x3873B0 appends 0 (becomes [ebp+20h], shrink off) and calls 0x3874A0', 'push 0' in seq[-18:], seq[-18:])
check('0x3873B0 cleans 34h bytes after calling 0x3874A0 (the thunk does the same)',
      seq[-1] == 'add esp, 0x34', seq[-1:])

# 4. 0x3874A0: [ebp+18h] = wrap (to the label and the shrink gate), [ebp+20h] = shrink, string [ebp+24h].
g = ins(0x3874A0, 98)
check('0x3874A0: [ebp+18h] -> [ebp-30h] and [ebp-1Ch]; [ebp+1Ch] -> [ebp-34h]; string at [ebp+24h]',
      'mov eax, dword ptr [ebp + 0x18]' in g and 'mov dword ptr [ebp - 0x30], eax' in g
      and 'mov byte ptr [ebp - 0x1c], al' in g and 'lea eax, [ebp + 0x24]' in g, g[:40])
gate = ins(0x38756D, 10)
check('0x3874A0: shrink-to-fit 0x2370B0 runs only if byte [ebp-30h] (wrap) == 0 and [ebp+20h] != 0',
      gate[:5] == ['cmp byte ptr [ebp - 0x30], 0', 'mov al, byte ptr [ebp + 0x20]',
                   'mov byte ptr [esi + 0xe4], al', 'jne 0x38758c', 'test al, al']
      and 'call 0x2370b0' in gate, gate)
check('0x3874A0: shrink width is xmm3 (stored at [ebp-10h], passed in xmm1)',
      'movss dword ptr [ebp - 0x10], xmm3' in g and 'movss xmm1, dword ptr [ebp - 0x10]' in gate, gate)

# 5. The label keeps the two flags and re-applies the same rule whenever its text changes.
h = ins(0xD67E20, 110)
check('0xD67E20 stores the wrap flag at label+164h', 'mov byte ptr [esi + 0x164], al' in h)
k = ins(0x38C866, 12)
check('0x38C3B0 (text update): shrink again only if +164h == 0 and +0E4h != 0, to width +114h',
      k[0] == 'cmp byte ptr [edi + 0x164], 0' and 'cmp byte ptr [edi + 0xe4], 0' in k
      and 'movss xmm1, dword ptr [edi + 0x114]' in k and 'call 0x2370b0' in k, k)

# 6. 0x2370B0 only ever scales DOWN: scale * width > max -> setScale(scale * max / width).
s = ins(0x23714B, 16)
check('0x2370B0: compares scale*width with the max and calls setScale (vtable+40h) only when larger',
      'comiss xmm0, xmm2' in s and 'jbe 0x237171' in s and 'call dword ptr [eax + 0x40]' in s, s)

# 7. Skill popup widths (0xCB6750): three label-helper calls for the BB/SBB/UBB descriptions, each loading its
#    wrap width as movss xmm3, [0x16E56B0] (= 274.0); the patch repoints only those three operands.
import struct as _st
check('0x16E56B0 holds 274.0', abs(_st.unpack_from('<f', mem, 0x16E56B0 - pe.OPTIONAL_HEADER.ImageBase)[0] - 274.0) < 1e-6)
for rva, call, tag in ((0xCB988D, 0xCB98C7, 0xCB99EB), (0xCB9920, 0xCB993E, 0xCB9A47), (0xCB9981, 0xCB99B7, 0xCB9AA5)):
    check(f'popup width load at 0x{rva:X}: movss xmm3, [0x16e56b0]', at(rva) == 'movss xmm3, dword ptr [0x16e56b0]', at(rva))
    check(f'... feeds the label-helper call at 0x{call:X}', at(call) == 'call 0x387100', at(call))
names = [at(t) for t in (0xCB99EB, 0xCB9A47, 0xCB9AA5)]
check('the three labels are tagged descData / descDataEx / descDataUl (BB, SBB, UBB)',
      names == ['push 0x169045c', 'push 0x1690450', 'push 0x16903e0'], names)

# 8. Popup vertical fit (round 7): PopupDescThunk replaces those three `call 0x387100` and scales the returned label
#    by 3 / lines when it has more than 3 lines.  It relies on: the caller cleaning the 24h argument bytes itself
#    (so the thunk can pass the stack through untouched), the label's line count at +168h being final when the
#    helper returns (0x38C3B0 zeroes it, then adds one per laid-out line), and setScale at vtable +40h.
for call in (0xCB98C7, 0xCB993E, 0xCB99B7):
    after = ins(call, 3)
    check(f'popup description call at 0x{call:X} is caller-cleaned (add esp, 24h right after; nothing pops in between)',
          after[0] == 'call 0x387100' and 'add esp, 0x24' in after[1:3]
          and not any(i.startswith(('pop', 'push', 'ret')) for i in after[1:after.index('add esp, 0x24')]), after)
check('0x38C3B0 zeroes the line count [edi+168h] before laying out the lines (0x38F0D0)',
      ins(0x38C7E8, 2) == ['mov dword ptr [edi + 0x168], 0', 'call 0x38f0d0'], ins(0x38C7E8, 2))
check('0x38C3B0 adds one to [edi+168h] per line, in the loop over the line list',
      at(0x38C84C) == 'inc dword ptr [edi + 0x168]' and 'jb 0x38c810' in ins(0x38C84C, 10), ins(0x38C84C, 10))
lc = [i for i in ins(0x38C3B0, 700) if '+ 0x168]' in i]
check('0x38C3B0 writes +168h nowhere else', lc == ['mov dword ptr [edi + 0x168], 0', 'inc dword ptr [edi + 0x168]'], lc)
check('the text is in place when the label is created: [ebp-150h] = the BB description (0x60B280) is the string argument',
      'call 0x60b280' in ins(0xCB974B, 1) and 'lea eax, [ebp - 0x150]' in ins(0xCB987B, 1), (ins(0xCB974B, 1), ins(0xCB987B, 1)))

# 9. What the v2 fit replays (round 7, run v3): the label's own scaled layout.
import struct as _st2
_vt = 0x18E8CE0 - pe.OPTIONAL_HEADER.ImageBase
_slot = lambda off: _st2.unpack_from('<I', mem, _vt + off)[0] - pe.OPTIONAL_HEADER.ImageBase
check('label vtable (0x18E8CE0) +48h is the label setPosition(x, y) override 0x38CDC0', _slot(0x48) == 0x38CDC0, hex(_slot(0x48)))
check('0x38BF60 (label ctor body) installs vtable 0x18E8CE0', 'mov dword ptr [esi], 0x18e8ce0' in ins(0x38BF60, 30))
lay = ins(0x38CDC0, 40)
check('0x38CDC0 reads the label scale (getScaleX +30h, getScaleY +38h) and walks the line list at +100h',
      'mov eax, dword ptr [eax + 0x30]' in lay and 'mov eax, dword ptr [eax + 0x38]' in lay
      and 'mov ecx, dword ptr [edi + 0x100]' in lay, lay)
put = ins(0x38D064, 40)
check('0x38CDC0 places each line at its +23Ch/+240h offset, scaled about the block centre, via the line setPosition',
      'movss xmm0, dword ptr [esi + 0x240]' in put and 'movss xmm0, dword ptr [esi + 0x23c]' in put
      and 'call dword ptr [eax + 0x48]' in put, put)
tail = ins(0x38D111, 5)
check('0x38CDC0 stores x, y at +0F4h/+0F8h and returns 8 (two floats, callee-cleaned)',
      'movss dword ptr [edi + 0xf4], xmm0' in tail and 'movss dword ptr [edi + 0xf8], xmm0' in ins(0x38D111, 6)
      and at(0x38D13B) == 'ret 8', tail)
_idx = mem[0x38D14C:0x38D154]
_tg = [_st2.unpack_from('<I', mem, 0x38D140 + 4 * k)[0] - pe.OPTIONAL_HEADER.ImageBase for k in range(3)]
check('align 4 keeps the (w*s - w)/2 shift, so a scaled left-aligned block keeps its left edge', _tg[_idx[2]] == 0x38D001, hex(_tg[_idx[2]]))
check('0x38C3B0 gives every line the label scale (line->setScale(label->getScale())) before laying out',
      ins(0x38C82E, 6)[1:] == ['mov eax, dword ptr [eax + 0x44]', 'call eax', 'push ecx', 'mov ecx, dword ptr [ebp - 0x30]', 'fstp dword ptr [esp]']
      and at(0x38C83C) == 'call dword ptr [esi + 0x40]', ins(0x38C82E, 7))

# 10. The re-wrap (v3): the label's setString 0x38C3B0(force, text) and the client's string assign 0xDE250.
st = ins(0x38C3B0, 40)
check('0x38C3B0: text by value at [ebp+0Ch] compared with the stored text +14Ch; returns early only if equal and force == 0',
      'lea esi, [edi + 0x14c]' in st and 'lea eax, [ebp + 0xc]' in st and 'cmp byte ptr [ebp + 8], al' in st
      and 'je 0x38c972' in st, st[:30])
check('0x38C3B0: frees the by-value text on the early exit too, and returns 1Ch (force + 18h-byte string)',
      ins(0x38C972, 4)[:3] == ['cmp dword ptr [ebp + 0x20], 0x10', 'jb 0x38c984', 'push dword ptr [ebp + 0xc]']
      and at(0x38C99E) == 'ret 0x1c', ins(0x38C972, 4))
check('0x38C3B0: removes the old lines from the layer (removeChild +0ECh, cleanup 1) before laying out again',
      ins(0x38C59E, 3) == ['push 1', 'push dword ptr [ebp - 0x30]', 'call dword ptr [eax + 0xec]'], ins(0x38C59E, 3))
check('0x38C3B0: the layout wraps at the label width +114h (copied to the layout +50h)',
      ins(0x38C72C, 2) == ['movss xmm0, dword ptr [edi + 0x114]', 'movss dword ptr [esi + 0x50], xmm0'], ins(0x38C72C, 2))
check('the client calls it the same way: a copied string (0xDE250 assign, pos 0, npos), then push 0 (force), this = label',
      ins(0xD67F2A, 9)[0:2] == ['push -1', 'push 0'] and 'call 0xde250' in ins(0xD67F2A, 9)
      and ins(0xD67F45, 3) == ['push 0', 'mov ecx, esi', 'call 0x38c3b0'], (ins(0xD67F2A, 9), ins(0xD67F45, 3)))
asg = ins(0xDE250, 12)
check('0xDE250: assign(src [ebp+8], pos [ebp+0Ch], count [ebp+10h]) reading the source size at +10h; returns 0Ch',
      'mov ebx, dword ptr [ebp + 8]' in asg and 'mov ecx, dword ptr [ebp + 0xc]' in asg
      and 'mov edi, dword ptr [ebx + 0x10]' in asg and at(0xDE2AF) == 'ret 0xc', asg)

# 11. What the round-8 failure policy relies on (cp_name_fit_logic.cpp FitPopupDesc): the identity check before any
#     change, and a restore that lays the label out the way the client built it.
check('the runtime identity check: vtable 0x18E8CE0 is RVA 0x14E8CE0 (kLabelVtableRva)', _vt == 0x14E8CE0, hex(_vt))
_imp = {i.address: i.name.decode() for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports if i.name}


def _import_of_slot(off):
    jmp = ins(_slot(off), 1)[0]                                   # each slot is a `jmp dword ptr [IAT]` stub
    return _imp.get(int(jmp.split('[')[1].rstrip(']'), 16), jmp) if jmp.startswith('jmp dword ptr [0x') else jmp


for _off, _name in ((0x30, '?getScaleX@CCNode@cocos2d@@UAEMXZ'), (0x38, '?getScaleY@CCNode@cocos2d@@UAEMXZ'),
                    (0x40, '?setScale@CCNode@cocos2d@@UAEXM@Z'), (0x44, '?getScale@CCNode@cocos2d@@UAEMXZ')):
    check(f'label vtable +{_off:X}h is the cocos import {_name}', _import_of_slot(_off) == _name, _import_of_slot(_off))
_mk = [i for i in ins(0xD67E20, 120) if i.startswith('call 0x')]
check('0xD67E20 builds the label: constructor 0x38BF60, then the text copy 0xDE250, then setString 0x38C3B0',
      'call 0x38bf60' in _mk and 'call 0xde250' in _mk and 'call 0x38c3b0' in _mk
      and _mk.index('call 0x38bf60') < _mk.index('call 0xde250') < _mk.index('call 0x38c3b0'), _mk)
check('0x3874A0, after creating it, calls the label setPosition(+0F4h, +0F8h) (vtable +48h)',
      at(0x387563) == 'call 0xd67e20' and ins(0x38758C, 8)[0] == 'movss xmm0, dword ptr [esi + 0xf8]'
      and ins(0x38758C, 8)[5] == 'movss xmm0, dword ptr [esi + 0xf4]' and at(0x3875AE) == 'call dword ptr [eax + 0x48]',
      ins(0x38758C, 8))
check('0x38C3B0 itself ends with setPosition (+48h) and +158h (0x38C9B0): a setString replays the helper tail',
      at(0x38C8C4) == 'call dword ptr [eax + 0x48]' and at(0x38C8CB) == 'call dword ptr [eax + 0x158]'
      and _slot(0x158) == 0x38C9B0, (at(0x38C8C4), at(0x38C8CB), hex(_slot(0x158))))

print(f'check_name_fit_site: {failures} failure(s)')
sys.exit(1 if failures else 0)
