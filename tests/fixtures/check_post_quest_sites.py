"""Verify the two no-prompt branches against the supported x86 executable.

Run: python tests/fixtures/check_post_quest_sites.py <extracted Appx folder>
Reads the executable without modifying it. Tests the replacement instructions
in memory. Actual reward/friend/map navigation still requires client testing.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32


def main():
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('../BraveFrontierAppxClient')
    exe = folder / 'BraveFrontier.Windows.exe'
    fixture = json.loads(Path(__file__).with_name('bf_2.19.6.0_signatures.json').read_text())
    raw = exe.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == fixture['modules'][0]['sha256'], 'unsupported executable'
    pe = pefile.PE(data=raw)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    base = pe.OPTIONAL_HEADER.ImageBase
    source = (Path(__file__).resolve().parents[2] / 'OfflineMod.win32/content/cp_post_quest.cpp').read_text()
    for sig in fixture['post_quest_sites']:
        data = pe.get_data(sig['rva'], len(sig['mask']))
        assert data == bytes.fromhex(sig['bytes']), sig['name']
        # Every unmasked one-byte corruption is rejected by signature matching.
        def matches(candidate):
            return all(m == '?' or a == b for a, b, m in zip(candidate, data, sig['mask']))
        for i, mask in enumerate(sig['mask']):
            if mask == 'x':
                changed = bytearray(data)
                changed[i] ^= 1
                assert not matches(changed)
        print('PASS signature and mutation refusal:', sig['name'])
    for site, target, expected in [(0xA25CD6, 0xA25CDD, b'\x74\x05'),
                                   (0xA1F92E, 0xA1F98A, b'\x74\x5a')]:
        assert f'0x{site:X}' in source
        stock = pe.get_data(site, 2)
        assert stock == expected
        old = next(md.disasm(stock, base + site))
        new = next(md.disasm(b'\xeb' + stock[1:], base + site))
        assert old.mnemonic == 'je' and new.mnemonic == 'jmp'
        assert old.size == new.size == 2
        assert old.operands[0].imm == new.operands[0].imm == base + target
        print(f'PASS {site:X}: unconditional jump to the existing no-prompt path {target:X}')
    assert 'WriteOpcode(site, 0xEB)' in source and 'WriteOpcode(patch.site, 0x74)' in source
    # Rating branch skips exactly the optional call; the existing caller already
    # reaches this continuation without invoking that function.
    call = next(md.disasm(pe.get_data(0xA25CD8, 5), base + 0xA25CD8))
    assert call.mnemonic == 'call' and call.operands[0].imm == base + 0xE50400
    assert call.address + call.size == base + 0xA25CDD
    text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    data = text.get_data()
    callers = [text.VirtualAddress + i for i in range(len(data)-4)
               if data[i] == 0xe8 and text.VirtualAddress + i + 5
               + struct.unpack_from('<i', data, i+1)[0] == 0xE50400]
    assert callers == [0xA25CD8], callers
    print('PASS rating prompt: sole direct call skipped, result continuation retained')
    # The Facebook branch skips dialog creation and its input-disable write,
    # then executes the existing scene-navigation calls and common cleanup.
    skipped = list(md.disasm(pe.get_data(0xA1F930, 0x5a), base + 0xA1F930))
    assert any(i.mnemonic == 'and' and '[edi + 0xf4]' in i.op_str for i in skipped)
    assert any(i.mnemonic == 'call' and i.operands[0].imm == base + 0x7EDB00 for i in skipped)
    continuation = list(md.disasm(pe.get_data(0xA1F98A, 0x12), base + 0xA1F98A))
    assert [i.mnemonic for i in continuation] == ['mov', 'call', 'push', 'mov', 'call']
    assert [i.operands[0].imm-base for i in continuation if i.mnemonic == 'call'] == [0xA1CAD0, 0x7F58D0]
    assert continuation[-1].address + continuation[-1].size == base + 0xA1F99C
    print('PASS Facebook prompt: input-disable/dialog skipped; stock navigation and cleanup retained')
    print('post-quest patch sites: PASS')


if __name__ == '__main__':
    main()
