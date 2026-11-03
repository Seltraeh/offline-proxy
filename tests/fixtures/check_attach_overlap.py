"""Prove which bytes of the game EXE the DLL's own patches change before each component checks its sites.

Run: python tests/fixtures/check_attach_overlap.py [<extracted Appx folder>] [--negative]

Session 17: the C16 client logged `startup coverage path DECLINED: censusLookup: ... byte +0 is E9,
expected 55`.  The startup path verified its signatures after ContentProvider_Attach, and the
provider detours the downloaded-name lookup 0xE417E0, which is also a startup site.  This proof reads
the sources and BraveFrontier.Windows.exe (unmodified) and replays main.cpp's attach sequence:

  attach   every component's checks and patches in main.cpp's order (DetourAttach()); a Detours
           detour changes the target's first whole instructions (>= 5 bytes, decoded with capstone
           from the file), a rel32 or opcode patch exactly its bytes;
  overlap  for each check, the patches already in place that reach its signature bytes.  Required:
           Startup_Prepare and every other check meet none; Startup_Attach meets exactly the pairs
           cp_startup.cpp declares in kSharedSites (censusLookup <- the provider's
           isFileAlreadyDownloaded detour), each detour starting at that site's first byte and
           ending inside its signature; no two patches touch the same byte;
  before   the pre-Session-17 sequence (the startup sites checked once, strictly, after the
           provider) meets that same overlap: the client's failure;
  detach   DetourDetach(): Startup_Detach before ContentProvider_Detach (the decisions use the
           provider);
  sync     cp_hooks.cpp records every detour it places (the `placed` table Startup_Attach checks),
           and tests/test_main.cpp's TestStartupAttachOrder replays exactly the provider's game-EXE
           detours.

--negative runs the same proof on altered copies of the model and requires each to fail: the
pre-Session-17 order, Startup_Prepare after the provider, an empty kSharedSites, an extra provider
detour on the census builder, the detach order reversed, and the test's replay missing a detour.
"""
from __future__ import annotations

import copy
import re
import sys
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

ROOT = Path(__file__).resolve().parents[2]
CONTENT = ROOT / 'OfflineMod.win32' / 'content'


def read(path: Path) -> str:
    return path.read_text(encoding='utf-8').replace('\r\n', '\n')


def body(text: str, signature: str) -> str:
    """The braces-balanced body of the first function whose header contains `signature`."""
    start = text.index(signature)
    open_ = text.index('{', start)
    depth = 0
    for i in range(open_, len(text)):
        depth += {'{': 1, '}': -1}.get(text[i], 0)
        if depth == 0:
            return text[open_:i + 1]
    raise ValueError(signature)


def signature_tables() -> dict[str, list[dict]]:
    text = read(CONTENT / 'cp_signatures.h')
    tables = {}
    for m in re.finditer(r'static const SiteSignature (\w+)\[\d+\] = \{(.*?)\n\};', text, re.S):
        rows = []
        for r in re.finditer(r'\{ "(\w+)", (\d)u, 0x([0-9A-F]+)u,\s*"([0-9A-F]+)",\s*"([x?]+)" \}', m.group(2)):
            rows.append({'name': r.group(1), 'module': int(r.group(2)), 'rva': int(r.group(3), 16),
                         'length': len(r.group(5))})
        tables[m.group(1)] = rows
    return tables


def model() -> dict:
    """Everything the proof needs, read from the sources (the --negative copies alter it)."""
    hooks = read(CONTENT / 'cp_hooks.cpp')
    attach = body(hooks, 'void ContentProvider_Attach(void)')
    site_of = dict(re.findall(r'(g_\w+) = reinterpret_cast<void\*>\(SiteAddress\(bases, "(\w+)"\)\);', attach))
    detoured = re.findall(r'DetourAttach\(&(g_\w+), reinterpret_cast<PVOID>\((\w+)\)\);', attach)
    placed = re.findall(r'\{ "(\w+)", reinterpret_cast<PVOID>\((\w+)\), (g_\w+) \}', attach)
    startup = read(CONTENT / 'cp_startup.cpp')
    shared = re.findall(r'\{ "(\w+)", "(\w+)" \}', re.search(r'kSharedSites\[\] = \{(.*?)\};', startup).group(1))
    census = int(re.search(r'kCensusRva = (0x[0-9A-F]+);', startup).group(1), 16)
    prompt_call = int(re.search(r'kPromptCallRva = (0x[0-9A-F]+);', startup).group(1), 16)
    gate = read(CONTENT / 'cp_gate_flash.cpp')
    gate_site = int(re.search(r'kSiteRva = (0x[0-9A-F]+);', gate).group(1), 16)
    gate_len = int(re.search(r'uint8_t jmp\[(\d+)\]', gate).group(1))
    post = read(CONTENT / 'cp_post_quest.cpp')
    post_sites = [int(x, 16) for x in re.findall(r'\{(0x[0-9A-F]+), "', re.search(r'Patch patches\[\] = \{(.*?)\};', post, re.S).group(1))]
    main = read(ROOT / 'OfflineMod.win32' / 'main.cpp')
    order = re.findall(r'\b(\w+_(?:Prepare|Attach))\(\);', body(main, 'static void DetourAttach()'))
    detach = re.findall(r'\b(\w+_Detach)\(\);', body(main, 'static void DetourDetach()'))
    tests = read(ROOT / 'tests' / 'test_main.cpp')
    replay = re.findall(r'\{ "(\w+)", reinterpret_cast<PVOID>\((?:hooks::)?(\w+)\), nullptr \}',
                        body(tests, 'struct ProviderExeDetours'))
    return {
        'provider_detours': [(site_of[v], hook) for v, hook in detoured],
        'provider_vars': {v: site_of[v] for v, _ in detoured},
        'placed': placed, 'shared': shared, 'census': census, 'prompt_call': prompt_call,
        'gate': (gate_site, gate_len), 'post': post_sites, 'order': order, 'detach': detach,
        'replay': replay, 'strict_startup_after_provider': False,
    }


class Proof:
    def __init__(self, exe: Path):
        self.pe = pefile.PE(str(exe), fast_load=True)
        self.image = self.pe.get_memory_mapped_image()
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.tables = signature_tables()
        self.failures: list[str] = []

    def check(self, ok: bool, what: str, detail=''):
        print(('PASS  ' if ok else 'FAIL  ') + what + (f'  -- {detail}' if not ok and detail else ''))
        if not ok:
            self.failures.append(what)

    def displaced(self, rva: int) -> int:
        """Bytes a Detours x86 detour of the function at rva replaces: whole instructions, >= 5."""
        n = 0
        for ins in self.md.disasm(bytes(self.image[rva:rva + 32]), rva):
            n += ins.size
            if n >= 5:
                return n
        raise ValueError(f'cannot decode 5 bytes at {rva:#x}')

    def sites(self, table: str) -> list[tuple[str, int, int]]:
        return [(r['name'], r['rva'], r['rva'] + r['length']) for r in self.tables[table] if r['module'] == 0]

    def run(self, m: dict) -> list[str]:
        self.failures = []
        exe_rows = {r['name']: r for r in self.tables['kSiteSignatures']}
        exe_rows.update(m.get('extra_rows', {}))
        provider_patches = []
        for site, hook in m['provider_detours']:
            row = exe_rows[site]
            if row['module'] == 0:
                provider_patches.append(('content provider', f'{site} detour ({hook})', row['rva'],
                                         row['rva'] + self.displaced(row['rva']), site))
        startup_patches = [('startup', 'census detour (Hook_Census)', m['census'], m['census'] + self.displaced(m['census']), 'census'),
                           ('startup', 'prompt call rel32', m['prompt_call'] + 1, m['prompt_call'] + 5, 'promptCall')]
        gate_patches = [('gate flash', 'trigger jmp', m['gate'][0], m['gate'][0] + m['gate'][1], 'gateFlashTrigger')]
        post_patches = [('post quest', f'branch opcode {rva:#x}', rva, rva + 1, f'post{rva:x}') for rva in m['post']]
        # Each attach step: (step, the sites it checks, the patches it then makes).
        steps = {
            'Startup_Prepare': ('kStartupSignatures', []),
            'ContentProvider_Attach': ('kSiteSignatures', provider_patches),
            'Startup_Attach': ('kStartupSignatures', startup_patches),
            'GateFlash_Attach': ('kGateFlashSignatures', gate_patches),
            'PostQuest_Attach': ('kPostQuestSignatures', post_patches),
        }
        order = m['order']
        self.check(all(s in order for s in steps), 'main.cpp attaches every component',
                   [s for s in steps if s not in order])
        self.check(order.index('Startup_Prepare') < order.index('ContentProvider_Attach') < order.index('Startup_Attach')
                   if all(s in order for s in ('Startup_Prepare', 'ContentProvider_Attach', 'Startup_Attach')) else False,
                   'main.cpp: Startup_Prepare, then ContentProvider_Attach, then Startup_Attach', order)
        applied: list[tuple] = []
        shared = {tuple(p) for p in m['shared']}
        met_shared = set()
        for step in [s for s in order if s in steps]:
            table, patches = steps[step]
            meets = []
            for name, lo, hi in self.sites(table):
                for owner, what, plo, phi, psite in applied:
                    if plo < hi and lo < phi:
                        meets.append((name, lo, hi, owner, what, plo, phi, psite))
            if step == 'Startup_Attach' and not m['strict_startup_after_provider']:
                allowed = [x for x in meets if x[3] == 'content provider' and (x[0], x[7]) in shared
                           and x[5] == x[1] and x[6] <= x[2]]
                met_shared |= {(x[0], x[7]) for x in allowed}
                rest = [x for x in meets if x not in allowed]
                self.check(not rest, f'{step}: no patch of another component reaches its sites but the declared kSharedSites',
                           [f'{x[0]} [{x[1]:#x},{x[2]:#x}) <- {x[3]} {x[4]} [{x[5]:#x},{x[6]:#x})' for x in rest])
            else:
                self.check(not meets, f'{step}: its sites hold the untouched bytes when it checks them',
                           [f'{x[0]} [{x[1]:#x},{x[2]:#x}) <- {x[3]} {x[4]} [{x[5]:#x},{x[6]:#x})' for x in meets])
            for p in patches:
                clash = [a for a in applied if a[2] < p[3] and p[2] < a[3]]
                self.check(not clash, f'{step}: {p[1]} [{p[2]:#x},{p[3]:#x}) touches no byte another patch changed',
                           [f'{a[0]} {a[1]}' for a in clash])
            applied += patches
        self.check(met_shared == shared and bool(shared),
                   f'kSharedSites {sorted(shared)} is exactly the overlap Startup_Attach meets', sorted(met_shared))
        # The pre-Session-17 sequence: one strict check of the startup sites after the provider.
        old = [(name, lo, hi, what, plo, phi) for name, lo, hi in self.sites('kStartupSignatures')
               for owner, what, plo, phi, psite in provider_patches if plo < hi and lo < phi]
        self.check([(o[0], o[4]) for o in old] == [('censusLookup', 0xE417E0)],
                   'the pre-Session-17 order (startup sites checked only after the provider) meets the provider\'s '
                   'lookup detour at censusLookup +0: the C16 client\'s DECLINED line',
                   [f'{o[0]} <- {o[3]} [{o[4]:#x},{o[5]:#x})' for o in old])
        detach = m['detach']
        self.check('Startup_Detach' in detach and 'ContentProvider_Detach' in detach
                   and detach.index('Startup_Detach') < detach.index('ContentProvider_Detach'),
                   'DetourDetach(): Startup_Detach before ContentProvider_Detach', detach)
        placed = {site: (hook, var) for site, hook, var in m['placed']}
        detoured_sites = {site for site, _ in m['provider_detours']}
        hooks_of = {site: hook for site, hook in m['provider_detours']}
        self.check(set(placed) == detoured_sites
                   and all(placed[s][0] == hooks_of[s] and m['provider_vars'].get(placed[s][1], s) == s
                           for s in placed if s in hooks_of or s == 'getTexture'),
                   f'cp_hooks.cpp records each of its {len(detoured_sites)} detours (placed) with its own hook and trampoline',
                   sorted(set(placed) ^ detoured_sites))
        exe_detours = sorted(site for site, _ in m['provider_detours'] if exe_rows[site]['module'] == 0)
        self.check(sorted(r[0] for r in m['replay']) == exe_detours
                   and all(hooks_of[s] == h for s, h in m['replay'] if s in hooks_of),
                   f'TestStartupAttachOrder replays exactly the provider\'s game-EXE detours {exe_detours}',
                   sorted(r[0] for r in m['replay']))
        for owner, what, lo, hi, _ in provider_patches + startup_patches:
            if 'detour' in what:
                print(f'      {owner}: {what} changes [{lo:#x},{hi:#x}) ({hi - lo} bytes)')
        return self.failures


def negatives(m: dict) -> list[tuple[str, dict]]:
    out = []
    a = copy.deepcopy(m)
    a['order'] = [s for s in a['order'] if s != 'Startup_Prepare']
    a['strict_startup_after_provider'] = True
    out.append(('the pre-Session-17 order: no Startup_Prepare, one strict check after the provider', a))
    b = copy.deepcopy(m)
    b['order'].remove('Startup_Prepare')
    b['order'].insert(b['order'].index('ContentProvider_Attach') + 1, 'Startup_Prepare')
    out.append(('Startup_Prepare after ContentProvider_Attach', b))
    c = copy.deepcopy(m)
    c['shared'] = []
    out.append(('an empty kSharedSites', c))
    d = copy.deepcopy(m)
    d['provider_detours'].append(('census', 'Hook_Census'))
    d['placed'].append(('census', 'Hook_Census', 'g_fCensusExtra'))
    d['extra_rows'] = {'census': {'name': 'census', 'module': 0, 'rva': 0xE415D0, 'length': 48}}
    out.append(('an extra provider detour on the census builder', d))
    e = copy.deepcopy(m)
    e['detach'] = list(reversed(e['detach']))
    out.append(('Startup_Detach after ContentProvider_Detach', e))
    f = copy.deepcopy(m)
    f['replay'] = [r for r in f['replay'] if r[0] != 'isFileAlreadyDownloaded']
    out.append(('the test replay without the lookup detour', f))
    return out


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith('--')]
    appx = Path(args[0]) if args else Path(r'C:\Users\Evan\BF\BraveFrontierAppxClient')
    proof = Proof(appx / 'BraveFrontier.Windows.exe')
    m = model()
    if '--negative' in argv:
        caught = 0
        for what, mutant in negatives(m):
            failures = proof.run(mutant)
            ok = bool(failures)
            caught += ok
            print(f'{"PASS" if ok else "FAIL"}  negative control "{what}": {len(failures)} check(s) fail')
        print(f'attach overlap (negative controls): {"PASS" if caught == len(negatives(m)) else "FAIL"}')
        return 0 if caught == len(negatives(m)) else 1
    failures = proof.run(m)
    print(f'attach overlap: {"PASS" if not failures else "FAIL"} ({len(failures)} failure(s))')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
