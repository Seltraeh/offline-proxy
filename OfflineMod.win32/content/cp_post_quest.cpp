// Disable obsolete post-quest promotions on the verified Windows client.
// Both edits take an existing no-prompt branch. No callbacks, rewards,
// account flags, friendship requests or scene transitions are manufactured.
#include "../pch.h"
#include "cp_post_quest.h"

#if defined(CONTENT_PROVIDER) && CONTENT_PROVIDER
#include "cp_signatures.h"
#include "cp_log.h"
#include <string>

namespace {
struct Patch {
    uintptr_t rva;
    const char* name;
    uint8_t* site = nullptr;
};
Patch patches[] = {
    {0xA25CD6, "Windows Store rating"},
    {0xA1F92E, "Facebook gem promotion"},
};

bool WriteOpcode(uint8_t* site, uint8_t opcode)
{
    DWORD old = 0;
    if (!VirtualProtect(site, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    *site = opcode;
    FlushInstructionCache(GetCurrentProcess(), site, 1);
    DWORD unused = 0;
    if (!VirtualProtect(site, 1, old, &unused))
        CP_LOG_WARN("post-quest prompts: protection restore failed (%lu)", GetLastError());
    return true;
}
}

void PostQuest_Attach()
{
    if (patches[0].site || patches[1].site) return;
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    std::string why;
    if (!cp::MatchIdentity(cp::kSupportedModules[0], reinterpret_cast<const uint8_t*>(base), 4096, why)) {
        CP_LOG_WARN("post-quest prompts DECLINED: %s", why.c_str());
        return;
    }
    // Verify both complete contexts before writing either branch. Relocations
    // in string addresses are masked by the generated signature fixture.
    for (const auto& sig : cp::kPostQuestSignatures) {
        const auto* p = reinterpret_cast<const uint8_t*>(base + sig.rva);
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(p, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT
            || !(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            || !cp::MatchSignature(sig, p, strlen(sig.mask), why)) {
            CP_LOG_WARN("post-quest prompts DECLINED: %s %s", sig.name, why.c_str());
            return;
        }
    }
    for (auto& patch : patches) {
        auto* site = reinterpret_cast<uint8_t*>(base + patch.rva);
        // JE rel8 -> JMP rel8. The displacement and all following code stay.
        if (*site != 0x74 || !WriteOpcode(site, 0xEB)) {
            CP_LOG_WARN("post-quest prompts DECLINED: %s branch; restoring prior edits", patch.name);
            PostQuest_Detach();
            return;
        }
        patch.site = site;
    }
    CP_LOG_INFO("post-quest prompts disabled: Windows Store rating and Facebook gem promotion; stock no-prompt continuations");
}

void PostQuest_Detach()
{
    for (auto& patch : patches) {
        if (patch.site && *patch.site == 0xEB && WriteOpcode(patch.site, 0x74))
            patch.site = nullptr;
    }
}
#endif
