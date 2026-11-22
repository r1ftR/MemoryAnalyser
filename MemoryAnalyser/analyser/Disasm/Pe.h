#pragma once
#include <cstdint>
#include <string>
#include <vector>

class MemoryManager;

namespace analyser::disasm {

struct PeSection
{
	std::string name;
	uintptr_t address = 0; // absolute
	size_t size = 0;
	bool executable = false;
};

// Reads section headers of a module mapped in the target process.
// Works for both PE32 and PE32+ images.
bool ReadSections(MemoryManager& memory, uintptr_t moduleBase, std::vector<PeSection>& out);

struct PeExport
{
    std::string name;
    uintptr_t address = 0; // absolute
};

// Reads named exports from the module's export directory. Forwarded exports are skipped.
bool ReadExports(MemoryManager& memory, uintptr_t moduleBase, std::vector<PeExport>& out);

}
