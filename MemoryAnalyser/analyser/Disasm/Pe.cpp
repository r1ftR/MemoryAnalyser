#include "Pe.h"
#include "../../MemoryManager/MemoryManager.h"

namespace analyser::disasm {

bool ReadSections(MemoryManager& memory, uintptr_t moduleBase, std::vector<PeSection>& out)
{
	out.clear();
	IMAGE_DOS_HEADER dos{};
	if (!memory.readMemory(moduleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	const uintptr_t ntAddr = moduleBase + static_cast<uintptr_t>(dos.e_lfanew);
	DWORD signature = 0;
	IMAGE_FILE_HEADER file{};
	if (!memory.readMemory(ntAddr, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE)
		return false;
	if (!memory.readMemory(ntAddr + sizeof(DWORD), &file, sizeof(file)))
		return false;
	if (file.NumberOfSections == 0 || file.NumberOfSections > 96)
		return false;

	const uintptr_t secAddr = ntAddr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file.SizeOfOptionalHeader;
	std::vector<IMAGE_SECTION_HEADER> headers(file.NumberOfSections);
	if (!memory.readMemory(secAddr, headers.data(), headers.size() * sizeof(IMAGE_SECTION_HEADER)))
		return false;

	for (const auto& h : headers) {
		PeSection s;
		char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
		memcpy(name, h.Name, IMAGE_SIZEOF_SHORT_NAME);
		s.name = name;
		s.address = moduleBase + h.VirtualAddress;
		s.size = h.Misc.VirtualSize ? h.Misc.VirtualSize : h.SizeOfRawData;
		s.executable = (h.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		out.push_back(std::move(s));
	}
	return true;
}

bool ReadExports(MemoryManager& memory, uintptr_t moduleBase, std::vector<PeExport>& out)
{
	out.clear();
	IMAGE_DOS_HEADER dos{};
	if (!memory.readMemory(moduleBase, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	const uintptr_t optAddr = moduleBase + static_cast<uintptr_t>(dos.e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	WORD magic = 0;
	if (!memory.readMemory(optAddr, &magic, sizeof(magic)))
		return false;

	IMAGE_DATA_DIRECTORY dir{};
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		IMAGE_OPTIONAL_HEADER64 opt{};
		if (!memory.readMemory(optAddr, &opt, sizeof(opt)))
			return false;
		dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	} else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		IMAGE_OPTIONAL_HEADER32 opt{};
		if (!memory.readMemory(optAddr, &opt, sizeof(opt)))
			return false;
		dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	} else {
		return false;
	}
	if (dir.VirtualAddress == 0 || dir.Size == 0)
		return true;

	IMAGE_EXPORT_DIRECTORY exp{};
	if (!memory.readMemory(moduleBase + dir.VirtualAddress, &exp, sizeof(exp)))
		return false;
	if (exp.NumberOfNames == 0 || exp.NumberOfNames > 0x10000 || exp.NumberOfFunctions > 0x10000)
		return true;

	std::vector<DWORD> functions(exp.NumberOfFunctions);
	std::vector<DWORD> names(exp.NumberOfNames);
	std::vector<WORD> ordinals(exp.NumberOfNames);
	if (!memory.readMemory(moduleBase + exp.AddressOfFunctions, functions.data(), functions.size() * sizeof(DWORD)) ||
		!memory.readMemory(moduleBase + exp.AddressOfNames, names.data(), names.size() * sizeof(DWORD)) ||
		!memory.readMemory(moduleBase + exp.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(WORD)))
		return false;

	out.reserve(names.size());
	for (size_t i = 0; i < names.size(); ++i) {
		if (ordinals[i] >= functions.size())
			continue;
		const DWORD rva = functions[ordinals[i]];
		// Forwarders point back inside the export directory.
		if (rva == 0 || (rva >= dir.VirtualAddress && rva < dir.VirtualAddress + dir.Size))
			continue;
		char name[256] = {};
		// Names can sit near a page end, so fall back to a shorter read.
		if (!memory.readMemory(moduleBase + names[i], name, sizeof(name) - 1) &&
			!memory.readMemory(moduleBase + names[i], name, 64))
			continue;
		PeExport e;
		e.name = name;
		e.address = moduleBase + rva;
		out.push_back(std::move(e));
	}
	return true;
}

}
