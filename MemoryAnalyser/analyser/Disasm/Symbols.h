#pragma once

#include "../../MemoryManager/MemoryManager.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace analyser::disasm
{
// Resolves addresses to names. Priority: user labels > PDB (DbgHelp) > exports.
// Exports and PDBs are loaded on a worker thread; DbgHelp is only touched from that thread.
class SymbolResolver
{
public:
	SymbolResolver(MemoryManager& memory, std::vector<ModuleInfo> modules);
	~SymbolResolver();
	SymbolResolver(const SymbolResolver&) = delete;
	SymbolResolver& operator=(const SymbolResolver&) = delete;

	// Queues a PDB load for the module containing address (no-op if already queued/loaded).
	void RequestPdb(uintptr_t address);

	// Name if a symbol starts exactly at address.
	std::optional<std::string> NameAt(uintptr_t address) const;
	// "module!symbol+0x10", "module+0x1234" or "" when outside every module.
	std::string Describe(uintptr_t address) const;

	void SetLabel(uintptr_t address, const std::string& name);
	void RemoveLabel(uintptr_t address);
	std::optional<std::string> LabelAt(uintptr_t address) const;

	// Absolute address <-> "module" + offset, for saving labels and trace sets.
	bool ToModuleOffset(uintptr_t address, std::string& module, uint64_t& offset) const;
	std::optional<uintptr_t> FromModuleOffset(const std::string& module, uint64_t offset) const;

	// All non-label symbols in a module, sorted by address (used to pick trace targets).
	std::vector<std::pair<uintptr_t, std::string>> SymbolsInModule(size_t moduleIndex) const;
	const std::vector<ModuleInfo>& Modules() const { return modules; }
	std::string Status() const;

private:
	struct Symbol
	{
		std::string name;
		int priority = 0; // 0 export, 1 pdb
	};

	const ModuleInfo* ModuleFor(uintptr_t address, size_t* index = nullptr) const;
	void Worker();
	void LoadExports(size_t index);
	void LoadPdb(size_t index);
	void AddSymbol(uintptr_t address, std::string name, int priority);

	MemoryManager& memory;
	std::vector<ModuleInfo> modules;

	mutable std::mutex mutex;
	std::map<uintptr_t, Symbol> symbols;
	std::map<uintptr_t, std::string> labels;
	std::vector<uint8_t> pdbState; // 0 none, 1 queued, 2 done
	std::deque<size_t> pdbQueue;
	std::string status;

	std::condition_variable wake;
	std::atomic<bool> stopping{ false };
	std::thread worker;
};
}
