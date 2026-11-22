#pragma once

#include "../AnalyserState.h"
#include "../StaticResolver/StaticFinder.h"

#include <cstdint>
#include <string>
#include <vector>

class MemoryManager;

namespace analyser
{
namespace disasm
{
class SymbolResolver;
}

// Non-blocking window for discovering static RVAs, signatures, function globals, and XRefs.
class StaticRefsView
{
public:
	explicit StaticRefsView(int id);

	void Render(AnalyserState& state, MemoryManager& memory, disasm::SymbolResolver* symbols);
	bool IsOpen() const { return open; }

	void ScanTarget(MemoryManager& memory, const disasm::SymbolResolver* symbols, uintptr_t address, size_t pointerSize);
	void ScanBatch(MemoryManager& memory, const disasm::SymbolResolver* symbols, std::vector<uintptr_t> targets, size_t pointerSize);

private:
	void RenderLocatorsSection(AnalyserState& state, MemoryManager& memory, disasm::SymbolResolver* symbols, const FunctionStaticReport& report);
	void RenderGlobalsSection(AnalyserState& state, const FunctionStaticReport& report);
	void RenderXRefsSection(AnalyserState& state, disasm::SymbolResolver* symbols, const FunctionStaticReport& report);

	int id;
	bool open = true;
	bool scanXRefs = true;
	char addressInput[64] = {};
	char saveNameInput[64] = {};
	std::string status;
	std::string verifyResult;

	StaticFinder finder;
	std::vector<FunctionStaticReport> reports;
	int selectedReport = 0;
};
}
