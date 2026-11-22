#pragma once

#include "../AnalyserState.h"
#include "Disassembler.h"

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

// Live, named disassembly window. Click a jump/call target to follow; Back returns.
class DisasmView
{
public:
	DisasmView(int id, MemoryManager& memory, size_t pointerSize, DisasmOpenRequest request);

	void Render(AnalyserState& state, disasm::SymbolResolver* symbols);
	bool IsOpen() const { return open; }
	void NavigateTo(uintptr_t target) { Navigate(target); }

private:
	struct Row
	{
		size_t line = 0;
		bool isLabel = false;
		std::string label;
	};

	void Refresh();
	void BuildRows(disasm::SymbolResolver* symbols);
	void Navigate(uintptr_t target);
	void GoBack();
	std::string LineText(size_t index, disasm::SymbolResolver* symbols, uintptr_t& followTarget) const;
	void RenderContextMenu(AnalyserState& state, disasm::SymbolResolver* symbols);

	int id;
	MemoryManager& memory;
	size_t pointerSize;

	uintptr_t address = 0;
	std::vector<uintptr_t> backStack;
	std::vector<disasm::InstructionLine> lines;
	// For indirect branches: the pointer value stored in the memory slot (0 if unreadable).
	std::vector<uintptr_t> slotValues;
	std::vector<Row> rows;
	bool readOk = false;
	bool scrollTop = false;
	bool showBytes = true;
	bool showSymbols = true;

	bool open = true;
	bool paused = false;
	int refreshMs = 250;
	double lastRefresh = -1.0;

	char viewName[64] = {};
	char gotoInput[64] = {};
	std::string status;

	uintptr_t menuAddress = 0;
	uintptr_t menuTarget = 0;
	char labelInput[64] = {};
	bool openLabelPopup = false;
};
}
