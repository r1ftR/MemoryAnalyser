#pragma once

#include "Storage/TableStore.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace analyser
{
struct StructOpenRequest
{
	uintptr_t base = 0;
	std::vector<uintptr_t> offsets;
	std::string label;
	// Set when opening a saved table: use this layout instead of the default rows.
	std::optional<SavedTable> layout;
};

struct AttachState
{
	char processName[128] = "notepad.exe";
	char moduleName[128] = "notepad.exe";
	int architecture = 0; // 0 = x64, 1 = x86
	bool attachRequested = false;
	bool detachRequested = false;

	bool attached = false;
	unsigned long processId = 0;
	uintptr_t moduleBase = 0;
	std::string status = "Not attached";

	size_t PointerSize() const { return architecture == 1 ? 4 : 8; }
};

struct AnalyserState
{
	AttachState attach;
	char baseInput[64] = "+0x0";
	bool baseIsPointer = true;
	std::vector<StructOpenRequest> openRequests;

	bool autoDetectDefault = true;
	int selectedSaved = -1;
	bool openSavedAtBase = false;
	std::vector<SavedTable> saveRequests;
};
}
