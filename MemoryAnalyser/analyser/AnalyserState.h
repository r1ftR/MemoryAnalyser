#pragma once

#include "Storage/TableStore.h"
#include "Hooking/HookTarget.h"

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

struct DisasmOpenRequest
{
	uintptr_t address = 0;
	std::string name;
};

struct LabelRequest
{
	uintptr_t address = 0;
	std::string name; // empty = remove
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

struct ResolvedSavedFunction
{
	SavedFunction saved;
	uintptr_t address = 0;
	std::string error;
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

	char disasmAddress[64] = "+0x1000";
	int selectedModule = -1;
	int selectedSection = -1;
	int selectedSavedDisasm = -1;
	std::vector<DisasmOpenRequest> disasmOpenRequests;
	std::vector<SavedDisasm> disasmSaveRequests;
	std::vector<LabelRequest> labelRequests;
	// Addresses the user asked to trace from a disassembly window.
	std::vector<uintptr_t> traceRequests;
	// Addresses a trace window asked to open in disassembly.
	std::vector<uintptr_t> disasmGotoRequests;
	std::vector<SavedTrace> traceSaveRequests;
	int selectedSavedTrace = -1;
	bool openTraceRequested = false;
	bool startDebuggerRequested = false;
	bool stopDebuggerRequested = false;

	std::optional<hooking::HookTarget> hookRequest;
	std::optional<SavedFunction> savedHookRequest;
	bool openStaticRefsRequested = false;
	std::vector<uintptr_t> staticScanRequests;
	std::vector<std::vector<uintptr_t>> staticBatchScanRequests;
	std::vector<SavedLocator> locatorSaveRequests;
	std::vector<SavedFunction> functionSaveRequests;
	std::vector<ResolvedSavedFunction> savedFunctions;
	std::string storageStatus;
	std::string savedFunctionStatus;
	std::string locatorStatus;
	int selectedSavedFunction = -1;
	int selectedSavedLocator = -1;
};
}
