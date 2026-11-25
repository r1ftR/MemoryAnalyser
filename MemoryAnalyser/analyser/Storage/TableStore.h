#pragma once

#include "../Format/FieldTypes.h"
#include "../Hooking/HookTarget.h"

#include <cstdint>
#include <string>
#include <vector>

namespace analyser
{
struct SavedField
{
	FieldType type = FieldType::Hex64;
	std::string name;
};

struct SavedTable
{
	std::string name;
	size_t pointerSize = 8;
	// Where the table was opened from: base address + pointer chain offsets.
	bool hasLocation = false;
	// True: base is an offset from the module base (survives restarts/ASLR).
	bool relative = false;
	uint64_t base = 0;
	std::vector<uint64_t> chain;
	std::vector<SavedField> fields;
};

struct SavedDisasm
{
	std::string name;
	size_t pointerSize = 8;
	// True: address is an offset from the module base.
	bool relative = false;
	uint64_t address = 0;
};

// Address saved as module name + offset so it survives restarts/ASLR.
struct ModuleOffset
{
	std::string module;
	uint64_t offset = 0;
};

struct SavedLabel
{
	ModuleOffset at;
	std::string name;
};

struct SavedTrace
{
	std::string name;
	std::vector<ModuleOffset> targets;
};

struct SavedLocator
{
	std::string name;
	// Serialized polymorphic locator string from IStaticLocator::Serialize().
	std::string spec;
};

struct SavedFunction
{
	// Durable snapshot: address/PID/creation time are cleared on upsert and never serialized.
	hooking::HookTarget target;
	std::string locatorSpec;
	std::vector<std::wstring> projects;
};

// All saved analyser records, stored in one plain-text file next to the exe.
class TableStore
{
public:
	TableStore();
	explicit TableStore(std::wstring storagePath);

	bool Load();
	bool Save();

	// Replaces a table with the same name, or adds it.
	void Upsert(SavedTable table);
	void Remove(size_t index);

	const std::vector<SavedTable>& Tables() const { return tables; }

	void UpsertDisasm(SavedDisasm view);
	void RemoveDisasm(size_t index);
	const std::vector<SavedDisasm>& DisasmViews() const { return disasmViews; }

	void SetLabel(SavedLabel label); // empty name removes
	const std::vector<SavedLabel>& Labels() const { return labels; }

	void UpsertTrace(SavedTrace trace);
	void RemoveTrace(size_t index);
	const std::vector<SavedTrace>& Traces() const { return traces; }

	void UpsertLocator(SavedLocator locator);
	void RemoveLocator(size_t index);
	const std::vector<SavedLocator>& Locators() const { return locators; }
	const std::vector<SavedFunction>& Functions() const { return functions; }
	SavedFunction* FindFunction(const hooking::HookTarget& target);
	const SavedFunction* FindFunction(const hooking::HookTarget& target) const;
	void UpsertFunction(SavedFunction function);
	bool AddFunctionProject(const hooking::HookTarget& target, const std::wstring& project);
	bool ReplaceFunctionProject(const hooking::HookTarget& target, size_t index, const std::wstring& project);
	static bool SameFunctionIdentity(const hooking::HookTarget& left, const hooking::HookTarget& right);
	const std::string& LastError() const { return lastError; }

private:
	std::wstring path;
	std::vector<SavedTable> tables;
	std::vector<SavedDisasm> disasmViews;
	std::vector<SavedLabel> labels;
	std::vector<SavedTrace> traces;
	std::vector<SavedLocator> locators;
	std::vector<SavedFunction> functions;
	std::string lastError;
};
}
