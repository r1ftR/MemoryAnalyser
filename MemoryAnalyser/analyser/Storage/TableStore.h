#pragma once

#include "../Format/FieldTypes.h"

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

// All saved struct tables, stored in one plain-text file next to the exe.
class TableStore
{
public:
	TableStore();

	bool Load();
	bool Save();

	// Replaces a table with the same name, or adds it.
	void Upsert(SavedTable table);
	void Remove(size_t index);

	const std::vector<SavedTable>& Tables() const { return tables; }
	const std::string& LastError() const { return lastError; }

private:
	std::wstring path;
	std::vector<SavedTable> tables;
	std::string lastError;
};
}
