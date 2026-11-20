#pragma once

#include "../AnalyserState.h"
#include "../Format/FieldTypes.h"

#include <cstdint>
#include <string>
#include <vector>

class MemoryManager;

namespace analyser
{
class StructViewPanel
{
public:
	StructViewPanel(int id, MemoryManager& memory, size_t pointerSize, StructOpenRequest request);

	void Render(AnalyserState& state);
	bool IsOpen() const { return open; }

private:
	struct Field
	{
		FieldType type;
		char name[32] = {};
		bool readOk = false;
		bool hexDisplay = false;
	};

	void Refresh();
	void AddBytes(size_t count);
	void SetFieldType(size_t index, FieldType newType);
	void InsertPadding(size_t position, size_t size);
	size_t TotalSize() const;
	void RenderRow(AnalyserState& state, size_t index, size_t offset, bool& layoutChanged);
	void RenderValuePopup(AnalyserState& state, Field& field, size_t offset, const uint8_t* data);
	void RenderStructOptions();
	void OpenPointer(AnalyserState& state, size_t offset);

	int id;
	MemoryManager& memory;
	size_t pointerSize;
	StructOpenRequest source;

	std::vector<Field> fields;
	std::vector<uint8_t> buffer;
	uintptr_t address = 0;
	bool chainOk = false;

	bool open = true;
	bool paused = false;
	bool editing = false;
	char editBuffer[128] = {};
	std::string editStatus;
	bool editStatusError = false;
	int refreshMs = 100;
	double lastRefresh = -1.0;
};
}
