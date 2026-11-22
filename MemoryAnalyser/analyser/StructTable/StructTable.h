#pragma once

#include "../AnalyserState.h"
#include "../Format/FieldTypes.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

class MemoryManager;

namespace analyser
{
class StructTable
{
public:
	StructTable(int id, MemoryManager& memory, size_t pointerSize, StructOpenRequest request, bool autoDetect);

	void Render(AnalyserState& state);
	bool IsOpen() const { return open; }

private:
	struct Field
	{
		FieldType type;
		char name[32] = {};
		bool readOk = false;
		bool hexDisplay = false;
		// Set by the user (or loaded from file); auto-detect leaves it alone.
		bool userSet = false;
	};

	void Refresh();
	void AddBytes(size_t count);
	void SetFieldType(size_t index, FieldType newType);
	void InsertPadding(size_t position, size_t size);
	size_t TotalSize() const;
	void RenderRow(AnalyserState& state, size_t index, size_t offset, bool& layoutChanged);
	void RenderValuePopup(AnalyserState& state, Field& field, size_t offset, const uint8_t* data);
	void RenderStructOptions(AnalyserState& state);
	void StartDetect();
	void CollectDetectSample(double now);
	void ApplyDetect();
	bool ProbePointer(uint64_t target);
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

	char tableName[64] = {};
	std::string saveStatus;

	// One-shot detection: take a few samples over about a second, guess once, stop.
	bool detecting = false;
	double lastSample = -1.0;
	std::vector<std::vector<uint8_t>> detectSamples;
	std::vector<std::pair<uint64_t, bool>> probeCache;

	// Live indicator.
	double lastReadTime = -1.0;
	size_t readsOk = 0;
};
}
