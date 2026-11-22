#pragma once

#include "../AnalyserState.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

class ProcessDebugger;

namespace analyser
{
namespace disasm
{
class SymbolResolver;
}

// Live function trace: shows which traced functions run, how often, and when.
class TraceView
{
public:
	explicit TraceView(int id);

	// debugger may be null (not started). Returns addresses the user clicked to open in disassembly.
	void Render(AnalyserState& state, ProcessDebugger* debugger, disasm::SymbolResolver* symbols);
	bool IsOpen() const { return open; }

	void AddTarget(uintptr_t address, ProcessDebugger* debugger);
	const std::vector<uintptr_t>& Targets() const { return targets; }
	void SetName(const std::string& name);
	// Called when the debugger is (re)started so all targets get armed.
	void ArmAll(ProcessDebugger& debugger);
	// Counts hits on this window's targets (ignored while paused).
	void ApplyHits(const std::vector<std::pair<uintptr_t, std::pair<unsigned long, unsigned long long>>>& hits);

private:
	struct Stat
	{
		uint64_t count = 0;
		uint64_t recentCount = 0;
		unsigned long lastThread = 0;
		unsigned long long lastTick = 0;
		std::string name;
	};

	void RenderPicker(AnalyserState& state, ProcessDebugger* debugger, disasm::SymbolResolver* symbols);
	void RemoveTarget(uintptr_t address, ProcessDebugger* debugger);

	int id;
	bool open = true;
	bool paused = false;
	char traceName[64] = {};
	std::string status;

	std::vector<uintptr_t> targets;
	std::map<uintptr_t, Stat> stats;
	int sortMode = 0; // 0 count, 1 last hit, 2 name
	bool hideZero = false;
	double lastRateUpdate = -1.0;
	std::map<uintptr_t, uint64_t> rateBase;
	std::map<uintptr_t, double> rates;

	int pickerModule = -1;
	char pickerFilter[64] = {};
	char addInput[64] = {};
	int maxBreakpoints = 512;
};
}
