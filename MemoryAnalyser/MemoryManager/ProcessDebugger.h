#pragma once
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Attaches to a running process as a debugger and records software (int3) breakpoint hits.
// All debug API calls run on one worker thread; the public API is thread-safe.
// Breakpoints are restored and the debugger detaches without killing the target on Stop().
class ProcessDebugger
{
public:
	struct Hit
	{
		uintptr_t address = 0;
		DWORD threadId = 0;
		ULONGLONG tick = 0; // GetTickCount64
	};

	explicit ProcessDebugger(DWORD processId);
	~ProcessDebugger();
	ProcessDebugger(const ProcessDebugger&) = delete;
	ProcessDebugger& operator=(const ProcessDebugger&) = delete;

	// Blocks until attach succeeds or fails.
	bool Start();
	void Stop();
	bool IsRunning() const { return running; }
	std::string LastError() const;

	// Queued; applied by the worker thread.
	void AddBreakpoint(uintptr_t address);
	void RemoveBreakpoint(uintptr_t address);
	void ClearBreakpoints();
	size_t BreakpointCount() const;

	// Returns and clears hits recorded since the last call.
	std::vector<Hit> DrainHits();
	size_t DroppedHits() const { return dropped; }

private:
	struct Command
	{
		enum Kind { Add, Remove, Clear } kind;
		uintptr_t address;
	};

	void Run();
	void ApplyCommands();
	bool WriteByte(uintptr_t address, uint8_t value);
	bool Install(uintptr_t address);
	void Uninstall(uintptr_t address);
	DWORD HandleException(const DEBUG_EVENT& event);
	bool SetTrapAndRewind(DWORD threadId, uintptr_t address);
	void SetError(const std::string& text);

	DWORD processId;
	HANDLE process = nullptr;
	bool wow64Context = false;

	std::thread worker;
	std::atomic<bool> running{ false };
	std::atomic<bool> stopRequested{ false };
	std::atomic<int> attachResult{ 0 }; // 0 pending, 1 ok, -1 failed

	mutable std::mutex mutex;
	std::vector<Command> commands;
	std::vector<Hit> hits;
	std::atomic<size_t> dropped{ 0 };
	std::string lastError;
	std::atomic<size_t> breakpointCount{ 0 };

	// Worker thread only.
	std::map<uintptr_t, uint8_t> breakpoints; // address -> original byte
	std::map<DWORD, uintptr_t> pendingRearm;  // thread -> breakpoint to re-arm after single step
	bool sawInitialBreak = false;
	bool sawInitialWowBreak = false;
};
