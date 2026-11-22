#include "ProcessDebugger.h"

#include <condition_variable>

namespace
{
constexpr DWORD kWx86Breakpoint = 0x4000001F;  // STATUS_WX86_BREAKPOINT
constexpr DWORD kWx86SingleStep = 0x4000001E;  // STATUS_WX86_SINGLE_STEP
constexpr DWORD kTrapFlag = 0x100;
constexpr size_t kMaxQueuedHits = 200000;
}

ProcessDebugger::ProcessDebugger(DWORD processId) : processId(processId)
{
}

ProcessDebugger::~ProcessDebugger()
{
	Stop();
}

void ProcessDebugger::SetError(const std::string& text)
{
	std::lock_guard lock(mutex);
	lastError = text;
}

std::string ProcessDebugger::LastError() const
{
	std::lock_guard lock(mutex);
	return lastError;
}

bool ProcessDebugger::Start()
{
	if (running || worker.joinable())
	{
		return running;
	}
	stopRequested = false;
	attachResult = 0;
	worker = std::thread([this] { Run(); });
	while (attachResult == 0)
	{
		Sleep(5);
	}
	if (attachResult < 0)
	{
		worker.join();
		return false;
	}
	return true;
}

void ProcessDebugger::Stop()
{
	stopRequested = true;
	if (worker.joinable())
	{
		worker.join();
	}
	running = false;
}

void ProcessDebugger::AddBreakpoint(uintptr_t address)
{
	std::lock_guard lock(mutex);
	commands.push_back({ Command::Add, address });
}

void ProcessDebugger::RemoveBreakpoint(uintptr_t address)
{
	std::lock_guard lock(mutex);
	commands.push_back({ Command::Remove, address });
}

void ProcessDebugger::ClearBreakpoints()
{
	std::lock_guard lock(mutex);
	commands.push_back({ Command::Clear, 0 });
}

size_t ProcessDebugger::BreakpointCount() const
{
	return breakpointCount;
}

std::vector<ProcessDebugger::Hit> ProcessDebugger::DrainHits()
{
	std::lock_guard lock(mutex);
	std::vector<Hit> result;
	result.swap(hits);
	return result;
}

bool ProcessDebugger::WriteByte(uintptr_t address, uint8_t value)
{
	LPVOID target = reinterpret_cast<LPVOID>(address);
	DWORD oldProtect = 0;
	if (!VirtualProtectEx(process, target, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		return false;
	}
	SIZE_T written = 0;
	const BOOL ok = WriteProcessMemory(process, target, &value, 1, &written);
	DWORD ignored = 0;
	VirtualProtectEx(process, target, 1, oldProtect, &ignored);
	FlushInstructionCache(process, target, 1);
	return ok && written == 1;
}

bool ProcessDebugger::Install(uintptr_t address)
{
	if (breakpoints.count(address))
	{
		return true;
	}
	uint8_t original = 0;
	SIZE_T read = 0;
	if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), &original, 1, &read) || read != 1)
	{
		return false;
	}
	if (original == 0xCC)
	{
		return false; // Already an int3 (ours from a previous session or the target's own).
	}
	if (!WriteByte(address, 0xCC))
	{
		return false;
	}
	breakpoints[address] = original;
	return true;
}

void ProcessDebugger::Uninstall(uintptr_t address)
{
	auto it = breakpoints.find(address);
	if (it == breakpoints.end())
	{
		return;
	}
	// Threads mid-step re-arm only if the breakpoint still exists, so restoring here is safe.
	WriteByte(address, it->second);
	breakpoints.erase(it);
}

void ProcessDebugger::ApplyCommands()
{
	std::vector<Command> pending;
	{
		std::lock_guard lock(mutex);
		pending.swap(commands);
	}
	for (const auto& command : pending)
	{
		switch (command.kind)
		{
		case Command::Add:
			if (!Install(command.address))
			{
				char buf[96];
				sprintf_s(buf, "Could not set breakpoint at 0x%llX", static_cast<unsigned long long>(command.address));
				SetError(buf);
			}
			break;
		case Command::Remove:
			Uninstall(command.address);
			break;
		case Command::Clear:
			while (!breakpoints.empty())
			{
				Uninstall(breakpoints.begin()->first);
			}
			break;
		}
	}
	breakpointCount = breakpoints.size();
}

bool ProcessDebugger::SetTrapAndRewind(DWORD threadId, uintptr_t address)
{
	HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, threadId);
	if (!thread)
	{
		return false;
	}
	bool ok = false;
#ifdef _WIN64
	if (wow64Context)
	{
		WOW64_CONTEXT context{};
		context.ContextFlags = WOW64_CONTEXT_CONTROL;
		if (Wow64GetThreadContext(thread, &context))
		{
			context.Eip = static_cast<DWORD>(address);
			context.EFlags |= kTrapFlag;
			ok = Wow64SetThreadContext(thread, &context) != FALSE;
		}
	}
	else
	{
		CONTEXT context{};
		context.ContextFlags = CONTEXT_CONTROL;
		if (GetThreadContext(thread, &context))
		{
			context.Rip = address;
			context.EFlags |= kTrapFlag;
			ok = SetThreadContext(thread, &context) != FALSE;
		}
	}
#else
	CONTEXT context{};
	context.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(thread, &context))
	{
		context.Eip = static_cast<DWORD>(address);
		context.EFlags |= kTrapFlag;
		ok = SetThreadContext(thread, &context) != FALSE;
	}
#endif
	CloseHandle(thread);
	return ok;
}

DWORD ProcessDebugger::HandleException(const DEBUG_EVENT& event)
{
	const EXCEPTION_RECORD& record = event.u.Exception.ExceptionRecord;
	const DWORD code = record.ExceptionCode;
	const uintptr_t address = reinterpret_cast<uintptr_t>(record.ExceptionAddress);

	if (code == EXCEPTION_BREAKPOINT || code == kWx86Breakpoint)
	{
		auto it = breakpoints.find(address);
		if (it != breakpoints.end())
		{
			{
				std::lock_guard lock(mutex);
				if (hits.size() < kMaxQueuedHits)
				{
					hits.push_back({ address, event.dwThreadId, GetTickCount64() });
				}
				else
				{
					++dropped;
				}
			}
			// Put the real byte back, re-run the instruction one step, then re-arm.
			WriteByte(address, it->second);
			if (SetTrapAndRewind(event.dwThreadId, address))
			{
				pendingRearm[event.dwThreadId] = address;
			}
			else
			{
				breakpoints.erase(it);
				breakpointCount = breakpoints.size();
			}
			return DBG_CONTINUE;
		}
		// The attach breakpoint (plus the WOW64 one for 32-bit targets).
		if (code == EXCEPTION_BREAKPOINT && !sawInitialBreak)
		{
			sawInitialBreak = true;
			return DBG_CONTINUE;
		}
		if (code == kWx86Breakpoint && !sawInitialWowBreak)
		{
			sawInitialWowBreak = true;
			return DBG_CONTINUE;
		}
		return DBG_EXCEPTION_NOT_HANDLED;
	}

	if (code == EXCEPTION_SINGLE_STEP || code == kWx86SingleStep)
	{
		auto pending = pendingRearm.find(event.dwThreadId);
		if (pending != pendingRearm.end())
		{
			if (breakpoints.count(pending->second))
			{
				WriteByte(pending->second, 0xCC);
			}
			pendingRearm.erase(pending);
			return DBG_CONTINUE;
		}
		return DBG_EXCEPTION_NOT_HANDLED;
	}

	return DBG_EXCEPTION_NOT_HANDLED;
}

void ProcessDebugger::Run()
{
	process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
		FALSE, processId);
	if (!process)
	{
		SetError("OpenProcess failed (" + std::to_string(GetLastError()) + ")");
		attachResult = -1;
		return;
	}
#ifdef _WIN64
	BOOL isWow64 = FALSE;
	IsWow64Process(process, &isWow64);
	wow64Context = isWow64 != FALSE;
#endif

	if (!DebugActiveProcess(processId))
	{
		const DWORD error = GetLastError();
		SetError(error == ERROR_ACCESS_DENIED || error == ERROR_NOT_SUPPORTED
			? "Attach refused (already being debugged, protected, or architecture mismatch)"
			: "DebugActiveProcess failed (" + std::to_string(error) + ")");
		CloseHandle(process);
		process = nullptr;
		attachResult = -1;
		return;
	}
	DebugSetProcessKillOnExit(FALSE);
	running = true;
	attachResult = 1;

	bool exited = false;
	ULONGLONG stopDeadline = 0;
	while (!exited)
	{
		if (stopRequested)
		{
			if (stopDeadline == 0)
			{
				// Restore every byte first so no new hits happen while draining.
				while (!breakpoints.empty())
				{
					Uninstall(breakpoints.begin()->first);
				}
				breakpointCount = 0;
				stopDeadline = GetTickCount64() + 1000;
			}
			if (pendingRearm.empty() || GetTickCount64() > stopDeadline)
			{
				break;
			}
		}
		else
		{
			ApplyCommands();
		}

		DEBUG_EVENT event{};
		if (!WaitForDebugEvent(&event, 20))
		{
			continue;
		}

		DWORD status = DBG_CONTINUE;
		switch (event.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			if (event.u.CreateProcessInfo.hFile)
			{
				CloseHandle(event.u.CreateProcessInfo.hFile);
			}
			break;
		case LOAD_DLL_DEBUG_EVENT:
			if (event.u.LoadDll.hFile)
			{
				CloseHandle(event.u.LoadDll.hFile);
			}
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			pendingRearm.erase(event.dwThreadId);
			break;
		case EXCEPTION_DEBUG_EVENT:
			status = HandleException(event);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			exited = true;
			SetError("Target process exited");
			break;
		default:
			break;
		}
		ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status);
	}

	if (!exited)
	{
		DebugActiveProcessStop(processId);
	}
	breakpoints.clear();
	pendingRearm.clear();
	breakpointCount = 0;
	CloseHandle(process);
	process = nullptr;
	running = false;
}
