#include "../analyser/Hooking/HookTarget.h"
#include "../analyser/StaticResolver/StaticFinder.h"
#include "../MemoryManager/MemoryManager.h"

#include <Windows.h>
#include <cstdio>

__declspec(noinline) int HookFixtureFunction(int value)
{
	return value + 1;
}

int main()
{
	MemoryManager memory(L"HookTargetTests.exe", L"HookTargetTests.exe");
	const uintptr_t address = reinterpret_cast<uintptr_t>(&HookFixtureFunction);
	const uintptr_t base = memory.GetBaseAddress();
	if (address < base) return 1;

	analyser::FunctionStaticReport report;
	report.inModule = true;
	report.moduleName = "HookTargetTests.exe";
	report.targetName = "HookFixtureFunction";
	report.targetAddress = address;
	report.rva = address - base;

	analyser::hooking::HookTarget target;
	std::string error;
	if (!analyser::hooking::ValidateHookTarget(memory, report, target, error) ||
		!analyser::hooking::RevalidateHookTarget(memory, target, error))
	{
		std::fprintf(stderr, "Valid target was rejected: %s\n", error.c_str());
		return 2;
	}

	auto stale = target;
	++stale.processCreation;
	if (analyser::hooking::RevalidateHookTarget(memory, stale, error))
	{
		std::fputs("Stale process identity was accepted\n", stderr);
		return 3;
	}
	stale = target;
	stale.x64 = !stale.x64;
	if (analyser::hooking::RevalidateHookTarget(memory, stale, error))
	{
		std::fputs("Wrong target architecture was accepted\n", stderr);
		return 3;
	}
	stale = target;
	++stale.imageTimestamp;
	if (analyser::hooking::RevalidateHookTarget(memory, stale, error))
	{
		std::fputs("Changed module identity was accepted\n", stderr);
		return 3;
	}
	++report.rva;
	if (analyser::hooking::ValidateHookTarget(memory, report, target, error))
	{
		std::fputs("Mismatched RVA was accepted\n", stderr);
		return 3;
	}

	DWORD previous = 0;
	if (!VirtualProtect(reinterpret_cast<void*>(address), 1, PAGE_EXECUTE_READWRITE, &previous))
	{
		std::fprintf(stderr, "VirtualProtect failed: %lu\n", GetLastError());
		return 4;
	}
	auto* bytes = reinterpret_cast<unsigned char*>(address);
	const unsigned char original = *bytes;
	*bytes ^= 1;
	const bool acceptedChangedBytes = analyser::hooking::RevalidateHookTarget(memory, target, error);
	*bytes = original;
	DWORD ignored = 0;
	const bool restored = VirtualProtect(reinterpret_cast<void*>(address), 1, previous, &ignored) != FALSE;
	FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(address), 1);
	if (!restored || acceptedChangedBytes || !analyser::hooking::RevalidateHookTarget(memory, target, error))
	{
		std::fprintf(stderr, "Target byte revalidation failed: %s\n", error.c_str());
		return 5;
	}
	std::puts("Hook target validation passed");
	return 0;
}
