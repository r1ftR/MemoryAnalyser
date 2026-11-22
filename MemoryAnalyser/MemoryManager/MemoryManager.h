#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <vector>
#include <cstdint>
#include <string>

struct ModuleInfo
{
	std::wstring name;
	std::wstring path;
	uintptr_t base = 0;
	size_t size = 0;
};

class MemoryManager
{
private:
	HANDLE hProcess;
	DWORD processId;
	uintptr_t moduleBaseAddress;
public:
	
	MemoryManager(const wchar_t* processName, const wchar_t* moduleName);
	~MemoryManager();
	MemoryManager(const MemoryManager&) = delete;
	MemoryManager& operator=(const MemoryManager&) = delete;

	uintptr_t GetBaseAddress() const { return moduleBaseAddress; }
	DWORD GetAttachedProcessId() const { return processId; }
	HANDLE GetNativeHandle() const { return hProcess; }

	DWORD GetProcessId(const wchar_t* processName);
	uintptr_t GetModuleBaseAddress(DWORD processId, const wchar_t* moduleName);
	HANDLE GetProcessHandle(DWORD processId);

	std::vector<ModuleInfo> EnumerateModules() const;

	bool readMemory(uintptr_t address, void* buffer, size_t size);
	bool writeMemory(uintptr_t address, const void* buffer, size_t size);

	// Like writeMemory, but also works on read-only code pages.
	bool patchMemory(uintptr_t address, const void* buffer, size_t size);

	bool resolvePointerChain(uintptr_t address, const std::vector<uintptr_t>& offsets, uintptr_t& result, size_t pointerSize);
};