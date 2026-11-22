#include <stdexcept>     
#include "MemoryManager.h"


MemoryManager::MemoryManager(const wchar_t* processName, const wchar_t* moduleName)
	: hProcess(NULL), processId(0), moduleBaseAddress(0)
{
	processId = GetProcessId(processName);
	if (processId == 0) {
		throw std::runtime_error("Process not found.");
	}
	hProcess = GetProcessHandle(processId);
	moduleBaseAddress = GetModuleBaseAddress(processId, moduleName);
	if (moduleBaseAddress == 0) {
		CloseHandle(hProcess);
		throw std::runtime_error("Module not found.");
	}
}

MemoryManager::~MemoryManager()
{
	if (hProcess) {
		CloseHandle(hProcess);
	}
}

DWORD MemoryManager::GetProcessId(const wchar_t* processName)
{
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	if (Process32First(hSnapshot, &processEntry)) {
		do {
			if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
				CloseHandle(hSnapshot);
				return processEntry.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &processEntry));
	}
	CloseHandle(hSnapshot);
	return 0;
}

uintptr_t MemoryManager::GetModuleBaseAddress(DWORD processId, const wchar_t* moduleName)
{
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	if (Module32First(hSnapshot, &moduleEntry)) {
		do {
			if (_wcsicmp(moduleEntry.szModule, moduleName) == 0) {
				CloseHandle(hSnapshot);
				return reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
			}
		} while (Module32Next(hSnapshot, &moduleEntry));
	}
	CloseHandle(hSnapshot);
	return 0;
}

std::vector<ModuleInfo> MemoryManager::EnumerateModules() const
{
	std::vector<ModuleInfo> modules;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return modules;
	}
	MODULEENTRY32W moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);
	if (Module32FirstW(hSnapshot, &moduleEntry)) {
		do {
			ModuleInfo info;
			info.name = moduleEntry.szModule;
			info.path = moduleEntry.szExePath;
			info.base = reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
			info.size = moduleEntry.modBaseSize;
			modules.push_back(std::move(info));
		} while (Module32NextW(hSnapshot, &moduleEntry));
	}
	CloseHandle(hSnapshot);
	return modules;
}

HANDLE MemoryManager::GetProcessHandle(DWORD processId)
{
	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess == NULL) {
		throw std::runtime_error("Failed to open process handle.");
	}
	return hProcess;
}

bool MemoryManager::resolvePointerChain(uintptr_t address, const std::vector<uintptr_t>& offsets, uintptr_t& result, size_t pointerSize)
{
	if (pointerSize != 4 && pointerSize != 8) {
		return false;
	}
	for (size_t i = 0; i < offsets.size(); i++) {
		uint64_t pointer = 0;
		if (!readMemory(address, &pointer, pointerSize) || pointer == 0) {
			return false;
		}
		address = static_cast<uintptr_t>(pointer) + offsets[i];
	}
	result = address;
	return true;
}

bool MemoryManager::readMemory(uintptr_t address, void* buffer, size_t size)
{
	SIZE_T bytesRead;
	return ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buffer, size, &bytesRead) && bytesRead == size;
}

bool MemoryManager::writeMemory(uintptr_t address, const void* buffer, size_t size)
{
	SIZE_T bytesWritten;
	return WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), buffer, size, &bytesWritten) && bytesWritten == size;
}

bool MemoryManager::patchMemory(uintptr_t address, const void* buffer, size_t size)
{
	LPVOID target = reinterpret_cast<LPVOID>(address);
	DWORD oldProtect = 0;
	if (!VirtualProtectEx(hProcess, target, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		return false;
	}

	const bool written = writeMemory(address, buffer, size);

	DWORD ignored = 0;
	VirtualProtectEx(hProcess, target, size, oldProtect, &ignored);
	FlushInstructionCache(hProcess, target, size);
	return written;
}
