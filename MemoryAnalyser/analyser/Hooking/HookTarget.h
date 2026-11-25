#pragma once

#include <array>
#include <cstdint>
#include <string>

class MemoryManager;

namespace analyser
{
struct FunctionStaticReport;

namespace hooking
{
struct HookTarget
{
	std::string name;
	std::string moduleName;
	uint64_t rva = 0;
	uintptr_t address = 0;
	unsigned long processId = 0;
	uint64_t processCreation = 0; // FILETIME ticks
	bool x64 = false;
	std::wstring modulePath;
	uint32_t volumeSerial = 0;
	uint64_t fileId = 0;
	uint64_t fileSize = 0;
	uint64_t fileLastWrite = 0; // FILETIME ticks
	uint32_t imageSize = 0;
	uint32_t imageTimestamp = 0;
	uint32_t imageChecksum = 0;
	uint16_t imageMachine = 0;
	std::array<uint8_t, 16> originalBytes{};
};

bool ValidateHookTarget(MemoryManager& memory, const FunctionStaticReport& report,
	HookTarget& target, std::string& error);
bool RevalidateHookTarget(MemoryManager& memory, const HookTarget& target, std::string& error);
}
}
