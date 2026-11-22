#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace analyser::disasm {

enum class FlowKind { None, Jump, CondJump, Call, Ret };

struct InstructionLine
{
	uintptr_t address = 0;
	uint8_t length = 0;
	uint8_t bytes[15] = {};
	std::string text;
	std::string mnemonic;
	bool valid = false;
	FlowKind flow = FlowKind::None;
	bool hasTarget = false;
	uintptr_t target = 0;
	// Indirect branch through a fixed memory slot, e.g. call [rip+X] (IAT).
	bool hasMemTarget = false;
	uintptr_t memTarget = 0;
};

// Decodes buffer (located at runtimeAddress in the target) into lines.
// Invalid bytes produce one-byte "db" lines so the listing never stalls.
void Decode(const uint8_t* data, size_t size, uintptr_t runtimeAddress, size_t pointerSize,
			size_t maxLines, std::vector<InstructionLine>& out);

}
