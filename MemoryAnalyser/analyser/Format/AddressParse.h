#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace analyser
{
// Text parsing only. Memory access stays in MemoryManager.
std::optional<uint64_t> ParseHex(const std::string& text);

// Accepts "7FF6A1B20000", "0x7FF6A1B20000" or "+0x1234" (relative to moduleBase).
std::optional<uintptr_t> ParseBaseAddress(const std::string& text, uintptr_t moduleBase);

// Accepts "0x10, 0x28 8" (comma or space separated, hex).
std::optional<std::vector<uintptr_t>> ParseOffsets(const std::string& text);
}
