#pragma once

#include "FieldTypes.h"

#include <cstdint>
#include <functional>
#include <vector>

namespace analyser
{
// Returns true if the address can be read in the target. Keeps format code free of MemoryManager.
using PointerProbe = std::function<bool(uint64_t address)>;

// One read of the struct bytes. Detection looks at several taken over a short time.
using Sample = std::vector<uint8_t>;

// Guesses types for bytes [start, end) from all samples. The result exactly covers the range.
std::vector<FieldType> DetectRange(const std::vector<Sample>& samples, size_t start, size_t end,
	size_t pointerSize, const PointerProbe& probe);
}
