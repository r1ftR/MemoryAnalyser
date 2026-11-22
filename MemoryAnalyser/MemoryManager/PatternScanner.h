#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class MemoryManager;

struct PatternByte
{
	uint8_t value = 0;
	bool wildcard = false;
};

namespace PatternScanner
{
	// Parses IDA-style byte patterns such as "48 89 5C 24 ? E8 ? ? ? ?".
	bool ParsePattern(const std::string& text, std::vector<PatternByte>& out);

	// Formats PatternByte vector as IDA-style string ("48 89 5C 24 ?").
	std::string FormatIdaPattern(const std::vector<PatternByte>& pattern);

	// Formats PatternByte vector as C-style byte + mask strings ("\\x48\\x89...", "xxxx?...").
	void FormatCodePattern(const std::vector<PatternByte>& pattern, std::string& bytesOut, std::string& maskOut);

	// Matches pattern inside an in-memory buffer, returning buffer-relative offsets.
	std::vector<size_t> MatchBuffer(const uint8_t* data, size_t size, const std::vector<PatternByte>& pattern, size_t maxMatches = 0);

	// Scans [start, start + size) in target process using chunked buffered reads.
	// maxMatches == 0 means unlimited.
	std::vector<uintptr_t> ScanRange(MemoryManager& memory, uintptr_t start, size_t size,
		const std::vector<PatternByte>& pattern, size_t maxMatches = 0);

	// Scans [start, start + size) for aligned pointer-sized slots holding targetValue.
	std::vector<uintptr_t> ScanPointerValues(MemoryManager& memory, uintptr_t start, size_t size,
		uintptr_t targetValue, size_t pointerSize, size_t maxMatches = 0);
}
