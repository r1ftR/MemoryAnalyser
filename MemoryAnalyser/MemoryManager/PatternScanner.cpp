#include "PatternScanner.h"
#include "MemoryManager.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace PatternScanner
{
namespace
{
	constexpr size_t kChunkSize = 64 * 1024;
	constexpr size_t kPageStep = 4096;

	bool ParseHexByte(const std::string& token, uint8_t& out)
	{
		if (token.empty() || token.size() > 2)
		{
			return false;
		}
		char* end = nullptr;
		const unsigned long val = std::strtoul(token.c_str(), &end, 16);
		if (end != token.c_str() + token.size() || val > 0xFF)
		{
			return false;
		}
		out = static_cast<uint8_t>(val);
		return true;
	}

	void ReadRegionWithFallback(MemoryManager& memory, uintptr_t address, uint8_t* buffer, size_t size, std::vector<uint8_t>& validMask)
	{
		validMask.assign(size, 0);
		if (memory.readMemory(address, buffer, size))
		{
			std::fill(validMask.begin(), validMask.end(), static_cast<uint8_t>(1));
			return;
		}

		// Fall back to page-sized reads so partially unmapped regions do not drop adjacent valid pages.
		size_t offset = 0;
		while (offset < size)
		{
			const size_t step = (std::min)(kPageStep, size - offset);
			if (memory.readMemory(address + offset, buffer + offset, step))
			{
				std::fill(validMask.begin() + static_cast<std::ptrdiff_t>(offset),
					validMask.begin() + static_cast<std::ptrdiff_t>(offset + step),
					static_cast<uint8_t>(1));
			}
			offset += step;
		}
	}
}

bool ParsePattern(const std::string& text, std::vector<PatternByte>& out)
{
	out.clear();
	std::istringstream stream(text);
	std::string token;
	while (stream >> token)
	{
		if (token == "?" || token == "??")
		{
			out.push_back(PatternByte{ 0, true });
			continue;
		}
		uint8_t byte = 0;
		if (!ParseHexByte(token, byte))
		{
			out.clear();
			return false;
		}
		out.push_back(PatternByte{ byte, false });
	}
	return !out.empty();
}

std::string FormatIdaPattern(const std::vector<PatternByte>& pattern)
{
	std::string result;
	result.reserve(pattern.size() * 3);
	char buf[8];
	for (size_t i = 0; i < pattern.size(); ++i)
	{
		if (i > 0)
		{
			result.push_back(' ');
		}
		if (pattern[i].wildcard)
		{
			result.push_back('?');
		}
		else
		{
			std::snprintf(buf, sizeof(buf), "%02X", pattern[i].value);
			result += buf;
		}
	}
	return result;
}

void FormatCodePattern(const std::vector<PatternByte>& pattern, std::string& bytesOut, std::string& maskOut)
{
	bytesOut.clear();
	maskOut.clear();
	bytesOut.reserve(pattern.size() * 4);
	maskOut.reserve(pattern.size());
	char buf[8];
	for (const auto& entry : pattern)
	{
		if (entry.wildcard)
		{
			bytesOut += "\\x00";
			maskOut.push_back('?');
		}
		else
		{
			std::snprintf(buf, sizeof(buf), "\\x%02X", entry.value);
			bytesOut += buf;
			maskOut.push_back('x');
		}
	}
}

std::vector<size_t> MatchBuffer(const uint8_t* data, size_t size, const std::vector<PatternByte>& pattern, size_t maxMatches)
{
	std::vector<size_t> matches;
	if (!data || pattern.empty() || size < pattern.size())
	{
		return matches;
	}

	const size_t patLen = pattern.size();
	// Find first non-wildcard anchor byte for fast skipping.
	size_t anchorIdx = patLen;
	uint8_t anchorVal = 0;
	for (size_t i = 0; i < patLen; ++i)
	{
		if (!pattern[i].wildcard)
		{
			anchorIdx = i;
			anchorVal = pattern[i].value;
			break;
		}
	}

	const size_t limit = size - patLen;
	for (size_t pos = 0; pos <= limit; ++pos)
	{
		if (anchorIdx < patLen && data[pos + anchorIdx] != anchorVal)
		{
			continue;
		}
		bool ok = true;
		for (size_t k = 0; k < patLen; ++k)
		{
			if (!pattern[k].wildcard && data[pos + k] != pattern[k].value)
			{
				ok = false;
				break;
			}
		}
		if (ok)
		{
			matches.push_back(pos);
			if (maxMatches > 0 && matches.size() >= maxMatches)
			{
				break;
			}
		}
	}
	return matches;
}

std::vector<uintptr_t> ScanRange(MemoryManager& memory, uintptr_t start, size_t size,
	const std::vector<PatternByte>& pattern, size_t maxMatches)
{
	std::vector<uintptr_t> results;
	if (pattern.empty() || size < pattern.size())
	{
		return results;
	}

	const size_t patLen = pattern.size();
	const size_t overlap = patLen - 1;
	std::vector<uint8_t> buffer(kChunkSize + overlap);
	std::vector<uint8_t> valid;

	size_t anchorIdx = patLen;
	uint8_t anchorVal = 0;
	for (size_t i = 0; i < patLen; ++i)
	{
		if (!pattern[i].wildcard)
		{
			anchorIdx = i;
			anchorVal = pattern[i].value;
			break;
		}
	}

	size_t offset = 0;
	while (offset < size)
	{
		const size_t readSize = (std::min)(kChunkSize + overlap, size - offset);
		if (readSize < patLen)
		{
			break;
		}

		ReadRegionWithFallback(memory, start + offset, buffer.data(), readSize, valid);

		const size_t limit = readSize - patLen;
		for (size_t pos = 0; pos <= limit; ++pos)
		{
			if (!valid[pos] || !valid[pos + patLen - 1])
			{
				continue;
			}
			if (anchorIdx < patLen && buffer[pos + anchorIdx] != anchorVal)
			{
				continue;
			}
			bool ok = true;
			for (size_t k = 0; k < patLen; ++k)
			{
				if (!valid[pos + k] || (!pattern[k].wildcard && buffer[pos + k] != pattern[k].value))
				{
					ok = false;
					break;
				}
			}
			if (ok)
			{
				results.push_back(start + offset + pos);
				if (maxMatches > 0 && results.size() >= maxMatches)
				{
					return results;
				}
			}
		}

		if (offset + kChunkSize >= size)
		{
			break;
		}
		offset += kChunkSize;
	}
	return results;
}

std::vector<uintptr_t> ScanPointerValues(MemoryManager& memory, uintptr_t start, size_t size,
	uintptr_t targetValue, size_t pointerSize, size_t maxMatches)
{
	std::vector<uintptr_t> results;
	if ((pointerSize != 4 && pointerSize != 8) || size < pointerSize)
	{
		return results;
	}

	std::vector<uint8_t> buffer(kChunkSize);
	std::vector<uint8_t> valid;
	const size_t step = pointerSize;

	size_t offset = 0;
	while (offset < size)
	{
		const size_t readSize = (std::min)(kChunkSize, size - offset);
		if (readSize < pointerSize)
		{
			break;
		}

		ReadRegionWithFallback(memory, start + offset, buffer.data(), readSize, valid);

		for (size_t pos = 0; pos + pointerSize <= readSize; pos += step)
		{
			if (!valid[pos] || !valid[pos + pointerSize - 1])
			{
				continue;
			}
			uintptr_t val = 0;
			if (pointerSize == 8)
			{
				uint64_t raw = 0;
				std::memcpy(&raw, buffer.data() + pos, sizeof(raw));
				val = static_cast<uintptr_t>(raw);
			}
			else
			{
				uint32_t raw = 0;
				std::memcpy(&raw, buffer.data() + pos, sizeof(raw));
				val = static_cast<uintptr_t>(raw);
			}

			if (val == targetValue)
			{
				results.push_back(start + offset + pos);
				if (maxMatches > 0 && results.size() >= maxMatches)
				{
					return results;
				}
			}
		}
		offset += readSize;
	}
	return results;
}
}
