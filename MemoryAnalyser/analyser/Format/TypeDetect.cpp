#include "TypeDetect.h"

#include <cmath>
#include <cstring>

namespace analyser
{
namespace
{
uint32_t Read32(const Sample& sample, size_t offset)
{
	return ReadAs<uint32_t>(sample.data() + offset);
}

// A float a program would realistically store (health, position, speed...).
bool PlausibleFloat(uint32_t bits)
{
	float value;
	std::memcpy(&value, &bits, sizeof(value));
	if (std::fpclassify(value) != FP_NORMAL)
	{
		return false;
	}
	const float magnitude = std::fabs(value);
	return magnitude >= 1e-4f && magnitude <= 1e7f;
}

bool SmallInt(uint32_t bits)
{
	const int32_t value = static_cast<int32_t>(bits);
	return value > -1000000 && value < 1000000;
}

bool LooksLikeText(const uint8_t* data, size_t size)
{
	size_t printable = 0;
	while (printable < size && data[printable] >= 0x20 && data[printable] < 0x7F)
	{
		++printable;
	}
	return printable >= 4 && (printable == size || data[printable] == 0);
}

FieldType Classify4(const std::vector<Sample>& samples, size_t offset)
{
	bool anyNonZero = false;
	bool allFloat = true;
	bool allInt = true;
	for (const auto& sample : samples)
	{
		const uint32_t bits = Read32(sample, offset);
		if (bits == 0)
		{
			continue;
		}
		anyNonZero = true;
		allFloat = allFloat && PlausibleFloat(bits);
		allInt = allInt && SmallInt(bits);
	}
	if (!anyNonZero)
	{
		return FieldType::Hex32;
	}
	if (allInt)
	{
		return FieldType::Int32;
	}
	if (allFloat)
	{
		return FieldType::Float;
	}
	return FieldType::Hex32;
}

bool ClassifyPointer(const std::vector<Sample>& samples, size_t offset, size_t pointerSize, const PointerProbe& probe)
{
	const uint64_t maxUser = pointerSize == 4 ? 0xFFFFFFFFull : 0x7FFFFFFEFFFFull;
	for (const auto& sample : samples)
	{
		const uint64_t value = ReadPointer(sample.data() + offset, pointerSize);
		if (value == 0)
		{
			continue;
		}
		if (value < 0x10000 || value > maxUser || (value & 3) != 0)
		{
			return false;
		}
		// A float in the low half (zero above it on x64) can look like an address.
		const uint32_t low = static_cast<uint32_t>(value);
		const bool upperZero = pointerSize == 4 || (value >> 32) == 0;
		if (upperZero && PlausibleFloat(low))
		{
			return false;
		}
	}

	const uint64_t last = ReadPointer(samples.back().data() + offset, pointerSize);
	if (last == 0 || !probe || !probe(last))
	{
		return false;
	}
	// If it changed while sampling, every value it held must also be readable.
	for (const auto& sample : samples)
	{
		const uint64_t value = ReadPointer(sample.data() + offset, pointerSize);
		if (value != 0 && value != last && !probe(value))
		{
			return false;
		}
	}
	return true;
}

void PushHexFill(std::vector<FieldType>& out, size_t size)
{
	while (size > 0)
	{
		if (size >= 8) { out.push_back(FieldType::Hex64); size -= 8; }
		else if (size >= 4) { out.push_back(FieldType::Hex32); size -= 4; }
		else if (size >= 2) { out.push_back(FieldType::Hex16); size -= 2; }
		else { out.push_back(FieldType::Hex8); size -= 1; }
	}
}
}

std::vector<FieldType> DetectRange(const std::vector<Sample>& samples, size_t start, size_t end,
	size_t pointerSize, const PointerProbe& probe)
{
	std::vector<FieldType> out;
	if (samples.empty() || end <= start)
	{
		PushHexFill(out, end > start ? end - start : 0);
		return out;
	}
	for (const auto& sample : samples)
	{
		if (sample.size() < end)
		{
			PushHexFill(out, end - start);
			return out;
		}
	}

	size_t pos = start;
	const size_t aligned = (start + pointerSize - 1) / pointerSize * pointerSize;
	if (aligned > pos && aligned <= end)
	{
		PushHexFill(out, aligned - pos);
		pos = aligned;
	}

	while (pos + pointerSize <= end)
	{
		if (ClassifyPointer(samples, pos, pointerSize, probe))
		{
			out.push_back(FieldType::Pointer);
			pos += pointerSize;
			continue;
		}

		if (pos + 16 <= end && LooksLikeText(samples.back().data() + pos, 16))
		{
			out.push_back(FieldType::Text16);
			pos += 16;
			continue;
		}

		const FieldType low = Classify4(samples, pos);
		if (pointerSize == 8)
		{
			const FieldType high = Classify4(samples, pos + 4);
			if (low == FieldType::Hex32 && high == FieldType::Hex32)
			{
				out.push_back(FieldType::Hex64);
			}
			else
			{
				out.push_back(low);
				out.push_back(high);
			}
		}
		else
		{
			out.push_back(low);
		}
		pos += pointerSize;
	}

	PushHexFill(out, end - pos);
	return out;
}
}
