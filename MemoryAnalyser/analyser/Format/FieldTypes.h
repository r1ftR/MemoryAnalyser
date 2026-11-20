#pragma once

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace analyser
{
enum class FieldType : int
{
	Hex8,
	Hex16,
	Hex32,
	Hex64,
	Int8,
	Int16,
	Int32,
	Int64,
	UInt8,
	UInt16,
	UInt32,
	UInt64,
	Float,
	Double,
	Bool,
	Pointer,
	Text16,
	WText16,
	Count
};

inline const char* const* FieldTypeNames()
{
	static const char* names[] = {
		"Hex8", "Hex16", "Hex32", "Hex64",
		"Int8", "Int16", "Int32", "Int64",
		"UInt8", "UInt16", "UInt32", "UInt64",
		"Float", "Double", "Bool", "Pointer",
		"Text[16]", "WText[8]"
	};
	return names;
}

inline size_t FieldSize(FieldType type, size_t pointerSize)
{
	switch (type)
	{
	case FieldType::Hex8: case FieldType::Int8: case FieldType::UInt8: case FieldType::Bool: return 1;
	case FieldType::Hex16: case FieldType::Int16: case FieldType::UInt16: return 2;
	case FieldType::Hex32: case FieldType::Int32: case FieldType::UInt32: case FieldType::Float: return 4;
	case FieldType::Hex64: case FieldType::Int64: case FieldType::UInt64: case FieldType::Double: return 8;
	case FieldType::Pointer: return pointerSize;
	case FieldType::Text16: case FieldType::WText16: return 16;
	default: return 1;
	}
}

inline FieldType DefaultFieldType(size_t pointerSize)
{
	return pointerSize == 4 ? FieldType::Hex32 : FieldType::Hex64;
}

template <typename T>
T ReadAs(const uint8_t* data)
{
	T value{};
	std::memcpy(&value, data, sizeof(T));
	return value;
}

inline uint64_t ReadPointer(const uint8_t* data, size_t pointerSize)
{
	return pointerSize == 4 ? ReadAs<uint32_t>(data) : ReadAs<uint64_t>(data);
}

inline std::string FormatHexBytes(const uint8_t* data, size_t size)
{
	std::string out;
	char buf[4];
	for (size_t i = 0; i < size; ++i)
	{
		std::snprintf(buf, sizeof(buf), "%02X ", data[i]);
		out += buf;
	}
	return out;
}

inline bool IsIntegerType(FieldType type)
{
	return type >= FieldType::Int8 && type <= FieldType::UInt64;
}

inline std::string FormatField(FieldType type, const uint8_t* data, size_t pointerSize, bool hexIntegers = false)
{
	if (hexIntegers && IsIntegerType(type))
	{
		uint64_t value = 0;
		std::memcpy(&value, data, FieldSize(type, pointerSize));
		char hex[32];
		std::snprintf(hex, sizeof(hex), "0x%llX", static_cast<unsigned long long>(value));
		return hex;
	}

	char buf[128] = {};
	switch (type)
	{
	case FieldType::Hex8:
	case FieldType::Hex16:
	case FieldType::Hex32:
	case FieldType::Hex64:
		return FormatHexBytes(data, FieldSize(type, pointerSize));
	case FieldType::Int8: std::snprintf(buf, sizeof(buf), "%d", ReadAs<int8_t>(data)); break;
	case FieldType::Int16: std::snprintf(buf, sizeof(buf), "%d", ReadAs<int16_t>(data)); break;
	case FieldType::Int32: std::snprintf(buf, sizeof(buf), "%d", ReadAs<int32_t>(data)); break;
	case FieldType::Int64: std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(ReadAs<int64_t>(data))); break;
	case FieldType::UInt8: std::snprintf(buf, sizeof(buf), "%u", ReadAs<uint8_t>(data)); break;
	case FieldType::UInt16: std::snprintf(buf, sizeof(buf), "%u", ReadAs<uint16_t>(data)); break;
	case FieldType::UInt32: std::snprintf(buf, sizeof(buf), "%u", ReadAs<uint32_t>(data)); break;
	case FieldType::UInt64: std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(ReadAs<uint64_t>(data))); break;
	case FieldType::Float: std::snprintf(buf, sizeof(buf), "%.4f", ReadAs<float>(data)); break;
	case FieldType::Double: std::snprintf(buf, sizeof(buf), "%.6f", ReadAs<double>(data)); break;
	case FieldType::Bool: return data[0] ? "true" : "false";
	case FieldType::Pointer: std::snprintf(buf, sizeof(buf), "-> 0x%llX", static_cast<unsigned long long>(ReadPointer(data, pointerSize))); break;
	case FieldType::Text16:
	{
		std::string text;
		for (size_t i = 0; i < 16 && data[i]; ++i)
		{
			text += (data[i] >= 32 && data[i] < 127) ? static_cast<char>(data[i]) : '.';
		}
		return "\"" + text + "\"";
	}
	case FieldType::WText16:
	{
		std::string text;
		for (size_t i = 0; i < 8; ++i)
		{
			const uint16_t ch = ReadAs<uint16_t>(data + i * 2);
			if (ch == 0)
			{
				break;
			}
			text += (ch >= 32 && ch < 127) ? static_cast<char>(ch) : '.';
		}
		return "L\"" + text + "\"";
	}
	default: break;
	}
	return buf;
}

// Parses user input into bytes to write. The input syntax decides how it is read:
//   123 / -5      decimal integer (field size)
//   0x64          hex integer (field size)
//   1.5           float (8 bytes if field is Double, else 4)
//   true / false  bool
//   0x1234*       pointer (pointer size)
//   "text"        string (UTF-16 for WText fields), zero padded to field size
inline bool ParseValueInput(const std::string& input, FieldType type, size_t pointerSize,
	std::vector<uint8_t>& out, std::string& error)
{
	out.clear();
	error.clear();

	size_t start = 0;
	size_t end = input.size();
	while (start < end && std::isspace(static_cast<unsigned char>(input[start]))) ++start;
	while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
	const std::string text = input.substr(start, end - start);
	if (text.empty())
	{
		error = "Empty value";
		return false;
	}

	const size_t fieldSize = FieldSize(type, pointerSize);

	auto parseUnsigned = [](const std::string& digits, int base, uint64_t& value) -> bool
	{
		if (digits.empty())
		{
			return false;
		}
		value = 0;
		for (char c : digits)
		{
			int digit;
			if (c >= '0' && c <= '9') digit = c - '0';
			else if (base == 16 && c >= 'a' && c <= 'f') digit = c - 'a' + 10;
			else if (base == 16 && c >= 'A' && c <= 'F') digit = c - 'A' + 10;
			else return false;
			if (value > (UINT64_MAX - static_cast<uint64_t>(digit)) / static_cast<uint64_t>(base))
			{
				return false;
			}
			value = value * static_cast<uint64_t>(base) + static_cast<uint64_t>(digit);
		}
		return true;
	};

	auto storeInteger = [&](uint64_t value, size_t size) -> bool
	{
		if (size < 8 && (value >> (size * 8)) != 0)
		{
			error = "Value does not fit in " + std::to_string(size) + " byte(s)";
			return false;
		}
		out.resize(size);
		std::memcpy(out.data(), &value, size);
		return true;
	};

	auto isHexPrefix = [](const std::string& s)
	{
		return s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
	};

	// Text: "..."
	if (text.size() >= 2 && text.front() == '"' && text.back() == '"')
	{
		const std::string content = text.substr(1, text.size() - 2);
		if (type == FieldType::WText16)
		{
			if (content.size() * 2 > fieldSize)
			{
				error = "Text longer than field";
				return false;
			}
			out.assign(fieldSize, 0);
			for (size_t i = 0; i < content.size(); ++i)
			{
				const uint16_t ch = static_cast<unsigned char>(content[i]);
				std::memcpy(out.data() + i * 2, &ch, 2);
			}
		}
		else
		{
			if (content.size() > fieldSize)
			{
				error = "Text longer than field";
				return false;
			}
			out.assign(fieldSize, 0);
			std::memcpy(out.data(), content.data(), content.size());
		}
		return true;
	}

	// Bool
	if (text == "true" || text == "false")
	{
		const uint64_t value = text == "true" ? 1 : 0;
		return storeInteger(value, type == FieldType::Bool ? 1 : fieldSize);
	}

	// Pointer: ends with '*'
	if (text.back() == '*')
	{
		std::string digits = text.substr(0, text.size() - 1);
		if (isHexPrefix(digits))
		{
			digits = digits.substr(2);
		}
		uint64_t value = 0;
		if (!parseUnsigned(digits, 16, value))
		{
			error = "Invalid pointer (use 0x1234*)";
			return false;
		}
		return storeInteger(value, pointerSize);
	}

	// Float: contains '.'
	if (text.find('.') != std::string::npos)
	{
		char* parseEnd = nullptr;
		const double value = std::strtod(text.c_str(), &parseEnd);
		if (parseEnd == text.c_str() || *parseEnd != '\0')
		{
			error = "Invalid float";
			return false;
		}
		if (type == FieldType::Double)
		{
			out.resize(8);
			std::memcpy(out.data(), &value, 8);
		}
		else
		{
			const float single = static_cast<float>(value);
			out.resize(4);
			std::memcpy(out.data(), &single, 4);
		}
		return true;
	}

	// Hex integer: 0x...
	if (isHexPrefix(text))
	{
		uint64_t value = 0;
		if (!parseUnsigned(text.substr(2), 16, value))
		{
			error = "Invalid hex value";
			return false;
		}
		return storeInteger(value, fieldSize);
	}

	// Decimal integer (optionally negative)
	const bool negative = text[0] == '-';
	uint64_t magnitude = 0;
	if (!parseUnsigned(negative ? text.substr(1) : text, 10, magnitude))
	{
		error = "Unrecognised value";
		return false;
	}
	if (!negative)
	{
		return storeInteger(magnitude, fieldSize);
	}

	const uint64_t limit = fieldSize >= 8 ? (1ull << 63) : (1ull << (fieldSize * 8 - 1));
	if (magnitude > limit)
	{
		error = "Value does not fit in " + std::to_string(fieldSize) + " byte(s)";
		return false;
	}
	const uint64_t value = static_cast<uint64_t>(0) - magnitude;
	out.resize(fieldSize);
	std::memcpy(out.data(), &value, fieldSize);
	return true;
}
}
