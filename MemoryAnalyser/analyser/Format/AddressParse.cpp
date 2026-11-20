#include "AddressParse.h"

#include <cctype>

namespace analyser
{
namespace
{
std::string Trim(const std::string& text)
{
	size_t start = 0;
	size_t end = text.size();
	while (start < end && std::isspace(static_cast<unsigned char>(text[start])))
	{
		++start;
	}
	while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1])))
	{
		--end;
	}
	return text.substr(start, end - start);
}
}

std::optional<uint64_t> ParseHex(const std::string& input)
{
	std::string text = Trim(input);
	if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
	{
		text = text.substr(2);
	}
	if (text.empty() || text.size() > 16)
	{
		return std::nullopt;
	}

	uint64_t value = 0;
	for (char c : text)
	{
		if (!std::isxdigit(static_cast<unsigned char>(c)))
		{
			return std::nullopt;
		}
		const int digit = std::isdigit(static_cast<unsigned char>(c)) ? c - '0' : (std::toupper(static_cast<unsigned char>(c)) - 'A' + 10);
		value = (value << 4) | static_cast<uint64_t>(digit);
	}
	return value;
}

std::optional<uintptr_t> ParseBaseAddress(const std::string& input, uintptr_t moduleBase)
{
	const std::string text = Trim(input);
	if (!text.empty() && text[0] == '+')
	{
		const auto offset = ParseHex(text.substr(1));
		if (!offset)
		{
			return std::nullopt;
		}
		return moduleBase + static_cast<uintptr_t>(*offset);
	}

	const auto value = ParseHex(text);
	if (!value)
	{
		return std::nullopt;
	}
	return static_cast<uintptr_t>(*value);
}

std::optional<std::vector<uintptr_t>> ParseOffsets(const std::string& input)
{
	std::vector<uintptr_t> offsets;
	std::string token;

	auto flush = [&]() -> bool
	{
		if (token.empty())
		{
			return true;
		}
		const auto value = ParseHex(token);
		token.clear();
		if (!value)
		{
			return false;
		}
		offsets.push_back(static_cast<uintptr_t>(*value));
		return true;
	};

	for (char c : input)
	{
		if (c == ',' || std::isspace(static_cast<unsigned char>(c)))
		{
			if (!flush())
			{
				return std::nullopt;
			}
		}
		else
		{
			token += c;
		}
	}
	if (!flush())
	{
		return std::nullopt;
	}
	return offsets;
}
}
