#include "TableStore.h"

#include <Windows.h>

#include <cstdlib>
#include <fstream>
#include <sstream>

// File format:
// [Name]
// arch=x64
// Type,field name
// ...

namespace analyser
{
namespace
{
std::wstring DefaultPath()
{
	wchar_t exe[MAX_PATH] = {};
	GetModuleFileNameW(nullptr, exe, MAX_PATH);
	std::wstring dir(exe);
	const size_t slash = dir.find_last_of(L"\\/");
	dir = slash == std::wstring::npos ? L"" : dir.substr(0, slash + 1);
	return dir + L"tables.txt";
}

std::string Trim(const std::string& text)
{
	const size_t start = text.find_first_not_of(" \t\r\n");
	if (start == std::string::npos)
	{
		return {};
	}
	const size_t end = text.find_last_not_of(" \t\r\n");
	return text.substr(start, end - start + 1);
}

bool ParseTypeName(const std::string& text, FieldType& type)
{
	for (int index = 0; index < static_cast<int>(FieldType::Count); ++index)
	{
		if (text == FieldTypeNames()[index])
		{
			type = static_cast<FieldType>(index);
			return true;
		}
	}
	return false;
}
}

TableStore::TableStore() : path(DefaultPath())
{
}

bool TableStore::Load()
{
	tables.clear();
	std::ifstream file(path);
	if (!file)
	{
		return true; // No file yet.
	}

	SavedTable* current = nullptr;
	std::string line;
	while (std::getline(file, line))
	{
		line = Trim(line);
		if (line.empty())
		{
			continue;
		}
		if (line.front() == '[' && line.back() == ']')
		{
			SavedTable table;
			table.name = line.substr(1, line.size() - 2);
			tables.push_back(std::move(table));
			current = &tables.back();
			continue;
		}
		if (current == nullptr)
		{
			continue;
		}
		if (line.rfind("base=", 0) == 0)
		{
			const char* value = line.c_str() + 5;
			current->relative = *value == '+';
			current->base = std::strtoull(current->relative ? value + 1 : value, nullptr, 16);
			current->hasLocation = true;
			continue;
		}
		if (line.rfind("chain=", 0) == 0)
		{
			std::istringstream offsets(line.substr(6));
			std::string token;
			while (std::getline(offsets, token, ' '))
			{
				if (!token.empty())
				{
					current->chain.push_back(std::strtoull(token.c_str(), nullptr, 16));
				}
			}
			continue;
		}
		if (line.rfind("arch=", 0) == 0)
		{
			current->pointerSize = line.substr(5) == "x86" ? 4 : 8;
			continue;
		}

		const size_t comma = line.find(',');
		SavedField field;
		if (ParseTypeName(Trim(line.substr(0, comma)), field.type))
		{
			field.name = comma == std::string::npos ? "" : Trim(line.substr(comma + 1));
			current->fields.push_back(std::move(field));
		}
	}
	return true;
}

bool TableStore::Save()
{
	std::ofstream file(path, std::ios::trunc);
	if (!file)
	{
		lastError = "Could not write tables.txt";
		return false;
	}

	for (const auto& table : tables)
	{
		file << '[' << table.name << "]\n";
		file << "arch=" << (table.pointerSize == 4 ? "x86" : "x64") << '\n';
		if (table.hasLocation)
		{
			file << "base=" << (table.relative ? "+" : "") << std::hex << std::uppercase << table.base << '\n';
			file << "chain=";
			for (const uint64_t offset : table.chain)
			{
				file << offset << ' ';
			}
			file << std::dec << '\n';
		}
		for (const auto& field : table.fields)
		{
			file << FieldTypeNames()[static_cast<int>(field.type)] << ',' << field.name << '\n';
		}
		file << '\n';
	}
	lastError.clear();
	return true;
}

void TableStore::Upsert(SavedTable table)
{
	for (auto& existing : tables)
	{
		if (existing.name == table.name)
		{
			existing = std::move(table);
			return;
		}
	}
	tables.push_back(std::move(table));
}

void TableStore::Remove(size_t index)
{
	if (index < tables.size())
	{
		tables.erase(tables.begin() + static_cast<std::ptrdiff_t>(index));
	}
}
}
