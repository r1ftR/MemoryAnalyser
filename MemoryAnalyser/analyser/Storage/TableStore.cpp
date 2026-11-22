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

bool ParseModuleOffset(const std::string& text, ModuleOffset& out)
{
	const size_t plus = text.rfind('+');
	if (plus == std::string::npos || plus == 0)
	{
		return false;
	}
	out.module = Trim(text.substr(0, plus));
	out.offset = std::strtoull(text.c_str() + plus + 1, nullptr, 16);
	return true;
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
	disasmViews.clear();
	labels.clear();
	traces.clear();
	locators.clear();
	std::ifstream file(path);
	if (!file)
	{
		return true; // No file yet.
	}

	SavedTable* current = nullptr;
	SavedDisasm* currentDisasm = nullptr;
	SavedTrace* currentTrace = nullptr;
	SavedLocator* currentLocator = nullptr;
	bool inLabels = false;
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
			currentDisasm = nullptr;
			currentTrace = nullptr;
			currentLocator = nullptr;
			inLabels = false;
			continue;
		}
		if (line == "kind=labels" && current != nullptr)
		{
			tables.pop_back();
			current = nullptr;
			inLabels = true;
			continue;
		}
		if (line == "kind=trace" && current != nullptr)
		{
			SavedTrace trace;
			trace.name = current->name;
			tables.pop_back();
			current = nullptr;
			traces.push_back(std::move(trace));
			currentTrace = &traces.back();
			continue;
		}
		if (line == "kind=locator" && current != nullptr)
		{
			SavedLocator locator;
			locator.name = current->name;
			tables.pop_back();
			current = nullptr;
			locators.push_back(std::move(locator));
			currentLocator = &locators.back();
			continue;
		}
		if (inLabels)
		{
			const size_t eq = line.find('=');
			SavedLabel label;
			if (eq != std::string::npos && ParseModuleOffset(line.substr(0, eq), label.at))
			{
				label.name = Trim(line.substr(eq + 1));
				if (!label.name.empty())
				{
					labels.push_back(std::move(label));
				}
			}
			continue;
		}
		if (currentTrace != nullptr)
		{
			ModuleOffset target;
			if (line.rfind("at=", 0) == 0 && ParseModuleOffset(line.substr(3), target))
			{
				currentTrace->targets.push_back(std::move(target));
			}
			continue;
		}
		if (currentLocator != nullptr)
		{
			if (line.rfind("spec=", 0) == 0)
			{
				currentLocator->spec = Trim(line.substr(5));
			}
			continue;
		}
		if (line == "kind=disasm" && current != nullptr)
		{
			SavedDisasm view;
			view.name = current->name;
			tables.pop_back();
			current = nullptr;
			disasmViews.push_back(std::move(view));
			currentDisasm = &disasmViews.back();
			continue;
		}
		if (currentDisasm != nullptr)
		{
			if (line.rfind("arch=", 0) == 0)
			{
				currentDisasm->pointerSize = line.substr(5) == "x86" ? 4 : 8;
			}
			else if (line.rfind("base=", 0) == 0)
			{
				const char* value = line.c_str() + 5;
				currentDisasm->relative = *value == '+';
				currentDisasm->address = std::strtoull(currentDisasm->relative ? value + 1 : value, nullptr, 16);
			}
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
	for (const auto& view : disasmViews)
	{
		file << '[' << view.name << "]\n";
		file << "kind=disasm\n";
		file << "arch=" << (view.pointerSize == 4 ? "x86" : "x64") << '\n';
		file << "base=" << (view.relative ? "+" : "") << std::hex << std::uppercase << view.address << std::dec << "\n\n";
	}
	if (!labels.empty())
	{
		file << "[Labels]\nkind=labels\n";
		for (const auto& label : labels)
		{
			file << label.at.module << '+' << std::hex << std::uppercase << label.at.offset << std::dec << '=' << label.name << '\n';
		}
		file << '\n';
	}
	for (const auto& trace : traces)
	{
		file << '[' << trace.name << "]\nkind=trace\n";
		for (const auto& target : trace.targets)
		{
			file << "at=" << target.module << '+' << std::hex << std::uppercase << target.offset << std::dec << '\n';
		}
		file << '\n';
	}
	for (const auto& locator : locators)
	{
		if (!locator.spec.empty())
		{
			file << '[' << locator.name << "]\nkind=locator\n";
			file << "spec=" << locator.spec << "\n\n";
		}
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

void TableStore::SetLabel(SavedLabel label)
{
	for (size_t i = 0; i < labels.size(); ++i)
	{
		if (_stricmp(labels[i].at.module.c_str(), label.at.module.c_str()) == 0 && labels[i].at.offset == label.at.offset)
		{
			if (label.name.empty())
			{
				labels.erase(labels.begin() + static_cast<std::ptrdiff_t>(i));
			}
			else
			{
				labels[i].name = std::move(label.name);
			}
			return;
		}
	}
	if (!label.name.empty())
	{
		labels.push_back(std::move(label));
	}
}

void TableStore::UpsertTrace(SavedTrace trace)
{
	for (auto& existing : traces)
	{
		if (existing.name == trace.name)
		{
			existing = std::move(trace);
			return;
		}
	}
	traces.push_back(std::move(trace));
}

void TableStore::RemoveTrace(size_t index)
{
	if (index < traces.size())
	{
		traces.erase(traces.begin() + static_cast<std::ptrdiff_t>(index));
	}
}

void TableStore::UpsertDisasm(SavedDisasm view)
{
	for (auto& existing : disasmViews)
	{
		if (existing.name == view.name)
		{
			existing = std::move(view);
			return;
		}
	}
	disasmViews.push_back(std::move(view));
}

void TableStore::RemoveDisasm(size_t index)
{
	if (index < disasmViews.size())
	{
		disasmViews.erase(disasmViews.begin() + static_cast<std::ptrdiff_t>(index));
	}
}

void TableStore::Remove(size_t index)
{
	if (index < tables.size())
	{
		tables.erase(tables.begin() + static_cast<std::ptrdiff_t>(index));
	}
}

void TableStore::UpsertLocator(SavedLocator locator)
{
	for (auto& existing : locators)
	{
		if (existing.name == locator.name)
		{
			existing = std::move(locator);
			return;
		}
	}
	locators.push_back(std::move(locator));
}

void TableStore::RemoveLocator(size_t index)
{
	if (index < locators.size())
	{
		locators.erase(locators.begin() + static_cast<std::ptrdiff_t>(index));
	}
}
}
