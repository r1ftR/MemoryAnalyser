#include "TableStore.h"

#include <Windows.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <utility>
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

std::string Encode(const void* data, size_t size)
{
	constexpr char digits[] = "0123456789ABCDEF";
	std::string result;
	const auto* bytes = static_cast<const unsigned char*>(data);
	for (size_t i = 0; i < size; ++i) { result += digits[bytes[i] >> 4]; result += digits[bytes[i] & 15]; }
	return result;
}

bool Decode(const std::string& text, std::string& result)
{
	if (text.size() % 2) return false;
	auto digit = [](char c) -> int {
		if (c >= '0' && c <= '9') return c - '0';
		if (c >= 'A' && c <= 'F') return c - 'A' + 10;
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		return -1;
	};
	result.clear();
	for (size_t i = 0; i < text.size(); i += 2)
	{
		const int high = digit(text[i]), low = digit(text[i + 1]);
		if (high < 0 || low < 0) return false;
		result += static_cast<char>((high << 4) | low);
	}
	return true;
}

bool DecodeWide(const std::string& bytes, std::wstring& result)
{
	if (bytes.size() % sizeof(wchar_t)) return false;
	result.resize(bytes.size() / sizeof(wchar_t));
	if (!bytes.empty()) memcpy(result.data(), bytes.data(), bytes.size());
	return result.find(L'\0') == std::wstring::npos;
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

TableStore::TableStore(std::wstring storagePath) : path(std::move(storagePath))
{
}

bool TableStore::Load()
{
	tables.clear();
	disasmViews.clear();
	labels.clear();
	traces.clear();
	locators.clear();
	functions.clear();
	lastError.clear();
	std::ifstream file(path);
	if (!file)
	{
		if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND)
			return true;
		lastError = "Could not read saved analyser records";
		return false;
	}

	SavedTable* current = nullptr;
	SavedDisasm* currentDisasm = nullptr;
	SavedTrace* currentTrace = nullptr;
	SavedLocator* currentLocator = nullptr;
	SavedFunction* currentFunction = nullptr;
	std::vector<unsigned> functionFields;
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
			currentFunction = nullptr;
			inLabels = false;
			continue;
		}
		if (line == "kind=function-v1" && current != nullptr)
		{
			tables.pop_back();
			current = nullptr;
			functions.emplace_back();
			functionFields.push_back(0);
			currentFunction = &functions.back();
			continue;
		}
		if (currentFunction != nullptr)
		{
			const size_t eq = line.find('=');
			const std::string key = line.substr(0, eq);
			const std::string value = eq == std::string::npos ? "" : line.substr(eq + 1);
			auto& t = currentFunction->target;
			bool valid = true;
			std::string decoded;
			if (key == "identity")
			{
				std::istringstream values(value);
				valid = static_cast<bool>(values >> t.rva >> t.x64 >> t.volumeSerial >> t.fileId >> t.fileSize >> t.fileLastWrite
					>> t.imageSize >> t.imageTimestamp >> t.imageChecksum >> t.imageMachine);
				values >> std::ws;
				valid = valid && values.eof();
			}
			else if (key == "name" || key == "module" || key == "path" || key == "locator" || key == "project" || key == "bytes")
			{
				valid = Decode(value, decoded);
				if (valid && key == "name") t.name = decoded;
				else if (valid && key == "module") t.moduleName = decoded;
				else if (valid && key == "path") valid = DecodeWide(decoded, t.modulePath);
				else if (valid && key == "locator") currentFunction->locatorSpec = decoded;
				else if (valid && key == "project")
				{
					std::wstring project;
					valid = DecodeWide(decoded, project);
					if (valid && !project.empty()) currentFunction->projects.push_back(std::move(project));
				}
				else if (valid && key == "bytes")
				{
					valid = decoded.size() == t.originalBytes.size();
					if (valid) std::copy(decoded.begin(), decoded.end(), t.originalBytes.begin());
				}
			}
			if (valid)
			{
				if (key == "identity") functionFields.back() |= 1;
				if (key == "module") functionFields.back() |= 2;
				if (key == "path") functionFields.back() |= 4;
				if (key == "bytes") functionFields.back() |= 8;
			}
			if (!valid) { lastError = "Malformed saved function record"; functions.clear(); return false; }
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
	if (file.bad()) { lastError = "Could not finish reading saved analyser records"; return false; }
	for (size_t i = 0; i < functions.size(); ++i)
	{
		const auto& t = functions[i].target;
		if (functionFields[i] != 15 || t.modulePath.empty() || t.moduleName.empty() || !t.imageSize || t.rva >= t.imageSize ||
			(t.imageMachine != IMAGE_FILE_MACHINE_AMD64 && t.imageMachine != IMAGE_FILE_MACHINE_I386) ||
			(t.x64 != (t.imageMachine == IMAGE_FILE_MACHINE_AMD64)) || !t.fileSize ||
			!t.fileId || t.originalBytes.size() > t.imageSize - t.rva ||
			t.moduleName.find('\0') != std::string::npos)
		{
			lastError = "Incomplete saved function identity";
			functions.clear();
			return false;
		}
	}
	return true;
}

bool TableStore::Save()
{
	const std::wstring pendingPath = path + L".pending";
	std::ofstream file(pendingPath, std::ios::trunc);
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
	for (const auto& function : functions)
	{
		const auto& t = function.target;
		file << "[SavedFunction]\nkind=function-v1\n";
		file << "name=" << Encode(t.name.data(), t.name.size()) << "\nmodule=" << Encode(t.moduleName.data(), t.moduleName.size())
			<< "\npath=" << Encode(t.modulePath.data(), t.modulePath.size() * sizeof(wchar_t))
			<< "\nlocator=" << Encode(function.locatorSpec.data(), function.locatorSpec.size()) << '\n';
		file << "identity=" << std::dec << t.rva << ' ' << t.x64 << ' ' << t.volumeSerial << ' ' << t.fileId << ' '
			<< t.fileSize << ' ' << t.fileLastWrite << ' ' << t.imageSize << ' ' << t.imageTimestamp << ' '
			<< t.imageChecksum << ' ' << t.imageMachine << '\n';
		file << "bytes=" << Encode(t.originalBytes.data(), t.originalBytes.size()) << '\n';
		for (const auto& project : function.projects) file << "project=" << Encode(project.data(), project.size() * sizeof(wchar_t)) << '\n';
		file << '\n';
	}
	file.flush();
	const bool written = static_cast<bool>(file);
	file.close();
	if (!written || file.fail() || !MoveFileExW(pendingPath.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
	{
		lastError = "Could not persist saved analyser records";
		DeleteFileW(pendingPath.c_str());
		return false;
	}
	lastError.clear();
	return true;
}

bool TableStore::SameFunctionIdentity(const hooking::HookTarget& a, const hooking::HookTarget& b)
{
	return !a.modulePath.empty() && !b.modulePath.empty() &&
		CompareStringOrdinal(a.modulePath.c_str(), -1, b.modulePath.c_str(), -1, TRUE) == CSTR_EQUAL &&
		a.rva == b.rva && a.imageMachine == b.imageMachine && a.imageSize == b.imageSize &&
		a.imageTimestamp == b.imageTimestamp && a.imageChecksum == b.imageChecksum;
}

SavedFunction* TableStore::FindFunction(const hooking::HookTarget& target)
{
	for (auto& function : functions) if (SameFunctionIdentity(function.target, target)) return &function;
	return nullptr;
}

const SavedFunction* TableStore::FindFunction(const hooking::HookTarget& target) const
{
	for (const auto& function : functions) if (SameFunctionIdentity(function.target, target)) return &function;
	return nullptr;
}

void TableStore::UpsertFunction(SavedFunction function)
{
	function.target.address = 0;
	function.target.processId = 0;
	function.target.processCreation = 0;
	if (auto* existing = FindFunction(function.target))
	{
		for (const auto& project : existing->projects)
			if (std::find(function.projects.begin(), function.projects.end(), project) == function.projects.end()) function.projects.push_back(project);
		*existing = std::move(function);
	}
	else functions.push_back(std::move(function));
}

bool TableStore::AddFunctionProject(const hooking::HookTarget& target, const std::wstring& project)
{
	auto* function = FindFunction(target);
	if (!function || project.empty()) { lastError = "Saved function or project path is missing"; return false; }
	for (const auto& existing : function->projects)
		if (CompareStringOrdinal(existing.c_str(), -1, project.c_str(), -1, TRUE) == CSTR_EQUAL) return true;
	function->projects.push_back(project);
	lastError.clear();
	return true;
}

bool TableStore::ReplaceFunctionProject(const hooking::HookTarget& target, size_t index, const std::wstring& project)
{
	auto* function = FindFunction(target);
	if (!function || index >= function->projects.size() || project.empty())
	{
		lastError = "Saved function, project index, or replacement path is invalid";
		return false;
	}
	for (size_t i = 0; i < function->projects.size(); ++i)
	{
		if (i != index && CompareStringOrdinal(function->projects[i].c_str(), -1, project.c_str(), -1, TRUE) == CSTR_EQUAL)
		{
			lastError = "Replacement project is already associated with this function";
			return false;
		}
	}
	function->projects[index] = project;
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
