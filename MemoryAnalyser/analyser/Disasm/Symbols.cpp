#include "Symbols.h"
#include "Pe.h"

#include <Windows.h>
#include <DbgHelp.h>

#include <cstdio>
#include <cstdlib>

namespace analyser::disasm
{
namespace
{
std::string Narrow(const std::wstring& text)
{
	const int length = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
	if (length <= 0)
	{
		return {};
	}
	std::string result(static_cast<size_t>(length - 1), '\0');
	WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, result.data(), length, nullptr, nullptr);
	return result;
}

std::wstring SymbolPath()
{
	wchar_t local[MAX_PATH] = {};
	GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
	std::wstring path = L"srv*";
	path += local;
	path += L"\\MemoryAnalyser\\sym*https://msdl.microsoft.com/download/symbols";
	wchar_t env[2048] = {};
	if (GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", env, 2048) > 0)
	{
		path = std::wstring(env) + L";" + path;
	}
	return path;
}

struct EnumContext
{
	SymbolResolver* self;
	std::vector<std::pair<uintptr_t, std::string>> found;
};

BOOL CALLBACK OnSymbol(PSYMBOL_INFOW info, ULONG, PVOID context)
{
	// SymTagFunction = 5, SymTagPublicSymbol = 10 (cvconst.h is not part of the Windows SDK)
	if (info->Tag == 5 || info->Tag == 10)
	{
		auto* ctx = static_cast<EnumContext*>(context);
		ctx->found.emplace_back(static_cast<uintptr_t>(info->Address), Narrow(std::wstring(info->Name, info->NameLen)));
	}
	return TRUE;
}
}

SymbolResolver::SymbolResolver(MemoryManager& memory, std::vector<ModuleInfo> modules)
	: memory(memory), modules(std::move(modules))
{
	pdbState.assign(this->modules.size(), 0);
	status = "Loading exports...";
	worker = std::thread([this] { Worker(); });
}

SymbolResolver::~SymbolResolver()
{
	stopping = true;
	wake.notify_all();
	if (worker.joinable())
	{
		worker.join();
	}
}

const ModuleInfo* SymbolResolver::ModuleFor(uintptr_t address, size_t* index) const
{
	for (size_t i = 0; i < modules.size(); ++i)
	{
		if (address >= modules[i].base && address < modules[i].base + modules[i].size)
		{
			if (index)
			{
				*index = i;
			}
			return &modules[i];
		}
	}
	return nullptr;
}

void SymbolResolver::RequestPdb(uintptr_t address)
{
	size_t index = 0;
	if (!ModuleFor(address, &index))
	{
		return;
	}
	std::lock_guard lock(mutex);
	if (pdbState[index] != 0)
	{
		return;
	}
	pdbState[index] = 1;
	pdbQueue.push_back(index);
	wake.notify_all();
}

void SymbolResolver::AddSymbol(uintptr_t address, std::string name, int priority)
{
	auto it = symbols.find(address);
	if (it == symbols.end() || it->second.priority <= priority)
	{
		symbols[address] = Symbol{ std::move(name), priority };
	}
}

void SymbolResolver::LoadExports(size_t index)
{
	std::vector<PeExport> exports;
	if (!ReadExports(memory, modules[index].base, exports))
	{
		return;
	}
	std::lock_guard lock(mutex);
	for (auto& e : exports)
	{
		AddSymbol(e.address, std::move(e.name), 0);
	}
}

void SymbolResolver::LoadPdb(size_t index)
{
	const ModuleInfo& module = modules[index];
	{
		std::lock_guard lock(mutex);
		status = "Loading symbols for " + Narrow(module.name) + "...";
	}
	HANDLE process = memory.GetNativeHandle();
	EnumContext ctx{ this, {} };
	const DWORD64 loaded = SymLoadModuleExW(process, nullptr, module.path.c_str(), module.name.c_str(),
		module.base, static_cast<DWORD>(module.size), nullptr, 0);
	if (loaded != 0 || GetLastError() == ERROR_SUCCESS)
	{
		SymEnumSymbolsW(process, module.base, L"*", OnSymbol, &ctx);
	}

	std::lock_guard lock(mutex);
	for (auto& [address, name] : ctx.found)
	{
		AddSymbol(address, std::move(name), 1);
	}
	pdbState[index] = 2;
	status = "Symbols loaded for " + Narrow(module.name) + " (" + std::to_string(ctx.found.size()) + ")";
}

void SymbolResolver::Worker()
{
	for (size_t i = 0; i < modules.size() && !stopping; ++i)
	{
		LoadExports(i);
	}
	{
		std::lock_guard lock(mutex);
		status = "Exports loaded";
	}

	HANDLE process = memory.GetNativeHandle();
	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
	const bool symOk = SymInitializeW(process, SymbolPath().c_str(), FALSE) != FALSE;
	if (!symOk)
	{
		std::lock_guard lock(mutex);
		status = "DbgHelp unavailable; exports only";
	}

	while (!stopping)
	{
		size_t index = 0;
		{
			std::unique_lock lock(mutex);
			wake.wait(lock, [this] { return stopping || !pdbQueue.empty(); });
			if (stopping)
			{
				break;
			}
			index = pdbQueue.front();
			pdbQueue.pop_front();
		}
		if (symOk)
		{
			LoadPdb(index);
		}
		else
		{
			std::lock_guard lock(mutex);
			pdbState[index] = 2;
		}
	}

	if (symOk)
	{
		SymCleanup(process);
	}
}

std::optional<std::string> SymbolResolver::NameAt(uintptr_t address) const
{
	std::lock_guard lock(mutex);
	if (auto it = labels.find(address); it != labels.end())
	{
		return it->second;
	}
	auto it = symbols.find(address);
	if (it == symbols.end())
	{
		return std::nullopt;
	}
	size_t index = 0;
	const ModuleInfo* module = ModuleFor(address, &index);
	return module ? Narrow(module->name) + "!" + it->second.name : it->second.name;
}

std::string SymbolResolver::Describe(uintptr_t address) const
{
	size_t index = 0;
	const ModuleInfo* module = ModuleFor(address);
	if (!module)
	{
		return {};
	}
	const std::string moduleName = Narrow(module->name);
	char buf[64];

	std::lock_guard lock(mutex);
	auto label = labels.upper_bound(address);
	auto symbol = symbols.upper_bound(address);
	const std::string* bestName = nullptr;
	uintptr_t bestAddress = 0;
	if (label != labels.begin())
	{
		--label;
		if (label->first >= module->base)
		{
			bestName = &label->second;
			bestAddress = label->first;
		}
	}
	if (symbol != symbols.begin())
	{
		--symbol;
		if (symbol->first >= module->base && (!bestName || symbol->first > bestAddress))
		{
			bestName = &symbol->second.name;
			bestAddress = symbol->first;
		}
	}
	(void)index;
	// Large distances usually mean the nearest symbol belongs to something else.
	if (bestName && address - bestAddress < 0x10000)
	{
		if (address == bestAddress)
		{
			return moduleName + "!" + *bestName;
		}
		std::snprintf(buf, sizeof(buf), "+0x%llX", static_cast<unsigned long long>(address - bestAddress));
		return moduleName + "!" + *bestName + buf;
	}
	std::snprintf(buf, sizeof(buf), "+0x%llX", static_cast<unsigned long long>(address - module->base));
	return moduleName + buf;
}

void SymbolResolver::SetLabel(uintptr_t address, const std::string& name)
{
	std::lock_guard lock(mutex);
	labels[address] = name;
}

void SymbolResolver::RemoveLabel(uintptr_t address)
{
	std::lock_guard lock(mutex);
	labels.erase(address);
}

std::optional<std::string> SymbolResolver::LabelAt(uintptr_t address) const
{
	std::lock_guard lock(mutex);
	if (auto it = labels.find(address); it != labels.end())
	{
		return it->second;
	}
	return std::nullopt;
}

bool SymbolResolver::ToModuleOffset(uintptr_t address, std::string& module, uint64_t& offset) const
{
	const ModuleInfo* info = ModuleFor(address);
	if (!info)
	{
		return false;
	}
	module = Narrow(info->name);
	offset = address - info->base;
	return true;
}

std::optional<uintptr_t> SymbolResolver::FromModuleOffset(const std::string& module, uint64_t offset) const
{
	for (const auto& info : modules)
	{
		if (_stricmp(Narrow(info.name).c_str(), module.c_str()) == 0 && offset < info.size)
		{
			return info.base + static_cast<uintptr_t>(offset);
		}
	}
	return std::nullopt;
}

std::vector<std::pair<uintptr_t, std::string>> SymbolResolver::SymbolsInModule(size_t moduleIndex) const
{
	std::vector<std::pair<uintptr_t, std::string>> result;
	if (moduleIndex >= modules.size())
	{
		return result;
	}
	const ModuleInfo& module = modules[moduleIndex];
	std::lock_guard lock(mutex);
	for (auto it = symbols.lower_bound(module.base); it != symbols.end() && it->first < module.base + module.size; ++it)
	{
		result.emplace_back(it->first, it->second.name);
	}
	return result;
}

std::string SymbolResolver::Status() const
{
	std::lock_guard lock(mutex);
	return status;
}
}
