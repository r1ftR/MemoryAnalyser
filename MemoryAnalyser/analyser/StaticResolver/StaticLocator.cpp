#include "StaticLocator.h"

#include "../Disasm/Pe.h"
#include "../Disasm/Symbols.h"
#include "../../MemoryManager/MemoryManager.h"

#include <Windows.h>

#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace analyser
{
namespace
{
	std::string NarrowModuleName(const std::wstring& wide)
	{
		if (wide.empty())
		{
			return {};
		}
		const int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
		if (len <= 0)
		{
			return {};
		}
		std::string out(static_cast<size_t>(len), '\0');
		WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), out.data(), len, nullptr, nullptr);
		return out;
	}

	std::optional<ModuleInfo> FindModule(const ResolveContext& ctx, const std::string& moduleName)
	{
		if (ctx.symbols)
		{
			for (const auto& mod : ctx.symbols->Modules())
			{
				if (_stricmp(NarrowModuleName(mod.name).c_str(), moduleName.c_str()) == 0)
				{
					return mod;
				}
			}
		}
		for (const auto& mod : ctx.memory.EnumerateModules())
		{
			if (_stricmp(NarrowModuleName(mod.name).c_str(), moduleName.c_str()) == 0)
			{
				return mod;
			}
		}
		return std::nullopt;
	}

	std::vector<std::string> SplitPipe(const std::string& text)
	{
		std::vector<std::string> parts;
		size_t start = 0;
		while (start <= text.size())
		{
			const size_t pos = text.find('|', start);
			if (pos == std::string::npos)
			{
				parts.push_back(text.substr(start));
				break;
			}
			parts.push_back(text.substr(start, pos - start));
			start = pos + 1;
		}
		return parts;
	}
}

ModuleOffsetLocator::ModuleOffsetLocator(std::string module, uint64_t offset, std::string section)
	: moduleName(std::move(module)), rva(offset), sectionName(std::move(section))
{
}

std::optional<uintptr_t> ModuleOffsetLocator::Resolve(const ResolveContext& ctx) const
{
	if (ctx.symbols)
	{
		if (const auto addr = ctx.symbols->FromModuleOffset(moduleName, rva))
		{
			return addr;
		}
	}
	const auto mod = FindModule(ctx, moduleName);
	if (!mod || rva >= mod->size)
	{
		return std::nullopt;
	}
	return mod->base + static_cast<uintptr_t>(rva);
}

std::string ModuleOffsetLocator::Describe() const
{
	char buf[256];
	if (!sectionName.empty())
	{
		std::snprintf(buf, sizeof(buf), "%s+0x%llX (%s)", moduleName.c_str(),
			static_cast<unsigned long long>(rva), sectionName.c_str());
	}
	else
	{
		std::snprintf(buf, sizeof(buf), "%s+0x%llX", moduleName.c_str(),
			static_cast<unsigned long long>(rva));
	}
	return buf;
}

std::string ModuleOffsetLocator::Serialize() const
{
	char buf[300];
	std::snprintf(buf, sizeof(buf), "rva|%s|%llX|%s",
		moduleName.c_str(), static_cast<unsigned long long>(rva), sectionName.c_str());
	return buf;
}

std::unique_ptr<IStaticLocator> ModuleOffsetLocator::Clone() const
{
	return std::make_unique<ModuleOffsetLocator>(*this);
}

ExportOffsetLocator::ExportOffsetLocator(std::string module, std::string expName, int64_t disp)
	: moduleName(std::move(module)), exportName(std::move(expName)), delta(disp)
{
}

std::optional<uintptr_t> ExportOffsetLocator::Resolve(const ResolveContext& ctx) const
{
	const auto mod = FindModule(ctx, moduleName);
	if (!mod)
	{
		return std::nullopt;
	}
	std::vector<disasm::PeExport> exports;
	if (!disasm::ReadExports(ctx.memory, mod->base, exports))
	{
		return std::nullopt;
	}
	for (const auto& exp : exports)
	{
		if (exp.name == exportName)
		{
			return static_cast<uintptr_t>(static_cast<int64_t>(exp.address) + delta);
		}
	}
	return std::nullopt;
}

std::string ExportOffsetLocator::Describe() const
{
	char buf[300];
	if (delta == 0)
	{
		std::snprintf(buf, sizeof(buf), "%s!%s", moduleName.c_str(), exportName.c_str());
	}
	else if (delta > 0)
	{
		std::snprintf(buf, sizeof(buf), "%s!%s+0x%llX", moduleName.c_str(), exportName.c_str(),
			static_cast<unsigned long long>(delta));
	}
	else
	{
		std::snprintf(buf, sizeof(buf), "%s!%s-0x%llX", moduleName.c_str(), exportName.c_str(),
			static_cast<unsigned long long>(-delta));
	}
	return buf;
}

std::string ExportOffsetLocator::Serialize() const
{
	char buf[320];
	std::snprintf(buf, sizeof(buf), "export|%s|%s|%lld",
		moduleName.c_str(), exportName.c_str(), static_cast<long long>(delta));
	return buf;
}

std::unique_ptr<IStaticLocator> ExportOffsetLocator::Clone() const
{
	return std::make_unique<ExportOffsetLocator>(*this);
}

PatternLocator::PatternLocator(std::string module, std::string section, std::vector<PatternByte> bytes, int64_t offset)
	: moduleName(std::move(module)), sectionName(std::move(section)), pattern(std::move(bytes)), postOffset(offset)
{
}

std::optional<uintptr_t> PatternLocator::Resolve(const ResolveContext& ctx) const
{
	if (pattern.empty())
	{
		return std::nullopt;
	}
	const auto mod = FindModule(ctx, moduleName);
	if (!mod)
	{
		return std::nullopt;
	}

	uintptr_t scanStart = mod->base;
	size_t scanSize = mod->size;

	if (!sectionName.empty())
	{
		std::vector<disasm::PeSection> sections;
		if (disasm::ReadSections(ctx.memory, mod->base, sections))
		{
			for (const auto& sec : sections)
			{
				if (sec.name == sectionName)
				{
					scanStart = sec.address;
					scanSize = sec.size;
					break;
				}
			}
		}
	}

	const auto matches = PatternScanner::ScanRange(ctx.memory, scanStart, scanSize, pattern, 1);
	if (matches.empty())
	{
		return std::nullopt;
	}
	return static_cast<uintptr_t>(static_cast<int64_t>(matches.front()) + postOffset);
}

std::string PatternLocator::IdaPattern() const
{
	return PatternScanner::FormatIdaPattern(pattern);
}

void PatternLocator::CodePattern(std::string& bytesOut, std::string& maskOut) const
{
	PatternScanner::FormatCodePattern(pattern, bytesOut, maskOut);
}

std::string PatternLocator::Describe() const
{
	std::string text = moduleName;
	if (!sectionName.empty())
	{
		text += " (" + sectionName + ")";
	}
	text += " sig: " + IdaPattern();
	if (postOffset != 0)
	{
		char buf[32];
		std::snprintf(buf, sizeof(buf), " %+lld", static_cast<long long>(postOffset));
		text += buf;
	}
	return text;
}

std::string PatternLocator::Serialize() const
{
	char buf[64];
	std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(postOffset));
	return "pattern|" + moduleName + "|" + sectionName + "|" + IdaPattern() + "|" + buf;
}

std::unique_ptr<IStaticLocator> PatternLocator::Clone() const
{
	return std::make_unique<PatternLocator>(*this);
}

PointerChainLocator::PointerChainLocator(std::string module, uint64_t rva, std::vector<uintptr_t> chain)
	: moduleName(std::move(module)), baseRva(rva), offsets(std::move(chain))
{
}

std::optional<uintptr_t> PointerChainLocator::Resolve(const ResolveContext& ctx) const
{
	const auto mod = FindModule(ctx, moduleName);
	if (!mod || baseRva >= mod->size)
	{
		return std::nullopt;
	}
	const uintptr_t baseAddr = mod->base + static_cast<uintptr_t>(baseRva);
	if (offsets.empty())
	{
		return baseAddr;
	}
	uintptr_t resolved = 0;
	if (!ctx.memory.resolvePointerChain(baseAddr, offsets, resolved, ctx.pointerSize))
	{
		return std::nullopt;
	}
	return resolved;
}

std::string PointerChainLocator::Describe() const
{
	char buf[160];
	std::snprintf(buf, sizeof(buf), "[%s+0x%llX]", moduleName.c_str(), static_cast<unsigned long long>(baseRva));
	std::string out = buf;
	for (const uintptr_t off : offsets)
	{
		std::snprintf(buf, sizeof(buf), " -> +0x%llX", static_cast<unsigned long long>(off));
		out += buf;
	}
	return out;
}

std::string PointerChainLocator::Serialize() const
{
	std::ostringstream out;
	out << "chain|" << moduleName << '|' << std::hex << std::uppercase << baseRva << '|';
	for (size_t i = 0; i < offsets.size(); ++i)
	{
		if (i > 0)
		{
			out << ',';
		}
		out << offsets[i];
	}
	return out.str();
}

std::unique_ptr<IStaticLocator> PointerChainLocator::Clone() const
{
	return std::make_unique<PointerChainLocator>(*this);
}

std::unique_ptr<IStaticLocator> IStaticLocator::Deserialize(const std::string& text)
{
	const auto parts = SplitPipe(text);
	if (parts.empty())
	{
		return nullptr;
	}
	if (parts[0] == "rva" && parts.size() >= 3)
	{
		const uint64_t rva = std::strtoull(parts[2].c_str(), nullptr, 16);
		const std::string sec = parts.size() >= 4 ? parts[3] : std::string();
		return std::make_unique<ModuleOffsetLocator>(parts[1], rva, sec);
	}
	if (parts[0] == "export" && parts.size() >= 4)
	{
		const int64_t delta = std::strtoll(parts[3].c_str(), nullptr, 10);
		return std::make_unique<ExportOffsetLocator>(parts[1], parts[2], delta);
	}
	if (parts[0] == "pattern" && parts.size() >= 5)
	{
		std::vector<PatternByte> pat;
		if (!PatternScanner::ParsePattern(parts[3], pat))
		{
			return nullptr;
		}
		const int64_t post = std::strtoll(parts[4].c_str(), nullptr, 10);
		return std::make_unique<PatternLocator>(parts[1], parts[2], std::move(pat), post);
	}
	if (parts[0] == "chain" && parts.size() >= 4)
	{
		const uint64_t rva = std::strtoull(parts[2].c_str(), nullptr, 16);
		std::vector<uintptr_t> chain;
		std::istringstream stream(parts[3]);
		std::string tok;
		while (std::getline(stream, tok, ','))
		{
			if (!tok.empty())
			{
				chain.push_back(static_cast<uintptr_t>(std::strtoull(tok.c_str(), nullptr, 16)));
			}
		}
		return std::make_unique<PointerChainLocator>(parts[1], rva, std::move(chain));
	}
	return nullptr;
}
}
