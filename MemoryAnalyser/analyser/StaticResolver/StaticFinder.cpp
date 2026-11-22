#include "StaticFinder.h"

#include "../Disasm/Pe.h"
#include "../Disasm/Symbols.h"
#include "../../MemoryManager/PatternScanner.h"

#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>

namespace analyser
{
namespace
{
	constexpr size_t kChunkBytes = 64 * 1024;
	constexpr size_t kPageBytes = 4096;

	std::string NarrowName(const std::wstring& wide)
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

	const ModuleInfo* FindModuleForAddress(const std::vector<ModuleInfo>& modules, uintptr_t address)
	{
		for (const auto& mod : modules)
		{
			if (address >= mod.base && address - mod.base < mod.size)
			{
				return &mod;
			}
		}
		return nullptr;
	}

	std::string FindSectionName(const std::vector<disasm::PeSection>& sections, uintptr_t address, const disasm::PeSection** outSec = nullptr)
	{
		for (const auto& sec : sections)
		{
			if (address >= sec.address && address - sec.address < sec.size)
			{
				if (outSec)
				{
					*outSec = &sec;
				}
				return sec.name;
			}
		}
		return {};
	}

	bool ReadSafe(MemoryManager& memory, uintptr_t address, uint8_t* out, size_t size, size_t& validBytes)
	{
		validBytes = 0;
		if (memory.readMemory(address, out, size))
		{
			validBytes = size;
			return true;
		}
		// Read in 64-byte increments up to first unreadable boundary.
		constexpr size_t kStep = 64;
		while (validBytes < size)
		{
			const size_t chunk = (std::min)(kStep, size - validBytes);
			if (!memory.readMemory(address + validBytes, out + validBytes, chunk))
			{
				break;
			}
			validBytes += chunk;
		}
		return validBytes > 0;
	}

	void ReadSectionBuffered(MemoryManager& memory, uintptr_t base, size_t size, std::vector<uint8_t>& data, std::vector<uint8_t>& valid)
	{
		data.assign(size, 0);
		valid.assign(size, 0);
		size_t offset = 0;
		while (offset < size)
		{
			const size_t chunk = (std::min)(kChunkBytes, size - offset);
			if (memory.readMemory(base + offset, data.data() + offset, chunk))
			{
				std::fill(valid.begin() + static_cast<std::ptrdiff_t>(offset),
					valid.begin() + static_cast<std::ptrdiff_t>(offset + chunk),
					static_cast<uint8_t>(1));
			}
			else
			{
				size_t sub = 0;
				while (sub < chunk)
				{
					const size_t page = (std::min)(kPageBytes, chunk - sub);
					if (memory.readMemory(base + offset + sub, data.data() + offset + sub, page))
					{
						std::fill(valid.begin() + static_cast<std::ptrdiff_t>(offset + sub),
							valid.begin() + static_cast<std::ptrdiff_t>(offset + sub + page),
							static_cast<uint8_t>(1));
					}
					sub += page;
				}
			}
			offset += chunk;
		}
	}

	size_t CountBufferedMatches(const std::vector<uint8_t>& data, const std::vector<uint8_t>& valid,
		const std::vector<PatternByte>& pattern, size_t maxMatches)
	{
		if (pattern.empty() || data.size() < pattern.size())
		{
			return 0;
		}
		const size_t patLen = pattern.size();
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

		size_t count = 0;
		const size_t limit = data.size() - patLen;
		for (size_t pos = 0; pos <= limit; ++pos)
		{
			if (!valid[pos] || !valid[pos + patLen - 1])
			{
				continue;
			}
			if (anchorIdx < patLen && data[pos + anchorIdx] != anchorVal)
			{
				continue;
			}
			bool ok = true;
			for (size_t k = 0; k < patLen; ++k)
			{
				if (!valid[pos + k] || (!pattern[k].wildcard && data[pos + k] != pattern[k].value))
				{
					ok = false;
					break;
				}
			}
			if (ok)
			{
				++count;
				if (maxMatches > 0 && count >= maxMatches)
				{
					return count;
				}
			}
		}
		return count;
	}

	bool ReadPointerAt(MemoryManager& memory, uintptr_t address, size_t pointerSize, uintptr_t& out)
	{
		out = 0;
		if (pointerSize == 8)
		{
			uint64_t val = 0;
			if (!memory.readMemory(address, &val, sizeof(val)))
			{
				return false;
			}
			out = static_cast<uintptr_t>(val);
			return true;
		}
		uint32_t val = 0;
		if (!memory.readMemory(address, &val, sizeof(val)))
		{
			return false;
		}
		out = static_cast<uintptr_t>(val);
		return true;
	}
}

StaticFinder::StaticFinder() = default;

StaticFinder::~StaticFinder()
{
	Cancel();
}

void StaticFinder::Cancel()
{
	cancelRequested.store(true);
	if (worker.joinable())
	{
		worker.join();
	}
	running.store(false);
}

void StaticFinder::SetProgress(const std::string& text)
{
	std::lock_guard<std::mutex> lock(mutex);
	progress = text;
}

std::string StaticFinder::ProgressText() const
{
	std::lock_guard<std::mutex> lock(mutex);
	return progress;
}

bool StaticFinder::ConsumeResults(std::vector<FunctionStaticReport>& out)
{
	std::lock_guard<std::mutex> lock(mutex);
	if (!hasNewResults)
	{
		return false;
	}
	out = std::move(pendingResults);
	pendingResults.clear();
	hasNewResults = false;
	return true;
}

void StaticFinder::StartSingle(MemoryManager& memory, const disasm::SymbolResolver* symbols,
	uintptr_t targetAddress, StaticScanOptions options)
{
	StartBatch(memory, symbols, std::vector<uintptr_t>{ targetAddress }, options);
}

void StaticFinder::StartBatch(MemoryManager& memory, const disasm::SymbolResolver* symbols,
	std::vector<uintptr_t> targets, StaticScanOptions options)
{
	Cancel();
	if (targets.empty())
	{
		return;
	}

	cancelRequested.store(false);
	running.store(true);
	SetProgress("Enumerating modules...");

	worker = std::thread([this, &memory, symbols, targets = std::move(targets), options]() {
		const auto modules = symbols ? symbols->Modules() : memory.EnumerateModules();
		std::vector<FunctionStaticReport> reports;
		reports.reserve(targets.size());

		for (size_t i = 0; i < targets.size(); ++i)
		{
			if (cancelRequested.load())
			{
				break;
			}
			char msg[160];
			std::snprintf(msg, sizeof(msg), "Scanning %zu / %zu (0x%llX)...",
				i + 1, targets.size(), static_cast<unsigned long long>(targets[i]));
			SetProgress(msg);

			// For large batch runs, skip full-module XRef scanning if there are more than 8 functions.
			StaticScanOptions itemOpts = options;
			if (targets.size() > 8)
			{
				itemOpts.scanXRefs = false;
			}
			reports.push_back(AnalyzeOne(memory, modules, symbols, targets[i], itemOpts));
		}

		{
			std::lock_guard<std::mutex> lock(mutex);
			pendingResults = std::move(reports);
			hasNewResults = true;
			progress = cancelRequested.load() ? "Scan cancelled" : "Scan complete";
		}
		running.store(false);
	});
}

FunctionStaticReport StaticFinder::AnalyzeOne(MemoryManager& memory, const std::vector<ModuleInfo>& modules,
	const disasm::SymbolResolver* symbols, uintptr_t targetAddress, const StaticScanOptions& options)
{
	FunctionStaticReport report;
	report.targetAddress = targetAddress;
	if (symbols)
	{
		report.targetName = symbols->Describe(targetAddress);
	}
	if (report.targetName.empty())
	{
		char buf[32];
		std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(targetAddress));
		report.targetName = buf;
	}

	const ModuleInfo* ownerMod = FindModuleForAddress(modules, targetAddress);
	std::vector<disasm::PeSection> ownerSections;
	const disasm::PeSection* targetSection = nullptr;

	if (ownerMod)
	{
		report.inModule = true;
		report.moduleName = NarrowName(ownerMod->name);
		report.rva = targetAddress - ownerMod->base;
		disasm::ReadSections(memory, ownerMod->base, ownerSections);
		report.sectionName = FindSectionName(ownerSections, targetAddress, &targetSection);

		// 1. Direct Module + RVA locator.
		report.locators.push_back(std::make_unique<ModuleOffsetLocator>(
			report.moduleName, report.rva, report.sectionName));

		// 2. Export match (exact or nearest export within +0x400).
		std::vector<disasm::PeExport> exports;
		if (disasm::ReadExports(memory, ownerMod->base, exports))
		{
			const disasm::PeExport* best = nullptr;
			uint64_t bestDelta = UINT64_MAX;
			for (const auto& exp : exports)
			{
				if (targetAddress >= exp.address)
				{
					const uint64_t d = targetAddress - exp.address;
					if (d < bestDelta)
					{
						bestDelta = d;
						best = &exp;
					}
				}
			}
			if (best && bestDelta <= 0x400)
			{
				report.locators.push_back(std::make_unique<ExportOffsetLocator>(
					report.moduleName, best->name, static_cast<int64_t>(bestDelta)));
			}
		}
	}

	// Read function bytes to decode body for signature + static globals.
	constexpr size_t kFuncReadMax = 2048;
	uint8_t funcBuf[kFuncReadMax] = {};
	size_t validFuncBytes = 0;
	if (!ReadSafe(memory, targetAddress, funcBuf, kFuncReadMax, validFuncBytes))
	{
		report.status = "Target memory is not readable";
		return report;
	}

	std::vector<disasm::InstructionLine> lines;
	disasm::Decode(funcBuf, validFuncBytes, targetAddress, options.pointerSize, options.maxFunctionInstructions, lines);

	// Cache section buffers for fast signature uniqueness checking and XRef scanning.
	std::vector<uint8_t> execBuffer;
	std::vector<uint8_t> execValid;
	uintptr_t execStart = 0;
	std::string execSecName;
	if (ownerMod)
	{
		if (targetSection && targetSection->size <= 64 * 1024 * 1024)
		{
			execStart = targetSection->address;
			execSecName = targetSection->name;
			ReadSectionBuffered(memory, targetSection->address, targetSection->size, execBuffer, execValid);
		}
		else if (ownerMod->size <= 32 * 1024 * 1024)
		{
			execStart = ownerMod->base;
			ReadSectionBuffered(memory, ownerMod->base, ownerMod->size, execBuffer, execValid);
		}
	}

	// 3. Build shortest unique Zydis-masked byte signature.
	if (ownerMod && !lines.empty() && !execBuffer.empty())
	{
		std::vector<PatternByte> sig;
		sig.reserve(options.maxSignatureBytes);
		size_t lastMatches = 0;

		for (const auto& line : lines)
		{
			if (!line.valid || sig.size() + line.length > options.maxSignatureBytes)
			{
				break;
			}
			for (uint8_t b = 0; b < line.length; ++b)
			{
				const bool masked = (line.wildcardMask & static_cast<uint16_t>(1u << b)) != 0;
				sig.push_back(PatternByte{ masked ? static_cast<uint8_t>(0) : line.bytes[b], masked });
			}
			// Trim trailing wildcards when testing uniqueness so signatures stay clean.
			std::vector<PatternByte> trimmed = sig;
			while (!trimmed.empty() && trimmed.back().wildcard)
			{
				trimmed.pop_back();
			}
			if (trimmed.size() < 5)
			{
				continue;
			}

			lastMatches = CountBufferedMatches(execBuffer, execValid, trimmed, 2);
			if (lastMatches == 1)
			{
				report.signatureUnique = true;
				report.signatureMatchCount = 1;
				report.locators.push_back(std::make_unique<PatternLocator>(
					report.moduleName, execSecName, std::move(trimmed), 0));
				break;
			}
		}

		if (!report.signatureUnique && !sig.empty())
		{
			while (!sig.empty() && sig.back().wildcard)
			{
				sig.pop_back();
			}
			if (!sig.empty())
			{
				report.signatureMatchCount = CountBufferedMatches(execBuffer, execValid, sig, 99);
				report.locators.push_back(std::make_unique<PatternLocator>(
					report.moduleName, execSecName, std::move(sig), 0));
			}
		}
	}

	// 4. Extract static globals accessed inside the function body (up to first ret after unconditional flow or cap).
	std::map<uintptr_t, size_t> globalIndexByAddr;
	for (const auto& line : lines)
	{
		if (!line.valid)
		{
			break;
		}
		if (line.mnemonic == "int3")
		{
			// Padding between functions.
			break;
		}

		if (line.hasStaticMem)
		{
			const ModuleInfo* globalMod = FindModuleForAddress(modules, line.staticMemAddress);
			// Accept any module-backed static address (or non-null fixed address when modules exist).
			if (globalMod != nullptr)
			{
				auto it = globalIndexByAddr.find(line.staticMemAddress);
				if (it != globalIndexByAddr.end())
				{
					++report.globals[it->second].hitCount;
				}
				else
				{
					StaticGlobalRef ref;
					ref.instructionAddress = line.address;
					ref.globalAddress = line.staticMemAddress;
					ref.moduleName = NarrowName(globalMod->name);
					ref.rva = line.staticMemAddress - globalMod->base;
					if (globalMod == ownerMod)
					{
						ref.sectionName = FindSectionName(ownerSections, line.staticMemAddress);
					}
					else
					{
						std::vector<disasm::PeSection> secs;
						if (disasm::ReadSections(memory, globalMod->base, secs))
						{
							ref.sectionName = FindSectionName(secs, line.staticMemAddress);
						}
					}
					ref.access = line.staticAccess;
					ref.instructionText = line.text;
					if (symbols)
					{
						ref.symbolName = symbols->Describe(line.staticMemAddress);
					}
					ref.hasPointerValue = ReadPointerAt(memory, line.staticMemAddress, options.pointerSize, ref.pointerValue);

					globalIndexByAddr[line.staticMemAddress] = report.globals.size();
					report.globals.push_back(std::move(ref));
				}
			}
		}

		if (line.flow == disasm::FlowKind::Ret)
		{
			break;
		}
	}

	// 5. Scan owner module sections for code XRefs (call/jmp/lea) and static data pointer XRefs (vtables/tables).
	if (ownerMod && options.scanXRefs && !cancelRequested.load())
	{
		for (const auto& sec : ownerSections)
		{
			if (cancelRequested.load() || report.xrefs.size() >= options.maxXRefs)
			{
				break;
			}
			if (sec.size == 0 || sec.size > 64 * 1024 * 1024)
			{
				continue;
			}

			if (sec.executable)
			{
				std::vector<uint8_t> localBuf;
				std::vector<uint8_t> localValid;
				const std::vector<uint8_t>* bufPtr = &localBuf;
				const std::vector<uint8_t>* valPtr = &localValid;
				if (targetSection && sec.address == targetSection->address && !execBuffer.empty())
				{
					bufPtr = &execBuffer;
					valPtr = &execValid;
				}
				else
				{
					ReadSectionBuffered(memory, sec.address, sec.size, localBuf, localValid);
				}

				const auto& data = *bufPtr;
				const auto& valid = *valPtr;
				std::vector<disasm::InstructionLine> decodedOne;

				for (size_t pos = 0; pos + 5 <= data.size() && report.xrefs.size() < options.maxXRefs; ++pos)
				{
					if (!valid[pos] || !valid[pos + 4])
					{
						continue;
					}
					const uint8_t b0 = data[pos];
					// Fast check for direct E8 call rel32 or E9 jmp rel32.
					if (b0 == 0xE8 || b0 == 0xE9)
					{
						int32_t rel = 0;
						std::memcpy(&rel, data.data() + pos + 1, sizeof(rel));
						const uintptr_t insAddr = sec.address + pos;
						const uintptr_t dest = static_cast<uintptr_t>(static_cast<int64_t>(insAddr + 5) + rel);
						if (dest == targetAddress)
						{
							disasm::Decode(data.data() + pos, (std::min)(static_cast<size_t>(15), data.size() - pos),
								insAddr, options.pointerSize, 1, decodedOne);
							if (!decodedOne.empty() && decodedOne[0].valid && decodedOne[0].hasTarget && decodedOne[0].target == targetAddress)
							{
								StaticXRef xref;
								xref.fromAddress = insAddr;
								xref.moduleName = report.moduleName;
								xref.sectionName = sec.name;
								xref.rva = insAddr - ownerMod->base;
								xref.kind = (b0 == 0xE8) ? XRefKind::Call : XRefKind::Jump;
								xref.detail = decodedOne[0].text;
								report.xrefs.push_back(std::move(xref));
							}
						}
					}
					// Fast check for x64 RIP-relative LEA: [REX] 8D modrm disp32 where modrm=(mod=00, rm=101).
					else if (options.pointerSize == 8 && pos + 7 <= data.size() && valid[pos + 6])
					{
						size_t opIdx = pos;
						if ((b0 & 0xF0) == 0x40)
						{
							++opIdx;
						}
						if (opIdx + 6 <= data.size() && data[opIdx] == 0x8D && (data[opIdx + 1] & 0xC7) == 0x05)
						{
							int32_t disp = 0;
							std::memcpy(&disp, data.data() + opIdx + 2, sizeof(disp));
							const size_t insLen = (opIdx - pos) + 6;
							const uintptr_t insAddr = sec.address + pos;
							const uintptr_t dest = static_cast<uintptr_t>(static_cast<int64_t>(insAddr + insLen) + disp);
							if (dest == targetAddress)
							{
								disasm::Decode(data.data() + pos, (std::min)(static_cast<size_t>(15), data.size() - pos),
									insAddr, options.pointerSize, 1, decodedOne);
								if (!decodedOne.empty() && decodedOne[0].valid &&
									decodedOne[0].hasStaticMem && decodedOne[0].staticMemAddress == targetAddress)
								{
									StaticXRef xref;
									xref.fromAddress = insAddr;
									xref.moduleName = report.moduleName;
									xref.sectionName = sec.name;
									xref.rva = insAddr - ownerMod->base;
									xref.kind = XRefKind::LeaAddress;
									xref.detail = decodedOne[0].text;
									report.xrefs.push_back(std::move(xref));
								}
							}
						}
					}
				}
			}
			else
			{
				// Non-executable section (.rdata, .data): scan for aligned static function pointers / vtable slots.
				const size_t remaining = options.maxXRefs - report.xrefs.size();
				const auto slots = PatternScanner::ScanPointerValues(
					memory, sec.address, sec.size, targetAddress, options.pointerSize, remaining);
				for (const uintptr_t slotAddr : slots)
				{
					StaticXRef xref;
					xref.fromAddress = slotAddr;
					xref.moduleName = report.moduleName;
					xref.sectionName = sec.name;
					xref.rva = slotAddr - ownerMod->base;
					xref.kind = XRefKind::DataPointer;
					char buf[96];
					std::snprintf(buf, sizeof(buf), "dq/dd -> 0x%llX (vtable / static fn ptr)",
						static_cast<unsigned long long>(targetAddress));
					xref.detail = buf;
					report.xrefs.push_back(std::move(xref));
				}
			}
		}
	}

	char summary[160];
	std::snprintf(summary, sizeof(summary), "%zu locators, %zu static globals, %zu xrefs",
		report.locators.size(), report.globals.size(), report.xrefs.size());
	report.status = summary;
	return report;
}
}
