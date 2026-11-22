#pragma once

#include "StaticLocator.h"
#include "../Disasm/Disassembler.h"
#include "../../MemoryManager/MemoryManager.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace analyser
{
namespace disasm
{
class SymbolResolver;
}

// A static global or IAT/pointer slot referenced by instructions inside a function body.
struct StaticGlobalRef
{
	uintptr_t instructionAddress = 0;
	uintptr_t globalAddress = 0;
	std::string moduleName;
	std::string sectionName;
	uint64_t rva = 0;
	disasm::StaticAccessKind access = disasm::StaticAccessKind::None;
	std::string instructionText;
	std::string symbolName;
	bool hasPointerValue = false;
	uintptr_t pointerValue = 0;
	size_t hitCount = 1;
};

enum class XRefKind
{
	Call,
	Jump,
	LeaAddress,
	DataPointer
};

// A code or static-data cross-reference pointing to the target function/address.
struct StaticXRef
{
	uintptr_t fromAddress = 0;
	std::string moduleName;
	std::string sectionName;
	uint64_t rva = 0;
	XRefKind kind = XRefKind::Call;
	std::string detail;
};

struct FunctionStaticReport
{
	uintptr_t targetAddress = 0;
	std::string targetName;
	std::string moduleName;
	std::string sectionName;
	uint64_t rva = 0;
	bool inModule = false;

	std::vector<std::unique_ptr<IStaticLocator>> locators;
	bool signatureUnique = false;
	size_t signatureMatchCount = 0;

	std::vector<StaticGlobalRef> globals;
	std::vector<StaticXRef> xrefs;
	std::string status;

	FunctionStaticReport() = default;
	FunctionStaticReport(FunctionStaticReport&&) noexcept = default;
	FunctionStaticReport& operator=(FunctionStaticReport&&) noexcept = default;
	FunctionStaticReport(const FunctionStaticReport&) = delete;
	FunctionStaticReport& operator=(const FunctionStaticReport&) = delete;
};

struct StaticScanOptions
{
	size_t pointerSize = 8;
	size_t maxFunctionInstructions = 220;
	size_t maxSignatureBytes = 64;
	size_t maxXRefs = 256;
	bool scanXRefs = true;
};

// Background worker that discovers static locators, signatures, globals, and XRefs without blocking UI.
class StaticFinder
{
public:
	StaticFinder();
	~StaticFinder();
	StaticFinder(const StaticFinder&) = delete;
	StaticFinder& operator=(const StaticFinder&) = delete;

	void StartSingle(MemoryManager& memory, const disasm::SymbolResolver* symbols,
		uintptr_t targetAddress, StaticScanOptions options = {});

	void StartBatch(MemoryManager& memory, const disasm::SymbolResolver* symbols,
		std::vector<uintptr_t> targets, StaticScanOptions options = {});

	void Cancel();
	bool IsRunning() const { return running.load(); }
	std::string ProgressText() const;

	// Moves finished reports out when a scan has completed (or returns false if none newly ready).
	bool ConsumeResults(std::vector<FunctionStaticReport>& out);

private:
	FunctionStaticReport AnalyzeOne(MemoryManager& memory, const std::vector<ModuleInfo>& modules,
		const disasm::SymbolResolver* symbols, uintptr_t targetAddress, const StaticScanOptions& options);

	void SetProgress(const std::string& text);

	mutable std::mutex mutex;
	std::string progress;
	std::vector<FunctionStaticReport> pendingResults;
	bool hasNewResults = false;

	std::atomic<bool> running{ false };
	std::atomic<bool> cancelRequested{ false };
	std::thread worker;
};
}
