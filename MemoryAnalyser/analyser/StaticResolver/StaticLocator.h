#pragma once

#include "../../MemoryManager/PatternScanner.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class MemoryManager;

namespace analyser
{
namespace disasm
{
class SymbolResolver;
}

enum class LocatorKind
{
	ModuleOffset,
	ExportOffset,
	Pattern,
	PointerChain
};

struct ResolveContext
{
	MemoryManager& memory;
	const disasm::SymbolResolver* symbols = nullptr;
	size_t pointerSize = 8;
};

// Polymorphic, GUI-free locator capable of resolving a static/function address across restarts and ASLR.
class IStaticLocator
{
public:
	virtual ~IStaticLocator() = default;

	virtual LocatorKind Kind() const = 0;
	virtual std::optional<uintptr_t> Resolve(const ResolveContext& ctx) const = 0;
	virtual std::string Describe() const = 0;
	// Compact single-line text representation suitable for persistence or clipboard sharing.
	virtual std::string Serialize() const = 0;
	virtual std::unique_ptr<IStaticLocator> Clone() const = 0;

	static std::unique_ptr<IStaticLocator> Deserialize(const std::string& text);
};

// Resolves "module.dll+0x1234" against enumerated loaded modules.
class ModuleOffsetLocator final : public IStaticLocator
{
public:
	ModuleOffsetLocator(std::string moduleName, uint64_t rva, std::string sectionName = {});

	LocatorKind Kind() const override { return LocatorKind::ModuleOffset; }
	std::optional<uintptr_t> Resolve(const ResolveContext& ctx) const override;
	std::string Describe() const override;
	std::string Serialize() const override;
	std::unique_ptr<IStaticLocator> Clone() const override;

	const std::string& Module() const { return moduleName; }
	uint64_t Rva() const { return rva; }
	const std::string& Section() const { return sectionName; }

private:
	std::string moduleName;
	uint64_t rva = 0;
	std::string sectionName;
};

// Resolves "module.dll!ExportName+0xOffset" via the target module's PE export directory.
class ExportOffsetLocator final : public IStaticLocator
{
public:
	ExportOffsetLocator(std::string moduleName, std::string exportName, int64_t delta = 0);

	LocatorKind Kind() const override { return LocatorKind::ExportOffset; }
	std::optional<uintptr_t> Resolve(const ResolveContext& ctx) const override;
	std::string Describe() const override;
	std::string Serialize() const override;
	std::unique_ptr<IStaticLocator> Clone() const override;

	const std::string& Module() const { return moduleName; }
	const std::string& ExportName() const { return exportName; }
	int64_t Delta() const { return delta; }

private:
	std::string moduleName;
	std::string exportName;
	int64_t delta = 0;
};

// Resolves an IDA-style wildcarded byte pattern inside a module (optionally scoped to a PE section).
class PatternLocator final : public IStaticLocator
{
public:
	PatternLocator(std::string moduleName, std::string sectionName, std::vector<PatternByte> pattern, int64_t postOffset = 0);

	LocatorKind Kind() const override { return LocatorKind::Pattern; }
	std::optional<uintptr_t> Resolve(const ResolveContext& ctx) const override;
	std::string Describe() const override;
	std::string Serialize() const override;
	std::unique_ptr<IStaticLocator> Clone() const override;

	const std::string& Module() const { return moduleName; }
	const std::string& Section() const { return sectionName; }
	const std::vector<PatternByte>& Pattern() const { return pattern; }
	std::string IdaPattern() const;
	void CodePattern(std::string& bytesOut, std::string& maskOut) const;
	int64_t PostOffset() const { return postOffset; }

private:
	std::string moduleName;
	std::string sectionName;
	std::vector<PatternByte> pattern;
	int64_t postOffset = 0;
};

// Resolves a module-relative static pointer followed by multi-level pointer offsets.
class PointerChainLocator final : public IStaticLocator
{
public:
	PointerChainLocator(std::string moduleName, uint64_t baseRva, std::vector<uintptr_t> offsets);

	LocatorKind Kind() const override { return LocatorKind::PointerChain; }
	std::optional<uintptr_t> Resolve(const ResolveContext& ctx) const override;
	std::string Describe() const override;
	std::string Serialize() const override;
	std::unique_ptr<IStaticLocator> Clone() const override;

	const std::string& Module() const { return moduleName; }
	uint64_t BaseRva() const { return baseRva; }
	const std::vector<uintptr_t>& Offsets() const { return offsets; }

private:
	std::string moduleName;
	uint64_t baseRva = 0;
	std::vector<uintptr_t> offsets;
};
}
