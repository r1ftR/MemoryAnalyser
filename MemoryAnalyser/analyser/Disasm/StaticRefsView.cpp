#include "StaticRefsView.h"
#include "Symbols.h"

#include "../Format/AddressParse.h"
#include "../../MemoryManager/MemoryManager.h"
#include "../../ui/Theme.h"
#include "../../third_party/ImGui/imgui.h"

#include <cstdio>

namespace analyser
{
namespace
{
	const char* AccessLabel(disasm::StaticAccessKind kind)
	{
		switch (kind)
		{
		case disasm::StaticAccessKind::Read: return "read";
		case disasm::StaticAccessKind::Write: return "write";
		case disasm::StaticAccessKind::ReadWrite: return "r/w";
		case disasm::StaticAccessKind::Lea: return "lea";
		case disasm::StaticAccessKind::CallSlot: return "call []";
		case disasm::StaticAccessKind::JumpSlot: return "jmp []";
		default: return "mem";
		}
	}

	const char* XRefLabel(XRefKind kind)
	{
		switch (kind)
		{
		case XRefKind::Call: return "call";
		case XRefKind::Jump: return "jmp";
		case XRefKind::LeaAddress: return "lea";
		case XRefKind::DataPointer: return "ptr";
		default: return "xref";
		}
	}

	const char* LocatorKindLabel(LocatorKind kind)
	{
		switch (kind)
		{
		case LocatorKind::ModuleOffset: return "RVA";
		case LocatorKind::ExportOffset: return "Export";
		case LocatorKind::Pattern: return "Signature";
		case LocatorKind::PointerChain: return "PtrChain";
		default: return "Locator";
		}
	}
}

StaticRefsView::StaticRefsView(int viewId) : id(viewId)
{
}

void StaticRefsView::ScanTarget(MemoryManager& memory, const disasm::SymbolResolver* symbols, uintptr_t address, size_t pointerSize)
{
	std::snprintf(addressInput, sizeof(addressInput), "0x%llX", static_cast<unsigned long long>(address));
	verifyResult.clear();
	StaticScanOptions opts;
	opts.pointerSize = pointerSize;
	opts.scanXRefs = scanXRefs;
	finder.StartSingle(memory, symbols, address, opts);
}

void StaticRefsView::ScanBatch(MemoryManager& memory, const disasm::SymbolResolver* symbols, std::vector<uintptr_t> targets, size_t pointerSize)
{
	if (targets.empty())
	{
		status = "No targets to scan";
		return;
	}
	verifyResult.clear();
	StaticScanOptions opts;
	opts.pointerSize = pointerSize;
	opts.scanXRefs = scanXRefs;
	finder.StartBatch(memory, symbols, std::move(targets), opts);
}

void StaticRefsView::RenderLocatorsSection(AnalyserState& state, MemoryManager& memory,
	disasm::SymbolResolver* symbols, const FunctionStaticReport& report)
{
	ImGui::SeparatorText("Static Locators (ASLR-safe)");
	if (report.locators.empty())
	{
		ImGui::TextDisabled("No static module/signature locators found (target may be dynamic heap/JIT memory).");
		return;
	}

	for (size_t i = 0; i < report.locators.size(); ++i)
	{
		const auto& loc = report.locators[i];
		ImGui::PushID(static_cast<int>(i));

		ImGui::TextColored(ui::GetTheme().accent, "[%s]", LocatorKindLabel(loc->Kind()));
		ImGui::SameLine();
		const std::string desc = loc->Describe();
		ImGui::TextUnformatted(desc.c_str());

		if (loc->Kind() == LocatorKind::Pattern)
		{
			ImGui::SameLine();
			if (report.signatureUnique)
			{
				ImGui::TextColored(ui::GetTheme().success, "(unique)");
			}
			else
			{
				ImGui::TextColored(ui::GetTheme().warning, "(%zu matches)", report.signatureMatchCount);
			}
		}

		if (ImGui::SmallButton("Copy"))
		{
			if (loc->Kind() == LocatorKind::Pattern)
			{
				const auto* pat = static_cast<const PatternLocator*>(loc.get());
				ImGui::SetClipboardText(pat->IdaPattern().c_str());
			}
			else
			{
				ImGui::SetClipboardText(desc.c_str());
			}
			status = "Copied to clipboard";
		}

		if (loc->Kind() == LocatorKind::Pattern)
		{
			ImGui::SameLine();
			if (ImGui::SmallButton("Copy C++ mask"))
			{
				const auto* pat = static_cast<const PatternLocator*>(loc.get());
				std::string bytesStr;
				std::string maskStr;
				pat->CodePattern(bytesStr, maskStr);
				const std::string combined = "\"" + bytesStr + "\", \"" + maskStr + "\"";
				ImGui::SetClipboardText(combined.c_str());
				status = "Copied C++ byte/mask pattern";
			}
		}

		ImGui::SameLine();
		if (ImGui::SmallButton("Test Resolve"))
		{
			ResolveContext ctx{ memory, symbols, state.attach.PointerSize() };
			if (const auto resolved = loc->Resolve(ctx))
			{
				char buf[160];
				std::snprintf(buf, sizeof(buf), "Resolved -> 0x%llX (%s)",
					static_cast<unsigned long long>(*resolved),
					*resolved == report.targetAddress ? "matches target" : "DIFFERENT address");
				verifyResult = buf;
			}
			else
			{
				verifyResult = "Resolve failed";
			}
		}

		ImGui::SameLine();
		if (ImGui::SmallButton("Save locator"))
		{
			SavedLocator saved;
			saved.name = saveNameInput[0] ? std::string(saveNameInput) : report.targetName;
			saved.spec = loc->Serialize();
			state.locatorSaveRequests.push_back(std::move(saved));
			status = "Saved locator to tables.txt";
		}

		ImGui::PopID();
	}

	ImGui::SetNextItemWidth(200);
	ImGui::InputTextWithHint("##saveLocName", "saved locator name (optional)", saveNameInput, sizeof(saveNameInput));
	if (!verifyResult.empty())
	{
		ImGui::SameLine();
		ImGui::TextDisabled("%s", verifyResult.c_str());
	}
}

void StaticRefsView::RenderGlobalsSection(AnalyserState& state, const FunctionStaticReport& report)
{
	char header[96];
	std::snprintf(header, sizeof(header), "Static Globals Accessed Inside Function (%zu)", report.globals.size());
	ImGui::SeparatorText(header);

	if (report.globals.empty())
	{
		ImGui::TextDisabled("No static [rip+disp32] / [disp32] globals referenced in function body.");
		return;
	}

	if (ImGui::BeginChild("globalsList", ImVec2(0, 175), ImGuiChildFlags_Borders | ImGuiChildFlags_ResizeY))
	{
		for (size_t i = 0; i < report.globals.size(); ++i)
		{
			const auto& g = report.globals[i];
			ImGui::PushID(static_cast<int>(i));

			char line[512];
			char valPart[64] = "";
			if (g.hasPointerValue)
			{
				std::snprintf(valPart, sizeof(valPart), "val=0x%llX", static_cast<unsigned long long>(g.pointerValue));
			}
			const std::string locText = !g.symbolName.empty()
				? g.symbolName
				: (g.moduleName + "+0x" + [&]() {
					char b[24];
					std::snprintf(b, sizeof(b), "%llX", static_cast<unsigned long long>(g.rva));
					return std::string(b);
				}());

			std::snprintf(line, sizeof(line), "[%-7s] %-6s  %-32s  %-20s  ; %s",
				AccessLabel(g.access),
				g.sectionName.empty() ? "?" : g.sectionName.c_str(),
				locText.c_str(),
				valPart,
				g.instructionText.c_str());

			if (ImGui::Selectable(line, false, ImGuiSelectableFlags_AllowDoubleClick) &&
				ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
			{
				state.disasmGotoRequests.push_back(g.instructionAddress);
			}

			if (ImGui::BeginPopupContextItem("globalCtx"))
			{
				ImGui::TextDisabled("Global: 0x%llX (%s+0x%llX)",
					static_cast<unsigned long long>(g.globalAddress),
					g.moduleName.c_str(), static_cast<unsigned long long>(g.rva));
				ImGui::Separator();
				if (ImGui::MenuItem("Open global in Struct Table (direct)"))
				{
					StructOpenRequest req;
					req.base = g.globalAddress;
					req.label = locText;
					state.openRequests.push_back(std::move(req));
				}
				if (g.hasPointerValue && g.pointerValue != 0 && ImGui::MenuItem("Dereference [global] in Struct Table"))
				{
					StructOpenRequest req;
					req.base = g.globalAddress;
					req.offsets = { 0 };
					req.label = "[" + locText + "]";
					state.openRequests.push_back(std::move(req));
				}
				if (ImGui::MenuItem("Jump to referencing instruction in Disasm"))
				{
					state.disasmGotoRequests.push_back(g.instructionAddress);
				}
				if (ImGui::MenuItem("Copy module+offset"))
				{
					char buf[160];
					std::snprintf(buf, sizeof(buf), "%s+0x%llX", g.moduleName.c_str(), static_cast<unsigned long long>(g.rva));
					ImGui::SetClipboardText(buf);
				}
				ImGui::EndPopup();
			}
			else if (ImGui::IsItemHovered())
			{
				ImGui::SetTooltip("Global address: 0x%llX (used %zu time%s)\nDouble-click: jump to instruction\nRight-click: open in Struct Table / copy RVA",
					static_cast<unsigned long long>(g.globalAddress), g.hitCount, g.hitCount == 1 ? "" : "s");
			}

			ImGui::PopID();
		}
	}
	ImGui::EndChild();
}

void StaticRefsView::RenderXRefsSection(AnalyserState& state, disasm::SymbolResolver* symbols, const FunctionStaticReport& report)
{
	char header[96];
	std::snprintf(header, sizeof(header), "Static Cross-References To Function (%zu)", report.xrefs.size());
	ImGui::SeparatorText(header);

	if (report.xrefs.empty())
	{
		ImGui::TextDisabled(scanXRefs
			? "No direct static call/jmp/lea/vtable references found in module."
			: "XRef scan skipped (enable 'Scan XRefs' or scan <= 8 targets).");
		return;
	}

	if (ImGui::BeginChild("xrefsList", ImVec2(0, 0), ImGuiChildFlags_Borders))
	{
		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(report.xrefs.size()));
		while (clipper.Step())
		{
			for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i)
			{
				const auto& xr = report.xrefs[static_cast<size_t>(i)];
				ImGui::PushID(i);

				std::string sym = symbols ? symbols->Describe(xr.fromAddress) : std::string();
				if (sym.empty())
				{
					char b[96];
					std::snprintf(b, sizeof(b), "%s+0x%llX", xr.moduleName.c_str(), static_cast<unsigned long long>(xr.rva));
					sym = b;
				}

				char line[512];
				std::snprintf(line, sizeof(line), "[%-4s] %-7s  %-34s  %s",
					XRefLabel(xr.kind),
					xr.sectionName.c_str(),
					sym.c_str(),
					xr.detail.c_str());

				if (ImGui::Selectable(line, false, ImGuiSelectableFlags_AllowDoubleClick) &&
					ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
				{
					if (xr.kind == XRefKind::DataPointer)
					{
						StructOpenRequest req;
						req.base = xr.fromAddress;
						req.label = sym;
						state.openRequests.push_back(std::move(req));
					}
					else
					{
						state.disasmGotoRequests.push_back(xr.fromAddress);
					}
				}

				if (ImGui::BeginPopupContextItem("xrefCtx"))
				{
					if (ImGui::MenuItem("Open in Disassembly"))
					{
						state.disasmGotoRequests.push_back(xr.fromAddress);
					}
					if (ImGui::MenuItem("Open in Struct Table (vtable / data)"))
					{
						StructOpenRequest req;
						req.base = xr.fromAddress;
						req.label = sym;
						state.openRequests.push_back(std::move(req));
					}
					if (ImGui::MenuItem("Trace caller"))
					{
						state.traceRequests.push_back(xr.fromAddress);
					}
					if (ImGui::MenuItem("Copy RVA"))
					{
						char buf[160];
						std::snprintf(buf, sizeof(buf), "%s+0x%llX", xr.moduleName.c_str(), static_cast<unsigned long long>(xr.rva));
						ImGui::SetClipboardText(buf);
					}
					ImGui::EndPopup();
				}
				else if (ImGui::IsItemHovered())
				{
					ImGui::SetTooltip("0x%llX\nDouble-click: jump in Disasm (or open vtable in Struct Table)\nRight-click for more actions",
						static_cast<unsigned long long>(xr.fromAddress));
				}

				ImGui::PopID();
			}
		}
	}
	ImGui::EndChild();
}

void StaticRefsView::Render(AnalyserState& state, MemoryManager& memory, disasm::SymbolResolver* symbols)
{
	std::vector<FunctionStaticReport> finished;
	if (finder.ConsumeResults(finished))
	{
		reports = std::move(finished);
		selectedReport = 0;
		status = finder.ProgressText();
	}

	char title[96];
	std::snprintf(title, sizeof(title), "Static References###staticRefs%d", id);
	ImGui::SetNextWindowSize(ImVec2(820, 620), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin(title, &open))
	{
		ImGui::End();
		return;
	}

	const bool busy = finder.IsRunning();
	ImGui::BeginDisabled(busy);
	ImGui::SetNextItemWidth(220);
	const bool enter = ImGui::InputTextWithHint("##staticAddr", "address or +offset", addressInput, sizeof(addressInput),
		ImGuiInputTextFlags_EnterReturnsTrue);
	ImGui::SameLine();
	if (ImGui::Button("Scan Function") || enter)
	{
		if (const auto target = ParseBaseAddress(addressInput, state.attach.moduleBase))
		{
			ScanTarget(memory, symbols, *target, state.attach.PointerSize());
		}
		else
		{
			status = "Invalid target address";
		}
	}
	ImGui::SameLine();
	ImGui::Checkbox("Scan XRefs", &scanXRefs);
	ImGui::EndDisabled();

	if (busy)
	{
		ImGui::SameLine();
		ImGui::TextColored(ui::GetTheme().warning, "%s", finder.ProgressText().c_str());
		ImGui::SameLine();
		if (ImGui::SmallButton("Cancel"))
		{
			finder.Cancel();
			status = "Cancelled";
		}
	}
	else if (!status.empty())
	{
		ImGui::SameLine();
		ImGui::TextDisabled("%s", status.c_str());
	}

	if (reports.empty())
	{
		ImGui::Separator();
		ImGui::TextDisabled("Enter a function address above, or right-click a function in Disassembly / Trace -> 'Find static references'.");
		ImGui::End();
		return;
	}

	if (reports.size() > 1)
	{
		if (selectedReport < 0 || selectedReport >= static_cast<int>(reports.size()))
		{
			selectedReport = 0;
		}
		ImGui::SetNextItemWidth(420);
		const auto& cur = reports[static_cast<size_t>(selectedReport)];
		char preview[256];
		std::snprintf(preview, sizeof(preview), "[%d/%zu] %s  (%zu globals, %zu locators)",
			selectedReport + 1, reports.size(), cur.targetName.c_str(), cur.globals.size(), cur.locators.size());
		if (ImGui::BeginCombo("Batch targets", preview))
		{
			for (int i = 0; i < static_cast<int>(reports.size()); ++i)
			{
				const auto& r = reports[static_cast<size_t>(i)];
				char item[256];
				std::snprintf(item, sizeof(item), "%s  -  %s", r.targetName.c_str(), r.status.c_str());
				if (ImGui::Selectable(item, i == selectedReport))
				{
					selectedReport = i;
					verifyResult.clear();
				}
			}
			ImGui::EndCombo();
		}
	}

	const auto& active = reports[static_cast<size_t>(selectedReport)];
	ImGui::Separator();
	ImGui::Text("Target: %s  (0x%llX)", active.targetName.c_str(), static_cast<unsigned long long>(active.targetAddress));
	ImGui::SameLine();
	if (ImGui::SmallButton("Open in Disasm"))
	{
		state.disasmGotoRequests.push_back(active.targetAddress);
	}
	ImGui::SameLine();
	if (ImGui::SmallButton("Trace"))
	{
		state.traceRequests.push_back(active.targetAddress);
	}

	RenderLocatorsSection(state, memory, symbols, active);
	RenderGlobalsSection(state, active);
	RenderXRefsSection(state, symbols, active);

	ImGui::End();
}
}
