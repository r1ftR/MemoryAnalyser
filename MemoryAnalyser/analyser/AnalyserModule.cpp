#include "AnalyserModule.h"

#include "Format/AddressParse.h"
#include "../MemoryManager/MemoryManager.h"
#include "../third_party/ImGui/imgui.h"
#include "../ui/Theme.h"

#include <Windows.h>

#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string>

namespace analyser
{
namespace
{
std::wstring ToWide(const char* text)
{
	const int length = MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
	if (length <= 0)
	{
		return {};
	}
	std::wstring result(static_cast<size_t>(length - 1), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, text, -1, result.data(), length);
	return result;
}
}

AnalyserModule::AnalyserModule()
{
	if (!store.Load()) state.storageStatus = store.LastError();
	RefreshSavedFunctions();
}
AnalyserModule::~AnalyserModule() = default;

void AnalyserModule::ConfigureWindow(platform::WindowConfig& config)
{
	config.title = L"Memory Analyser";
	config.trayTooltip = L"Memory Analyser";
}

void AnalyserModule::RenderTabs(ui::UiState&)
{
	if (ImGui::BeginTabItem("Memory"))
	{
		RenderAttachSection();
		ImGui::EndTabItem();
	}
	if (ImGui::BeginTabItem("Struct Tables"))
	{
		RenderStructSection();
		ImGui::EndTabItem();
	}
	if (ImGui::BeginTabItem("Injector"))
	{
		injector.Render(state.attach, memory.get());
		ImGui::EndTabItem();
	}
	if (ImGui::BeginTabItem("Hooking"))
	{
		RenderSavedFunctions(true);
		hookPanel.Render(memory.get(), store);
		ImGui::EndTabItem();
	}
	if (ImGui::BeginTabItem("Disassembly"))
	{
		RenderDisasmSection();
		ImGui::EndTabItem();
	}
}

void AnalyserModule::OnFrame(ui::UiState& ui)
{
	if (ui.showMainPanel)
	{
		Rendertables();
		RenderDisasmViews();
		RenderTraceViews();
		RenderStaticRefsViews();
	}
	HandleSymbolRequests();
	HandleAttachRequests();
	if (state.hookRequest && memory)
	{
		hookPanel.Select(*state.hookRequest);
	}
	state.hookRequest.reset();
	if (state.savedHookRequest)
	{
		hooking::HookTarget target;
		if (ResolveSavedFunction(*state.savedHookRequest, target, state.savedFunctionStatus))
		{
			hookPanel.Select(target);
			state.savedFunctionStatus = "Saved function selected; open the Hooking tab";
		}
		state.savedHookRequest.reset();
	}
	hookPanel.Poll(memory.get());
	injector.Poll(memory.get(), [this]() {
		RefreshModules();
		return !modules.empty();
	});
}

void AnalyserModule::OnShutdown()
{
	hookPanel.OnShutdown();
	injector.OnShutdown();
	tables.clear();
	ClearDisasm();
	memory.reset();
}

void AnalyserModule::RenderAttachSection()
{
	AttachState& attach = state.attach;
	ImGui::SeparatorText("Target");
	ImGui::BeginDisabled(attach.attached);
	ImGui::InputText("Process", attach.processName, sizeof(attach.processName));
	ImGui::InputText("Module", attach.moduleName, sizeof(attach.moduleName));
	ImGui::RadioButton("x64", &attach.architecture, 0);
	ImGui::SameLine();
	ImGui::RadioButton("x86 (WOW64)", &attach.architecture, 1);
	ImGui::EndDisabled();

	if (!attach.attached)
	{
		if (ImGui::Button("Attach"))
		{
			attach.attachRequested = true;
		}
	}
	else if (ImGui::Button("Detach"))
	{
		attach.detachRequested = true;
	}

	if (attach.attached)
	{
		ImGui::Text("PID: %lu  Module base: 0x%llX", attach.processId, static_cast<unsigned long long>(attach.moduleBase));
	}
	else
	{
		ImGui::TextDisabled("%s", attach.status.c_str());
	}
}

void AnalyserModule::RenderStructSection()
{
	ImGui::SeparatorText("Struct Tables");
	ImGui::BeginDisabled(!state.attach.attached);

	ImGui::InputText("Base", state.baseInput, sizeof(state.baseInput));
	ImGui::SameLine();
	ImGui::TextDisabled("(?)");
	if (ImGui::IsItemHovered())
	{
		ImGui::SetTooltip("Hex address (7FF6A1B20000) or +0x1234 for module base + offset.");
	}

	ImGui::Checkbox("Base is pointer", &state.baseIsPointer);
	ImGui::SameLine();
	ImGui::TextDisabled("(?)");
	if (ImGui::IsItemHovered())
	{
		ImGui::SetTooltip("On: open the struct the pointer at Base points to (e.g. LocalPlayer).\n"
			"Off: open memory at Base itself.\nFollow deeper pointers from inside the struct window.");
	}

	const auto base = ParseBaseAddress(state.baseInput, state.attach.moduleBase);

	std::string path;
	if (!base)
	{
		ImGui::TextColored(ui::GetTheme().error, "Invalid base address");
	}
	else
	{
		char buf[192];
		const char* text = state.baseInput;
		while (*text == ' ')
		{
			++text;
		}
		if (*text == '+')
		{
			std::snprintf(buf, sizeof(buf), "%s+%llX", state.attach.moduleName,
				static_cast<unsigned long long>(*base - state.attach.moduleBase));
		}
		else
		{
			std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(*base));
		}
		path = state.baseIsPointer ? "[" + std::string(buf) + "]" : std::string(buf);
		ImGui::TextDisabled("Opens: %s", path.c_str());
	}

	ImGui::BeginDisabled(!base);
	if (ImGui::Button("Open table"))
	{
		StructOpenRequest request;
		request.base = *base;
		if (state.baseIsPointer)
		{
			request.offsets = { 0 };
		}
		request.label = path;
		state.openRequests.push_back(std::move(request));
	}
	ImGui::SameLine();
	ImGui::Checkbox("Auto-detect new tables", &state.autoDetectDefault);

	const auto& saved = store.Tables();
	if (state.selectedSaved >= static_cast<int>(saved.size()))
	{
		state.selectedSaved = -1;
	}
	const char* preview = state.selectedSaved >= 0 ? saved[state.selectedSaved].name.c_str() : "(none)";
	ImGui::SetNextItemWidth(200);
	if (ImGui::BeginCombo("Saved tables", preview))
	{
		for (int index = 0; index < static_cast<int>(saved.size()); ++index)
		{
			if (ImGui::Selectable(saved[index].name.c_str(), index == state.selectedSaved))
			{
				state.selectedSaved = index;
			}
		}
		ImGui::EndCombo();
	}

	const bool hasSelection = state.selectedSaved >= 0;
	ImGui::BeginDisabled(!hasSelection);
	if (ImGui::Button("Open saved"))
	{
		const SavedTable& table = saved[state.selectedSaved];
		StructOpenRequest request;
		if (table.hasLocation && !state.openSavedAtBase)
		{
			request.base = static_cast<uintptr_t>(table.base) + (table.relative ? state.attach.moduleBase : 0);
			request.offsets.assign(table.chain.begin(), table.chain.end());
			request.label = table.name;
		}
		else
		{
			request.base = *base;
			if (state.baseIsPointer)
			{
				request.offsets = { 0 };
			}
			request.label = path;
		}
		request.layout = table;
		state.openRequests.push_back(std::move(request));
	}
	ImGui::SameLine();
	ImGui::Checkbox("Use current Base instead", &state.openSavedAtBase);
	ImGui::SameLine();
	if (ImGui::Button("Delete"))
	{
		store.Remove(static_cast<size_t>(state.selectedSaved));
		PersistStore();
		state.selectedSaved = -1;
	}
	ImGui::EndDisabled();

	if (state.selectedSaved >= 0 && saved[state.selectedSaved].pointerSize != state.attach.PointerSize())
	{
		ImGui::TextColored(ui::GetTheme().warning, "Saved as %s, current target is %s",
			saved[state.selectedSaved].pointerSize == 4 ? "x86" : "x64", state.attach.PointerSize() == 4 ? "x86" : "x64");
	}
	if (!store.LastError().empty())
	{
		ImGui::TextColored(ui::GetTheme().error, "%s", store.LastError().c_str());
	}
	ImGui::EndDisabled();

	ImGui::EndDisabled();
}

void AnalyserModule::HandleAttachRequests()
{
	AttachState& attach = state.attach;
	if (attach.detachRequested)
	{
		attach.detachRequested = false;
		hookPanel.OnDetach();
		injector.OnDetach();
		tables.clear();
		ClearDisasm();
		memory.reset();
		attach.attached = false;
		attach.processId = 0;
		attach.moduleBase = 0;
		attach.status = "Detached";
	}

	if (attach.attachRequested)
	{
		attach.attachRequested = false;
		try
		{
			const std::wstring process = ToWide(attach.processName);
			const std::wstring module = ToWide(attach.moduleName);
			memory = std::make_unique<MemoryManager>(process.c_str(), module.c_str());
			attach.attached = true;
			attach.processId = memory->GetAttachedProcessId();
			attach.moduleBase = memory->GetBaseAddress();
			attach.status = "Attached";
			modules = memory->EnumerateModules();
			symbols = std::make_unique<disasm::SymbolResolver>(*memory, modules);
			ApplySavedLabels();
			RefreshSavedFunctions();
		}
		catch (const std::exception& error)
		{
			memory.reset();
			attach.attached = false;
			attach.status = std::string("Attach failed: ") + error.what();
		}
	}
}

void AnalyserModule::Rendertables()
{
	if (memory)
	{
		for (auto& request : state.openRequests)
		{
			tables.push_back(std::make_unique<StructTable>(
				nextTableId++, *memory, state.attach.PointerSize(), std::move(request), state.autoDetectDefault));
		}
	}
	state.openRequests.clear();

	// Index loop: tables may queue new requests while rendering.
	for (size_t index = 0; index < tables.size(); ++index)
	{
		tables[index]->Render(state);
	}

	std::erase_if(tables, [](const auto& table) { return !table->IsOpen(); });

	if (!state.saveRequests.empty())
	{
		for (auto& saved : state.saveRequests)
		{
			const uintptr_t moduleBase = state.attach.moduleBase;
			if (saved.hasLocation && moduleBase != 0 && saved.base >= moduleBase && saved.base - moduleBase < 0x10000000)
			{
				saved.base -= moduleBase;
				saved.relative = true;
			}
			store.Upsert(std::move(saved));
		}
		state.saveRequests.clear();
		PersistStore();
	}
}

void AnalyserModule::ApplySavedLabels()
{
	if (!symbols)
	{
		return;
	}
	for (const auto& label : store.Labels())
	{
		if (const auto address = symbols->FromModuleOffset(label.at.module, label.at.offset))
		{
			symbols->SetLabel(*address, label.name);
		}
	}
}

void AnalyserModule::HandleSymbolRequests()
{
	if (!state.functionSaveRequests.empty())
	{
		for (auto& function : state.functionSaveRequests) store.UpsertFunction(std::move(function));
		state.functionSaveRequests.clear();
		PersistStore();
		RefreshSavedFunctions();
	}
	if (!state.labelRequests.empty())
	{
		bool changed = false;
		for (const auto& request : state.labelRequests)
		{
			if (!symbols)
			{
				break;
			}
			if (request.name.empty())
			{
				symbols->RemoveLabel(request.address);
			}
			else
			{
				symbols->SetLabel(request.address, request.name);
			}
			SavedLabel saved;
			saved.name = request.name;
			if (symbols->ToModuleOffset(request.address, saved.at.module, saved.at.offset))
			{
				store.SetLabel(std::move(saved));
				changed = true;
			}
		}
		state.labelRequests.clear();
		if (changed)
		{
			PersistStore();
		}
	}

	if (!state.traceSaveRequests.empty())
	{
		for (auto& trace : state.traceSaveRequests)
		{
			store.UpsertTrace(std::move(trace));
		}
		state.traceSaveRequests.clear();
		PersistStore();
	}

	if (!state.locatorSaveRequests.empty())
	{
		for (auto& locator : state.locatorSaveRequests)
		{
			store.UpsertLocator(std::move(locator));
		}
		state.locatorSaveRequests.clear();
		PersistStore();
	}
}

void AnalyserModule::RenderTraceViews()
{
	if (state.stopDebuggerRequested)
	{
		state.stopDebuggerRequested = false;
		debugger.reset();
	}
	if (state.startDebuggerRequested)
	{
		state.startDebuggerRequested = false;
		if (memory && !(debugger && debugger->IsRunning()))
		{
			debugger = std::make_unique<ProcessDebugger>(memory->GetAttachedProcessId());
			if (debugger->Start())
			{
				for (auto& view : traceViews)
				{
					view->ArmAll(*debugger);
				}
			}
		}
	}

	if (memory && (state.openTraceRequested || (!state.traceRequests.empty() && traceViews.empty())))
	{
		traceViews.push_back(std::make_unique<TraceView>(nextTraceId++));
	}
	state.openTraceRequested = false;
	if (!traceViews.empty())
	{
		// Addresses from disassembly go to the most recently opened trace window.
		for (const uintptr_t address : state.traceRequests)
		{
			traceViews.back()->AddTarget(address, debugger.get());
		}
	}
	state.traceRequests.clear();

	if (debugger)
	{
		const auto raw = debugger->DrainHits();
		if (!raw.empty())
		{
			std::vector<std::pair<uintptr_t, std::pair<unsigned long, unsigned long long>>> hits;
			hits.reserve(raw.size());
			for (const auto& hit : raw)
			{
				hits.push_back({ hit.address, { hit.threadId, hit.tick } });
			}
			for (auto& view : traceViews)
			{
				view->ApplyHits(hits);
			}
		}
	}

	for (auto& view : traceViews)
	{
		view->Render(state, debugger.get(), symbols.get());
	}
	for (auto& view : traceViews)
	{
		if (!view->IsOpen() && debugger && debugger->IsRunning())
		{
			for (const uintptr_t address : view->Targets())
			{
				debugger->RemoveBreakpoint(address);
			}
		}
	}
	std::erase_if(traceViews, [](const auto& view) { return !view->IsOpen(); });
	// No trace windows left: detach so the target runs untouched.
	if (traceViews.empty() && debugger)
	{
		debugger.reset();
	}

	if (!state.disasmGotoRequests.empty())
	{
		for (const uintptr_t address : state.disasmGotoRequests)
		{
			if (!disasmViews.empty())
			{
				disasmViews.back()->NavigateTo(address);
			}
			else
			{
				state.disasmOpenRequests.push_back(DisasmOpenRequest{ address, {} });
			}
		}
		state.disasmGotoRequests.clear();
	}
}

void AnalyserModule::RenderStaticRefsViews()
{
	if (!memory)
	{
		state.openStaticRefsRequested = false;
		state.staticScanRequests.clear();
		state.staticBatchScanRequests.clear();
		return;
	}

	if (state.openStaticRefsRequested ||
		((!state.staticScanRequests.empty() || !state.staticBatchScanRequests.empty()) && staticRefsViews.empty()))
	{
		staticRefsViews.push_back(std::make_unique<StaticRefsView>(nextStaticRefsId++));
	}
	state.openStaticRefsRequested = false;

	if (!staticRefsViews.empty())
	{
		for (const uintptr_t target : state.staticScanRequests)
		{
			staticRefsViews.back()->ScanTarget(*memory, symbols.get(), target, state.attach.PointerSize());
		}
		for (auto& batch : state.staticBatchScanRequests)
		{
			staticRefsViews.back()->ScanBatch(*memory, symbols.get(), std::move(batch), state.attach.PointerSize());
		}
	}
	state.staticScanRequests.clear();
	state.staticBatchScanRequests.clear();

	for (size_t i = 0; i < staticRefsViews.size(); ++i)
	{
		staticRefsViews[i]->Render(state, *memory, symbols.get());
	}
	std::erase_if(staticRefsViews, [](const auto& view) { return !view->IsOpen(); });
}

void AnalyserModule::ClearDisasm()
{
	staticRefsViews.clear();
	traceViews.clear();
	debugger.reset();
	symbols.reset();
	disasmViews.clear();
	modules.clear();
	sections.clear();
	state.selectedModule = -1;
	state.selectedSection = -1;
	state.disasmOpenRequests.clear();
	state.traceRequests.clear();
	state.disasmGotoRequests.clear();
	state.labelRequests.clear();
	state.staticScanRequests.clear();
	state.staticBatchScanRequests.clear();
	state.functionSaveRequests.clear();
	for (auto& function : state.savedFunctions) { function.address = 0; function.error = "No attached process"; }
}

void AnalyserModule::RefreshModules()
{
	modules = memory->EnumerateModules();
	state.selectedModule = -1;
	state.selectedSection = -1;
	sections.clear();
	// Trace windows hold resolver-independent addresses, so only symbols need rebuilding.
	symbols = std::make_unique<disasm::SymbolResolver>(*memory, modules);
	ApplySavedLabels();
	RefreshSavedFunctions();
}

void AnalyserModule::RenderDisasmSection()
{
	ImGui::SeparatorText("Disassembly");
	ImGui::BeginDisabled(!state.attach.attached || !memory);

	if (memory && ((modules.empty() && !symbols) || ImGui::Button("Refresh modules")))
		RefreshModules();

	char modulePreview[300] = "(select module)";
	if (state.selectedModule >= 0 && state.selectedModule < static_cast<int>(modules.size()))
	{
		std::snprintf(modulePreview, sizeof(modulePreview), "%ls", modules[state.selectedModule].name.c_str());
	}
	ImGui::SetNextItemWidth(260);
	if (ImGui::BeginCombo("Module", modulePreview))
	{
		for (int index = 0; index < static_cast<int>(modules.size()); ++index)
		{
			const auto& info = modules[index];
			char label[300];
			std::snprintf(label, sizeof(label), "%ls  (0x%llX)", info.name.c_str(), static_cast<unsigned long long>(info.base));
			if (ImGui::Selectable(label, index == state.selectedModule))
			{
				state.selectedModule = index;
				state.selectedSection = -1;
				if (!disasm::ReadSections(*memory, info.base, sections))
				{
					sections.clear();
				}
			}
		}
		ImGui::EndCombo();
	}

	const char* sectionPreview = state.selectedSection >= 0 && state.selectedSection < static_cast<int>(sections.size())
		? sections[state.selectedSection].name.c_str() : "(select section)";
	ImGui::SetNextItemWidth(260);
	if (ImGui::BeginCombo("Section", sectionPreview))
	{
		for (int index = 0; index < static_cast<int>(sections.size()); ++index)
		{
			const auto& section = sections[index];
			char label[128];
			std::snprintf(label, sizeof(label), "%-8s 0x%llX  size 0x%zX%s", section.name.c_str(),
				static_cast<unsigned long long>(section.address), section.size, section.executable ? "  [exec]" : "");
			if (ImGui::Selectable(label, index == state.selectedSection))
			{
				state.selectedSection = index;
				std::snprintf(state.disasmAddress, sizeof(state.disasmAddress), "%llX",
					static_cast<unsigned long long>(section.address));
			}
		}
		ImGui::EndCombo();
	}

	ImGui::SetNextItemWidth(260);
	ImGui::InputText("Address", state.disasmAddress, sizeof(state.disasmAddress));
	ImGui::SameLine();
	ImGui::TextDisabled("(?)");
	if (ImGui::IsItemHovered())
	{
		ImGui::SetTooltip("Hex address (7FF6A1B21000) or +0x1000 for attached module base + offset.");
	}
	const auto address = ParseBaseAddress(state.disasmAddress, state.attach.moduleBase);
	ImGui::BeginDisabled(!address);
	if (ImGui::Button("Open disassembly"))
	{
		DisasmOpenRequest request;
		request.address = *address;
		state.disasmOpenRequests.push_back(std::move(request));
	}
	ImGui::EndDisabled();
	if (!address)
	{
		ImGui::SameLine();
		ImGui::TextColored(ui::GetTheme().error, "Invalid address");
	}

	ImGui::SeparatorText("Saved views");
	const auto& saved = store.DisasmViews();
	if (state.selectedSavedDisasm >= static_cast<int>(saved.size()))
	{
		state.selectedSavedDisasm = -1;
	}
	ImGui::SetNextItemWidth(200);
	if (ImGui::BeginCombo("##savedDisasm", state.selectedSavedDisasm >= 0 ? saved[state.selectedSavedDisasm].name.c_str() : "(none)"))
	{
		for (int index = 0; index < static_cast<int>(saved.size()); ++index)
		{
			if (ImGui::Selectable(saved[index].name.c_str(), index == state.selectedSavedDisasm))
			{
				state.selectedSavedDisasm = index;
			}
		}
		ImGui::EndCombo();
	}
	ImGui::BeginDisabled(state.selectedSavedDisasm < 0);
	ImGui::SameLine();
	if (ImGui::Button("Open saved##disasm"))
	{
		const SavedDisasm& view = saved[state.selectedSavedDisasm];
		DisasmOpenRequest request;
		request.address = static_cast<uintptr_t>(view.address) + (view.relative ? state.attach.moduleBase : 0);
		request.name = view.name;
		state.disasmOpenRequests.push_back(std::move(request));
	}
	ImGui::SameLine();
	if (ImGui::Button("Delete##disasm"))
	{
		store.RemoveDisasm(static_cast<size_t>(state.selectedSavedDisasm));
		PersistStore();
		state.selectedSavedDisasm = -1;
	}
	ImGui::EndDisabled();
	if (state.selectedSavedDisasm >= 0 && saved[state.selectedSavedDisasm].pointerSize != state.attach.PointerSize())
	{
		ImGui::TextColored(ui::GetTheme().warning, "Saved as %s, current target is %s",
			saved[state.selectedSavedDisasm].pointerSize == 4 ? "x86" : "x64", state.attach.PointerSize() == 4 ? "x86" : "x64");
	}

	ImGui::SeparatorText("Function trace");
	if (ImGui::Button("New trace window"))
	{
		state.openTraceRequested = true;
	}
	ImGui::SameLine();
	ImGui::TextDisabled("(?)");
	if (ImGui::IsItemHovered())
	{
		ImGui::SetTooltip("Shows which functions actually run, live.\n"
			"Attaches as a debugger and sets int3 breakpoints on chosen functions.\n"
			"Add functions from the trace window, or right-click a line in disassembly.");
	}
	if (debugger && debugger->IsRunning())
	{
		ImGui::SameLine();
		ImGui::TextColored(ui::GetTheme().success, "Debugger attached (%zu breakpoints)", debugger->BreakpointCount());
	}

	const auto& savedTraces = store.Traces();
	if (state.selectedSavedTrace >= static_cast<int>(savedTraces.size()))
	{
		state.selectedSavedTrace = -1;
	}
	ImGui::SetNextItemWidth(200);
	if (ImGui::BeginCombo("##savedTrace", state.selectedSavedTrace >= 0 ? savedTraces[state.selectedSavedTrace].name.c_str() : "(none)"))
	{
		for (int index = 0; index < static_cast<int>(savedTraces.size()); ++index)
		{
			if (ImGui::Selectable(savedTraces[index].name.c_str(), index == state.selectedSavedTrace))
			{
				state.selectedSavedTrace = index;
			}
		}
		ImGui::EndCombo();
	}
	ImGui::BeginDisabled(state.selectedSavedTrace < 0 || !symbols);
	ImGui::SameLine();
	if (ImGui::Button("Open saved##trace"))
	{
		const SavedTrace& trace = savedTraces[state.selectedSavedTrace];
		auto view = std::make_unique<TraceView>(nextTraceId++);
		view->SetName(trace.name);
		for (const auto& target : trace.targets)
		{
			if (const auto address = symbols->FromModuleOffset(target.module, target.offset))
			{
				view->AddTarget(*address, debugger.get());
			}
		}
		traceViews.push_back(std::move(view));
	}
	ImGui::SameLine();
	if (ImGui::Button("Delete##trace"))
	{
		store.RemoveTrace(static_cast<size_t>(state.selectedSavedTrace));
		PersistStore();
		state.selectedSavedTrace = -1;
	}
	ImGui::EndDisabled();

	ImGui::SeparatorText("Static references & signatures");
	if (ImGui::Button("New static refs window"))
	{
		state.openStaticRefsRequested = true;
	}
	ImGui::SameLine();
	ImGui::BeginDisabled(!address);
	if (ImGui::Button("Find static refs at Address"))
	{
		state.staticScanRequests.push_back(*address);
	}
	ImGui::EndDisabled();
	ImGui::SameLine();
	ImGui::TextDisabled("(?)");
	if (ImGui::IsItemHovered())
	{
		ImGui::SetTooltip("Automatically finds ASLR-safe RVAs, exports, unique Zydis byte signatures,\n"
			"static globals used inside a function, and callers / vtable pointers.");
	}

	const auto& savedLocators = store.Locators();
	if (state.selectedSavedLocator >= static_cast<int>(savedLocators.size()))
	{
		state.selectedSavedLocator = -1;
	}
	ImGui::SetNextItemWidth(200);
	if (ImGui::BeginCombo("##savedLocator", state.selectedSavedLocator >= 0 ? savedLocators[state.selectedSavedLocator].name.c_str() : "(none)"))
	{
		for (int index = 0; index < static_cast<int>(savedLocators.size()); ++index)
		{
			if (ImGui::Selectable(savedLocators[index].name.c_str(), index == state.selectedSavedLocator))
			{
				state.selectedSavedLocator = index;
			}
		}
		ImGui::EndCombo();
	}
	ImGui::BeginDisabled(state.selectedSavedLocator < 0 || !memory);
	ImGui::SameLine();
	if (ImGui::Button("Resolve & Disasm##locator"))
	{
		const auto& savedLoc = savedLocators[state.selectedSavedLocator];
		state.locatorStatus.clear();
		if (const auto locator = IStaticLocator::Deserialize(savedLoc.spec))
		{
			ResolveContext ctx{ *memory, symbols.get(), state.attach.PointerSize() };
			if (const auto resolved = locator->Resolve(ctx); resolved && *resolved)
			{
				state.disasmOpenRequests.push_back({ *resolved, savedLoc.name });
			}
			else state.locatorStatus = "Saved locator did not resolve in the attached process: " + savedLoc.name;
		}
		else state.locatorStatus = "Invalid saved locator specification: " + savedLoc.name;
	}
	ImGui::SameLine();
	if (ImGui::Button("Open static references scan##locator"))
	{
		const auto& savedLoc = savedLocators[state.selectedSavedLocator];
		state.locatorStatus.clear();
		if (const auto locator = IStaticLocator::Deserialize(savedLoc.spec))
		{
			ResolveContext ctx{ *memory, symbols.get(), state.attach.PointerSize() };
			if (const auto resolved = locator->Resolve(ctx); resolved && *resolved)
				state.staticScanRequests.push_back(*resolved);
			else state.locatorStatus = "Saved locator did not resolve in the attached process: " + savedLoc.name;
		}
		else state.locatorStatus = "Invalid saved locator specification: " + savedLoc.name;
	}
	ImGui::SameLine();
	if (ImGui::Button("Delete##locator"))
	{
		store.RemoveLocator(static_cast<size_t>(state.selectedSavedLocator));
		PersistStore();
		state.selectedSavedLocator = -1;
	}
	ImGui::EndDisabled();
	if (!state.locatorStatus.empty()) ImGui::TextColored(ui::GetTheme().error, "%s", state.locatorStatus.c_str());

	ImGui::EndDisabled();
	RenderSavedFunctions(false);
}

bool AnalyserModule::PersistStore()
{
	if (!store.Save())
	{
		state.storageStatus = store.LastError();
		return false;
	}
	state.storageStatus.clear();
	return true;
}

bool AnalyserModule::ResolveSavedFunction(const SavedFunction& saved, hooking::HookTarget& target, std::string& error)
{
	error.clear();
	if (!memory || !state.attach.attached) { error = "No attached process"; return false; }
	const auto& expected = saved.target;
	const auto loaded = memory->EnumerateModules();
	const ModuleInfo* matched = nullptr;
	for (const auto& module : loaded)
	{
		if (CompareStringOrdinal(module.path.c_str(), -1, expected.modulePath.c_str(), -1, TRUE) != CSTR_EQUAL) continue;
		if (matched) { error = "Saved module path is ambiguous in the attached process"; return false; }
		matched = &module;
	}
	if (!matched) { error = "Saved module path is not loaded in the attached process"; return false; }
	if (expected.rva >= matched->size || expected.rva > (std::numeric_limits<uintptr_t>::max)() - matched->base)
	{
		error = "Saved function RVA is outside the loaded module";
		return false;
	}
	FunctionStaticReport report;
	report.inModule = true;
	report.moduleName = expected.moduleName;
	report.targetName = expected.name;
	report.rva = expected.rva;
	report.targetAddress = matched->base + static_cast<uintptr_t>(expected.rva);
	if (!hooking::ValidateHookTarget(*memory, report, target, error)) return false;
	if (!TableStore::SameFunctionIdentity(expected, target) || expected.x64 != target.x64 ||
		expected.volumeSerial != target.volumeSerial || expected.fileId != target.fileId ||
		expected.fileSize != target.fileSize || expected.fileLastWrite != target.fileLastWrite ||
		expected.originalBytes != target.originalBytes)
	{
		error = "Saved function module identity, version, architecture, or original bytes changed; rescan the function";
		return false;
	}
	return hooking::RevalidateHookTarget(*memory, target, error);
}

void AnalyserModule::RefreshSavedFunctions()
{
	state.savedFunctions.clear();
	for (const auto& saved : store.Functions())
	{
		ResolvedSavedFunction entry;
		entry.saved = saved;
		hooking::HookTarget target;
		if (ResolveSavedFunction(saved, target, entry.error)) entry.address = target.address;
		state.savedFunctions.push_back(std::move(entry));
	}
	if (state.selectedSavedFunction >= static_cast<int>(state.savedFunctions.size())) state.selectedSavedFunction = -1;
}

void AnalyserModule::RenderSavedFunctions(bool forHooking)
{
	ImGui::PushID(forHooking ? "hookSavedFunctions" : "staticSavedFunctions");
	ImGui::SeparatorText("Saved functions");
	const auto& functions = store.Functions();
	if (state.selectedSavedFunction >= static_cast<int>(functions.size())) state.selectedSavedFunction = -1;
	const char* preview = state.selectedSavedFunction >= 0 ? functions[state.selectedSavedFunction].target.name.c_str() : "(select saved function)";
	if (ImGui::BeginCombo("Function", preview))
	{
		for (int i = 0; i < static_cast<int>(functions.size()); ++i)
		{
			ImGui::PushID(i);
			const auto& t = functions[i].target;
			char label[512];
			std::snprintf(label, sizeof(label), "%s (%s+0x%llX, PE %08X)", t.name.c_str(), t.moduleName.c_str(),
				static_cast<unsigned long long>(t.rva), t.imageTimestamp);
			if (ImGui::Selectable(label, i == state.selectedSavedFunction))
			{
				state.selectedSavedFunction = i;
				state.savedFunctionStatus.clear();
			}
			ImGui::PopID();
		}
		ImGui::EndCombo();
	}
	if (ImGui::Button("Refresh saved targets")) RefreshSavedFunctions();
	ImGui::SameLine();
	ImGui::BeginDisabled(state.selectedSavedFunction < 0);
	if (ImGui::Button(forHooking ? "Select for hooking" : "Open static references scan"))
	{
		hooking::HookTarget target;
		if (ResolveSavedFunction(functions[state.selectedSavedFunction], target, state.savedFunctionStatus))
		{
			if (forHooking) { hookPanel.Select(target); state.savedFunctionStatus = "Saved function validated and selected"; }
			else { state.staticScanRequests.push_back(target.address); state.savedFunctionStatus = "Static references scan queued"; }
		}
	}
	ImGui::EndDisabled();
	if (!memory) ImGui::TextDisabled("Attach a process before resolving saved functions.");
	if (state.selectedSavedFunction >= 0 && state.selectedSavedFunction < static_cast<int>(state.savedFunctions.size()))
	{
		const auto& entry = state.savedFunctions[state.selectedSavedFunction];
		if (!entry.error.empty()) ImGui::TextColored(ui::GetTheme().error, "%s", entry.error.c_str());
	}
	if (!state.savedFunctionStatus.empty()) ImGui::TextWrapped("%s", state.savedFunctionStatus.c_str());
	if (!state.storageStatus.empty())
	{
		ImGui::TextColored(ui::GetTheme().error, "%s", state.storageStatus.c_str());
		if (ImGui::Button("Retry saving records")) PersistStore();
	}
	ImGui::PopID();
}
void AnalyserModule::RenderDisasmViews()
{
	if (memory)
	{
		for (auto& request : state.disasmOpenRequests)
		{
			disasmViews.push_back(std::make_unique<DisasmView>(
				nextDisasmId++, *memory, state.attach.PointerSize(), std::move(request)));
		}
	}
	state.disasmOpenRequests.clear();

	for (auto& view : disasmViews)
	{
		view->Render(state, symbols.get());
	}
	std::erase_if(disasmViews, [](const auto& view) { return !view->IsOpen(); });

	if (!state.disasmSaveRequests.empty())
	{
		for (auto& saved : state.disasmSaveRequests)
		{
			const uintptr_t moduleBase = state.attach.moduleBase;
			if (moduleBase != 0 && saved.address >= moduleBase && saved.address - moduleBase < 0x10000000)
			{
				saved.address -= moduleBase;
				saved.relative = true;
			}
			store.UpsertDisasm(std::move(saved));
		}
		state.disasmSaveRequests.clear();
		PersistStore();
	}
}
}
