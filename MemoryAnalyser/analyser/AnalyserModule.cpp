#include "AnalyserModule.h"

#include "Format/AddressParse.h"
#include "../MemoryManager/MemoryManager.h"
#include "../third_party/ImGui/imgui.h"

#include <Windows.h>

#include <cstdio>
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
	store.Load();
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
}

void AnalyserModule::OnFrame(ui::UiState& ui)
{
	if (ui.showMainPanel)
	{
		Rendertables();
	}
	HandleAttachRequests();
}

void AnalyserModule::OnShutdown()
{
	tables.clear();
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
		ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "Invalid base address");
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
		store.Save();
		state.selectedSaved = -1;
	}
	ImGui::EndDisabled();

	if (state.selectedSaved >= 0 && saved[state.selectedSaved].pointerSize != state.attach.PointerSize())
	{
		ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "Saved as %s, current target is %s",
			saved[state.selectedSaved].pointerSize == 4 ? "x86" : "x64", state.attach.PointerSize() == 4 ? "x86" : "x64");
	}
	if (!store.LastError().empty())
	{
		ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "%s", store.LastError().c_str());
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
		tables.clear();
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
		store.Save();
	}
}
}
