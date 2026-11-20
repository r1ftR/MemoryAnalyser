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

AnalyserModule::AnalyserModule() = default;
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
		RenderStructSection();
		ImGui::EndTabItem();
	}
}

void AnalyserModule::OnFrame(ui::UiState& ui)
{
	if (ui.showMainPanel)
	{
		RenderStructPanels();
	}
	HandleAttachRequests();
}

void AnalyserModule::OnShutdown()
{
	structPanels.clear();
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
	ImGui::SeparatorText("Struct Viewer");
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
	if (ImGui::Button("Open struct"))
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
	ImGui::EndDisabled();

	ImGui::EndDisabled();
}

void AnalyserModule::HandleAttachRequests()
{
	AttachState& attach = state.attach;
	if (attach.detachRequested)
	{
		attach.detachRequested = false;
		structPanels.clear();
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

void AnalyserModule::RenderStructPanels()
{
	if (memory)
	{
		for (auto& request : state.openRequests)
		{
			structPanels.push_back(std::make_unique<StructViewPanel>(
				nextPanelId++, *memory, state.attach.PointerSize(), std::move(request)));
		}
	}
	state.openRequests.clear();

	// Index loop: panels may queue new requests while rendering.
	for (size_t index = 0; index < structPanels.size(); ++index)
	{
		structPanels[index]->Render(state);
	}

	std::erase_if(structPanels, [](const auto& panel) { return !panel->IsOpen(); });
}
}
