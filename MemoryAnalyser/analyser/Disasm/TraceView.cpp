#include "TraceView.h"
#include "Symbols.h"

#include "../Format/AddressParse.h"
#include "../../MemoryManager/ProcessDebugger.h"
#include "../../third_party/ImGui/imgui.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace analyser
{
namespace
{
bool WildcardMatch(const char* pattern, const char* text)
{
	// Case-insensitive, '*' and '?' supported.
	if (*pattern == '\0')
	{
		return *text == '\0';
	}
	if (*pattern == '*')
	{
		return WildcardMatch(pattern + 1, text) || (*text && WildcardMatch(pattern, text + 1));
	}
	if (*text && (*pattern == '?' || tolower(static_cast<unsigned char>(*pattern)) == tolower(static_cast<unsigned char>(*text))))
	{
		return WildcardMatch(pattern + 1, text + 1);
	}
	return false;
}

bool FilterMatch(const char* filter, const std::string& name)
{
	if (filter[0] == '\0')
	{
		return true;
	}
	if (std::strchr(filter, '*') || std::strchr(filter, '?'))
	{
		return WildcardMatch(filter, name.c_str());
	}
	// Plain text: substring, case-insensitive.
	std::string lowerName(name);
	std::string lowerFilter(filter);
	std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });
	std::transform(lowerFilter.begin(), lowerFilter.end(), lowerFilter.begin(), [](unsigned char c) { return static_cast<char>(tolower(c)); });
	return lowerName.find(lowerFilter) != std::string::npos;
}
}

TraceView::TraceView(int id) : id(id)
{
}

void TraceView::SetName(const std::string& name)
{
	std::snprintf(traceName, sizeof(traceName), "%s", name.c_str());
}

void TraceView::AddTarget(uintptr_t address, ProcessDebugger* debugger)
{
	if (std::find(targets.begin(), targets.end(), address) != targets.end())
	{
		return;
	}
	if (static_cast<int>(targets.size()) >= maxBreakpoints)
	{
		status = "Breakpoint limit reached";
		return;
	}
	targets.push_back(address);
	stats[address];
	if (debugger && debugger->IsRunning())
	{
		debugger->AddBreakpoint(address);
	}
}

void TraceView::RemoveTarget(uintptr_t address, ProcessDebugger* debugger)
{
	std::erase(targets, address);
	stats.erase(address);
	if (debugger && debugger->IsRunning())
	{
		debugger->RemoveBreakpoint(address);
	}
}

void TraceView::ArmAll(ProcessDebugger& debugger)
{
	for (const uintptr_t address : targets)
	{
		debugger.AddBreakpoint(address);
	}
}

void TraceView::ApplyHits(const std::vector<std::pair<uintptr_t, std::pair<unsigned long, unsigned long long>>>& hits)
{
	if (paused)
	{
		return;
	}
	for (const auto& [address, info] : hits)
	{
		auto it = stats.find(address);
		if (it != stats.end())
		{
			++it->second.count;
			it->second.lastThread = info.first;
			it->second.lastTick = info.second;
		}
	}
}

void TraceView::RenderPicker(AnalyserState& state, ProcessDebugger* debugger, disasm::SymbolResolver* symbols)
{
	if (!ImGui::CollapsingHeader("Add functions"))
	{
		return;
	}

	ImGui::SetNextItemWidth(200);
	const bool enter = ImGui::InputTextWithHint("##addAddr", "address or +offset", addInput, sizeof(addInput),
		ImGuiInputTextFlags_EnterReturnsTrue);
	ImGui::SameLine();
	if (ImGui::Button("Add address") || enter)
	{
		if (const auto address = ParseBaseAddress(addInput, state.attach.moduleBase))
		{
			AddTarget(*address, debugger);
		}
		else
		{
			status = "Invalid address";
		}
	}

	if (!symbols)
	{
		return;
	}
	const auto& modules = symbols->Modules();
	char preview[300] = "(module)";
	if (pickerModule >= 0 && pickerModule < static_cast<int>(modules.size()))
	{
		std::snprintf(preview, sizeof(preview), "%ls", modules[pickerModule].name.c_str());
	}
	ImGui::SetNextItemWidth(200);
	if (ImGui::BeginCombo("##pickModule", preview))
	{
		for (int i = 0; i < static_cast<int>(modules.size()); ++i)
		{
			char label[300];
			std::snprintf(label, sizeof(label), "%ls", modules[i].name.c_str());
			if (ImGui::Selectable(label, i == pickerModule))
			{
				pickerModule = i;
				symbols->RequestPdb(modules[i].base);
			}
		}
		ImGui::EndCombo();
	}
	ImGui::SameLine();
	ImGui::SetNextItemWidth(200);
	ImGui::InputTextWithHint("##pickFilter", "filter, e.g. Create*W", pickerFilter, sizeof(pickerFilter));

	if (pickerModule < 0)
	{
		return;
	}
	const auto symbolsInModule = symbols->SymbolsInModule(static_cast<size_t>(pickerModule));
	std::vector<const std::pair<uintptr_t, std::string>*> matches;
	for (const auto& entry : symbolsInModule)
	{
		if (FilterMatch(pickerFilter, entry.second))
		{
			matches.push_back(&entry);
		}
	}

	ImGui::SameLine();
	ImGui::BeginDisabled(matches.empty());
	char addAll[48];
	std::snprintf(addAll, sizeof(addAll), "Add all %zu", matches.size());
	if (ImGui::Button(addAll))
	{
		for (const auto* match : matches)
		{
			AddTarget(match->first, debugger);
		}
	}
	ImGui::EndDisabled();

	if (ImGui::BeginChild("picker", ImVec2(0, 140), ImGuiChildFlags_Borders))
	{
		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(matches.size()));
		while (clipper.Step())
		{
			for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i)
			{
				const auto* match = matches[static_cast<size_t>(i)];
				const bool traced = std::find(targets.begin(), targets.end(), match->first) != targets.end();
				ImGui::PushID(i);
				if (ImGui::Selectable(match->second.c_str(), traced))
				{
					if (traced)
					{
						RemoveTarget(match->first, debugger);
					}
					else
					{
						AddTarget(match->first, debugger);
					}
				}
				ImGui::PopID();
			}
		}
	}
	ImGui::EndChild();
}

void TraceView::Render(AnalyserState& state, ProcessDebugger* debugger, disasm::SymbolResolver* symbols)
{
	char title[128];
	std::snprintf(title, sizeof(title), "Trace: %s###trace%d", traceName[0] ? traceName : "(unnamed)", id);
	ImGui::SetNextWindowSize(ImVec2(620, 520), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin(title, &open))
	{
		ImGui::End();
		return;
	}

	const bool running = debugger && debugger->IsRunning();
	if (running)
	{
		ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "Tracing");
		ImGui::SameLine();
		if (ImGui::Button("Stop debugger"))
		{
			state.stopDebuggerRequested = true;
		}
	}
	else
	{
		ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "Debugger not attached");
		ImGui::SameLine();
		if (ImGui::Button("Start tracing"))
		{
			state.startDebuggerRequested = true;
		}
		if (ImGui::IsItemHovered())
		{
			ImGui::SetTooltip("Attaches as a debugger and sets int3 breakpoints on the traced functions.\n"
				"Fails if another debugger is attached or the target blocks debugging.");
		}
	}
	ImGui::SameLine();
	ImGui::Checkbox("Pause view", &paused);
	ImGui::SameLine();
	if (ImGui::Button("Reset counts"))
	{
		for (auto& [address, stat] : stats)
		{
			stat.count = 0;
			stat.recentCount = 0;
			stat.lastTick = 0;
		}
		rateBase.clear();
		rates.clear();
	}
	ImGui::SameLine();
	if (ImGui::Button("Scan hit static refs"))
	{
		std::vector<uintptr_t> hitTargets;
		for (const auto& [address, stat] : stats)
		{
			if (stat.count > 0)
			{
				hitTargets.push_back(address);
			}
		}
		if (hitTargets.empty())
		{
			hitTargets = targets;
		}
		if (!hitTargets.empty())
		{
			state.staticBatchScanRequests.push_back(std::move(hitTargets));
			status = "Queued static scan";
		}
	}

	ImGui::SetNextItemWidth(180);
	ImGui::InputTextWithHint("##traceName", "trace name", traceName, sizeof(traceName));
	ImGui::SameLine();
	ImGui::BeginDisabled(traceName[0] == '\0' || !symbols);
	if (ImGui::Button("Save"))
	{
		SavedTrace saved;
		saved.name = traceName;
		for (const uintptr_t address : targets)
		{
			ModuleOffset at;
			if (symbols->ToModuleOffset(address, at.module, at.offset))
			{
				saved.targets.push_back(std::move(at));
			}
		}
		state.traceSaveRequests.push_back(std::move(saved));
		status = "Saved";
	}
	ImGui::EndDisabled();
	ImGui::SameLine();
	ImGui::Text("%zu functions", targets.size());
	if (debugger)
	{
		ImGui::SameLine();
		ImGui::TextDisabled("(%zu armed)", debugger->BreakpointCount());
	}

	if (debugger)
	{
		const std::string error = debugger->LastError();
		if (!error.empty())
		{
			ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", error.c_str());
		}
		if (debugger->DroppedHits() > 0)
		{
			ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "%zu hits dropped (too many). Trace fewer hot functions.",
				debugger->DroppedHits());
		}
	}
	if (!status.empty())
	{
		ImGui::TextDisabled("%s", status.c_str());
	}

	RenderPicker(state, debugger, symbols);

	// Per-second rate, updated once per second.
	const double now = ImGui::GetTime();
	if (lastRateUpdate < 0.0 || now - lastRateUpdate >= 1.0)
	{
		const double elapsed = lastRateUpdate < 0.0 ? 1.0 : now - lastRateUpdate;
		for (auto& [address, stat] : stats)
		{
			rates[address] = static_cast<double>(stat.count - rateBase[address]) / elapsed;
			rateBase[address] = stat.count;
		}
		lastRateUpdate = now;
	}

	ImGui::Separator();
	ImGui::TextDisabled("Sort:");
	ImGui::SameLine();
	ImGui::RadioButton("Count", &sortMode, 0);
	ImGui::SameLine();
	ImGui::RadioButton("Last hit", &sortMode, 1);
	ImGui::SameLine();
	ImGui::RadioButton("Name", &sortMode, 2);
	ImGui::SameLine();
	ImGui::Checkbox("Hide never hit", &hideZero);

	struct Entry
	{
		uintptr_t address;
		const Stat* stat;
	};
	std::vector<Entry> entries;
	entries.reserve(stats.size());
	for (auto& [address, stat] : stats)
	{
		if (symbols)
		{
			std::string name = symbols->Describe(address);
			stat.name = name.empty() ? std::string() : std::move(name);
		}
		if (stat.name.empty())
		{
			char buf[32];
			std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(address));
			stat.name = buf;
		}
		if (!hideZero || stat.count > 0)
		{
			entries.push_back({ address, &stat });
		}
	}
	std::sort(entries.begin(), entries.end(), [this](const Entry& a, const Entry& b) {
		if (sortMode == 1)
		{
			return a.stat->lastTick > b.stat->lastTick;
		}
		if (sortMode == 2)
		{
			return a.stat->name < b.stat->name;
		}
		return a.stat->count > b.stat->count;
	});

	const ULONGLONG nowTick = GetTickCount64();
	uintptr_t remove = 0;
	if (ImGui::BeginChild("traceList", ImVec2(0, 0), ImGuiChildFlags_Borders))
	{
		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(entries.size()));
		while (clipper.Step())
		{
			for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i)
			{
				const Entry& entry = entries[static_cast<size_t>(i)];
				const Stat& stat = *entry.stat;
				// Recently hit functions glow green, fading over two seconds.
				const double age = stat.lastTick ? static_cast<double>(nowTick - stat.lastTick) / 1000.0 : 99.0;
				const float glow = age < 2.0 ? static_cast<float>(1.0 - age / 2.0) : 0.0f;
				const ImVec4 base = stat.count ? ImGui::GetStyleColorVec4(ImGuiCol_Text) : ImVec4(0.55f, 0.55f, 0.55f, 1.0f);
				const ImVec4 color(base.x + (0.4f - base.x) * glow, base.y + (1.0f - base.y) * glow, base.z + (0.4f - base.z) * glow, 1.0f);

				char line[512];
				std::snprintf(line, sizeof(line), "%10llu  %8.1f/s  tid %-6lu  %s",
					static_cast<unsigned long long>(stat.count), rates[entry.address],
					static_cast<unsigned long>(stat.lastThread), stat.name.c_str());

				ImGui::PushID(i);
				ImGui::PushStyleColor(ImGuiCol_Text, color);
				if (ImGui::Selectable(line, false, ImGuiSelectableFlags_AllowDoubleClick) && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
				{
					state.disasmGotoRequests.push_back(entry.address);
				}
				ImGui::PopStyleColor();
				if (ImGui::BeginPopupContextItem("traceRowCtx"))
				{
					ImGui::TextDisabled("0x%llX", static_cast<unsigned long long>(entry.address));
					ImGui::Separator();
					if (ImGui::MenuItem("Find static references"))
					{
						state.staticScanRequests.push_back(entry.address);
					}
					if (ImGui::MenuItem("Open in Disassembly"))
					{
						state.disasmGotoRequests.push_back(entry.address);
					}
					if (ImGui::MenuItem("Remove from trace"))
					{
						remove = entry.address;
					}
					ImGui::EndPopup();
				}
				else if (ImGui::IsItemHovered())
				{
					ImGui::SetTooltip("0x%llX\nDouble-click to open in disassembly\nRight-click for static refs / remove",
						static_cast<unsigned long long>(entry.address));
				}
				ImGui::PopID();
			}
		}
	}
	ImGui::EndChild();
	if (remove != 0)
	{
		RemoveTarget(remove, debugger);
	}

	ImGui::End();
}
}
