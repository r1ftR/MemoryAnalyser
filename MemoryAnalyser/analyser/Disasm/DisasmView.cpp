#include "DisasmView.h"
#include "Symbols.h"

#include "../Format/AddressParse.h"
#include "../../MemoryManager/MemoryManager.h"
#include "../../third_party/ImGui/imgui.h"

#include <cstdio>
#include <cstring>

namespace analyser
{
namespace
{
constexpr size_t kReadSize = 0x1000;
constexpr size_t kChunk = 0x200;
constexpr size_t kMaxLines = 2000;

const ImVec4 kLabelColor(0.55f, 0.95f, 0.55f, 1.0f);
}

DisasmView::DisasmView(int id, MemoryManager& memory, size_t pointerSize, DisasmOpenRequest request)
	: id(id), memory(memory), pointerSize(pointerSize), address(request.address)
{
	std::snprintf(viewName, sizeof(viewName), "%s", request.name.c_str());
	Refresh();
}

void DisasmView::Refresh()
{
	// Read in chunks so an unreadable page only truncates the listing.
	std::vector<uint8_t> buffer(kReadSize);
	size_t readable = 0;
	while (readable < kReadSize && memory.readMemory(address + readable, buffer.data() + readable, kChunk))
	{
		readable += kChunk;
	}
	readOk = readable > 0;
	disasm::Decode(buffer.data(), readable, address, pointerSize, kMaxLines, lines);

	// Resolve "call [slot]" so IAT calls show the imported function.
	slotValues.assign(lines.size(), 0);
	for (size_t i = 0; i < lines.size(); ++i)
	{
		if (lines[i].hasMemTarget)
		{
			uint64_t value = 0;
			if (memory.readMemory(lines[i].memTarget, &value, pointerSize))
			{
				slotValues[i] = static_cast<uintptr_t>(value);
			}
		}
	}
	lastRefresh = ImGui::GetTime();
}

void DisasmView::BuildRows(disasm::SymbolResolver* symbols)
{
	rows.clear();
	rows.reserve(lines.size() + 16);
	for (size_t i = 0; i < lines.size(); ++i)
	{
		if (symbols && showSymbols)
		{
			if (auto name = symbols->NameAt(lines[i].address))
			{
				rows.push_back(Row{ i, true, *name });
			}
		}
		rows.push_back(Row{ i, false, {} });
	}
}

void DisasmView::Navigate(uintptr_t target)
{
	backStack.push_back(address);
	address = target;
	scrollTop = true;
	Refresh();
}

void DisasmView::GoBack()
{
	if (backStack.empty())
	{
		return;
	}
	address = backStack.back();
	backStack.pop_back();
	scrollTop = true;
	Refresh();
}

std::string DisasmView::LineText(size_t index, disasm::SymbolResolver* symbols, uintptr_t& followTarget) const
{
	const auto& line = lines[index];
	followTarget = 0;
	if (line.hasTarget)
	{
		followTarget = line.target;
	}
	else if (line.hasMemTarget && slotValues[index] != 0)
	{
		followTarget = slotValues[index];
	}
	if (!symbols || !showSymbols || !line.valid)
	{
		return line.text;
	}

	if (line.hasTarget)
	{
		const std::string name = symbols->Describe(line.target);
		if (!name.empty())
		{
			return line.mnemonic + " " + name;
		}
	}
	else if (line.hasMemTarget && line.flow != disasm::FlowKind::None)
	{
		const std::string name = slotValues[index] != 0 ? symbols->Describe(slotValues[index]) : std::string();
		if (!name.empty())
		{
			return line.text + "  ; -> " + name;
		}
	}
	return line.text;
}

void DisasmView::RenderContextMenu(AnalyserState& state, disasm::SymbolResolver* symbols)
{
	char popupId[32];
	std::snprintf(popupId, sizeof(popupId), "lineMenu%d", id);
	if (ImGui::BeginPopup(popupId))
	{
		ImGui::TextDisabled("0x%llX", static_cast<unsigned long long>(menuAddress));
		ImGui::Separator();
		if (ImGui::MenuItem("Copy address"))
		{
			char buf[32];
			std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(menuAddress));
			ImGui::SetClipboardText(buf);
		}
		if (ImGui::MenuItem("Label this address...", nullptr, false, symbols != nullptr))
		{
			const auto existing = symbols->LabelAt(menuAddress);
			std::snprintf(labelInput, sizeof(labelInput), "%s", existing ? existing->c_str() : "");
			openLabelPopup = true;
		}
		if (ImGui::MenuItem("Trace this address"))
		{
			state.traceRequests.push_back(menuAddress);
			status = "Added to trace";
		}
		if (ImGui::MenuItem("Find static references"))
		{
			state.staticScanRequests.push_back(menuAddress);
			status = "Scanning static references";
		}
		if (menuTarget != 0)
		{
			ImGui::Separator();
			if (ImGui::MenuItem("Follow target"))
			{
				Navigate(menuTarget);
			}
			if (ImGui::MenuItem("Trace target function"))
			{
				state.traceRequests.push_back(menuTarget);
				status = "Added to trace";
			}
			if (ImGui::MenuItem("Find static references for target"))
			{
				state.staticScanRequests.push_back(menuTarget);
				status = "Scanning target static references";
			}
		}
		ImGui::EndPopup();
	}

	char labelId[32];
	std::snprintf(labelId, sizeof(labelId), "labelEdit%d", id);
	if (openLabelPopup)
	{
		ImGui::OpenPopup(labelId);
		openLabelPopup = false;
	}
	if (ImGui::BeginPopup(labelId))
	{
		ImGui::Text("Label for 0x%llX", static_cast<unsigned long long>(menuAddress));
		if (ImGui::IsWindowAppearing())
		{
			ImGui::SetKeyboardFocusHere();
		}
		const bool enter = ImGui::InputText("##label", labelInput, sizeof(labelInput), ImGuiInputTextFlags_EnterReturnsTrue);
		if (ImGui::Button("OK") || enter)
		{
			state.labelRequests.push_back(LabelRequest{ menuAddress, labelInput });
			ImGui::CloseCurrentPopup();
		}
		ImGui::SameLine();
		if (ImGui::Button("Remove"))
		{
			state.labelRequests.push_back(LabelRequest{ menuAddress, {} });
			ImGui::CloseCurrentPopup();
		}
		ImGui::SameLine();
		if (ImGui::Button("Cancel"))
		{
			ImGui::CloseCurrentPopup();
		}
		ImGui::EndPopup();
	}
}

void DisasmView::Render(AnalyserState& state, disasm::SymbolResolver* symbols)
{
	if (!paused && ImGui::GetTime() - lastRefresh >= refreshMs / 1000.0)
	{
		Refresh();
	}
	if (symbols)
	{
		symbols->RequestPdb(address);
	}

	char title[128];
	std::snprintf(title, sizeof(title), "Disasm: %s###disasm%d", viewName[0] ? viewName : "(unnamed)", id);
	ImGui::SetNextWindowSize(ImVec2(720, 520), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin(title, &open))
	{
		ImGui::End();
		return;
	}

	ImGui::BeginDisabled(backStack.empty());
	if (ImGui::Button("< Back"))
	{
		GoBack();
	}
	ImGui::EndDisabled();
	ImGui::SameLine();
	ImGui::SetNextItemWidth(180);
	const bool enter = ImGui::InputTextWithHint("##goto", "address or +offset", gotoInput, sizeof(gotoInput),
		ImGuiInputTextFlags_EnterReturnsTrue);
	ImGui::SameLine();
	if (ImGui::Button("Go to") || enter)
	{
		if (const auto target = ParseBaseAddress(gotoInput, state.attach.moduleBase))
		{
			Navigate(*target);
			status.clear();
		}
		else
		{
			status = "Invalid address";
		}
	}
	ImGui::SameLine();
	ImGui::Checkbox("Pause", &paused);

	ImGui::SetNextItemWidth(180);
	ImGui::InputTextWithHint("##name", "view name", viewName, sizeof(viewName));
	ImGui::SameLine();
	ImGui::BeginDisabled(viewName[0] == '\0');
	if (ImGui::Button("Save"))
	{
		SavedDisasm saved;
		saved.name = viewName;
		saved.pointerSize = pointerSize;
		saved.address = address;
		state.disasmSaveRequests.push_back(std::move(saved));
		status = "Saved";
	}
	ImGui::EndDisabled();
	ImGui::SameLine();
	if (symbols)
	{
		const std::string where = symbols->Describe(address);
		ImGui::Text("%s", where.c_str());
		ImGui::SameLine();
	}
	ImGui::TextDisabled("0x%llX", static_cast<unsigned long long>(address));
	if (!readOk)
	{
		ImGui::SameLine();
		ImGui::TextColored(ImVec4(1.0f, 0.35f, 0.35f, 1.0f), "unreadable");
	}

	ImGui::Checkbox("Show bytes", &showBytes);
	ImGui::SameLine();
	ImGui::Checkbox("Show symbols", &showSymbols);
	if (symbols)
	{
		ImGui::SameLine();
		ImGui::TextDisabled("%s", symbols->Status().c_str());
	}
	if (!status.empty())
	{
		ImGui::SameLine();
		ImGui::TextDisabled("| %s", status.c_str());
	}

	BuildRows(symbols);

	char popupId[32];
	std::snprintf(popupId, sizeof(popupId), "lineMenu%d", id);
	bool openMenu = false;

	if (ImGui::BeginChild("listing", ImVec2(0, 0), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar))
	{
		if (scrollTop)
		{
			ImGui::SetScrollY(0.0f);
			scrollTop = false;
		}
		ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));

		uintptr_t follow = 0;
		ImGuiListClipper clipper;
		clipper.Begin(static_cast<int>(rows.size()));
		while (clipper.Step())
		{
			for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r)
			{
				const Row& row = rows[static_cast<size_t>(r)];
				const auto& line = lines[row.line];
				if (row.isLabel)
				{
					ImGui::TextColored(kLabelColor, "%s:", row.label.c_str());
					continue;
				}

				char prefix[96];
				int pos = std::snprintf(prefix, sizeof(prefix), pointerSize == 4 ? "  %08llX  " : "  %016llX  ",
					static_cast<unsigned long long>(line.address));
				if (showBytes)
				{
					for (uint8_t i = 0; i < 10; ++i)
					{
						pos += i < line.length
							? std::snprintf(prefix + pos, sizeof(prefix) - pos, "%02X ", line.bytes[i])
							: std::snprintf(prefix + pos, sizeof(prefix) - pos, "   ");
					}
					std::snprintf(prefix + pos, sizeof(prefix) - pos, line.length > 10 ? "+ " : "  ");
				}
				ImGui::TextDisabled("%s", prefix);
				ImGui::SameLine(0.0f, 0.0f);

				ImVec4 color = ImGui::GetStyleColorVec4(ImGuiCol_Text);
				if (!line.valid)
				{
					color = ImVec4(0.6f, 0.6f, 0.6f, 1.0f);
				}
				else if (line.flow == disasm::FlowKind::Call)
				{
					color = ImVec4(0.4f, 0.8f, 1.0f, 1.0f);
				}
				else if (line.flow == disasm::FlowKind::Jump || line.flow == disasm::FlowKind::CondJump)
				{
					color = ImVec4(1.0f, 0.8f, 0.4f, 1.0f);
				}
				else if (line.flow == disasm::FlowKind::Ret)
				{
					color = ImVec4(1.0f, 0.45f, 0.45f, 1.0f);
				}

				uintptr_t target = 0;
				const std::string text = LineText(row.line, symbols, target);
				const bool followable = target != 0 && line.flow != disasm::FlowKind::None;

				ImGui::PushID(r);
				ImGui::PushStyleColor(ImGuiCol_Text, color);
				if (ImGui::Selectable(text.c_str(), false) && followable)
				{
					follow = target;
				}
				ImGui::PopStyleColor();
				if (followable && ImGui::IsItemHovered())
				{
					ImGui::SetTooltip("Click to follow 0x%llX\nRight-click for more", static_cast<unsigned long long>(target));
				}
				if (ImGui::IsItemClicked(ImGuiMouseButton_Right))
				{
					menuAddress = line.address;
					menuTarget = followable ? target : 0;
					openMenu = true;
				}
				ImGui::PopID();
			}
		}
		ImGui::PopStyleVar();
		if (follow != 0)
		{
			Navigate(follow);
		}
	}
	ImGui::EndChild();

	if (openMenu)
	{
		ImGui::OpenPopup(popupId);
	}
	RenderContextMenu(state, symbols);

	ImGui::End();
}
}
