#include "StructTable.h"

#include "../Format/TypeDetect.h"
#include "../../MemoryManager/MemoryManager.h"
#include "../../third_party/ImGui/imgui.h"

#include <cstdio>
#include <cstring>

namespace analyser
{
namespace
{
const ImVec4 kErrorColor(1.0f, 0.35f, 0.35f, 1.0f);
const ImVec4 kPointerColor(0.45f, 0.8f, 1.0f, 1.0f);
constexpr size_t kDetectSamples = 10;
constexpr double kDetectInterval = 0.1;

// Plain text has no ID, so BeginPopupContextItem can't attach to it.
// Open the popup manually when the last drawn item is right-clicked.
void OpenPopupOnRightClick(const char* popupId)
{
	if (ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right))
	{
		ImGui::OpenPopup(popupId);
	}
}
}

StructTable::StructTable(int id, MemoryManager& memory, size_t pointerSize, StructOpenRequest request, bool autoDetect)
	: id(id), memory(memory), pointerSize(pointerSize), source(std::move(request))
{
	if (source.layout && !source.layout->fields.empty())
	{
		for (const auto& saved : source.layout->fields)
		{
			Field field;
			field.type = saved.type;
			std::snprintf(field.name, sizeof(field.name), "%s", saved.name.c_str());
			field.userSet = true;
			fields.push_back(field);
		}
		std::snprintf(tableName, sizeof(tableName), "%s", source.layout->name.c_str());
	}
	else
	{
		AddBytes(0x40);
		if (autoDetect)
		{
			StartDetect();
		}
	}
}

bool StructTable::ProbePointer(uint64_t target)
{
	for (const auto& [cached, ok] : probeCache)
	{
		if (cached == target)
		{
			return ok;
		}
	}
	uint8_t byte = 0;
	const bool ok = memory.readMemory(static_cast<uintptr_t>(target), &byte, 1);
	if (probeCache.size() >= 256)
	{
		probeCache.erase(probeCache.begin());
	}
	probeCache.emplace_back(target, ok);
	return ok;
}

void StructTable::StartDetect()
{
	detecting = true;
	detectSamples.clear();
	probeCache.clear();
	lastSample = -1.0;
}

void StructTable::CollectDetectSample(double now)
{
	if (!detecting || !chainOk || now - lastSample < kDetectInterval)
	{
		return;
	}
	lastSample = now;
	detectSamples.push_back(buffer);
	if (detectSamples.size() >= kDetectSamples)
	{
		ApplyDetect();
		detecting = false;
		detectSamples.clear();
		lastRefresh = -1.0;
	}
}

void StructTable::ApplyDetect()
{
	const PointerProbe probe = [this](uint64_t target) { return ProbePointer(target); };

	// Rebuild each run of untouched rows from the guess; user-set rows stay as they are.
	std::vector<Field> rebuilt;
	size_t offset = 0;
	size_t index = 0;
	while (index < fields.size())
	{
		if (fields[index].userSet)
		{
			rebuilt.push_back(fields[index]);
			offset += FieldSize(fields[index].type, pointerSize);
			++index;
			continue;
		}

		const size_t runStart = offset;
		while (index < fields.size() && !fields[index].userSet)
		{
			offset += FieldSize(fields[index].type, pointerSize);
			++index;
		}

		for (const FieldType type : DetectRange(detectSamples, runStart, offset, pointerSize, probe))
		{
			Field field;
			field.type = type;
			rebuilt.push_back(field);
		}
	}
	fields = std::move(rebuilt);
}

size_t StructTable::TotalSize() const
{
	size_t size = 0;
	for (const auto& field : fields)
	{
		size += FieldSize(field.type, pointerSize);
	}
	return size;
}

void StructTable::AddBytes(size_t count)
{
	const size_t rowSize = FieldSize(DefaultFieldType(pointerSize), pointerSize);
	for (size_t added = 0; added < count; added += rowSize)
	{
		Field field;
		field.type = DefaultFieldType(pointerSize);
		fields.push_back(field);
	}
	lastRefresh = -1.0;
}

void StructTable::InsertPadding(size_t position, size_t size)
{
	// Fill the gap with the largest hex fields that fit so offsets after it stay the same.
	while (size > 0)
	{
		Field pad;
		if (size >= 8) { pad.type = FieldType::Hex64; size -= 8; }
		else if (size >= 4) { pad.type = FieldType::Hex32; size -= 4; }
		else if (size >= 2) { pad.type = FieldType::Hex16; size -= 2; }
		else { pad.type = FieldType::Hex8; size -= 1; }
		fields.insert(fields.begin() + static_cast<std::ptrdiff_t>(position), pad);
		++position;
	}
}

void StructTable::SetFieldType(size_t index, FieldType newType)
{
	const size_t oldSize = FieldSize(fields[index].type, pointerSize);
	const size_t newSize = FieldSize(newType, pointerSize);
	fields[index].type = newType;

	if (newSize < oldSize)
	{
		InsertPadding(index + 1, oldSize - newSize);
	}
	else if (newSize > oldSize)
	{
		// Consume the following fields that the larger type now overlaps.
		size_t needed = newSize - oldSize;
		while (needed > 0 && index + 1 < fields.size())
		{
			const size_t nextSize = FieldSize(fields[index + 1].type, pointerSize);
			fields.erase(fields.begin() + static_cast<std::ptrdiff_t>(index + 1));
			if (nextSize > needed)
			{
				InsertPadding(index + 1, nextSize - needed);
				needed = 0;
			}
			else
			{
				needed -= nextSize;
			}
		}
	}
	lastRefresh = -1.0;
}

void StructTable::Refresh()
{
	if (source.offsets.empty())
	{
		address = source.base;
		chainOk = true;
	}
	else
	{
		uintptr_t result = 0;
		chainOk = memory.resolvePointerChain(source.base, source.offsets, result, pointerSize);
		address = chainOk ? result : 0;
	}

	buffer.assign(TotalSize(), 0);
	if (!chainOk)
	{
		for (auto& field : fields)
		{
			field.readOk = false;
		}
		readsOk = 0;
		return;
	}

	const bool wholeOk = memory.readMemory(address, buffer.data(), buffer.size());
	size_t offset = 0;
	readsOk = 0;
	for (auto& field : fields)
	{
		const size_t size = FieldSize(field.type, pointerSize);
		field.readOk = wholeOk || memory.readMemory(address + offset, buffer.data() + offset, size);
		readsOk += field.readOk ? 1 : 0;
		offset += size;
	}
	lastReadTime = ImGui::GetTime();
}

void StructTable::OpenPointer(AnalyserState& state, size_t offset)
{
	// Keep the full chain so the child window follows the pointer live.
	StructOpenRequest child;
	child.base = source.base;
	child.offsets = source.offsets;
	if (child.offsets.empty())
	{
		child.base += offset;
	}
	else
	{
		child.offsets.back() += offset;
	}
	child.offsets.push_back(0);

	char label[256];
	std::snprintf(label, sizeof(label), "[%s+%zX]", source.label.c_str(), offset);
	child.label = label;
	state.openRequests.push_back(std::move(child));
}

void StructTable::RenderValuePopup(AnalyserState& state, Field& field, size_t offset, const uint8_t* data)
{
	if (ImGui::IsWindowAppearing())
	{
		editBuffer[0] = '\0';
		editStatus.clear();
		if (data != nullptr)
		{
			std::snprintf(editBuffer, sizeof(editBuffer), "%s",
				FormatField(field.type, data, pointerSize, field.hexDisplay).c_str());
		}
	}
	editing = true;

	ImGui::Text("%s at +%04zX", FieldTypeNames()[static_cast<int>(field.type)], offset);
	ImGui::Separator();

	if (IsIntegerType(field.type))
	{
		ImGui::TextDisabled("Display");
		ImGui::SameLine();
		int display = field.hexDisplay ? 1 : 0;
		if (ImGui::RadioButton("Dec", &display, 0)) field.hexDisplay = false;
		ImGui::SameLine();
		if (ImGui::RadioButton("Hex", &display, 1)) field.hexDisplay = true;
	}

	if (field.type == FieldType::Pointer && data != nullptr && ReadPointer(data, pointerSize) != 0)
	{
		if (ImGui::Button("Open in new window"))
		{
			OpenPointer(state, offset);
			ImGui::CloseCurrentPopup();
		}
	}

	ImGui::SeparatorText("Write");
	if (ImGui::IsWindowAppearing())
	{
		ImGui::SetKeyboardFocusHere();
	}
	ImGui::SetNextItemWidth(220);
	const bool submitted = ImGui::InputText("##value", editBuffer, sizeof(editBuffer), ImGuiInputTextFlags_EnterReturnsTrue);
	ImGui::SameLine();
	ImGui::TextDisabled("(?)");
	if (ImGui::IsItemHovered())
	{
		ImGui::SetTooltip("123 / -5    decimal\n0x64        hex\n1.5         float (double if field is Double)\ntrue/false  bool\n0x1234*     pointer\n\"text\"      string");
	}

	std::vector<uint8_t> bytes;
	std::string parseError;
	const bool parsed = ParseValueInput(editBuffer, field.type, pointerSize, bytes, parseError);
	if (parsed)
	{
		ImGui::TextDisabled("-> %s", FormatHexBytes(bytes.data(), bytes.size()).c_str());
	}
	else if (editBuffer[0] != '\0')
	{
		ImGui::TextColored(kErrorColor, "%s", parseError.c_str());
	}

	ImGui::BeginDisabled(!parsed || !chainOk);
	if (ImGui::Button("Write") || (submitted && parsed && chainOk))
	{
		if (memory.writeMemory(address + offset, bytes.data(), bytes.size()))
		{
			editStatus = "Written";
			editStatusError = false;
			lastRefresh = -1.0;
		}
		else
		{
			editStatus = "Write failed (error " + std::to_string(GetLastError()) + ")";
			editStatusError = true;
		}
	}
	ImGui::EndDisabled();

	if (!editStatus.empty())
	{
		ImGui::SameLine();
		if (editStatusError)
		{
			ImGui::TextColored(kErrorColor, "%s", editStatus.c_str());
		}
		else
		{
			ImGui::TextDisabled("%s", editStatus.c_str());
		}
	}
}

void StructTable::RenderStructOptions(AnalyserState& state)
{
	ImGui::SetNextItemWidth(180);
	ImGui::InputTextWithHint("##tablename", "Table name", tableName, sizeof(tableName));
	ImGui::SameLine();
	ImGui::BeginDisabled(tableName[0] == '\0');
	if (ImGui::Button("Save"))
	{
		SavedTable saved;
		saved.name = tableName;
		saved.pointerSize = pointerSize;
		saved.hasLocation = true;
		saved.base = source.base;
		saved.chain.assign(source.offsets.begin(), source.offsets.end());
		for (const auto& field : fields)
		{
			saved.fields.push_back({ field.type, field.name });
		}
		state.saveRequests.push_back(std::move(saved));
		saveStatus = "Saved";
	}
	ImGui::EndDisabled();
	if (!saveStatus.empty())
	{
		ImGui::SameLine();
		ImGui::TextDisabled("%s", saveStatus.c_str());
	}
	ImGui::SameLine();
	ImGui::BeginDisabled(detecting);
	if (ImGui::Button("Detect types"))
	{
		StartDetect();
	}
	ImGui::EndDisabled();
	if (detecting)
	{
		ImGui::SameLine();
		ImGui::TextColored(kPointerColor, "Detecting... %zu/%zu", detectSamples.size(), kDetectSamples);
	}

	ImGui::Checkbox("Pause", &paused);
	ImGui::SameLine();
	ImGui::SetNextItemWidth(120);
	ImGui::SliderInt("Refresh (ms)", &refreshMs, 16, 2000);
	ImGui::SameLine();
	if (ImGui::Button("Add 0x40"))
	{
		AddBytes(0x40);
	}
	ImGui::SameLine();
	if (ImGui::Button("Remove last") && fields.size() > 1)
	{
		fields.pop_back();
		lastRefresh = -1.0;
	}
}

void StructTable::RenderRow(AnalyserState& state, size_t index, size_t offset, bool& layoutChanged)
{
	Field& field = fields[index];
	const size_t size = FieldSize(field.type, pointerSize);
	const uint8_t* data = (field.readOk && buffer.size() >= offset + size) ? buffer.data() + offset : nullptr;

	const float fontWidth = ImGui::CalcTextSize("0").x;
	const float addressColumn = fontWidth * 7;
	const float typeColumn = addressColumn + fontWidth * (pointerSize == 4 ? 10 : 18);
	const float nameColumn = typeColumn + fontWidth * 10;
	const float valueColumn = nameColumn + fontWidth * 18;

	ImGui::PushID(static_cast<int>(index));

	// Row hover highlight.
	const ImVec2 rowMin = ImGui::GetCursorScreenPos();
	const ImVec2 rowMax(rowMin.x + ImGui::GetContentRegionAvail().x, rowMin.y + ImGui::GetTextLineHeightWithSpacing());
	if (ImGui::IsMouseHoveringRect(rowMin, rowMax) && ImGui::IsWindowHovered(ImGuiHoveredFlags_AllowWhenBlockedByPopup))
	{
		ImGui::GetWindowDrawList()->AddRectFilled(rowMin, rowMax, ImGui::GetColorU32(ImGuiCol_FrameBgHovered));
	}

	const float lineStart = ImGui::GetCursorPosX();

	ImGui::TextDisabled("+%04zX", offset);

	ImGui::SameLine(lineStart + addressColumn);
	ImGui::TextDisabled("%llX", static_cast<unsigned long long>(address + offset));

	// Type (right-click to change).
	ImGui::SameLine(lineStart + typeColumn);
	ImGui::TextColored(ImVec4(0.6f, 0.85f, 0.6f, 1.0f), "%s", FieldTypeNames()[static_cast<int>(field.type)]);
	OpenPopupOnRightClick("TypePopup");
	if (ImGui::BeginPopup("TypePopup"))
	{
		ImGui::Text("Field type");
		ImGui::Separator();
		for (int typeIndex = 0; typeIndex < static_cast<int>(FieldType::Count); ++typeIndex)
		{
			const auto type = static_cast<FieldType>(typeIndex);
			if (ImGui::Selectable(FieldTypeNames()[typeIndex], type == field.type))
			{
				SetFieldType(index, type);
				fields[index].userSet = true;
				layoutChanged = true;
			}
		}
		ImGui::EndPopup();
	}
	if (layoutChanged)
	{
		ImGui::PopID();
		return;
	}

	// Name (right-click to rename).
	ImGui::SameLine(lineStart + nameColumn);
	if (field.name[0] != '\0')
	{
		ImGui::TextUnformatted(field.name);
	}
	else
	{
		ImGui::TextDisabled("-");
	}
	OpenPopupOnRightClick("NamePopup");
	if (ImGui::BeginPopup("NamePopup"))
	{
		ImGui::Text("Field name");
		ImGui::Separator();
		if (ImGui::IsWindowAppearing())
		{
			ImGui::SetKeyboardFocusHere();
		}
		ImGui::SetNextItemWidth(200);
		if (ImGui::InputText("##name", field.name, sizeof(field.name), ImGuiInputTextFlags_EnterReturnsTrue))
		{
			ImGui::CloseCurrentPopup();
		}
		if (ImGui::IsItemEdited())
		{
			field.userSet = true;
		}
		ImGui::EndPopup();
	}

	// Value (right-click to edit/write).
	ImGui::SameLine(lineStart + valueColumn);
	if (data == nullptr)
	{
		ImGui::TextColored(kErrorColor, "??");
	}
	else if (field.type == FieldType::Pointer)
	{
		ImGui::TextColored(kPointerColor, "%s", FormatField(field.type, data, pointerSize, field.hexDisplay).c_str());
	}
	else
	{
		ImGui::TextUnformatted(FormatField(field.type, data, pointerSize, field.hexDisplay).c_str());
	}
	OpenPopupOnRightClick("ValuePopup");
	if (ImGui::BeginPopup("ValuePopup"))
	{
		RenderValuePopup(state, field, offset, data);
		ImGui::EndPopup();
	}

	ImGui::PopID();
}

void StructTable::Render(AnalyserState& state)
{
	// Hold the values still while a value is being edited.
	const bool wasEditing = editing;
	editing = false;

	const double now = ImGui::GetTime();
	// While detecting, keep reading even if paused/editing so samples cover real changes.
	const double interval = detecting ? kDetectInterval : refreshMs / 1000.0;
	if (lastRefresh < 0.0 || ((detecting || (!paused && !wasEditing)) && now - lastRefresh >= interval))
	{
		Refresh();
		lastRefresh = now;
		CollectDetectSample(now);
	}

	char title[320];
	std::snprintf(title, sizeof(title), "Table: %s###StructTable%d", tableName[0] != '\0' ? tableName : source.label.c_str(), id);

	ImGui::SetNextWindowSize(ImVec2(620, 480), ImGuiCond_FirstUseEver);
	if (!ImGui::Begin(title, &open))
	{
		ImGui::End();
		return;
	}

	if (chainOk)
	{
		ImGui::Text("0x%llX", static_cast<unsigned long long>(address));
	}
	else
	{
		ImGui::TextColored(kErrorColor, "Pointer chain could not be resolved");
	}
	ImGui::SameLine();
	ImGui::TextDisabled("%zu bytes, %s", TotalSize(), pointerSize == 4 ? "x86" : "x64");
	ImGui::SameLine();
	if (lastReadTime >= 0.0 && readsOk == fields.size())
	{
		ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f), "live (%.1fs)", now - lastReadTime);
	}
	else
	{
		ImGui::TextColored(kErrorColor, "%zu/%zu rows readable", readsOk, fields.size());
	}
	RenderStructOptions(state);
	ImGui::Separator();

	if (ImGui::BeginChild("Rows", ImVec2(0, 0), ImGuiChildFlags_None))
	{
		size_t offset = 0;
		for (size_t index = 0; index < fields.size(); ++index)
		{
			bool layoutChanged = false;
			RenderRow(state, index, offset, layoutChanged);
			if (layoutChanged)
			{
				break;
			}
			offset += FieldSize(fields[index].type, pointerSize);
		}
	}
	ImGui::EndChild();

	ImGui::End();
}
}
