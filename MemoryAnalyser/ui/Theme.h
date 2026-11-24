#pragma once

#include "../third_party/ImGui/imgui.h"

namespace ui
{
// Shared semantic colors complement the standard ImGui style colors.
struct Theme
{
	ImVec4 error{ 1.0f, 0.35f, 0.35f, 1.0f };
	ImVec4 warning{ 1.0f, 0.8f, 0.35f, 1.0f };
	ImVec4 success{ 0.4f, 1.0f, 0.4f, 1.0f };
	ImVec4 accent{ 0.45f, 0.8f, 1.0f, 1.0f };
	ImVec4 muted{ 0.55f, 0.55f, 0.55f, 1.0f };
};

inline Theme& GetTheme()
{
	static Theme theme;
	return theme;
}

inline void ApplyDefaultTheme()
{
	ImGui::StyleColorsDark();
	GetTheme() = Theme{};
}
}
