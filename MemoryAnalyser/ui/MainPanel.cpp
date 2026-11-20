#include "MainPanel.h"

#include "../third_party/ImGui/imgui.h"

namespace ui
{
namespace
{
void RenderFeatureOption(FeatureOption& feature, int index)
{
	ImGui::PushID(index);
	ImGui::Checkbox(feature.name.c_str(), &feature.enabled);
	if (ImGui::BeginPopupContextItem("Settings"))
	{
		ImGui::Text("%s settings", feature.name.c_str());
		if (feature.waitingForKey)
		{
			ImGui::Text("Press a key...");
		}
		else if (ImGui::Button("Bind key"))
		{
			feature.waitingForKey = true;
		}

		ImGui::Text("Key: %u", feature.toggleKey);
		ImGui::EndPopup();
	}
	ImGui::PopID();
}

void RenderExitButton(UiState& state)
{
	if (ImGui::Button("Exit process"))
	{
		state.exitRequested = true;
	}
}
}

void MainPanel::Render(UiState& state)
{
	if (!state.showMainPanel)
	{
		return;
	}

	if (ImGui::Begin(title.c_str()))
	{
		if (ImGui::BeginTabBar("MainTabs"))
		{
			if (renderTabs)
			{
				renderTabs(state);
			}

			if (ImGui::BeginTabItem("Config"))
			{
				ImGui::Text("Right-click a feature for settings.");
				RenderFeatureOption(state.menuToggle, -1);
				RenderExitButton(state);
				ImGui::EndTabItem();
			}

			ImGui::EndTabBar();
		}
	}

	ImGui::End();
}
}

