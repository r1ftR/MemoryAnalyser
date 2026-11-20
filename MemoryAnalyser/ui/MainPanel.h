#pragma once

#include "UiPanel.h"

#include <functional>
#include <string>

namespace ui
{
class MainPanel final : public UiPanel
{
public:
	using TabRenderer = std::function<void(UiState&)>;

	void SetTitle(std::string newTitle) { title = std::move(newTitle); }

	// Extra tabs drawn before the built-in Config tab.
	void SetTabRenderer(TabRenderer renderer) { renderTabs = std::move(renderer); }

	void Render(UiState& state) override;

private:
	std::string title = "Main";
	TabRenderer renderTabs;
};
}

