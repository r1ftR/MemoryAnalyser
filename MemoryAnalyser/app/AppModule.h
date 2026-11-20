#pragma once

#include "../platform/WindowConfig.h"
#include "../ui/UiState.h"

namespace app
{
// Extension point for project code built on top of the base.
// Override only what you need; every hook has an empty default.
class AppModule
{
public:
	virtual ~AppModule() = default;

	// Called before the window is created. Change title, size, hotkeys, ...
	virtual void ConfigureWindow(platform::WindowConfig&) {}

	// Called once after the UI state is created. Add features, set the panel title, ...
	virtual void OnStart(ui::UiState&) {}

	// Called inside the main panel's tab bar, before the built-in tabs.
	virtual void RenderTabs(ui::UiState&) {}

	// Called every frame after the main panel. Draw extra windows here.
	virtual void OnFrame(ui::UiState&) {}

	// Called once before the renderer shuts down.
	virtual void OnShutdown() {}
};
}
