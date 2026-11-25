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

	// Called every visible frame after the main panel; may also run while hidden
	// when BackgroundFrameIntervalMs returns a nonzero interval.
	virtual void OnFrame(ui::UiState&) {}

	// Return zero to sleep until a window message while hidden.
	virtual unsigned BackgroundFrameIntervalMs() const { return 0; }

	// Called once before the renderer shuts down.
	virtual void OnShutdown() {}
};
}
