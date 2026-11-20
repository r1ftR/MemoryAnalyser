#pragma once

#include <Windows.h>

namespace platform
{
// All settings for the overlay window in one place.
// Change these values in your project instead of editing Win32Window.cpp.
struct WindowConfig
{
	const wchar_t* title = L"ImGui Base";

	// Window size in pixels. 0 means "use the full screen size".
	int width = 0;
	int height = 0;

	// Keep the window above all other windows.
	bool alwaysOnTop = true;

	// Pixels with this color become see-through.
	// The renderer clears the screen with the same color.
	bool transparent = true;
	COLORREF transparentColor = RGB(0, 0, 0);

	// Tray icon in the taskbar notification area.
	bool showTrayIcon = true;
	const wchar_t* trayTooltip = L"ImGui Base";

	// Global hotkeys that work even when the window is not focused.
	UINT menuToggleKey = VK_INSERT;
	UINT exitKey = VK_DELETE;
};
}
