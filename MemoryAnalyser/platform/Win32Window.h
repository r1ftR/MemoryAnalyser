#pragma once

#include <Windows.h>
#include <shellapi.h>

#include "WindowConfig.h"

namespace platform
{
class Win32Window
{
public:
	~Win32Window();

	bool Initialize(HINSTANCE instance, const WindowConfig& config);
	bool ProcessMessages();
	void Shutdown();
	void Show(bool visible);
	bool ConsumeOpenRequest();
	bool ConsumeToggleRequest();
	bool ConsumeExitRequest();
	bool ConsumeKeyPress(UINT& key);
	bool SetMenuToggleKey(UINT key);
	bool SetExitKey(UINT key);

	HWND GetHandle() const { return handle_; }
	UINT GetWidth() const { return width_; }
	UINT GetHeight() const { return height_; }
	const WindowConfig& GetConfig() const { return config_; }
	bool ConsumeResize(UINT& width, UINT& height);

	// Call once per frame while the menu is visible.
	// Keeps mouse input on the overlay so the game underneath doesn't react to hovering.
	// A click outside the UI hands focus to the window under the cursor.
	void UpdateMouseCapture(bool clickedOutsideUi);

private:
	void TakeInputFocus();
	bool RegisterHotkeys();
	bool CreateTrayIcon();
	void RemoveTrayIcon();
	void UnregisterHotkeys();
	static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam);

	WindowConfig config_;
	HWND handle_ = nullptr;
	UINT width_ = 0;
	UINT height_ = 0;
	bool resized_ = false;
	bool openRequested_ = false;
	bool toggleRequested_ = false;
	bool exitRequested_ = false;
	UINT pressedKey_ = 0;
	UINT menuToggleKey_ = VK_INSERT;
	UINT exitKey_ = VK_DELETE;
	NOTIFYICONDATAW trayIcon_{};
	bool trayIconAdded_ = false;
};
}

