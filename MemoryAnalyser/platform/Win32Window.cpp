#include "Win32Window.h"

#include "../third_party/ImGui/backends/imgui_impl_win32.h"

#pragma comment(lib, "Shell32.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
	HWND window,
	UINT message,
	WPARAM wParam,
	LPARAM lParam);

namespace platform
{
namespace
{
constexpr wchar_t kWindowClassName[] = L"ImGuiBaseWinDxWindow";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayCallbackMessage = WM_APP + 1;
constexpr UINT kMenuToggleHotkeyId = 1;
constexpr UINT kExitHotkeyId = 2;
constexpr UINT kTrayOpenCommand = 1000;
constexpr UINT kTrayExitCommand = 1001;
}

Win32Window::~Win32Window()
{
	Shutdown();
}

bool Win32Window::Initialize(HINSTANCE instance, const WindowConfig& config)
{
	config_ = config;
	menuToggleKey_ = config.menuToggleKey;
	exitKey_ = config.exitKey;

	// A size of 0 means "use the full screen".
	const int width = config.width > 0 ? config.width : GetSystemMetrics(SM_CXSCREEN);
	const int height = config.height > 0 ? config.height : GetSystemMetrics(SM_CYSCREEN);
	width_ = static_cast<UINT>(width);
	height_ = static_cast<UINT>(height);

	WNDCLASSEXW windowClass{};
	windowClass.cbSize = sizeof(WNDCLASSEXW);
	windowClass.hInstance = instance;
	windowClass.lpfnWndProc = WindowProc;
	windowClass.lpszClassName = kWindowClassName;
	windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);

	if (!RegisterClassExW(&windowClass) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
	{
		return false;
	}

	DWORD extendedStyle = WS_EX_TOOLWINDOW;
	if (config.alwaysOnTop)
	{
		extendedStyle |= WS_EX_TOPMOST;
	}
	if (config.transparent)
	{
		extendedStyle |= WS_EX_LAYERED;
	}

	handle_ = CreateWindowExW(
		extendedStyle,
		kWindowClassName,
		config.title,
		WS_POPUP,
		0,
		0,
		width,
		height,
		nullptr,
		nullptr,
		instance,
		this);

	if (!handle_)
	{
		return false;
	}

	if (config.transparent)
	{
		SetLayeredWindowAttributes(handle_, config.transparentColor, 0, LWA_COLORKEY);
	}

	if (!RegisterHotkeys())
	{
		Shutdown();
		return false;
	}

	if (config.showTrayIcon && !CreateTrayIcon())
	{
		Shutdown();
		return false;
	}

	Show(true);
	return true;
}

void Win32Window::Shutdown()
{
	if (!handle_)
	{
		return;
	}

	RemoveTrayIcon();
	UnregisterHotkeys();
	DestroyWindow(handle_);
	handle_ = nullptr;
}

void Win32Window::Show(bool visible)
{
	if (!handle_)
	{
		return;
	}

	ShowWindow(handle_, visible ? SW_SHOW : SW_HIDE);
	if (visible)
	{
		UpdateWindow(handle_);
		TakeInputFocus();
	}
}

void Win32Window::TakeInputFocus()
{
	// Games usually hold focus, clip the cursor to their window and hide it.
	// Become the foreground window so mouse/keyboard input reaches the menu.
	const HWND foreground = GetForegroundWindow();
	if (foreground != handle_)
	{
		const DWORD foregroundThread = GetWindowThreadProcessId(foreground, nullptr);
		const DWORD currentThread = GetCurrentThreadId();
		const bool attached = foregroundThread != 0 && foregroundThread != currentThread &&
			AttachThreadInput(currentThread, foregroundThread, TRUE);

		BringWindowToTop(handle_);
		SetForegroundWindow(handle_);
		SetActiveWindow(handle_);
		SetFocus(handle_);

		if (attached)
		{
			AttachThreadInput(currentThread, foregroundThread, FALSE);
		}
	}

	ClipCursor(nullptr);
	while (ShowCursor(TRUE) < 0)
	{
	}
	SetCursor(LoadCursorW(nullptr, IDC_ARROW));
}

bool Win32Window::RegisterHotkeys()
{
	if (!RegisterHotKey(handle_, kMenuToggleHotkeyId, MOD_NOREPEAT, menuToggleKey_))
	{
		return false;
	}

	if (!RegisterHotKey(handle_, kExitHotkeyId, MOD_NOREPEAT, exitKey_))
	{
		UnregisterHotKey(handle_, kMenuToggleHotkeyId);
		return false;
	}

	return true;
}

bool Win32Window::CreateTrayIcon()
{
	trayIcon_.cbSize = sizeof(trayIcon_);
	trayIcon_.hWnd = handle_;
	trayIcon_.uID = kTrayIconId;
	trayIcon_.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
	trayIcon_.uCallbackMessage = kTrayCallbackMessage;
	trayIcon_.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
	wcscpy_s(trayIcon_.szTip, config_.trayTooltip);

	trayIconAdded_ = Shell_NotifyIconW(NIM_ADD, &trayIcon_) == TRUE;
	return trayIconAdded_;
}

void Win32Window::RemoveTrayIcon()
{
	if (!trayIconAdded_)
	{
		return;
	}

	Shell_NotifyIconW(NIM_DELETE, &trayIcon_);
	trayIconAdded_ = false;
}

bool Win32Window::ConsumeOpenRequest()
{
	const bool requested = openRequested_;
	openRequested_ = false;
	return requested;
}

void Win32Window::UnregisterHotkeys()
{
	if (handle_)
	{
		UnregisterHotKey(handle_, kMenuToggleHotkeyId);
		UnregisterHotKey(handle_, kExitHotkeyId);
	}
}

bool Win32Window::ConsumeToggleRequest()
{
	const bool requested = toggleRequested_;
	toggleRequested_ = false;
	return requested;
}

bool Win32Window::ConsumeExitRequest()
{
	const bool requested = exitRequested_;
	exitRequested_ = false;
	return requested;
}

bool Win32Window::ConsumeKeyPress(UINT& key)
{
	if (pressedKey_ == 0)
	{
		return false;
	}

	key = pressedKey_;
	pressedKey_ = 0;
	return true;
}

bool Win32Window::SetMenuToggleKey(UINT key)
{
	if (!handle_ || key == menuToggleKey_)
	{
		return true;
	}

	const UINT previousKey = menuToggleKey_;
	UnregisterHotKey(handle_, kMenuToggleHotkeyId);
	if (RegisterHotKey(handle_, kMenuToggleHotkeyId, MOD_NOREPEAT, key))
	{
		menuToggleKey_ = key;
		return true;
	}

	RegisterHotKey(handle_, kMenuToggleHotkeyId, MOD_NOREPEAT, previousKey);
	return false;
}

bool Win32Window::SetExitKey(UINT key)
{
	if (!handle_ || key == exitKey_)
	{
		return true;
	}

	const UINT previousKey = exitKey_;
	UnregisterHotKey(handle_, kExitHotkeyId);
	if (RegisterHotKey(handle_, kExitHotkeyId, MOD_NOREPEAT, key))
	{
		exitKey_ = key;
		return true;
	}

	RegisterHotKey(handle_, kExitHotkeyId, MOD_NOREPEAT, previousKey);
	return false;
}

bool Win32Window::ProcessMessages()
{
	MSG message{};
	while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
	{
		if (message.message == WM_QUIT)
		{
			return false;
		}

		TranslateMessage(&message);
		DispatchMessageW(&message);
	}

	return true;
}

bool Win32Window::ConsumeResize(UINT& width, UINT& height)
{
	if (!resized_)
	{
		return false;
	}

	width = width_;
	height = height_;
	resized_ = false;
	return true;
}

void Win32Window::UpdateMouseCapture(bool clickedOutsideUi)
{
	if (!handle_ || GetForegroundWindow() != handle_)
	{
		// Another window (e.g. the game) has focus; leave the mouse alone.
		return;
	}

	if (clickedOutsideUi)
	{
		ReleaseCapture();

		// Find the top-level window below the overlay at the cursor position.
		POINT cursor{};
		GetCursorPos(&cursor);
		HWND target = GetWindow(handle_, GW_HWNDNEXT);
		while (target)
		{
			RECT rect{};
			if (IsWindowVisible(target) && !IsIconic(target) && GetWindowRect(target, &rect) && PtInRect(&rect, cursor))
			{
				break;
			}
			target = GetWindow(target, GW_HWNDNEXT);
		}

		if (target)
		{
			SetForegroundWindow(target);
		}
		return;
	}

	// Route all mouse input to the overlay, including over transparent pixels.
	if (GetCapture() != handle_)
	{
		SetCapture(handle_);
	}
}

LRESULT CALLBACK Win32Window::WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
	if (ImGui::GetCurrentContext() && ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam))
	{
		return true;
	}

	auto* instance = reinterpret_cast<Win32Window*>(GetWindowLongPtrW(window, GWLP_USERDATA));

	if (message == WM_NCCREATE)
	{
		auto* createData = reinterpret_cast<CREATESTRUCTW*>(lParam);
		instance = static_cast<Win32Window*>(createData->lpCreateParams);
		SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(instance));
		instance->handle_ = window;
	}

	if (instance)
	{
		if (message == WM_HOTKEY && wParam == kMenuToggleHotkeyId)
		{
			instance->toggleRequested_ = true;
		}
		else if (message == WM_HOTKEY && wParam == kExitHotkeyId)
		{
			instance->exitRequested_ = true;
		}
		else if (message == WM_KEYDOWN && (lParam & 0x40000000) == 0)
		{
			instance->pressedKey_ = static_cast<UINT>(wParam);
		}
		else if (message == WM_SIZE && wParam != SIZE_MINIMIZED)
		{
			instance->width_ = LOWORD(lParam);
			instance->height_ = HIWORD(lParam);
			instance->resized_ = true;
		}
		else if (message == kTrayCallbackMessage &&
			(lParam == WM_RBUTTONUP || lParam == WM_CONTEXTMENU))
		{
			HMENU menu = CreatePopupMenu();
			AppendMenuW(menu, MF_STRING, kTrayOpenCommand, L"Open");
			AppendMenuW(menu, MF_STRING, kTrayExitCommand, L"Exit");

			POINT cursorPosition{};
			GetCursorPos(&cursorPosition);
			SetForegroundWindow(window);
			TrackPopupMenu(
				menu,
				TPM_RIGHTBUTTON,
				cursorPosition.x,
				cursorPosition.y,
				0,
				window,
				nullptr);
			DestroyMenu(menu);
			PostMessageW(window, WM_NULL, 0, 0);
		}
		else if (message == WM_COMMAND && LOWORD(wParam) == kTrayOpenCommand)
		{
			instance->openRequested_ = true;
		}
		else if (message == WM_COMMAND && LOWORD(wParam) == kTrayExitCommand)
		{
			instance->exitRequested_ = true;
		}
		else if (message == WM_DESTROY)
		{
			instance->RemoveTrayIcon();
			instance->UnregisterHotkeys();
			PostQuitMessage(0);
		}
		else if (message == WM_NCDESTROY)
		{
			SetWindowLongPtrW(window, GWLP_USERDATA, 0);
			instance->handle_ = nullptr;
		}
	}

	return DefWindowProcW(window, message, wParam, lParam);
}
}

