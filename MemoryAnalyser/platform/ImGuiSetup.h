#pragma once

#include <Windows.h>

namespace platform
{
// Creates and destroys the parts of ImGui that every renderer shares:
// the ImGui context, the style, and the Win32 input backend.
// The graphics part (DirectX 11, OpenGL, ...) is set up by the renderer.
class ImGuiSetup
{
public:
	~ImGuiSetup();

	bool Initialize(HWND window);
	void BeginFrame();
	void Shutdown();

private:
	bool initialized_ = false;
};
}
