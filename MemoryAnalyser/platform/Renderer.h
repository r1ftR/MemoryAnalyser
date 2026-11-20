#pragma once

#include <Windows.h>

namespace platform
{
// The list of things every graphics backend must be able to do.
// Dx11Renderer is one example. To add OpenGL, create a class such as
// OpenGlRenderer that inherits from Renderer and fills in these functions.
class Renderer
{
public:
	virtual ~Renderer() = default;

	// clearColor is { red, green, blue, alpha } from 0.0 to 1.0.
	virtual bool Initialize(HWND window, UINT width, UINT height, const float clearColor[4]) = 0;
	virtual void BeginFrame() = 0;
	virtual void RenderFrame() = 0;
	virtual void Resize(UINT width, UINT height) = 0;
	virtual void Shutdown() = 0;
};
}
