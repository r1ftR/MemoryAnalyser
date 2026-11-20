#pragma once

#include <Windows.h>
#include <d3d11.h>
#include <wrl/client.h>

#include "Renderer.h"

namespace platform
{
class Dx11Renderer : public Renderer
{
public:
	~Dx11Renderer() override;

	bool Initialize(HWND window, UINT width, UINT height, const float clearColor[4]) override;
	void BeginFrame() override;
	void RenderFrame() override;
	void Resize(UINT width, UINT height) override;
	void Shutdown() override;

private:
	bool CreateRenderTarget();
	void CleanupRenderTarget();

	Microsoft::WRL::ComPtr<ID3D11Device> device_;
	Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
	Microsoft::WRL::ComPtr<IDXGISwapChain> swapChain_;
	Microsoft::WRL::ComPtr<ID3D11RenderTargetView> renderTarget_;
	float clearColor_[4] = { 0.0f, 0.0f, 0.0f, 1.0f };
	bool imguiInitialized_ = false;
};
}

