#include "Dx11Renderer.h"

#include "../third_party/ImGui/imgui.h"
#include "../third_party/ImGui/backends/imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

namespace platform
{
Dx11Renderer::~Dx11Renderer()
{
	Shutdown();
}

bool Dx11Renderer::Initialize(HWND window, UINT width, UINT height, const float clearColor[4])
{
	for (int i = 0; i < 4; ++i)
	{
		clearColor_[i] = clearColor[i];
	}

	DXGI_SWAP_CHAIN_DESC swapChainDescription{};
	swapChainDescription.BufferCount = 2;
	swapChainDescription.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	swapChainDescription.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	swapChainDescription.OutputWindow = window;
	swapChainDescription.SampleDesc.Count = 1;
	swapChainDescription.Windowed = TRUE;
	swapChainDescription.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	D3D_FEATURE_LEVEL featureLevel;
	const auto result = D3D11CreateDeviceAndSwapChain(
		nullptr,
		D3D_DRIVER_TYPE_HARDWARE,
		nullptr,
		0,
		nullptr,
		0,
		D3D11_SDK_VERSION,
		&swapChainDescription,
		&swapChain_,
		&device_,
		&featureLevel,
		&context_);

	if (FAILED(result))
	{
		return false;
	}

	if (!CreateRenderTarget())
	{
		return false;
	}

	// The ImGui context must already exist (see ImGuiSetup).
	if (!ImGui_ImplDX11_Init(device_.Get(), context_.Get()))
	{
		return false;
	}

	imguiInitialized_ = true;

	return true;
}

void Dx11Renderer::BeginFrame()
{
	ImGui_ImplDX11_NewFrame();
}

void Dx11Renderer::RenderFrame()
{
	if (!renderTarget_ || !context_ || !swapChain_)
	{
		return;
	}

	ImGui::Render();

	context_->OMSetRenderTargets(1, renderTarget_.GetAddressOf(), nullptr);
	context_->ClearRenderTargetView(renderTarget_.Get(), clearColor_);
	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

	if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
	{
		ImGui::UpdatePlatformWindows();
		ImGui::RenderPlatformWindowsDefault();
	}

	swapChain_->Present(1, 0);
}

void Dx11Renderer::Resize(UINT width, UINT height)
{
	if (!swapChain_ || width == 0 || height == 0)
	{
		return;
	}

	CleanupRenderTarget();
	swapChain_->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
	CreateRenderTarget();
}

void Dx11Renderer::Shutdown()
{
	if (imguiInitialized_)
	{
		ImGui_ImplDX11_Shutdown();
		imguiInitialized_ = false;
	}

	CleanupRenderTarget();
	swapChain_.Reset();
	context_.Reset();
	device_.Reset();
}

bool Dx11Renderer::CreateRenderTarget()
{
	Microsoft::WRL::ComPtr<ID3D11Texture2D> backBuffer;
	if (FAILED(swapChain_->GetBuffer(0, IID_PPV_ARGS(&backBuffer))))
	{
		return false;
	}

	return SUCCEEDED(device_->CreateRenderTargetView(backBuffer.Get(), nullptr, &renderTarget_));
}

void Dx11Renderer::CleanupRenderTarget()
{
	renderTarget_.Reset();
}
}

