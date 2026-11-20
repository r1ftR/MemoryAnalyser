#include "ImGuiSetup.h"

#include "../third_party/ImGui/imgui.h"
#include "../third_party/ImGui/backends/imgui_impl_win32.h"

namespace platform
{
ImGuiSetup::~ImGuiSetup()
{
	Shutdown();
}

bool ImGuiSetup::Initialize(HWND window)
{
	IMGUI_CHECKVERSION();
	ImGui::CreateContext();
	ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
	ImGui::StyleColorsDark();

	if (!ImGui_ImplWin32_Init(window))
	{
		ImGui::DestroyContext();
		return false;
	}

	initialized_ = true;
	return true;
}

void ImGuiSetup::BeginFrame()
{
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();
}

void ImGuiSetup::Shutdown()
{
	if (!initialized_)
	{
		return;
	}

	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();
	initialized_ = false;
}
}
