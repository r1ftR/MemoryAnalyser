#include "Injector.h"

#include "../AnalyserState.h"
#include "../../MemoryManager/LibraryLoader.h"
#include "../../MemoryManager/MemoryManager.h"
#include "../../third_party/ImGui/imgui.h"

#include <Windows.h>
#include <commdlg.h>

namespace analyser
{
Injector::Injector() = default;
Injector::~Injector() = default;

void Injector::Render(const AttachState& attach, MemoryManager* memory)
{
	ImGui::SeparatorText("Load library");
	if (attach.attached && memory)
		ImGui::Text("Target: %s (PID %lu)", attach.processName, attach.processId);
	else
		ImGui::TextDisabled("Attach to a process in the Memory tab first.");

	ImGui::BeginDisabled(libraryLoad != nullptr);
	ImGui::InputText("DLL path (UTF-8)", libraryPath, sizeof(libraryPath));
	ImGui::BeginDisabled(!memory || !attach.attached || !libraryPath[0]);
	if (ImGui::Button("Load DLL"))
	{
		const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, libraryPath, -1, nullptr, 0);
		if (length <= 0)
			libraryStatus = "Invalid UTF-8 DLL path (Windows error " + std::to_string(GetLastError()) + ").";
		else
		{
			std::wstring path(static_cast<size_t>(length), L'\0');
			if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, libraryPath, -1, path.data(), length))
				libraryStatus = "Could not convert DLL path (Windows error " + std::to_string(GetLastError()) + ").";
			else
			{
				path.pop_back();
				libraryLoadTarget = std::string(attach.processName) + " (PID " + std::to_string(attach.processId) + ")";
				libraryLoad = LibraryLoader::Start(memory->GetNativeHandle(), path, libraryStatus);
				libraryLoadMatchesAttachment = libraryLoad != nullptr;
			}
		}
	}
	ImGui::EndDisabled();
	ImGui::SameLine();
	if (ImGui::Button("Browse..."))
	{
		wchar_t path[32768] = {};
		OPENFILENAMEW dialog{};
		dialog.lStructSize = sizeof(dialog);
		dialog.lpstrFilter = L"DLL files\0*.dll\0All files\0*.*\0\0";
		dialog.lpstrFile = path;
		dialog.nMaxFile = static_cast<DWORD>(sizeof(path) / sizeof(path[0]));
		dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
		if (GetOpenFileNameW(&dialog))
		{
			if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1,
				libraryPath, static_cast<int>(sizeof(libraryPath)), nullptr, nullptr))
				libraryStatus = "Could not convert the selected path to UTF-8 (Windows error " + std::to_string(GetLastError()) + ").";
		}
		else if (const DWORD error = CommDlgExtendedError())
			libraryStatus = "File dialog failed (error " + std::to_string(error) + ").";
	}
	ImGui::EndDisabled();
	if (!libraryLoadTarget.empty())
		ImGui::TextWrapped("Operation target: %s", libraryLoadTarget.c_str());
	ImGui::TextWrapped("%s", libraryStatus.c_str());
}

void Injector::Poll(MemoryManager* memory, const std::function<bool()>& refreshModules)
{
	if (!libraryLoad)
		return;
	const LibraryLoader::State result = libraryLoad->Poll(libraryStatus);
	if (result == LibraryLoader::State::Pending)
		return;
	if (result == LibraryLoader::State::ModuleObserved && libraryLoadMatchesAttachment && memory)
	{
		if (!refreshModules())
			libraryStatus += "; module refresh returned no modules";
	}
	libraryLoad.reset();
	libraryLoadMatchesAttachment = false;
}

void Injector::OnDetach()
{
	libraryLoadMatchesAttachment = false;
}

void Injector::OnShutdown()
{
	libraryLoad.reset();
}
}
