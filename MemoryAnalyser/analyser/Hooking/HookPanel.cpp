#include "HookPanel.h"

#include "Project.h"
#include "ProjectProtocol.h"
#include "../Storage/TableStore.h"
#include "../../MemoryManager/LibraryLoader.h"
#include "../../MemoryManager/MemoryManager.h"
#include "../../MemoryManager/RemoteExportCall.h"
#include "../../third_party/ImGui/imgui.h"

#include <Windows.h>
#include <commdlg.h>
#include <objbase.h>
#include <sddl.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <cfloat>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iterator>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Shell32.lib")

namespace analyser::hooking
{
namespace
{
constexpr uint32_t kPipeMagic = protocol::Magic;
constexpr uint32_t kPipeVersion = protocol::Version;
constexpr uint64_t kMaxPayloadCodeUnits = protocol::MaxPayloadCodeUnits;
constexpr DWORD kIoWaitMilliseconds = 100;

ProjectSpec MakeProjectSpec(const HookTarget& target, const std::wstring& directory,
	const std::wstring& session, const std::wstring& pipe)
{
	ProjectSpec spec{};
	spec.directory = directory;
	const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, target.moduleName.data(), static_cast<int>(target.moduleName.size()), nullptr, 0);
	if (size > 0)
	{
		spec.moduleName.resize(size);
		MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, target.moduleName.data(), static_cast<int>(target.moduleName.size()), spec.moduleName.data(), size);
	}
	spec.rva = target.rva;
	spec.x64 = target.x64;
	spec.sessionId = session;
	spec.pipeName = pipe;
	spec.modulePath = target.modulePath;
	spec.volumeSerial = target.volumeSerial;
	spec.fileId = target.fileId;
	spec.fileSize = target.fileSize;
	spec.fileLastWrite = target.fileLastWrite;
	spec.imageSize = target.imageSize;
	spec.imageTimestamp = target.imageTimestamp;
	spec.imageChecksum = target.imageChecksum;
	spec.imageMachine = target.imageMachine;
	spec.originalBytes = target.originalBytes;
	return spec;
}

bool SameAttachedInstance(MemoryManager* memory, const HookTarget& target)
{
	if (!memory || memory->GetAttachedProcessId() != target.processId) return false;
	HANDLE process = memory->GetNativeHandle();
	FILETIME creation{}, exit{}, kernel{}, user{};
	if (!process || GetProcessId(process) != target.processId ||
		!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return false;
	return ((static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime) == target.processCreation;
}

std::string ToUtf8(const std::wstring& text)
{
	if (text.empty())
		return {};
	const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
		static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
	if (required <= 0)
		return {};
	std::string result(static_cast<size_t>(required), '\0');
	if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
		static_cast<int>(text.size()), result.data(), required, nullptr, nullptr))
		return {};
	return result;
}

std::optional<std::wstring> FromUtf8(const std::string& text)
{
	if (text.empty())
		return std::wstring{};
	const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
		static_cast<int>(text.size()), nullptr, 0);
	if (required <= 0)
		return std::nullopt;
	std::wstring result(static_cast<size_t>(required), L'\0');
	if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
		static_cast<int>(text.size()), result.data(), required))
		return std::nullopt;
	return result;
}

std::optional<std::wstring> CreateSessionId()
{
	GUID guid{};
	if (FAILED(CoCreateGuid(&guid)))
		return std::nullopt;
	wchar_t text[40]{};
	if (!StringFromGUID2(guid, text, static_cast<int>(std::size(text))))
		return std::nullopt;
	return std::wstring(text + 1, 36);
}

std::wstring GetSafeProjectDirectory(const std::wstring& session)
{
	const DWORD required = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
	if (!required || required > 32768)
		return {};
	std::wstring localAppData(required, L'\0');
	const DWORD written = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData.data(), required);
	if (!written || written >= required)
		return {};
	localAppData.resize(written);
	return (std::filesystem::path(localAppData) / L"MemoryAnalyser" / L"Hooks" /
		(L"Hook-" + session)).wstring();
}

std::wstring GetFullPath(const std::wstring& path)
{
	if (path.empty())
		return {};
	const DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
	if (!required || required > 32768)
		return {};
	std::wstring result(required, L'\0');
	const DWORD written = GetFullPathNameW(path.c_str(), required, result.data(), nullptr);
	if (!written || written >= required)
		return {};
	result.resize(written);
	while (result.size() > 3 && (result.back() == L'\\' || result.back() == L'/'))
		result.pop_back();
	return result;
}

bool PathsEqual(const std::wstring& left, const std::wstring& right)
{
	const std::wstring fullLeft = GetFullPath(left);
	const std::wstring fullRight = GetFullPath(right);
	return !fullLeft.empty() && !fullRight.empty() &&
		CompareStringOrdinal(fullLeft.c_str(), static_cast<int>(fullLeft.size()),
			fullRight.c_str(), static_cast<int>(fullRight.size()), TRUE) == CSTR_EQUAL;
}

uint32_t ReadLe32(const uint8_t* bytes)
{
	return static_cast<uint32_t>(bytes[0]) |
		(static_cast<uint32_t>(bytes[1]) << 8) |
		(static_cast<uint32_t>(bytes[2]) << 16) |
		(static_cast<uint32_t>(bytes[3]) << 24);
}

bool IsValidUtf16(const std::wstring& value)
{
	for (size_t i = 0; i < value.size(); ++i)
	{
		const uint16_t unit = static_cast<uint16_t>(value[i]);
		if (unit == 0)
			return false;
		if (unit >= 0xD800 && unit <= 0xDBFF)
		{
			if (++i >= value.size())
				return false;
			const uint16_t low = static_cast<uint16_t>(value[i]);
			if (low < 0xDC00 || low > 0xDFFF)
				return false;
		}
		else if (unit >= 0xDC00 && unit <= 0xDFFF)
			return false;
	}
	return true;
}

bool WaitOverlapped(HANDLE pipe, OVERLAPPED& operation, const std::atomic<bool>& stopRequested,
	DWORD& transferred, ULONGLONG deadline = 0)
{
	for (;;)
	{
		DWORD waitMilliseconds = kIoWaitMilliseconds;
		if (deadline)
		{
			const ULONGLONG now = GetTickCount64();
			if (now >= deadline)
			{
				CancelIoEx(pipe, &operation);
				GetOverlappedResult(pipe, &operation, &transferred, TRUE);
				return false;
			}
			const ULONGLONG remaining = deadline - now;
			if (remaining < waitMilliseconds)
				waitMilliseconds = static_cast<DWORD>(remaining);
		}
		const DWORD waitResult = WaitForSingleObject(operation.hEvent, waitMilliseconds);
		if (waitResult == WAIT_OBJECT_0)
			return GetOverlappedResult(pipe, &operation, &transferred, FALSE) != FALSE;
		if (waitResult == WAIT_FAILED || stopRequested.load())
		{
			CancelIoEx(pipe, &operation);
			GetOverlappedResult(pipe, &operation, &transferred, TRUE);
			return false;
		}
	}
}

bool ReadExact(HANDLE pipe, uint8_t* destination, size_t length,
	const std::atomic<bool>& stopRequested, ULONGLONG deadline = 0)
{
	size_t offset = 0;
	while (offset < length && !stopRequested.load())
	{
		if (deadline && GetTickCount64() >= deadline)
			return false;
		OVERLAPPED operation{};
		operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!operation.hEvent)
			return false;
		DWORD transferred = 0;
		const DWORD requested = static_cast<DWORD>(length - offset);
		BOOL read = ReadFile(pipe, destination + offset, requested, &transferred, &operation);
		if (!read && GetLastError() == ERROR_IO_PENDING)
			read = WaitOverlapped(pipe, operation, stopRequested, transferred, deadline);
		else if (!read)
			transferred = 0;
		CloseHandle(operation.hEvent);
		if (!read || transferred == 0)
			return false;
		offset += transferred;
	}
	return offset == length;
}

bool ConnectPipe(HANDLE pipe, const std::atomic<bool>& stopRequested)
{
	OVERLAPPED operation{};
	operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!operation.hEvent)
		return false;
	BOOL connected = ConnectNamedPipe(pipe, &operation);
	if (!connected)
	{
		const DWORD error = GetLastError();
		if (error == ERROR_PIPE_CONNECTED)
			connected = TRUE;
		else if (error == ERROR_IO_PENDING)
		{
			DWORD transferred = 0;
			connected = WaitOverlapped(pipe, operation, stopRequested, transferred);
		}
	}
	CloseHandle(operation.hEvent);
	return connected != FALSE;
}

std::wstring DecodeUtf16(const uint8_t* bytes, uint32_t codeUnits)
{
	std::wstring result;
	result.reserve(codeUnits);
	for (uint32_t i = 0; i < codeUnits; ++i)
		result.push_back(static_cast<wchar_t>(static_cast<uint16_t>(bytes[i * 2]) |
			(static_cast<uint16_t>(bytes[i * 2 + 1]) << 8)));
	return result;
}

std::wstring GetFinalPath(HANDLE handle)
{
	const DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
	const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0, flags);
	if (!required || required > 32768)
		return {};
	std::wstring result(static_cast<size_t>(required) + 1, L'\0');
	const DWORD written = GetFinalPathNameByHandleW(handle, result.data(),
		static_cast<DWORD>(result.size()), flags);
	if (!written || written >= result.size())
		return {};
	result.resize(written);
	return result;
}

std::shared_ptr<void> OpenValidatedDll(const std::wstring& path,
	const std::wstring& projectDirectory, const std::wstring& platform,
	const std::wstring& configuration, bool x64, std::string& error)
{
	HANDLE root = CreateFileW(projectDirectory.c_str(), FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (root == INVALID_HANDLE_VALUE)
	{
		error = "Could not verify the generated project directory (Windows error " + std::to_string(GetLastError()) + ").";
		return {};
	}
	BY_HANDLE_FILE_INFORMATION rootInfo{};
	const bool safeRoot = GetFileInformationByHandle(root, &rootInfo) &&
		(rootInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
		!(rootInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
	const std::wstring finalRoot = safeRoot ? GetFinalPath(root) : std::wstring{};
	CloseHandle(root);
	if (finalRoot.empty())
	{
		error = "Generated project directory is not a stable, canonical directory.";
		return {};
	}

	HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (file == INVALID_HANDLE_VALUE)
	{
		error = "Could not open the reported build output (Windows error " + std::to_string(GetLastError()) + ").";
		return {};
	}
	auto closeOnFailure = [&]() { CloseHandle(file); };
	BY_HANDLE_FILE_INFORMATION info{};
	LARGE_INTEGER fileSize{};
	if (!GetFileInformationByHandle(file, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
		!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 0x40)
	{
		error = "Reported build output is not a regular DLL file.";
		closeOnFailure();
		return {};
	}
	const std::wstring finalFile = GetFinalPath(file);
	const std::wstring expectedFinal = (std::filesystem::path(finalRoot) / L"bin" /
		platform / configuration / L"Hook.dll").wstring();
	if (finalFile.empty() || !PathsEqual(finalFile, expectedFinal))
	{
		error = "Resolved build output is not inside the approved project session directory.";
		closeOnFailure();
		return {};
	}
	std::array<uint8_t, 0x40> dosHeader{};
	DWORD read = 0;
	if (!ReadFile(file, dosHeader.data(), static_cast<DWORD>(dosHeader.size()), &read, nullptr) ||
		read != dosHeader.size() || dosHeader[0] != 'M' || dosHeader[1] != 'Z')
	{
		error = "Reported build output has no valid PE header.";
		closeOnFailure();
		return {};
	}
	const uint32_t peOffset = ReadLe32(dosHeader.data() + 0x3C);
	if (peOffset < dosHeader.size() || static_cast<uint64_t>(peOffset) + 6 > static_cast<uint64_t>(fileSize.QuadPart))
	{
		error = "Reported build output contains an invalid PE header offset.";
		closeOnFailure();
		return {};
	}
	LARGE_INTEGER position{};
	position.QuadPart = peOffset;
	std::array<uint8_t, 6> peHeader{};
	if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN) ||
		!ReadFile(file, peHeader.data(), static_cast<DWORD>(peHeader.size()), &read, nullptr) ||
		read != peHeader.size() || peHeader[0] != 'P' || peHeader[1] != 'E' || peHeader[2] != 0 || peHeader[3] != 0)
	{
		error = "Reported build output has no valid PE signature.";
		closeOnFailure();
		return {};
	}
	const uint16_t machine = static_cast<uint16_t>(peHeader[4] | (static_cast<uint16_t>(peHeader[5]) << 8));
	const uint16_t expectedMachine = x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
	if (machine != expectedMachine)
	{
		error = "Reported DLL architecture does not match the selected target.";
		closeOnFailure();
		return {};
	}
	return std::shared_ptr<void>(file, [](void* handle) { CloseHandle(static_cast<HANDLE>(handle)); });
}

bool BuildSecurityAttributes(SECURITY_ATTRIBUTES& attributes, PSECURITY_DESCRIPTOR& descriptor)
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		return false;
	DWORD required = 0;
	GetTokenInformation(token, TokenUser, nullptr, 0, &required);
	std::vector<uint8_t> tokenUser(required);
	const bool tokenRead = required && GetTokenInformation(token, TokenUser, tokenUser.data(), required, &required) != FALSE;
	CloseHandle(token);
	if (!tokenRead)
		return false;
	LPWSTR sidText = nullptr;
	if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(tokenUser.data())->User.Sid, &sidText))
		return false;
	const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;" + std::wstring(sidText) + L")";
	LocalFree(sidText);
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
		&descriptor, nullptr))
		return false;
	attributes.nLength = sizeof(attributes);
	attributes.lpSecurityDescriptor = descriptor;
	attributes.bInheritHandle = FALSE;
	return true;
}

template <typename Notification>
bool ReadBuildMessage(HANDLE pipe, const std::wstring& expectedSession,
	const std::wstring& projectDirectory, const std::wstring& expectedPlatform, bool x64,
	const std::atomic<bool>& stopRequested, Notification& notification, std::string& error)
{
	const ULONGLONG deadline = GetTickCount64() + 5000;
	std::array<uint8_t, 24> header{};
	if (!ReadExact(pipe, header.data(), header.size(), stopRequested, deadline))
	{
		error = "Build notification header was incomplete.";
		return false;
	}
	const uint32_t magic = ReadLe32(header.data());
	const uint32_t version = ReadLe32(header.data() + 4);
	const uint32_t sessionLength = ReadLe32(header.data() + 8);
	const uint32_t pathLength = ReadLe32(header.data() + 12);
	const uint32_t configurationLength = ReadLe32(header.data() + 16);
	const uint32_t platformLength = ReadLe32(header.data() + 20);
	const uint64_t totalUnits = static_cast<uint64_t>(sessionLength) + pathLength + configurationLength + platformLength;
	if (magic != kPipeMagic || version != kPipeVersion || !sessionLength || !pathLength ||
		!configurationLength || !platformLength || totalUnits > kMaxPayloadCodeUnits)
	{
		error = "Build notification has an invalid header or exceeds the 32768-code-unit limit.";
		return false;
	}
	std::vector<uint8_t> payload(static_cast<size_t>(totalUnits * sizeof(uint16_t)));
	if (!ReadExact(pipe, payload.data(), payload.size(), stopRequested, deadline))
	{
		error = "Build notification payload was incomplete or timed out.";
		return false;
	}
	DWORD available = 0;
	if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr))
	{
		const DWORD peekError = GetLastError();
		if (peekError != ERROR_BROKEN_PIPE && peekError != ERROR_NO_DATA)
		{
			error = "Could not verify the end of the build notification (Windows error " + std::to_string(peekError) + ").";
			return false;
		}
	}
	else if (available != 0)
	{
		error = "Build notification contained trailing data.";
		return false;
	}
	size_t offset = 0;
	notification.session = DecodeUtf16(payload.data() + offset, sessionLength);
	offset += static_cast<size_t>(sessionLength) * 2;
	notification.targetPath = DecodeUtf16(payload.data() + offset, pathLength);
	offset += static_cast<size_t>(pathLength) * 2;
	notification.configuration = DecodeUtf16(payload.data() + offset, configurationLength);
	offset += static_cast<size_t>(configurationLength) * 2;
	notification.platform = DecodeUtf16(payload.data() + offset, platformLength);
	if (!IsValidUtf16(notification.session) || !IsValidUtf16(notification.targetPath) ||
		!IsValidUtf16(notification.configuration) || !IsValidUtf16(notification.platform))
	{
		error = "Build notification contains invalid UTF-16 text.";
		return false;
	}
	if (notification.session != expectedSession)
	{
		error = "Build notification belongs to a different project session.";
		return false;
	}
	if ((notification.configuration != L"Debug" && notification.configuration != L"Release") ||
		notification.platform != expectedPlatform)
	{
		error = "Build configuration or platform does not match the generated project.";
		return false;
	}
	if (!std::filesystem::path(notification.targetPath).is_absolute())
	{
		error = "Build output path is not absolute.";
		return false;
	}
	const std::wstring expectedDll = (std::filesystem::path(projectDirectory) / L"bin" /
		expectedPlatform / notification.configuration / L"Hook.dll").wstring();
	if (!PathsEqual(notification.targetPath, expectedDll))
	{
		error = "Build output path is not the generated project's expected Hook.dll output.";
		return false;
	}
	notification.fileGuard = OpenValidatedDll(notification.targetPath, projectDirectory,
		expectedPlatform, notification.configuration, x64, error);
	return notification.fileGuard != nullptr;
}
}

HookPanel::HookPanel()
{
	const auto id = CreateSessionId();
	if (!id)
	{
		SetStatus("Could not create a unique hook project session identifier.");
		return;
	}
	sessionId = *id;
	pipeName = L"\\\\.\\pipe\\MemoryAnalyser.HookBuild." + sessionId;
	const std::wstring safeDirectory = GetSafeProjectDirectory(sessionId);
	const std::string utf8Directory = ToUtf8(safeDirectory);
	if (utf8Directory.empty() || utf8Directory.size() >= sizeof(outputDirectory))
	{
		SetStatus("LOCALAPPDATA is unavailable or the safe project path is too long. Enter a project directory manually.");
		return;
	}
	std::memcpy(outputDirectory, utf8Directory.data(), utf8Directory.size());
	outputDirectory[utf8Directory.size()] = '\0';
	SetStatus("Select a function, verify its exact entry point, then generate a dedicated hook project.");
}

HookPanel::~HookPanel()
{
	OnShutdown();
}

void HookPanel::Select(const HookTarget& target)
{
	if (shutdown)
		return;
	if (projectGenerated || buildProcessed)
	{
		SetStatus("This project session is locked to its original target and cannot be retargeted.");
		return;
	}
	const bool changed = !selectedTarget || selectedTarget->processId != target.processId ||
		selectedTarget->processCreation != target.processCreation || selectedTarget->modulePath != target.modulePath ||
		selectedTarget->rva != target.rva || selectedTarget->address != target.address;
	selectedTarget = target;
	if (changed)
		{
			confirmation = false;
			selectedProject = 0;
		}
		if (!projectGenerated)
			detached.store(false);
	SetStatus("Review the target details and confirm that this is the exact function entry before generating.");
}

void HookPanel::Render(MemoryManager* memory, TableStore& store)
{
	ImGui::SeparatorText("Function hook project");
	if (selectedTarget)
	{
		const HookTarget& target = *selectedTarget;
		ImGui::TextWrapped("Function: %s", target.name.c_str());
		ImGui::Text("Module: %s  RVA: 0x%llX  Address: 0x%llX",
			target.moduleName.c_str(), static_cast<unsigned long long>(target.rva),
			static_cast<unsigned long long>(target.address));
		ImGui::Text("PID: %lu  Architecture: %s", target.processId, target.x64 ? "x64" : "x86 (Win32)");
		if (memory && memory->GetAttachedProcessId() == target.processId)
			ImGui::TextDisabled("Attached target matches selected PID; build-time revalidation is still required.");
		else
			ImGui::TextDisabled("Attach to the selected process before generating a project.");
	}
	else if (projectGenerated && sessionTarget)
	{
		ImGui::TextDisabled("Locked session target: %s (PID %lu), RVA 0x%llX. It cannot be reused after detach.",
			sessionTarget->name.c_str(), sessionTarget->processId,
			static_cast<unsigned long long>(sessionTarget->rva));
	}
	else
	{
		ImGui::TextDisabled("Select a function entry from a verified static function report first.");
	}

	bool confirmed = confirmation;
	ImGui::Checkbox("I verified this address is the exact function entry (not an instruction inside it)", &confirmed);
	confirmation = confirmed;
	bool automatic = autoInject.load();
	ImGui::Checkbox("Automatically inject after a matching successful build", &automatic);
	autoInject.store(automatic);
	bool buildWaiting = false;
	{
		std::lock_guard<std::mutex> lock(stateMutex);
		buildWaiting = pendingBuild.has_value();
	}
	if (buildWaiting && !automatic)
		ImGui::TextWrapped("A build is held for injection. Enable automatic injection to proceed, or start a new session before loading.");
	ImGui::TextWrapped("Stop disables new detours but keeps the DLL and trampoline loaded for callbacks already in flight.");

	ImGui::SetNextItemWidth(-FLT_MIN);
	ImGui::InputTextWithHint("Visual Studio executable (UTF-8)", "Automatic: Visual Studio 2026 with C++ tools", visualStudioPath, sizeof(visualStudioPath));
	ImGui::TextDisabled("Specify another devenv.exe explicitly only if you want to use a different installation.");
	ImGui::SetNextItemWidth(-FLT_MIN);
	ImGui::InputText("Project directory (UTF-8)", outputDirectory, sizeof(outputDirectory));
	const auto* saved = selectedTarget ? store.FindFunction(*selectedTarget) : nullptr;
	const bool hasProjects = saved && !saved->projects.empty();
	if (hasProjects)
	{
		if (selectedProject < 0 || static_cast<size_t>(selectedProject) >= saved->projects.size()) selectedProject = 0;
		const std::string preview = ToUtf8(saved->projects[selectedProject]);
		if (ImGui::BeginCombo("Hook project", preview.c_str()))
		{
			for (size_t i = 0; i < saved->projects.size(); ++i)
			{
				ImGui::PushID(static_cast<int>(i));
				const std::string label = ToUtf8(saved->projects[i]);
				if (ImGui::Selectable(label.c_str(), selectedProject == static_cast<int>(i))) selectedProject = static_cast<int>(i);
				ImGui::PopID();
			}
			ImGui::EndCombo();
		}
	}
	const bool matchingProcess = selectedTarget && SameAttachedInstance(memory, *selectedTarget);
	ImGui::BeginDisabled(shutdown || projectGenerated || buildProcessed || !matchingProcess || !confirmation || sessionId.empty());
	if (ImGui::Button(hasProjects ? "Open existing project in Visual Studio" : "Create project and open Visual Studio"))
		GenerateAndLaunch(memory, store);
	if (hasProjects)
	{
		ImGui::SameLine();
		if (ImGui::Button("Add another project")) GenerateAndLaunch(memory, store, true);
		if (ImGui::Button("Relink selected project..."))
		{
			wchar_t path[32768]{};
			OPENFILENAMEW dialog{};
			dialog.lStructSize = sizeof(dialog);
			dialog.lpstrFilter = L"Hook solution (Hook.sln)\0Hook.sln\0\0";
			dialog.lpstrFile = path;
			dialog.nMaxFile = static_cast<DWORD>(std::size(path));
			dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
			if (GetOpenFileNameW(&dialog))
			{
				std::wstring solution;
				std::string error;
				if (_wcsicmp(std::filesystem::path(path).filename().c_str(), L"Hook.sln") != 0 ||
					!RevalidateHookTarget(*memory, *selectedTarget, error) ||
					!ReconnectProject(MakeProjectSpec(*selectedTarget, std::filesystem::path(path).parent_path().wstring(), sessionId, pipeName), solution, error))
					SetStatus("Project relink refused: " + error);
				else if (!store.ReplaceFunctionProject(*selectedTarget, static_cast<size_t>(selectedProject), solution) || !store.Save())
					SetStatus("Could not save the relinked project: " + store.LastError());
				else SetStatus("Project relinked. Open it to connect a fresh build session.");
			}
			else if (const DWORD code = CommDlgExtendedError())
				SetStatus("Project browser failed (Windows error " + std::to_string(code) + ").");
		}
	}
	ImGui::EndDisabled();
	if (!solutionPath.empty())
	{
		bool listenerAvailable = false;
		{
			std::lock_guard<std::mutex> lock(listenerMutex);
			listenerAvailable = listenerReady && !listenerFailed;
		}
		ImGui::SameLine();
		ImGui::BeginDisabled(!listenerAvailable);
		if (ImGui::Button("Open solution again"))
				OpenSolution();
		ImGui::EndDisabled();
	}
	if (!projectDirectory.empty())
	{
		const std::string path = ToUtf8(projectDirectory);
		ImGui::TextWrapped("Generated project: %s", path.c_str());
	}
	if (dllObserved)
		ImGui::Text("DLL status: observed in the original target process.");
	else if (loadAttempted)
		ImGui::Text("DLL status: load was attempted; outcome may be pending or uncertain.");
	else
		ImGui::TextDisabled("DLL status: not observed.");
	const char* hookStatus = "not started";
	switch (hookPhase)
	{
	case HookPhase::Starting: hookStatus = "activation pending"; break;
	case HookPhase::StartReturned: hookStatus = "active (target acknowledgement received)"; break;
	case HookPhase::Stopping: hookStatus = "stop pending"; break;
	case HookPhase::StopReturned: hookStatus = "disabled (target acknowledgement received; DLL retained)"; break;
	case HookPhase::Unknown: hookStatus = "failed or unknown"; break;
	default: break;
	}
	ImGui::Text("Hook status: %s", hookStatus);
	const bool canStop = sessionTarget && SameAttachedInstance(memory, *sessionTarget);
	ImGui::BeginDisabled(hookPhase != HookPhase::StartReturned || detached.load() || !canStop);
	if (ImGui::Button("Stop hook"))
	{
		std::string error;
		if (!PrepareHookStatus(2)) return;
		exportCall = RemoteExportCall::Start(memory->GetNativeHandle(), loadedDllPath, "StopHook", error);
		if (exportCall)
		{
			hookPhase = HookPhase::Stopping;
			SetStatus("Stop requested; waiting for the target to disable the hook.");
		}
		else
		{
			hookPhase = HookPhase::Unknown;
			SetStatus("Could not start StopHook; the hook may still be active: " + error);
		}
	}
	ImGui::EndDisabled();
	const bool canReset = projectGenerated && !libraryLoad && !exportCall && !callCompleted &&
		(!loadAttempted || hookPhase == HookPhase::StopReturned || targetExited);
	ImGui::SameLine();
	ImGui::BeginDisabled(!canReset);
	if (ImGui::Button("New hook session")) ResetSession();
	ImGui::EndDisabled();
	ImGui::TextWrapped("%s", GetStatus().c_str());
}

void HookPanel::Poll(MemoryManager* memory)
{
	if (shutdown)
		return;
	if (!targetExited && sessionProcess && WaitForSingleObject(sessionProcess.get(), 0) == WAIT_OBJECT_0)
	{
		targetExited = true;
		hookPhase = HookPhase::Unknown;
		SetStatus("The original target process exited. Its hook is gone; start a new session after pending observation completes.");
	}
	if (projectGenerated && sessionTarget &&
		!SameAttachedInstance(memory, *sessionTarget))
	{
		if (!detached.exchange(true))
		{
			selectedTarget.reset();
			confirmation = false;
			SetStatus("Target detached or changed. The prior session is never reused; pending load observation continues.");
		}
	}
	else if (sessionTarget && loadAttempted && SameAttachedInstance(memory, *sessionTarget))
	{
		detached.store(false);
	}

	if (libraryLoad)
	{
		std::string loadStatus;
		const LibraryLoader::State state = libraryLoad->Poll(loadStatus);
		if (state == LibraryLoader::State::Pending)
			return;
		libraryLoad.reset();
		if (state == LibraryLoader::State::ModuleObserved)
		{
			dllObserved = true;
			std::string error;
			if (detached.load() || !sessionTarget || !memory ||
				!RevalidateHookTarget(*memory, *sessionTarget, error))
			{
				hookPhase = HookPhase::Unknown;
				SetStatus("DLL observed, but target changed or detached before activation; StartHook was not called. " + error);
			}
			else
			{
				if (!PrepareHookStatus(1)) { hookPhase = HookPhase::Unknown; return; }
				exportCall = RemoteExportCall::Start(memory->GetNativeHandle(), loadedDllPath, "StartHook", error);
				if (exportCall)
				{
					hookPhase = HookPhase::Starting;
					SetStatus("DLL observed; waiting for StartHook to complete.");
				}
				else
				{
					hookPhase = HookPhase::Unknown;
					SetStatus("DLL observed, but StartHook could not be started: " + error);
				}
			}
		}
		else
		{
			hookPhase = HookPhase::Unknown;
			SetStatus("DLL load failed or is indeterminate: " + loadStatus + ". No retry will be attempted.");
		}
	}

	if (exportCall || callCompleted)
	{
		const bool stopping = hookPhase == HookPhase::Stopping;
		if (exportCall)
		{
			std::string callStatus;
			const auto result = exportCall->Poll(callExitCode, callStatus);
			if (result == RemoteExportCall::State::Failed)
			{
				exportCall.reset();
				callCompleted = false;
				hookPhase = HookPhase::Unknown;
				SetStatus("Remote hook call failed or is uncertain: " + callStatus + ". No retry will be attempted.");
				return;
			}
			if (result == RemoteExportCall::State::Completed)
			{
				exportCall.reset();
				callCompleted = true;
			}
		}
		auto acknowledged = static_cast<protocol::HookStatus*>(hookStatusView.get());
		const bool ready = acknowledged && InterlockedCompareExchange(&acknowledged->completed, 0, 0) == 1;
		if (callCompleted && ready)
		{
			callCompleted = false;
			if (!sessionTarget || acknowledged->magic != protocol::StatusMagic || acknowledged->version != 1 ||
				acknowledged->processId != sessionTarget->processId || acknowledged->action != (stopping ? 2u : 1u) ||
				acknowledged->result != ERROR_SUCCESS || callExitCode != ERROR_SUCCESS ||
				acknowledged->stage != (stopping ? 5u : 4u))
			{
				hookPhase = HookPhase::Unknown;
				SetStatus("Hook action did not succeed: target result " + std::to_string(acknowledged->result) +
					", stage " + std::to_string(acknowledged->stage) + ", MinHook status " +
					std::to_string(acknowledged->minHookStatus) + ". Hook state is uncertain; no retry will occur.");
			}
			else
			{
				hookPhase = stopping ? HookPhase::StopReturned : HookPhase::StartReturned;
				SetStatus(stopping ? "Target acknowledged disabling the hook. DLL and trampoline remain loaded." :
					"Target acknowledged enabling the hook. The function ABI remains your responsibility.");
			}
		}
		else if (GetTickCount64() >= exportDeadline)
		{
			exportCall.reset();
			callCompleted = false;
			hookPhase = HookPhase::Unknown;
			SetStatus("Hook acknowledgement timed out. The remote call is not cancelled; outcome remains unknown. No retry will occur.");
			return;
		}
		else return;
	}

	std::optional<BuildNotification> build;
	{
		std::lock_guard<std::mutex> lock(stateMutex);
		if (pendingBuild && autoInject.load())
		{
			build = std::move(pendingBuild);
			pendingBuild.reset();
		}
	}
	if (!build || buildProcessed)
		return;
	buildProcessed = true;
	if (detached.load() || !memory || !sessionTarget || memory->GetAttachedProcessId() != sessionTarget->processId)
	{
		SetStatus("Matching build arrived after the target detached or changed. Injection was refused and this session is locked.");
		return;
	}
	std::string validationError;
	if (!RevalidateHookTarget(*memory, *sessionTarget, validationError))
	{
		SetStatus("Target revalidation failed; injection refused and this session is locked: " + validationError);
		return;
	}
	if (!build->fileGuard)
	{
		SetStatus("The validated build output could not be held against replacement. Injection was refused.");
		return;
	}
	for (const auto& target : attemptedTargets)
	{
		if (target.processId == sessionTarget->processId && target.processCreation == sessionTarget->processCreation &&
			target.modulePath == sessionTarget->modulePath && target.rva == sessionTarget->rva)
		{
			SetStatus("This function already had a load attempt in this process instance. Restart the target before running it again.");
			return;
		}
	}
	loadAttempted = true;
	attemptedTargets.push_back(*sessionTarget);
	builtDllGuard = std::move(build->fileGuard);
	loadedDllPath = build->targetPath;
	std::string error;
	libraryLoad = LibraryLoader::Start(memory->GetNativeHandle(), loadedDllPath, error);
	if (!libraryLoad)
	{
		builtDllGuard.reset();
		SetStatus("Could not start the one permitted DLL load: " + error + ". Outcome is treated as uncertain; no retry will occur.");
		return;
	}
	SetStatus("Matching build verified; DLL load is pending. Hook activation is not yet confirmed.");
}

bool HookPanel::PrepareHookStatus(unsigned long action)
{
	if (!sessionTarget) { SetStatus("No hook session target for acknowledgement."); return false; }
	if (!hookStatusView)
	{
		SECURITY_ATTRIBUTES security{};
		PSECURITY_DESCRIPTOR descriptor = nullptr;
		if (!BuildSecurityAttributes(security, descriptor))
		{ SetStatus("Could not secure the hook acknowledgement channel."); return false; }
		const std::wstring name = L"Local\\MemoryAnalyser.HookStatus." + sessionId;
		HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0,
			sizeof(protocol::HookStatus), name.c_str());
		const DWORD code = GetLastError();
		LocalFree(descriptor);
		if (!mapping || code == ERROR_ALREADY_EXISTS)
		{
			if (mapping) CloseHandle(mapping);
			SetStatus("Could not create a unique hook acknowledgement channel (Windows error " + std::to_string(code) + ").");
			return false;
		}
		void* view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(protocol::HookStatus));
		if (!view) { CloseHandle(mapping); SetStatus("Could not map the hook acknowledgement channel."); return false; }
		hookStatusView = std::shared_ptr<void>(view, [mapping](void* address) { UnmapViewOfFile(address); CloseHandle(mapping); });
	}
	auto status = static_cast<protocol::HookStatus*>(hookStatusView.get());
	*status = { protocol::StatusMagic, 1, sessionTarget->processId, action, ERROR_IO_PENDING, 0, 0, 0 };
	callCompleted = false;
	callExitCode = 0;
	exportDeadline = GetTickCount64() + 15000;
	return true;
}

void HookPanel::OpenSolution()
{
	std::string error;
	if (!visualStudioPath[0])
	{
		std::wstring executable;
		if (!FindVisualStudio2026(executable, error)) { SetStatus(error); return; }
		const std::string utf8 = ToUtf8(executable);
		if (utf8.empty() || utf8.size() >= sizeof(visualStudioPath)) { SetStatus("Visual Studio path is invalid or too long."); return; }
		std::memcpy(visualStudioPath, utf8.c_str(), utf8.size() + 1);
	}
	const auto executable = FromUtf8(visualStudioPath);
	if (!executable || !OpenVisualStudio(*executable, solutionPath, error)) SetStatus(error.empty() ? "Invalid Visual Studio path." : error);
}

void HookPanel::OnDetach()
{
	detached.store(true);
	selectedTarget.reset();
	confirmation = false;
	if (!shutdown)
		SetStatus("Target detached. The prior session is not reused; any pending DLL load remains tracked.");
}

void HookPanel::OnShutdown()
{
	if (shutdown)
		return;
	shutdown = true;
	stopRequested.store(true);
	if (buildListener.joinable())
		buildListener.join();
	exportCall.reset();
	libraryLoad.reset();
	builtDllGuard.reset();
	{
		std::lock_guard<std::mutex> lock(stateMutex);
		pendingBuild.reset();
	}
}

void HookPanel::ResetSession()
{
	stopRequested.store(true);
	if (buildListener.joinable()) buildListener.join();
	{
		std::lock_guard<std::mutex> lock(stateMutex);
		pendingBuild.reset();
	}
	{
		std::lock_guard<std::mutex> lock(listenerMutex);
		listenerReady = false;
		listenerFailed = false;
	}
	builtDllGuard.reset();
	hookStatusView.reset();
	sessionProcess.reset();
	targetExited = false;
	selectedTarget.reset();
	sessionTarget.reset();
	solutionPath.clear();
	projectDirectory.clear();
	loadedDllPath.clear();
	projectGenerated = buildProcessed = loadAttempted = dllObserved = confirmation = callCompleted = false;
	selectedProject = 0;
	hookPhase = HookPhase::NotStarted;
	detached.store(false);
	stopRequested.store(false);
	sessionId.clear();
	pipeName.clear();
	outputDirectory[0] = '\0';
	const auto id = CreateSessionId();
	if (!id)
	{
		SetStatus("Could not create a new hook session identifier.");
		return;
	}
	sessionId = *id;
	pipeName = L"\\\\.\\pipe\\MemoryAnalyser.HookBuild." + sessionId;
	const std::string path = ToUtf8(GetSafeProjectDirectory(sessionId));
	if (path.empty() || path.size() >= sizeof(outputDirectory))
	{
		SetStatus("Enter an empty directory for the new hook project.");
		return;
	}
	std::memcpy(outputDirectory, path.c_str(), path.size() + 1);
	SetStatus("New session created. Select a function from a static report.");
}

void HookPanel::GenerateAndLaunch(MemoryManager* memory, TableStore& store, bool additional)
{
	if (shutdown || projectGenerated || buildProcessed || !selectedTarget || !memory || !confirmation ||
		memory->GetAttachedProcessId() != selectedTarget->processId)
	{
		SetStatus("Project generation refused: target, attachment, or explicit entry confirmation is missing.");
		return;
	}
	std::string validationError;
	if (!RevalidateHookTarget(*memory, *selectedTarget, validationError))
	{
		SetStatus("Target revalidation failed; project was not generated: " + validationError);
		return;
	}
	const auto* saved = store.FindFunction(*selectedTarget);
	const bool reuse = !additional && saved && !saved->projects.empty();
	std::wstring directory;
	if (reuse)
	{
		if (selectedProject < 0 || static_cast<size_t>(selectedProject) >= saved->projects.size()) selectedProject = 0;
		directory = std::filesystem::path(saved->projects[selectedProject]).parent_path().wstring();
	}
	else
	{
		const auto text = FromUtf8(outputDirectory);
		if (!text || text->empty()) { SetStatus("Enter a valid UTF-8 project directory."); return; }
		directory = *text;
	}
	const std::wstring fullDirectory = GetFullPath(directory);
	if (fullDirectory.empty()) { SetStatus("Could not resolve the project directory."); return; }
	std::error_code directoryError;
	if (std::filesystem::exists(fullDirectory, directoryError))
	{
		const DWORD attributes = GetFileAttributesW(fullDirectory.c_str());
		if (directoryError || attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
			(attributes & FILE_ATTRIBUTE_REPARSE_POINT))
		{ SetStatus("Project directory must be a normal directory, not a file or reparse point."); return; }
		if (!reuse)
		{
			const std::filesystem::directory_iterator entries(fullDirectory, directoryError);
			if (directoryError || entries != std::filesystem::directory_iterator{})
			{ SetStatus("New projects require an empty directory. Existing source will not be overwritten."); return; }
		}
	}
	else if (directoryError || reuse)
	{ SetStatus("Saved project directory is missing or inaccessible. Relink it, or explicitly add another project."); return; }
	const ProjectSpec spec = MakeProjectSpec(*selectedTarget, fullDirectory, sessionId, pipeName);
	std::wstring generatedSolution;
	std::string error;
	if (!(reuse ? ReconnectProject(spec, generatedSolution, error) : GenerateProject(spec, generatedSolution, error)))
	{ SetStatus("Could not prepare the hook project: " + error); return; }
	if (!reuse && (!store.AddFunctionProject(*selectedTarget, generatedSolution) || !store.Save()))
	{ SetStatus("Project created but its association could not be saved; automatic injection is not connected: " + store.LastError()); return; }
	const std::wstring absoluteSolution = GetFullPath(generatedSolution);
	const DWORD attributes = absoluteSolution.empty() ? INVALID_FILE_ATTRIBUTES : GetFileAttributesW(absoluteSolution.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
	{
		SetStatus("Project generation returned a missing or invalid solution path.");
		return;
	}
	HANDLE liveProcess = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, selectedTarget->processId);
	FILETIME creation{}, exit{}, kernel{}, user{};
	if (!liveProcess || !GetProcessTimes(liveProcess, &creation, &exit, &kernel, &user) ||
		((static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime) != selectedTarget->processCreation ||
		WaitForSingleObject(liveProcess, 0) != WAIT_TIMEOUT)
	{
		if (liveProcess) CloseHandle(liveProcess);
		SetStatus("Could not retain the verified target process lifetime. Project exists but automatic injection is not connected.");
		return;
	}
	sessionProcess = std::shared_ptr<void>(liveProcess, [](void* handle) { CloseHandle(handle); });
	targetExited = false;
	solutionPath = absoluteSolution;
	projectDirectory = fullDirectory;
	sessionTarget = selectedTarget;
	const std::wstring platform = selectedTarget->x64 ? L"x64" : L"Win32";
	projectGenerated = true;
	detached.store(false);
	SetStatus("Project generated. Waiting for one bounded build-completion notification.");
	try
	{
		buildListener = std::thread(&HookPanel::RunBuildListener, this, projectDirectory, platform);
	}
	catch (const std::exception& exception)
	{
		SetStatus("Project generated, but the build notification listener could not start: " + std::string(exception.what()));
		return;
	}
	bool listenerAvailable = false;
	{
		std::unique_lock<std::mutex> lock(listenerMutex);
		listenerCondition.wait_for(lock, std::chrono::seconds(5), [this]() {
			return listenerReady || listenerFailed || stopRequested.load();
		});
		listenerAvailable = listenerReady && !listenerFailed;
	}
	if (!listenerAvailable)
	{
		SetStatus("Project generated, but the protected build listener did not become ready; Visual Studio was not launched.");
		return;
	}
	OpenSolution();
}

void HookPanel::RunBuildListener(std::wstring expectedProjectDirectory, std::wstring expectedPlatform)
{
	auto updateListenerState = [this](bool ready, bool failed) {
		{
			std::lock_guard<std::mutex> lock(listenerMutex);
			listenerReady = ready;
			listenerFailed = listenerFailed || failed;
		}
		listenerCondition.notify_all();
	};
	SECURITY_ATTRIBUTES security{};
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!BuildSecurityAttributes(security, descriptor))
	{
		updateListenerState(false, true);
		SetStatus("Could not secure the local build notification pipe; automatic injection is disabled.");
		return;
	}
	bool firstInstance = true;
	bool notificationAccepted = false;
	while (!stopRequested.load())
	{
		const DWORD access = PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED |
			(firstInstance ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0);
		HANDLE pipe = CreateNamedPipeW(pipeName.c_str(), access,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			1, 0, 0, 0, &security);
		if (pipe == INVALID_HANDLE_VALUE)
		{
			updateListenerState(false, !stopRequested.load());
			if (!stopRequested.load())
				SetStatus("Could not create the protected build pipe (Windows error " + std::to_string(GetLastError()) + ").");
			break;
		}
		updateListenerState(true, false);
		firstInstance = false;
		if (!ConnectPipe(pipe, stopRequested))
		{
			DisconnectNamedPipe(pipe);
			CloseHandle(pipe);
			updateListenerState(false, !stopRequested.load());
			if (!stopRequested.load())
				SetStatus(notificationAccepted
					? "Build pipe stopped after accepting a notification; that first notification remains authoritative."
					: "Build pipe accept failed; the listener stopped and no injection will occur.");
			break;
		}
		DWORD clientProcessId = 0;
		DWORD clientSession = 0;
		DWORD currentSession = 0;
		std::string error;
		bool acceptedTransport = GetNamedPipeClientProcessId(pipe, &clientProcessId) != FALSE && clientProcessId != 0 &&
			ProcessIdToSessionId(clientProcessId, &clientSession) != FALSE &&
			ProcessIdToSessionId(GetCurrentProcessId(), &currentSession) != FALSE && clientSession == currentSession;
		BuildNotification notification;
		bool valid = acceptedTransport && ReadBuildMessage(pipe, sessionId, expectedProjectDirectory,
			expectedPlatform, sessionTarget ? sessionTarget->x64 : false, stopRequested, notification, error);
		if (!acceptedTransport)
			error = "Build notification client is not in this local Windows session.";
		DisconnectNamedPipe(pipe);
		CloseHandle(pipe);
		if (stopRequested.load())
			break;
		if (!valid)
		{
			SetStatus(notificationAccepted
				? "Later invalid build notification ignored; the first valid notification remains authoritative: " + error
				: "Build notification rejected; no injection will occur: " + error);
			if (!notificationAccepted)
				break;
			continue;
		}
		if (!notificationAccepted)
		{
			bool duplicate = false;
			{
				std::lock_guard<std::mutex> lock(stateMutex);
				duplicate = pendingBuild.has_value();
				if (!duplicate)
					pendingBuild = std::move(notification);
			}
			if (duplicate)
			{
				SetStatus("Duplicate build notification rejected; the first notification remains authoritative.");
				continue;
			}
			notificationAccepted = true;
			SetStatus("One matching build notification was accepted and queued for target revalidation.");
		}
		else
		{
			SetStatus("Duplicate build notification rejected; this session will never inject more than once.");
		}
	}
	updateListenerState(false, false);
	LocalFree(descriptor);
}

void HookPanel::SetStatus(std::string text)
{
	std::lock_guard<std::mutex> lock(stateMutex);
	status = std::move(text);
}

std::string HookPanel::GetStatus() const
{
	std::lock_guard<std::mutex> lock(stateMutex);
	return status;
}
}