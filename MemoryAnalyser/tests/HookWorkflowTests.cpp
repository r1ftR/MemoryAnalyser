#include "../analyser/Hooking/Project.h"
#include "../analyser/Hooking/ProjectProtocol.h"
#include "../analyser/Hooking/HookTarget.h"
#include "../analyser/StaticResolver/StaticFinder.h"
#include "../MemoryManager/MemoryManager.h"
#include "../MemoryManager/LibraryLoader.h"
#include "../MemoryManager/RemoteExportCall.h"

#include <Windows.h>
#include <objbase.h>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

using namespace analyser::hooking;

#pragma optimize("", off)
extern "C" __declspec(dllexport) __declspec(noinline) int WINAPI WorkflowFixture(int value)
{
	volatile int result = value + 1;
	return result;
}
#pragma optimize("", on)

namespace
{
struct FixtureState
{
	volatile LONG ready = 0, command = 0, result = 0;
	std::uint64_t address = 0;
};

int RunFixtureHost(const wchar_t* name)
{
	HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
	if (!mapping) return 20;
	auto state = static_cast<FixtureState*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(FixtureState)));
	if (!state) { CloseHandle(mapping); return 20; }
	state->address = reinterpret_cast<std::uintptr_t>(&WorkflowFixture);
	InterlockedExchange(&state->ready, 1);
	for (;;)
	{
		const LONG command = InterlockedCompareExchange(&state->command, 0, 0);
		if (command == 2) break;
		if (command == 1)
		{
			int (WINAPI* volatile fixture)(int) = &WorkflowFixture;
			state->result = fixture(1);
			InterlockedExchange(&state->command, 0);
		}
		Sleep(5);
	}
	UnmapViewOfFile(state); CloseHandle(mapping);
	return 0;
}

struct FixtureHost
{
	HANDLE mapping = nullptr, process = nullptr;
	FixtureState* state = nullptr;
	std::wstring module = L"HookWorkflowTests.exe";
	std::filesystem::path executable;
	~FixtureHost()
	{
		if (state) InterlockedExchange(&state->command, 2);
		if (process)
		{
			if (WaitForSingleObject(process, 5000) != WAIT_OBJECT_0) TerminateProcess(process, ERROR_TIMEOUT);
			CloseHandle(process);
		}
		if (state) UnmapViewOfFile(state);
		if (mapping) CloseHandle(mapping);
		if (!executable.empty()) DeleteFileW(executable.c_str());
	}
	bool Start(const wchar_t* source)
	{
		module = L"WorkflowTarget" + std::to_wstring(GetCurrentProcessId()) + L".exe";
		executable = std::filesystem::absolute(std::filesystem::path(L"MemoryAnalyser\\tests\\build") / module);
		if (!CopyFileW(source, executable.c_str(), TRUE)) return false;
		const std::wstring name = L"Local\\HookWorkflowFixture" + std::to_wstring(GetCurrentProcessId());
		mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(FixtureState), name.c_str());
		if (!mapping) return false;
		state = static_cast<FixtureState*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(FixtureState)));
		if (!state) return false;
		*state = {};
		std::wstring command = L"\"" + executable.wstring() + L"\" --fixture-host \"" + name + L"\"";
		STARTUPINFOW startup{}; startup.cb = sizeof(startup);
		PROCESS_INFORMATION info{};
		if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &info)) return false;
		CloseHandle(info.hThread); process = info.hProcess;
		const ULONGLONG deadline = GetTickCount64() + 10000;
		while (GetTickCount64() < deadline)
		{
			if (InterlockedCompareExchange(&state->ready, 0, 0) == 1) return true;
			if (WaitForSingleObject(process, 5) == WAIT_OBJECT_0) return false;
		}
		return false;
	}
	int Evaluate()
	{
		if (!state) { int (WINAPI* volatile fixture)(int) = &WorkflowFixture; return fixture(1); }
		InterlockedExchange(&state->command, 1);
		const ULONGLONG deadline = GetTickCount64() + 10000;
		while (GetTickCount64() < deadline)
		{
			if (InterlockedCompareExchange(&state->command, 0, 0) == 0) return state->result;
			if (WaitForSingleObject(process, 5) == WAIT_OBJECT_0) return -1;
		}
		return -1;
	}
};

int failures = 0;
void Check(bool condition, const char* name)
{
	std::printf("%s: %s\n", name, condition ? "PASS" : "FAIL");
	if (!condition) ++failures;
}
std::string Read(const std::filesystem::path& path)
{
	std::ifstream input(path, std::ios::binary);
	return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}
bool Write(const std::filesystem::path& path, const std::string& text)
{
	std::ofstream output(path, std::ios::binary | std::ios::trunc);
	output << text;
	output.close();
	return !output.fail();
}
DWORD Build(const std::wstring& msbuild, const std::wstring& solution, bool x64)
{
	std::wstring command = L"\"" + msbuild + L"\" \"" + solution + L"\" /nologo /m /v:minimal /p:VisualStudioVersion=18.0 /p:Configuration=Debug /p:Platform=" + (x64 ? L"x64" : L"x86");
	STARTUPINFOW startup{}; startup.cb = sizeof(startup);
	PROCESS_INFORMATION process{};
	if (!CreateProcessW(msbuild.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &process)) return GetLastError();
	CloseHandle(process.hThread);
	if (WaitForSingleObject(process.hProcess, 240000) != WAIT_OBJECT_0)
	{
		TerminateProcess(process.hProcess, ERROR_TIMEOUT);
		CloseHandle(process.hProcess);
		return ERROR_TIMEOUT;
	}
	DWORD code = 1;
	GetExitCodeProcess(process.hProcess, &code);
	CloseHandle(process.hProcess);
	return code;
}
bool FailedBuildDoesNotNotify(const ProjectSpec& spec, const std::wstring& msbuild, const std::wstring& solution)
{
	HANDLE pipe = CreateNamedPipeW(spec.pipeName.c_str(), PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 0, 65536, 0, nullptr);
	if (pipe == INVALID_HANDLE_VALUE) return false;
	OVERLAPPED operation{};
	operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
	if (!operation.hEvent) { CloseHandle(pipe); return false; }
	const BOOL connected = ConnectNamedPipe(pipe, &operation);
	const DWORD connectError = GetLastError();
	const DWORD code = Build(msbuild, solution, spec.x64);
	DWORD count = 0;
	const BOOL delivered = GetOverlappedResult(pipe, &operation, &count, FALSE);
	const DWORD error = GetLastError();
	CancelIoEx(pipe, &operation);
	GetOverlappedResult(pipe, &operation, &count, TRUE);
	CloseHandle(operation.hEvent); CloseHandle(pipe);
	return !connected && connectError == ERROR_IO_PENDING && code != 0 && code != ERROR_TIMEOUT &&
		!delivered && error == ERROR_IO_INCOMPLETE;
}
bool Invoke(MemoryManager& memory, const std::wstring& dll, const char* name, DWORD expected)
{
	std::string error, status;
	auto call = RemoteExportCall::Start(memory.GetNativeHandle(), dll, name, error);
	if (!call) { std::printf("Remote call refused: %s\n", error.c_str()); return false; }
	DWORD code = 0;
	const ULONGLONG deadline = GetTickCount64() + 15000;
	while (GetTickCount64() < deadline)
	{
		const auto state = call->Poll(code, status);
		if (state != RemoteExportCall::State::Pending)
			return state == RemoteExportCall::State::Completed && code == expected;
		Sleep(10);
	}
	return false;
}
}

int wmain(int argc, wchar_t** argv)
{
	if (argc == 3 && std::wstring(argv[1]) == L"--fixture-host") return RunFixtureHost(argv[2]);
	if (argc != 2 && argc != 3) { std::puts("Usage: HookWorkflowTests.exe <MSBuild.exe> [x86 fixture executable]"); return 2; }
	FixtureHost host;
	if (argc == 3 && !host.Start(argv[2])) { std::puts("Could not launch controlled x86 fixture"); return 2; }
	MemoryManager memory(host.module.c_str(), host.module.c_str());
	analyser::FunctionStaticReport report;
	report.inModule = true;
	for (wchar_t ch : host.module) report.moduleName.push_back(static_cast<char>(ch));
	report.targetName = "WorkflowFixture";
	report.targetAddress = host.state ? static_cast<uintptr_t>(host.state->address) : reinterpret_cast<uintptr_t>(&WorkflowFixture);
	report.rva = report.targetAddress - memory.GetBaseAddress();
	HookTarget target;
	std::string error;
	if (!ValidateHookTarget(memory, report, target, error))
	{
		std::printf("Validation failed: %s (PID %lu address %llX base %llX)\n", error.c_str(), memory.GetAttachedProcessId(),
			static_cast<unsigned long long>(report.targetAddress), static_cast<unsigned long long>(memory.GetBaseAddress()));
		for (const auto& module : memory.EnumerateModules())
			std::printf("Module %ls base %llX size %zX path %ls\n", module.name.c_str(), static_cast<unsigned long long>(module.base), module.size, module.path.c_str());
		return 3;
	}
	GUID guid{};
	if (FAILED(CoCreateGuid(&guid))) return 4;
	wchar_t text[40]{};
	StringFromGUID2(guid, text, 40);
	ProjectSpec spec{};
	spec.directory = std::filesystem::absolute(std::filesystem::path(L"MemoryAnalyser\\tests\\build") / (L"workflow-project-" + std::to_wstring(GetCurrentProcessId()))).wstring();
	spec.moduleName = host.module;
	spec.rva = target.rva; spec.x64 = target.x64;
	spec.sessionId = std::wstring(text + 1, 36);
	spec.pipeName = L"\\\\.\\pipe\\MemoryAnalyser.HookBuild." + spec.sessionId;
	spec.modulePath = target.modulePath; spec.volumeSerial = target.volumeSerial; spec.fileId = target.fileId;
	spec.fileSize = target.fileSize; spec.fileLastWrite = target.fileLastWrite; spec.imageSize = target.imageSize;
	spec.imageTimestamp = target.imageTimestamp; spec.imageChecksum = target.imageChecksum;
	spec.imageMachine = target.imageMachine; spec.originalBytes = target.originalBytes;
	std::wstring solution;
	Check(GenerateProject(spec, solution, error), "Generate persistent hook project");
	if (failures) { std::printf("%s\n", error.c_str()); return 5; }
	const std::filesystem::path dir(spec.directory);
	std::string source = Read(dir / L"Hook.cpp");
	const size_t begin = source.find("#error Define TargetFunction");
	const size_t end = source.find("static constexpr wchar_t moduleName");
	if (begin == std::string::npos || end == std::string::npos) return 6;
	source.replace(begin, end - begin, "using TargetFunction = int (WINAPI*)(int);\nstatic TargetFunction original = nullptr;\nstatic int WINAPI Detour(int value) { return original(value) + 100; }\n\n");
	Check(Write(dir / L"Hook.cpp", source), "Supply controlled fixture ABI and detour");
	const std::string edited = Read(dir / L"Hook.cpp"), project = Read(dir / L"Hook.vcxproj"), firstHeader = Read(dir / L"HookSession.h");
	Check(!GenerateProject(spec, solution, error), "Generation refuses overwriting an existing project");
	CoCreateGuid(&guid); StringFromGUID2(guid, text, 40);
	spec.sessionId = std::wstring(text + 1, 36);
	spec.pipeName = L"\\\\.\\pipe\\MemoryAnalyser.HookBuild." + spec.sessionId;
	Check(ReconnectProject(spec, solution, error), "Reconnect same function after analyser restart");
	Check(Read(dir / L"Hook.cpp") == edited && Read(dir / L"Hook.vcxproj") == project, "Reconnect preserves user source and project edits");
	Check(Read(dir / L"HookSession.h") != firstHeader, "Reconnect rotates the compiled acknowledgement session");
	auto changed = spec; ++changed.rva;
	Check(!ReconnectProject(changed, solution, error), "Changed function identity cannot reuse solution");
	changed = spec; ++changed.imageTimestamp;
	Check(!ReconnectProject(changed, solution, error), "Changed module build cannot reuse solution");
	Check(ReconnectProject(spec, solution, error), "Restore current session after rejected reuse");
	Check(Read(dir / L"Hook.sln").find(spec.x64 ? "|x86" : "|x64") == std::string::npos, "Solution defaults to target architecture only");
	std::wstring visualStudio;
	const bool found = FindVisualStudio2026(visualStudio, error);
	if (!found) std::printf("Visual Studio discovery: %s\n", error.c_str());
	Check(found && visualStudio.find(L"\\18\\") != std::wstring::npos, "Discover Visual Studio 2026 explicitly");
	if (failures) return 7;
	std::string failingProject = project;
	const size_t closing = failingProject.rfind("</Project>");
	if (closing == std::string::npos) return 7;
	failingProject.insert(closing, "<Target Name=\"ExpectedTestFailure\" AfterTargets=\"Link\"><Error Text=\"Expected post-link test failure\" /></Target>\n");
	Check(Write(dir / L"Hook.vcxproj", failingProject), "Install controlled post-link failure");
	Check(FailedBuildDoesNotNotify(spec, argv[1], solution), "Post-link build failure sends no successful-build notification");
	Check(Write(dir / L"Hook.vcxproj", project) && Write(dir / L"Hook.cpp", edited + "\n"), "Restore project and force a fresh successful link");
	if (failures) return 7;

	HANDLE pipe = CreateNamedPipeW(spec.pipeName.c_str(), PIPE_ACCESS_INBOUND,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 0, 65536, 0, nullptr);
	if (pipe == INVALID_HANDLE_VALUE) return 8;
	std::vector<unsigned char> message;
	std::thread reader([&] {
		if (!ConnectNamedPipe(pipe, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) return;
		unsigned char buffer[65536]; DWORD count = 0;
		while (ReadFile(pipe, buffer, sizeof(buffer), &count, nullptr) && count) message.insert(message.end(), buffer, buffer + count);
	});
	const DWORD buildCode = Build(argv[1], solution, spec.x64);
	CancelSynchronousIo(reader.native_handle());
	reader.join(); CloseHandle(pipe);
	Check(buildCode == 0, "Build edited generated project");
	if (buildCode != 0) return 9;
	Check(message.size() >= sizeof(protocol::Header), "Successful build delivers a real completion notification");
	if (message.size() >= sizeof(protocol::Header))
	{
		protocol::Header header{}; std::memcpy(&header, message.data(), sizeof(header));
		Check(header.magic == protocol::Magic && header.version == protocol::Version && header.sessionLength == 36,
			"Build notification protocol and session are correct");
	}
	const std::wstring dll = (dir / L"bin" / (spec.x64 ? L"x64" : L"Win32") / L"Debug" / L"Hook.dll").wstring();
	auto loader = LibraryLoader::Start(memory.GetNativeHandle(), dll, error);
	Check(loader != nullptr, "Inject generated DLL into controlled process");
	if (!loader) { std::printf("%s\n", error.c_str()); return 10; }
	LibraryLoader::State state = LibraryLoader::State::Pending;
	const ULONGLONG deadline = GetTickCount64() + 15000;
	while (state == LibraryLoader::State::Pending && GetTickCount64() < deadline) { state = loader->Poll(error); Sleep(10); }
	Check(state == LibraryLoader::State::ModuleObserved, "Injected module is observed");
	loader.reset();
	if (state != LibraryLoader::State::ModuleObserved) return 11;
	const std::wstring mappingName = L"Local\\MemoryAnalyser.HookStatus." + spec.sessionId;
	HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(protocol::HookStatus), mappingName.c_str());
	if (!mapping) return 12;
	auto status = static_cast<protocol::HookStatus*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(protocol::HookStatus)));
	if (!status) { CloseHandle(mapping); return 12; }
	*status = {0, 1, target.processId, 1, ERROR_IO_PENDING, 0, 0, 0};
	Check(Invoke(memory, dll, "StartHook", ERROR_INVALID_DATA) && status->completed == 0, "Invalid acknowledgement session refuses activation");
	*status = {protocol::StatusMagic, 1, target.processId, 1, ERROR_IO_PENDING, 0, 0, 0};
	Check(Invoke(memory, dll, "StartHook", ERROR_SUCCESS), "StartHook returns success");
	Check(InterlockedCompareExchange(&status->completed, 0, 0) == 1 && status->result == 0 && status->stage == 4,
		"Independent activation acknowledgement received");
	Check(host.Evaluate() == 102, "Detour visibly changes function behavior");
	*status = {protocol::StatusMagic, 1, target.processId, 2, ERROR_IO_PENDING, 0, 0, 0};
	Check(Invoke(memory, dll, "StopHook", ERROR_SUCCESS), "StopHook returns success");
	Check(InterlockedCompareExchange(&status->completed, 0, 0) == 1 && status->result == 0 && status->stage == 5,
		"Independent stop acknowledgement received");
	Check(host.Evaluate() == 2, "Stop restores original function behavior");
	UnmapViewOfFile(status); CloseHandle(mapping);
	std::printf("Test project artifacts: %ls\n", spec.directory.c_str());
	return failures ? 1 : 0;
}
