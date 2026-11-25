#include "Project.h"
#include "ProjectProtocol.h"

#include <Windows.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <vector>

namespace analyser::hooking
{
namespace
{
	const char* const solution = R"SLN(Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("{BC8A1FFA-BEE3-4634-8014-F334798102B3}") = "Hook", "Hook.vcxproj", "{D0B99A79-404D-4659-95B6-A55D4F6A7474}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|x86 = Debug|x86
		Release|x86 = Release|x86
		Debug|x64 = Debug|x64
		Release|x64 = Release|x64
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{D0B99A79-404D-4659-95B6-A55D4F6A7474}.Debug|x86.ActiveCfg = Debug|Win32
		{D0B99A79-404D-4659-95B6-A55D4F6A7474}.Debug|x86.Build.0 = Debug|Win32
		{D0B99A79-404D-4659-95B6-A55D4F6A7474}.Release|x86.ActiveCfg = Release|Win32
		{D0B99A79-404D-4659-95B6-A55D4F6A7474}.Release|x86.Build.0 = Release|Win32
		{D0B99A79-404D-4659-95B6-A55D4F6A7474}.Debug|x64.ActiveCfg = Debug|x64
		{D0B99A79-404D-4659-95B6-A55D4F6A7474}.Debug|x64.Build.0 = Debug|x64
		{D0B99A79-404D-4659-95B6-A55D4F6A7474}.Release|x64.ActiveCfg = Release|x64
		{D0B99A79-404D-4659-95B6-A55D4F6A7474}.Release|x64.Build.0 = Release|x64
	EndGlobalSection
EndGlobal
)SLN";

	const char* const project = R"XML(<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
	<ProjectConfiguration Include="Debug|Win32"><Configuration>Debug</Configuration><Platform>Win32</Platform></ProjectConfiguration>
	<ProjectConfiguration Include="Release|Win32"><Configuration>Release</Configuration><Platform>Win32</Platform></ProjectConfiguration>
	<ProjectConfiguration Include="Debug|x64"><Configuration>Debug</Configuration><Platform>x64</Platform></ProjectConfiguration>
	<ProjectConfiguration Include="Release|x64"><Configuration>Release</Configuration><Platform>x64</Platform></ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals"><ProjectGuid>{D0B99A79-404D-4659-95B6-A55D4F6A7474}</ProjectGuid><Keyword>Win32Proj</Keyword><WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion></PropertyGroup>
  <Import Project="HookSession.props" />
  <PropertyGroup><Platform Condition="'$(Platform)'==''">@PLATFORM@</Platform></PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Label="Configuration"><ConfigurationType>DynamicLibrary</ConfigurationType><PlatformToolset Condition="'$(VisualStudioVersion)'=='18.0'">v145</PlatformToolset><PlatformToolset Condition="'$(VisualStudioVersion)'!='18.0'">v143</PlatformToolset><CharacterSet>Unicode</CharacterSet></PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)'=='Debug'"><UseDebugLibraries>true</UseDebugLibraries></PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)'=='Release'"><UseDebugLibraries>false</UseDebugLibraries></PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup><OutDir>$(ProjectDir)bin\$(Platform)\$(Configuration)\</OutDir><IntDir>$(ProjectDir)obj\$(Platform)\$(Configuration)\</IntDir></PropertyGroup>
  <ItemDefinitionGroup>
	<ClCompile><WarningLevel>Level3</WarningLevel><LanguageStandard>stdcpp17</LanguageStandard><AdditionalIncludeDirectories>$(ProjectDir)deps\minhook\include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories></ClCompile>
	<Link><AdditionalDependencies>Psapi.lib;%(AdditionalDependencies)</AdditionalDependencies></Link>
  </ItemDefinitionGroup>
  <ItemGroup>
	<ClCompile Include="Hook.cpp" />
	<ClCompile Include="deps\minhook\src\buffer.c" />
	<ClCompile Include="deps\minhook\src\hook.c"><ObjectFileName>$(IntDir)minhook_hook.obj</ObjectFileName></ClCompile>
	<ClCompile Include="deps\minhook\src\trampoline.c" />
	<ClCompile Include="deps\minhook\src\hde\hde32.c" Condition="'$(Platform)'=='Win32'" />
	<ClCompile Include="deps\minhook\src\hde\hde64.c" Condition="'$(Platform)'=='x64'" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <!-- MinHook v1.3.4, pinned to its immutable upstream commit. -->
  <UsingTask TaskName="RestorePinnedMinHook" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
	<ParameterGroup><Destination ParameterType="System.String" Required="true" /></ParameterGroup>
	<Task>
	  <Using Namespace="System" /><Using Namespace="System.IO" /><Using Namespace="System.IO.Compression" /><Using Namespace="System.Net" />
	  <Code Type="Fragment" Language="cs"><![CDATA[
		try {
		  string[] files = { "LICENSE.txt", "include/MinHook.h", "src/buffer.c", "src/buffer.h", "src/hook.c", "src/trampoline.c", "src/trampoline.h", "src/hde/hde32.c", "src/hde/hde32.h", "src/hde/hde64.c", "src/hde/hde64.h", "src/hde/pstdint.h", "src/hde/table32.h", "src/hde/table64.h" };
		  bool missing = false;
		  foreach (string file in files) if (!File.Exists(Path.Combine(Destination, file.Replace('/', Path.DirectorySeparatorChar)))) missing = true;
		  if (missing) {
			Log.LogMessage(Microsoft.Build.Framework.MessageImportance.High, "Restoring pinned MinHook v1.3.4 source...");
			using (var client = new WebClient()) {
			  client.Headers.Add("User-Agent", "HookProjectBuild");
			  byte[] bytes = client.DownloadData("https://codeload.github.com/TsudaKageyu/minhook/zip/c3fcafdc10146beb5919319d0683e44e3c30d537");
			  using (var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read)) {
				foreach (string file in files) {
				  var entry = archive.GetEntry("minhook-c3fcafdc10146beb5919319d0683e44e3c30d537/" + file);
				  if (entry == null) throw new Exception("Missing MinHook archive entry: " + file);
				  string path = Path.Combine(Destination, file.Replace('/', Path.DirectorySeparatorChar));
				  if (File.Exists(path)) continue;
				  Directory.CreateDirectory(Path.GetDirectoryName(path));
				  using (var input = entry.Open()) using (var output = new FileStream(path, FileMode.CreateNew)) input.CopyTo(output);
				}
			  }
			}
		  }
		} catch (Exception ex) { Log.LogError("MinHook restore failed: " + ex.Message); return false; }
	  ]]></Code>
	</Task>
  </UsingTask>
  <Target Name="RestoreHookDependency" BeforeTargets="ClCompile"><RestorePinnedMinHook Destination="$(ProjectDir)deps\minhook" /></Target>
  <UsingTask TaskName="CaptureHookTimestamp" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
	<ParameterGroup><Target ParameterType="System.String" Required="true" /><Timestamp ParameterType="System.String" Output="true" /></ParameterGroup>
	<Task><Using Namespace="System.IO" /><Code Type="Fragment" Language="cs"><![CDATA[
	  Timestamp = File.Exists(Target) ? File.GetLastWriteTimeUtc(Target).Ticks.ToString() : "0";
	]]></Code></Task>
  </UsingTask>
  <Target Name="CaptureBeforeHookLink" BeforeTargets="Link"><PropertyGroup><HookPreviousTimestamp>unavailable</HookPreviousTimestamp></PropertyGroup><CaptureHookTimestamp Target="$(TargetPath)" ContinueOnError="WarnAndContinue"><Output TaskParameter="Timestamp" PropertyName="HookPreviousTimestamp" /></CaptureHookTimestamp></Target>
  <UsingTask TaskName="NotifyHookBuild" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
	<ParameterGroup><Target ParameterType="System.String" Required="true" /><PreviousTimestamp ParameterType="System.String" /><Configuration ParameterType="System.String" Required="true" /><Platform ParameterType="System.String" Required="true" /><Session ParameterType="System.String" Required="true" /><Pipe ParameterType="System.String" Required="true" /></ParameterGroup>
	<Task>
	  <Using Namespace="System" /><Using Namespace="System.IO" /><Using Namespace="System.IO.Pipes" /><Using Namespace="System.Text" />
	  <Code Type="Fragment" Language="cs"><![CDATA[
		try {
		  if (String.IsNullOrEmpty(PreviousTimestamp) || PreviousTimestamp == "unavailable") { Log.LogWarning("Hook notification skipped: link timestamp unavailable"); return true; }
		  if (!File.Exists(Target) || File.GetLastWriteTimeUtc(Target).Ticks.ToString() == PreviousTimestamp) return true;
		  string session = Encoding.Unicode.GetString(Convert.FromBase64String(Session));
		  string pipeName = Encoding.Unicode.GetString(Convert.FromBase64String(Pipe));
		  string path = Path.GetFullPath(Target);
		  string[] values = { session, path, Configuration, Platform };
		  int count = 0;
		  foreach (string value in values) count = checked(count + value.Length);
		  if (count > 32768) throw new Exception("Notification payload is too large");
		  using (var memory = new MemoryStream()) using (var writer = new BinaryWriter(memory, Encoding.Unicode)) {
			writer.Write(0x4B4F4F48u); writer.Write(1u);
			foreach (string value in values) writer.Write((uint)value.Length);
			foreach (string value in values) writer.Write(Encoding.Unicode.GetBytes(value));
			writer.Flush();
			using (var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.Out, PipeOptions.Asynchronous)) {
			  pipe.Connect(250);
			  byte[] bytes = memory.ToArray();
			  var write = pipe.WriteAsync(bytes, 0, bytes.Length);
			  if (!write.Wait(1000)) throw new TimeoutException("Pipe write timed out");
			  write.GetAwaiter().GetResult();
			}
		  }
		} catch (Exception ex) { Log.LogWarning("Hook build notification was not delivered: " + ex.Message); }
	  ]]></Code>
	</Task>
  </UsingTask>
  <Target Name="NotifyHookBuildComplete" AfterTargets="Build">
	<NotifyHookBuild Target="$(TargetPath)" PreviousTimestamp="$(HookPreviousTimestamp)" Configuration="$(Configuration)" Platform="$(Platform)" Session="$(HookSession)" Pipe="$(HookPipe)" ContinueOnError="WarnAndContinue" />
  </Target>
</Project>
)XML";

	const char* const hook = R"CPP(#include <Windows.h>
#include <Psapi.h>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <vector>
#include <MinHook.h>
#include "HookSession.h"

// Replace this block with the exact return type, calling convention and
// parameters established for the target. Implement Detour with the same ABI,
// and call original only when appropriate. Do not guess the declaration.
#error Define TargetFunction and Detour for the verified target ABI, then remove this error.
// using TargetFunction = ...;
// TargetFunction original = nullptr;
// ... Detour(...) { ... }

static constexpr wchar_t moduleName[] = { @MODULE@, 0 };
static constexpr wchar_t modulePath[] = { @PATH@, 0 };
static constexpr std::uint64_t targetRva = 0x@RVA@ULL;
static constexpr DWORD expectedImageSize = @IMAGESIZE@u, expectedTimestamp = @TIMESTAMP@u, expectedChecksum = @CHECKSUM@u;
static constexpr WORD expectedMachine = @MACHINE@u;
static constexpr DWORD expectedVolume = @VOLUME@u;
static constexpr std::uint64_t expectedFileId = @FILEID@ULL, expectedFileSize = @FILESIZE@ULL, expectedWrite = @FILEWRITE@ULL;
static constexpr unsigned char expectedBytes[16] = { @BYTES@ };

#if @X64@
#ifndef _WIN64
#error This project was generated for an x64 target; build x64.
#endif
#else
#ifdef _WIN64
#error This project was generated for an x86 target; build Win32.
#endif
#pragma comment(linker, "/EXPORT:StartHook=_StartHook@0")
#pragma comment(linker, "/EXPORT:StopHook=_StopHook@0")
#endif

static void* installedTarget = nullptr;
static DWORD hookStage = 0;
static MH_STATUS lastMinHookStatus = MH_OK;

static DWORD StartHookImpl()
{
	hookStage = 1;
	if (installedTarget) return ERROR_ALREADY_EXISTS;
	HANDLE process = GetCurrentProcess();
	std::vector<HMODULE> modules(256);
	DWORD needed = 0;
	for (;;) {
		if (!EnumProcessModules(process, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &needed)) return GetLastError();
		if (needed <= modules.size() * sizeof(HMODULE)) break;
		if (needed > 65536 * sizeof(HMODULE)) return ERROR_BUFFER_OVERFLOW;
		modules.resize((needed + sizeof(HMODULE) - 1) / sizeof(HMODULE));
	}
	HMODULE found = nullptr;
	wchar_t name[32768];
	for (size_t i = 0; i < needed / sizeof(HMODULE); ++i) {
		DWORD n = GetModuleBaseNameW(process, modules[i], name, static_cast<DWORD>(std::size(name)));
		if (!n || n >= std::size(name) - 1) return ERROR_INVALID_DATA;
		if (_wcsicmp(name, moduleName) == 0) {
			if (found) return ERROR_DUP_NAME;
			found = modules[i];
		}
	}
	if (!found) return ERROR_MOD_NOT_FOUND;
	HMODULE module = nullptr;
	if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(found), &module)) return ERROR_MOD_NOT_FOUND;
	struct ModuleRef { HMODULE value; ~ModuleRef() { if (value) FreeLibrary(value); } } ref{module};
	if (module != found) return ERROR_MOD_NOT_FOUND;
	DWORD length = GetModuleFileNameW(module, name, static_cast<DWORD>(std::size(name)));
	if (!length || length >= std::size(name) - 1 || _wcsicmp(name, modulePath) != 0) return ERROR_REVISION_MISMATCH;
	HANDLE file = CreateFileW(name, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE) return ERROR_REVISION_MISMATCH;
	BY_HANDLE_FILE_INFORMATION fi{};
	BOOL gotFile = GetFileInformationByHandle(file, &fi);
	CloseHandle(file);
	auto pair64 = [](DWORD high, DWORD low) { return (std::uint64_t(high) << 32) | low; };
	if (!gotFile || fi.dwVolumeSerialNumber != expectedVolume || pair64(fi.nFileIndexHigh, fi.nFileIndexLow) != expectedFileId ||
		pair64(fi.nFileSizeHigh, fi.nFileSizeLow) != expectedFileSize || pair64(fi.ftLastWriteTime.dwHighDateTime, fi.ftLastWriteTime.dwLowDateTime) != expectedWrite) return ERROR_REVISION_MISMATCH;
	MODULEINFO info{};
	if (!GetModuleInformation(process, module, &info, sizeof(info))) return GetLastError();
	if (info.SizeOfImage != expectedImageSize || expectedImageSize < sizeof(IMAGE_DOS_HEADER) ||
		targetRva > expectedImageSize || expectedImageSize - targetRva < sizeof(expectedBytes) ||
		targetRva > UINTPTR_MAX - reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll)) return ERROR_INVALID_ADDRESS;
	auto base = reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll);
	auto readImage = [&](std::uint64_t offset, void* output, size_t count) {
		SIZE_T read = 0;
		return offset <= expectedImageSize && count <= expectedImageSize - offset && offset <= UINTPTR_MAX - base &&
			ReadProcessMemory(process, reinterpret_cast<void*>(base + static_cast<std::uintptr_t>(offset)), output, count, &read) && read == count;
	};
	IMAGE_DOS_HEADER dos{};
	IMAGE_NT_HEADERS nt{};
	if (!readImage(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0 ||
		!readImage(static_cast<std::uint64_t>(dos.e_lfanew), &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE ||
		nt.FileHeader.SizeOfOptionalHeader < sizeof(nt.OptionalHeader) || nt.FileHeader.Machine != expectedMachine ||
		nt.FileHeader.TimeDateStamp != expectedTimestamp || nt.OptionalHeader.SizeOfImage != expectedImageSize ||
		nt.OptionalHeader.CheckSum != expectedChecksum || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return ERROR_REVISION_MISMATCH;
	auto target = reinterpret_cast<void*>(base + static_cast<std::uintptr_t>(targetRva));
	MEMORY_BASIC_INFORMATION memory{};
	if (!VirtualQuery(target, &memory, sizeof(memory)) || memory.State != MEM_COMMIT || memory.AllocationBase != info.lpBaseOfDll ||
		(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
		!(memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return ERROR_INVALID_ADDRESS;
	unsigned char actual[sizeof(expectedBytes)];
	if (!readImage(targetRva, actual, sizeof(actual)) || std::memcmp(actual, expectedBytes, sizeof(actual)) != 0) return ERROR_REVISION_MISMATCH;
	hookStage = 2;
	lastMinHookStatus = MH_Initialize();
	if (lastMinHookStatus != MH_OK) return ERROR_DLL_INIT_FAILED;
	hookStage = 3;
	lastMinHookStatus = MH_CreateHook(target, reinterpret_cast<void*>(&Detour), reinterpret_cast<void**>(&original));
	if (lastMinHookStatus != MH_OK) { MH_Uninitialize(); return ERROR_INVALID_FUNCTION; }
	hookStage = 4;
	lastMinHookStatus = MH_EnableHook(target);
	if (lastMinHookStatus != MH_OK) { MH_RemoveHook(target); MH_Uninitialize(); return ERROR_INVALID_FUNCTION; }
	installedTarget = target;
	ref.value = nullptr;
	return ERROR_SUCCESS;
}

static DWORD StopHookImpl()
{
	hookStage = 5;
	if (!installedTarget) return ERROR_NOT_READY;
	lastMinHookStatus = MH_DisableHook(installedTarget);
	if (lastMinHookStatus != MH_OK) return ERROR_INVALID_FUNCTION;
	// Keep the DLL, target module and trampoline alive for callbacks already in flight.
	installedTarget = nullptr;
	return ERROR_SUCCESS;
}

static DWORD RunHookAction(DWORD action)
{
	HANDLE mapping = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, hookStatusName);
	if (!mapping) return ERROR_INVALID_HANDLE;
	auto status = static_cast<HookStatus*>(MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(HookStatus)));
	if (!status) { CloseHandle(mapping); return ERROR_INVALID_HANDLE; }
	if (status->magic != 0x48535432 || status->version != 1 || status->processId != GetCurrentProcessId() ||
		status->action != action || InterlockedCompareExchange(&status->completed, 0, 0) != 0) {
		UnmapViewOfFile(status); CloseHandle(mapping); return ERROR_INVALID_DATA;
	}
	lastMinHookStatus = MH_OK;
	DWORD result = action == 1 ? StartHookImpl() : StopHookImpl();
	status->result = result;
	status->stage = hookStage;
	status->minHookStatus = static_cast<LONG>(lastMinHookStatus);
	InterlockedExchange(&status->completed, 1);
	UnmapViewOfFile(status);
	CloseHandle(mapping);
	return result;
}

extern "C" __declspec(dllexport) DWORD WINAPI StartHook() { return RunHookAction(1); }
extern "C" __declspec(dllexport) DWORD WINAPI StopHook() { return RunHookAction(2); }

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
)CPP";

	const char* const readme = R"TXT(Hook project
============
This is a template, not a ready-to-inject hook. Edit Hook.cpp: determine the
correct function ABI and define TargetFunction, original and Detour, then
remove the #error. Build the target architecture in Visual Studio 2022 or 2026
with the corresponding C++ toolset and Windows SDK. The first build needs internet access to
restore MinHook v1.3.4 source at commit c3fcafdc10146beb5919319d0683e44e3c30d537.
The included MinHook license is restored to deps\minhook\LICENSE.txt.

Build while the original analyser session is connected to inject automatically.
The analyser invokes StartHook outside DllMain and requires a separate target
acknowledgement. Loading alone does not install a hook. Keep HookSession.h and
the generated StartHook/StopHook wrappers; standalone activation requires a
matching status mapping. Reopening through the analyser updates only the
session header and props, preserving your source. Reload changes when prompted.
The hook DLL must remain loaded. Before installation StartHook checks a unique
module basename, recorded path and file identity, PE metadata, image bounds,
executable page and original bytes. These checks are not a cryptographic proof
and can race with other code patching or replacing the module. They cannot
prove the function ABI. StopHook disables future detours but retains the DLL,
target module and trampoline because callbacks may still be executing. Do not
unload until application-specific quiescence has been established.

After a successful build an MSBuild task sends a bounded binary message
to the original session's local named pipe. If the analyser is absent, a
warning is logged and the build succeeds. Incremental builds that do not link
do not send a notification. No delivery acknowledgement is available.
)TXT";

	void replaceAll(std::string& value, const std::string& from, const std::string& to)
	{
		std::size_t pos = 0;
		while ((pos = value.find(from, pos)) != std::string::npos) { value.replace(pos, from.size(), to); pos += to.size(); }
	}

	std::string base64(const std::wstring& value)
	{
		static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		std::vector<unsigned char> bytes;
		for (wchar_t c : value) { bytes.push_back(static_cast<unsigned char>(c & 0xff)); bytes.push_back(static_cast<unsigned char>((c >> 8) & 0xff)); }
		std::string result;
		for (std::size_t i = 0; i < bytes.size(); i += 3)
		{
			unsigned v = static_cast<unsigned>(bytes[i]) << 16;
			if (i + 1 < bytes.size()) v |= static_cast<unsigned>(bytes[i + 1]) << 8;
			if (i + 2 < bytes.size()) v |= bytes[i + 2];
			result += alphabet[(v >> 18) & 63]; result += alphabet[(v >> 12) & 63];
			result += i + 1 < bytes.size() ? alphabet[(v >> 6) & 63] : '=';
			result += i + 2 < bytes.size() ? alphabet[v & 63] : '=';
		}
		return result;
	}

	std::string sessionHeader(const ProjectSpec& spec)
	{
		std::ostringstream name;
		name << std::hex;
		for (wchar_t ch : L"Local\\MemoryAnalyser.HookStatus." + spec.sessionId)
			name << "0x" << static_cast<unsigned short>(ch) << ", ";
		return "#pragma once\n#include <Windows.h>\nstruct HookStatus { DWORD magic, version, processId, action, result, stage; LONG minHookStatus; volatile LONG completed; };\n"
			"static_assert(sizeof(HookStatus) == 32, \"Unexpected status size\");\nstatic constexpr wchar_t hookStatusName[] = { " + name.str() + "0 };\n";
	}

	std::string sessionProps(const ProjectSpec& spec)
	{
		std::wstring pipe = spec.pipeName;
		const std::wstring prefix = L"\\\\.\\pipe\\";
		if (pipe.compare(0, prefix.size(), prefix) == 0) pipe.erase(0, prefix.size());
		return "<Project xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\"><PropertyGroup><HookSession>" +
			base64(spec.sessionId) + "</HookSession><HookPipe>" + base64(pipe) + "</HookPipe></PropertyGroup></Project>\n";
	}

	std::string projectIdentity(const ProjectSpec& spec)
	{
		std::ostringstream value;
		value << "MemoryAnalyser.HookProject.2\n" << base64(spec.modulePath) << '\n' << base64(spec.moduleName) << '\n'
			<< spec.rva << ' ' << spec.x64 << ' ' << spec.volumeSerial << ' ' << spec.fileId << ' '
			<< spec.fileSize << ' ' << spec.fileLastWrite << ' ' << spec.imageSize << ' ' << spec.imageTimestamp << ' '
			<< spec.imageChecksum << ' ' << spec.imageMachine << '\n';
		for (auto byte : spec.originalBytes) value << static_cast<unsigned>(byte) << ' ';
		return value.str();
	}

	bool writeNew(const std::filesystem::path& path, const std::string& text, std::string& error)
	{
		HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE) { error = "Cannot create project file (already exists or access denied), Windows error " + std::to_string(GetLastError()); return false; }
		DWORD written = 0;
		bool ok = text.size() <= (std::numeric_limits<DWORD>::max)() && WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) && written == text.size();
		DWORD code = ok ? 0 : GetLastError();
		if (!CloseHandle(file) && ok) { ok = false; code = GetLastError(); }
		if (!ok) { DeleteFileW(path.c_str()); error = "Cannot write project file, Windows error " + std::to_string(code); }
		return ok;
	}
}

bool GenerateProject(const ProjectSpec& spec, std::wstring& solutionPath, std::string& error)
{
	solutionPath.clear(); error.clear();
	try
	{
		std::wstring pipe = spec.pipeName;
		const std::wstring prefix = L"\\\\.\\pipe\\";
		if (pipe.compare(0, prefix.size(), prefix) == 0) pipe.erase(0, prefix.size());
		if (spec.directory.empty() || spec.moduleName.empty() || spec.sessionId.empty() || pipe.empty() ||
			spec.directory.find(L'\0') != std::wstring::npos || spec.moduleName.find(L'\0') != std::wstring::npos ||
			spec.sessionId.find(L'\0') != std::wstring::npos || pipe.find_first_of(L"\\/\0", 0, 3) != std::wstring::npos ||
			spec.sessionId.size() > protocol::MaxPayloadCodeUnits / 2 || pipe.size() > 256)
		{ error = "Invalid directory, module, session ID or local pipe name"; return false; }
		if (spec.modulePath.empty() || spec.modulePath.find(L'\0') != std::wstring::npos ||
			spec.moduleName.find_first_of(L"\\/") != std::wstring::npos || spec.imageSize < 16 ||
			spec.rva > spec.imageSize - 16 || spec.imageMachine != (spec.x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386) ||
			std::all_of(spec.originalBytes.begin(), spec.originalBytes.end(), [](std::uint8_t b) { return b == 0; }))
		{ error = "Missing or invalid target identity, machine, image size or original bytes"; return false; }
		auto dir = std::filesystem::absolute(spec.directory).lexically_normal();
		std::error_code ec;
		std::filesystem::create_directories(dir, ec);
		if (ec) { error = "Cannot create project directory: " + ec.message(); return false; }
		std::ostringstream module, rva;
		module << std::hex << std::uppercase;
		for (wchar_t ch : spec.moduleName) module << "0x" << static_cast<unsigned short>(ch) << ", ";
		std::string moduleText = module.str(); moduleText.resize(moduleText.size() - 2);
		rva << std::hex << std::uppercase << spec.rva;
		std::string source = hook;
		std::ostringstream pathText, bytes;
		pathText << std::hex << std::uppercase;
		for (wchar_t ch : spec.modulePath) pathText << "0x" << static_cast<unsigned short>(ch) << ", ";
		std::string pathArray = pathText.str(); pathArray.resize(pathArray.size() - 2);
		for (std::uint8_t b : spec.originalBytes) bytes << static_cast<unsigned>(b) << ", ";
		std::string bytesArray = bytes.str(); bytesArray.resize(bytesArray.size() - 2);
		replaceAll(source, "@MODULE@", moduleText); replaceAll(source, "@PATH@", pathArray);
		replaceAll(source, "@RVA@", rva.str()); replaceAll(source, "@X64@", spec.x64 ? "1" : "0");
		replaceAll(source, "@IMAGESIZE@", std::to_string(spec.imageSize)); replaceAll(source, "@TIMESTAMP@", std::to_string(spec.imageTimestamp));
		replaceAll(source, "@CHECKSUM@", std::to_string(spec.imageChecksum)); replaceAll(source, "@MACHINE@", std::to_string(spec.imageMachine));
		replaceAll(source, "@VOLUME@", std::to_string(spec.volumeSerial)); replaceAll(source, "@FILEID@", std::to_string(spec.fileId));
		replaceAll(source, "@FILESIZE@", std::to_string(spec.fileSize)); replaceAll(source, "@FILEWRITE@", std::to_string(spec.fileLastWrite));
		replaceAll(source, "@BYTES@", bytesArray);
		std::string xml = project;
		replaceAll(xml, "@PLATFORM@", spec.x64 ? "x64" : "Win32");
		std::istringstream solutionLines(solution);
		std::string targetSolution, line;
		while (std::getline(solutionLines, line))
		{
			if (line.find(spec.x64 ? "|x86" : "|x64") == std::string::npos) targetSolution += line + '\n';
		}
		const std::pair<const wchar_t*, std::string> files[] = {
			{L"Hook.sln", targetSolution}, {L"Hook.vcxproj", xml}, {L"Hook.cpp", source}, {L"README.txt", readme},
			{L"HookSession.h", sessionHeader(spec)}, {L"HookSession.props", sessionProps(spec)},
			{L"Hook.identity", projectIdentity(spec)} };
		std::vector<std::filesystem::path> created;
		for (const auto& file : files)
		{
			auto path = dir / file.first;
			if (!writeNew(path, file.second, error)) { for (const auto& p : created) DeleteFileW(p.c_str()); return false; }
			created.push_back(std::move(path));
		}
		solutionPath = (dir / L"Hook.sln").wstring();
		return true;
	}
	catch (const std::exception& e) { error = e.what(); return false; }
}

bool ReconnectProject(const ProjectSpec& spec, std::wstring& solutionPath, std::string& error)
{
	solutionPath.clear();
	error.clear();
	if (spec.sessionId.size() != 36 || spec.pipeName != L"\\\\.\\pipe\\MemoryAnalyser.HookBuild." + spec.sessionId)
	{ error = "Invalid hook session configuration."; return false; }
	const std::filesystem::path dir(spec.directory);
	for (const auto* file : { L"Hook.sln", L"Hook.vcxproj", L"Hook.cpp", L"HookSession.h", L"HookSession.props", L"Hook.identity" })
	{
		const DWORD attributes = GetFileAttributesW((dir / file).c_str());
		if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)))
		{ error = "Missing or unsafe project file. Relink a compatible project or explicitly add another; no source was overwritten."; return false; }
	}
	std::ifstream identity(dir / L"Hook.identity", std::ios::binary);
	std::string expected = projectIdentity(spec), actual(expected.size() + 1, '\0');
	identity.read(actual.data(), static_cast<std::streamsize>(actual.size()));
	actual.resize(static_cast<size_t>(identity.gcount()));
	if (actual != expected)
	{ error = "Project target identity differs from the verified function. Add a new project for this module build; existing source is preserved."; return false; }
	for (const auto& file : { std::pair<const wchar_t*, std::string>{L"HookSession.h", sessionHeader(spec)},
		std::pair<const wchar_t*, std::string>{L"HookSession.props", sessionProps(spec)} })
	{
		const auto target = dir / file.first;
		const auto temporary = dir / (std::wstring(file.first) + L"." + spec.sessionId + L".tmp");
		if (!writeNew(temporary, file.second, error)) return false;
		if (!MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		{
			error = "Could not update project session configuration (Windows error " + std::to_string(GetLastError()) + ").";
			DeleteFileW(temporary.c_str());
			return false;
		}
	}
	solutionPath = (dir / L"Hook.sln").wstring();
	return true;
}

bool FindVisualStudio2026(std::wstring& executable, std::string& error)
{
	executable.clear();
	wchar_t programFiles[32768]{};
	DWORD length = GetEnvironmentVariableW(L"ProgramFiles(x86)", programFiles, static_cast<DWORD>(std::size(programFiles)));
	if (!length || length >= std::size(programFiles))
	{ error = "Cannot locate the Visual Studio Installer. Specify devenv.exe explicitly."; return false; }
	const auto vswhere = std::filesystem::path(programFiles) / L"Microsoft Visual Studio" / L"Installer" / L"vswhere.exe";
	SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
	HANDLE read = nullptr, write = nullptr;
	if (!CreatePipe(&read, &write, &security, 32768))
	{ error = "Cannot create Visual Studio discovery pipe."; return false; }
	if (!SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0))
	{ CloseHandle(read); CloseHandle(write); error = "Cannot secure Visual Studio discovery pipe."; return false; }
	STARTUPINFOW startup{};
	startup.cb = sizeof(startup);
	startup.dwFlags = STARTF_USESTDHANDLES;
	startup.hStdOutput = write;
	startup.hStdError = write;
	startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	PROCESS_INFORMATION process{};
	std::wstring command = L"\"" + vswhere.wstring() + L"\" -latest -products * -version [18.0,19.0) -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find Common7\\IDE\\devenv.exe -utf8";
	BOOL launched = CreateProcessW(vswhere.c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
	CloseHandle(write);
	if (!launched)
	{ CloseHandle(read); error = "Cannot run vswhere to locate Visual Studio 2026. Specify devenv.exe explicitly."; return false; }
	CloseHandle(process.hThread);
	std::string output;
	const ULONGLONG deadline = GetTickCount64() + 5000;
	bool finished = false;
	while (GetTickCount64() < deadline)
	{
		DWORD available = 0;
		if (!PeekNamedPipe(read, nullptr, 0, nullptr, &available, nullptr)) break;
		if (available)
		{
			char buffer[4096]; DWORD count = 0;
			if (!ReadFile(read, buffer, (std::min)(available, static_cast<DWORD>(sizeof(buffer))), &count, nullptr)) break;
			output.append(buffer, count);
			if (output.size() > 32768) break;
			continue;
		}
		if (finished) break;
		if (WaitForSingleObject(process.hProcess, 10) == WAIT_OBJECT_0) finished = true;
	}
	DWORD code = 1;
	if (!finished) finished = WaitForSingleObject(process.hProcess, 100) == WAIT_OBJECT_0;
	if (finished) GetExitCodeProcess(process.hProcess, &code);
	else TerminateProcess(process.hProcess, ERROR_TIMEOUT);
	CloseHandle(process.hProcess);
	CloseHandle(read);
	if (!finished || code != 0)
	{ error = "Visual Studio 2026 discovery failed or timed out. Specify devenv.exe explicitly."; return false; }
	const size_t end = output.find_first_of("\r\n");
	if (end != std::string::npos) output.resize(end);
	int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, output.data(), static_cast<int>(output.size()), nullptr, 0);
	if (count <= 0)
	{ error = "Visual Studio 2026 with C++ tools was not found. Install it or explicitly select another devenv.exe."; return false; }
	executable.resize(count);
	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, output.data(), static_cast<int>(output.size()), executable.data(), count);
	if (GetFileAttributesW(executable.c_str()) == INVALID_FILE_ATTRIBUTES)
	{ executable.clear(); error = "Discovered Visual Studio executable is missing."; return false; }
	return true;
}

bool OpenVisualStudio(const std::wstring& executable, const std::wstring& solutionPath, std::string& error)
{
	if (executable.empty() || executable.find(L'\"') != std::wstring::npos || solutionPath.find(L'\"') != std::wstring::npos ||
		_wcsicmp(std::filesystem::path(executable).filename().c_str(), L"devenv.exe") != 0)
	{ error = "Choose a valid Visual Studio devenv.exe path."; return false; }
	std::wstring command = L"\"" + executable + L"\" \"" + solutionPath + L"\"";
	STARTUPINFOW startup{}; startup.cb = sizeof(startup);
	PROCESS_INFORMATION process{};
	if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &process))
	{ error = "Could not open Visual Studio (Windows error " + std::to_string(GetLastError()) + ")."; return false; }
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	return true;
}
}
