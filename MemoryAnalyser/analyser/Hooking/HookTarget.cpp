#include "HookTarget.h"

#include "../StaticResolver/StaticFinder.h"
#include "../../MemoryManager/MemoryManager.h"

#include <cstddef>
#include <limits>
#include <utility>

namespace analyser::hooking
{
namespace
{
struct Handle
{
	HANDLE value = nullptr;
	~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
	Handle(const Handle&) = delete;
	Handle& operator=(const Handle&) = delete;
	Handle() = default;
};

bool Fail(std::string& error, const char* message)
{
	error = message;
	return false;
}

bool WinFail(std::string& error, const char* message, DWORD code)
{
	error = std::string(message) + " (Windows error " + std::to_string(code) + ")";
	return false;
}

bool CreationTime(HANDLE process, uint64_t& result, std::string& error)
{
	FILETIME creation{}, exit{}, kernel{}, user{};
	if (!GetProcessTimes(process, &creation, &exit, &kernel, &user))
		return WinFail(error, "Could not query process creation time", GetLastError());
	result = (static_cast<uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
	if (!result) return Fail(error, "Invalid process creation time");
	return true;
}

bool CheckLive(HANDLE process, std::string& error)
{
	const DWORD wait = WaitForSingleObject(process, 0);
	if (wait == WAIT_TIMEOUT) return true;
	if (wait == WAIT_OBJECT_0) return Fail(error, "Target process has exited");
	return WinFail(error, "Could not check target process state", GetLastError());
}

bool ProcessIdentity(MemoryManager& memory, Handle& live, DWORD& pid, uint64_t& creation,
	std::string& error)
{
	const HANDLE attached = memory.GetNativeHandle();
	if (!attached || attached == INVALID_HANDLE_VALUE)
		return Fail(error, "No attached process handle");
	pid = GetProcessId(attached);
	if (!pid) return WinFail(error, "Could not query attached process ID", GetLastError());
	if (pid != memory.GetAttachedProcessId())
		return Fail(error, "Attached process ID does not match its handle");
	if (!CreationTime(attached, creation, error)) return false;
	live.value = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!live.value) return WinFail(error, "Could not open target process for identity verification", GetLastError());
	uint64_t liveCreation = 0;
	if (!CreationTime(live.value, liveCreation, error)) return false;
	if (creation != liveCreation) return Fail(error, "Target process identity changed");
	return CheckLive(live.value, error);
}

bool Architecture(HANDLE process, bool& x64, std::string& error)
{
	using IsWow64Process2Fn = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
	const HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	if (!kernel) return WinFail(error, "Could not access kernel32", GetLastError());
	const auto query = reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(kernel, "IsWow64Process2"));
	if (query)
	{
		USHORT processMachine = 0, nativeMachine = 0;
		if (!query(process, &processMachine, &nativeMachine))
			return WinFail(error, "Could not query target architecture", GetLastError());
		const USHORT machine = processMachine == IMAGE_FILE_MACHINE_UNKNOWN ? nativeMachine : processMachine;
		if (machine == IMAGE_FILE_MACHINE_I386) x64 = false;
		else if (machine == IMAGE_FILE_MACHINE_AMD64) x64 = true;
		else return Fail(error, "Target architecture is not supported (only x86 and x64)");
	}
	else
	{
		BOOL wow64 = FALSE;
		if (!IsWow64Process(process, &wow64))
			return WinFail(error, "Could not query target architecture", GetLastError());
		SYSTEM_INFO info{};
		GetNativeSystemInfo(&info);
		if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) x64 = false;
		else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) x64 = !wow64;
		else return Fail(error, "Cannot determine x86/x64 target architecture on this system");
	}
	if (x64 && sizeof(uintptr_t) < 8)
		return Fail(error, "A 32-bit analyser cannot validate a 64-bit target");
	return true;
}

bool ModuleName(const std::string& name, std::wstring& wide, std::string& error)
{
	if (name.empty() || name.find('\0') != std::string::npos ||
		name.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
		return Fail(error, "Invalid report module name");
	const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(),
		static_cast<int>(name.size()), nullptr, 0);
	if (!length) return WinFail(error, "Invalid UTF-8 module name", GetLastError());
	wide.resize(static_cast<size_t>(length));
	if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(),
		static_cast<int>(name.size()), &wide[0], length))
		return WinFail(error, "Could not convert module name", GetLastError());
	if (wide.find_first_of(L"\\/:") != std::wstring::npos)
		return Fail(error, "Module name must be a base name");
	return true;
}

bool FindModule(DWORD pid, const std::string& name, MODULEENTRY32W& found, std::string& error)
{
	std::wstring wide;
	if (!ModuleName(name, wide, error)) return false;
	Handle snapshot;
	for (int attempt = 0; attempt < 8; ++attempt)
	{
		snapshot.value = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (snapshot.value != INVALID_HANDLE_VALUE) break;
		const DWORD code = GetLastError();
		if (code != ERROR_BAD_LENGTH || attempt == 7)
			return WinFail(error, "Could not enumerate target modules", code);
	}
	MODULEENTRY32W entry{};
	entry.dwSize = sizeof(entry);
	if (!Module32FirstW(snapshot.value, &entry))
		return WinFail(error, "Could not read target module list", GetLastError());
	bool matched = false;
	do
	{
		const int comparison = CompareStringOrdinal(wide.c_str(), static_cast<int>(wide.size()),
			entry.szModule, -1, TRUE);
		if (!comparison) return WinFail(error, "Could not compare module names", GetLastError());
		if (comparison == CSTR_EQUAL)
		{
			if (matched && (found.modBaseAddr != entry.modBaseAddr || found.modBaseSize != entry.modBaseSize ||
				_wcsicmp(found.szExePath, entry.szExePath) != 0))
				return Fail(error, "Module name is ambiguous in the target process");
			found = entry;
			matched = true;
		}
	} while (Module32NextW(snapshot.value, &entry));
	const DWORD code = GetLastError();
	if (code != ERROR_NO_MORE_FILES) return WinFail(error, "Could not finish enumerating target modules", code);
	if (!matched) return Fail(error, "Target module is not loaded");
	return true;
}

bool CheckLocation(MemoryManager& memory, DWORD pid, const std::string& moduleName,
	uint64_t rva, uintptr_t address, MODULEENTRY32W& module, std::string& error)
{
	if (!address) return Fail(error, "Target address is zero");
	module = {};
	if (!FindModule(pid, moduleName, module, error)) return false;
	const uintptr_t base = reinterpret_cast<uintptr_t>(module.modBaseAddr);
	if (!base || !module.modBaseSize) return Fail(error, "Target module has an invalid range");
	const uintptr_t maxAddress = (std::numeric_limits<uintptr_t>::max)();
	if (static_cast<uint64_t>(module.modBaseSize - 1) > static_cast<uint64_t>(maxAddress - base))
		return Fail(error, "Target module address range overflows");
	if (rva >= module.modBaseSize || rva > static_cast<uint64_t>(maxAddress - base))
		return Fail(error, "Target RVA is outside the module or overflows");
	if (base + static_cast<uintptr_t>(rva) != address)
		return Fail(error, "Module and RVA do not resolve to the target address");

	MEMORY_BASIC_INFORMATION page{};
	if (!VirtualQueryEx(memory.GetNativeHandle(), reinterpret_cast<LPCVOID>(address), &page, sizeof(page)))
		return WinFail(error, "Could not query target memory page", GetLastError());
	if (page.State != MEM_COMMIT || page.Type != MEM_IMAGE ||
		reinterpret_cast<uintptr_t>(page.AllocationBase) != base)
		return Fail(error, "Target is not in the loaded module image allocation");
	if (page.Protect & (PAGE_GUARD | PAGE_NOACCESS))
		return Fail(error, "Target page is guarded or inaccessible");
	const DWORD protection = page.Protect & 0xff;
	if (protection != PAGE_EXECUTE && protection != PAGE_EXECUTE_READ &&
		protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY)
		return Fail(error, "Target page is not executable");
	return true;
}

struct PeIdentity
{
	uint16_t machine = 0;
	uint32_t timestamp = 0;
	uint32_t size = 0;
	uint32_t checksum = 0;
};

template<typename Reader>
bool ReadPeIdentity(Reader read, uint64_t limit, PeIdentity& pe, std::string& error)
{
	IMAGE_DOS_HEADER dos{};
	if (limit < sizeof(dos) || !read(0, &dos, sizeof(dos)) ||
		dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)))
		return Fail(error, "Could not read a valid module DOS header");
	const uint64_t nt = static_cast<uint32_t>(dos.e_lfanew);
	const uint64_t prefix = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	if (nt > limit || prefix > limit - nt)
		return Fail(error, "Module PE header is out of bounds");
	DWORD signature = 0;
	IMAGE_FILE_HEADER file{};
	if (!read(nt, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
		!read(nt + sizeof(signature), &file, sizeof(file)))
		return Fail(error, "Could not read a valid module PE header");
	const uint64_t optional = nt + prefix;
	constexpr size_t required = offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum) + sizeof(DWORD);
	if (file.SizeOfOptionalHeader < required || optional > limit || required > limit - optional)
		return Fail(error, "Module optional header is out of bounds");
	IMAGE_OPTIONAL_HEADER32 opt{};
	if (!read(optional, &opt, required)) return Fail(error, "Could not read module optional header");
	if ((file.Machine == IMAGE_FILE_MACHINE_I386 && opt.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) ||
		(file.Machine == IMAGE_FILE_MACHINE_AMD64 && opt.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
		(file.Machine != IMAGE_FILE_MACHINE_I386 && file.Machine != IMAGE_FILE_MACHINE_AMD64))
		return Fail(error, "Unsupported or inconsistent module PE architecture");
	pe.machine = file.Machine;
	pe.timestamp = file.TimeDateStamp;
	pe.size = opt.SizeOfImage;
	pe.checksum = opt.CheckSum;
	return true;
}

uint64_t FileTimeValue(const FILETIME& time)
{
	return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

bool CaptureIdentity(MemoryManager& memory, const MODULEENTRY32W& module,
	HookTarget& target, std::string& error)
{
	const uintptr_t base = reinterpret_cast<uintptr_t>(module.modBaseAddr);
	const uint64_t moduleSize = module.modBaseSize;
	if (target.rva >= moduleSize || target.originalBytes.size() > moduleSize - target.rva)
		return Fail(error, "Not enough image bytes at the target address");
	Handle file;
	file.value = CreateFileW(module.szExePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file.value == INVALID_HANDLE_VALUE)
		return WinFail(error, "Could not open target module file", GetLastError());
	BY_HANDLE_FILE_INFORMATION info{};
	if (!GetFileInformationByHandle(file.value, &info))
		return WinFail(error, "Could not query target module file identity", GetLastError());
	if (GetFileType(file.value) != FILE_TYPE_DISK || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		return Fail(error, "Target module path is not a disk file");
	const uint64_t fileSize = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
	auto readFile = [&](uint64_t offset, void* data, size_t length) {
		if (offset > fileSize || length > fileSize - offset || offset > static_cast<uint64_t>((std::numeric_limits<LONGLONG>::max)())) return false;
		LARGE_INTEGER position{};
		position.QuadPart = static_cast<LONGLONG>(offset);
		DWORD read = 0;
		return SetFilePointerEx(file.value, position, nullptr, FILE_BEGIN) &&
			ReadFile(file.value, data, static_cast<DWORD>(length), &read, nullptr) && read == length;
	};
	auto readImage = [&](uint64_t offset, void* data, size_t length) {
		if (offset > moduleSize || length > moduleSize - offset) return false;
		return memory.readMemory(base + static_cast<uintptr_t>(offset), data, length);
	};
	PeIdentity disk{}, image{};
	if (!ReadPeIdentity(readFile, fileSize, disk, error) || !ReadPeIdentity(readImage, moduleSize, image, error)) return false;
	if (disk.machine != image.machine || disk.timestamp != image.timestamp || disk.size != image.size ||
		disk.checksum != image.checksum || image.size != moduleSize ||
		image.machine != (target.x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386))
		return Fail(error, "Mapped module and file PE identities do not match the target architecture");
	if (!memory.readMemory(target.address, target.originalBytes.data(), target.originalBytes.size()))
		return Fail(error, "Could not read original target bytes");
	BY_HANDLE_FILE_INFORMATION after{};
	if (!GetFileInformationByHandle(file.value, &after))
		return WinFail(error, "Could not recheck target module file identity", GetLastError());
	if (info.dwVolumeSerialNumber != after.dwVolumeSerialNumber || info.nFileIndexHigh != after.nFileIndexHigh ||
		info.nFileIndexLow != after.nFileIndexLow || info.nFileSizeHigh != after.nFileSizeHigh ||
		info.nFileSizeLow != after.nFileSizeLow || FileTimeValue(info.ftLastWriteTime) != FileTimeValue(after.ftLastWriteTime))
		return Fail(error, "Target module file changed during validation");
	target.modulePath = module.szExePath;
	target.volumeSerial = info.dwVolumeSerialNumber;
	target.fileId = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
	target.fileSize = fileSize;
	target.fileLastWrite = FileTimeValue(info.ftLastWriteTime);
	target.imageSize = image.size;
	target.imageTimestamp = image.timestamp;
	target.imageChecksum = image.checksum;
	target.imageMachine = image.machine;
	return true;
}
}

bool ValidateHookTarget(MemoryManager& memory, const FunctionStaticReport& report,
	HookTarget& target, std::string& error)
{
	error.clear();
	if (!report.inModule || report.moduleName.empty())
		return Fail(error, "Report has no module-relative target");
	Handle live;
	DWORD pid = 0;
	uint64_t creation = 0;
	if (!ProcessIdentity(memory, live, pid, creation, error)) return false;
	bool x64 = false;
	MODULEENTRY32W module{};
	if (!Architecture(memory.GetNativeHandle(), x64, error) ||
		!CheckLocation(memory, pid, report.moduleName, report.rva, report.targetAddress, module, error)) return false;
	HookTarget validated;
	validated.name = report.targetName;
	validated.moduleName = report.moduleName;
	validated.rva = report.rva;
	validated.address = report.targetAddress;
	validated.processId = pid;
	validated.processCreation = creation;
	validated.x64 = x64;
	if (!CaptureIdentity(memory, module, validated, error) || !CheckLive(live.value, error)) return false;
	target = std::move(validated);
	return true;
}

bool RevalidateHookTarget(MemoryManager& memory, const HookTarget& target, std::string& error)
{
	error.clear();
	if (!target.processId || !target.processCreation)
		return Fail(error, "Target has no process identity");
	Handle live;
	DWORD pid = 0;
	uint64_t creation = 0;
	if (!ProcessIdentity(memory, live, pid, creation, error)) return false;
	if (pid != target.processId || creation != target.processCreation)
		return Fail(error, "Target belongs to a different process instance");
	bool x64 = false;
	if (!Architecture(memory.GetNativeHandle(), x64, error)) return false;
	if (x64 != target.x64) return Fail(error, "Target architecture changed");
	MODULEENTRY32W module{};
	if (!CheckLocation(memory, pid, target.moduleName, target.rva, target.address, module, error)) return false;
	HookTarget current;
	current.address = target.address;
	current.rva = target.rva;
	current.x64 = x64;
	if (!CaptureIdentity(memory, module, current, error)) return false;
	const int pathMatch = CompareStringOrdinal(target.modulePath.c_str(), -1, current.modulePath.c_str(), -1, TRUE);
	if (!pathMatch) return WinFail(error, "Could not compare module paths", GetLastError());
	if (pathMatch != CSTR_EQUAL || target.volumeSerial != current.volumeSerial ||
		target.fileId != current.fileId || target.fileSize != current.fileSize ||
		target.fileLastWrite != current.fileLastWrite || target.imageSize != current.imageSize ||
		target.imageTimestamp != current.imageTimestamp || target.imageChecksum != current.imageChecksum ||
		target.imageMachine != current.imageMachine || target.originalBytes != current.originalBytes)
		return Fail(error, "Target module identity, version, or original bytes changed");
	return CheckLive(live.value, error);
}
}
