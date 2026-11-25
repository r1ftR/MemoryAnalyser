#include "RemoteExportCall.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <system_error>
#include <thread>
#include <vector>

namespace
{
struct Handle
{
	HANDLE h = nullptr;
	explicit Handle(HANDLE value = nullptr) : h(value == INVALID_HANDLE_VALUE ? nullptr : value) {}
	~Handle() { if (h) CloseHandle(h); }
	Handle(const Handle&) = delete;
	Handle& operator=(const Handle&) = delete;
	HANDLE release() { HANDLE result = h; h = nullptr; return result; }
};

std::string WinError(const char* operation, DWORD code)
{
	return std::string(operation) + " (Windows error " + std::to_string(code) + ")";
}

bool AbsolutePath(const std::wstring& path)
{
	if (path.empty() || path.find(L'\0') != std::wstring::npos) return false;
	auto drive = [&](size_t i) { return path.size() > i + 2 &&
		((path[i] >= L'A' && path[i] <= L'Z') || (path[i] >= L'a' && path[i] <= L'z')) &&
		path[i + 1] == L':' && path[i + 2] == L'\\'; };
	if (drive(0)) return true;
	if (path.size() < 5 || path[0] != L'\\' || path[1] != L'\\') return false;
	size_t start = 2;
	if (path.compare(0, 4, L"\\\\?\\") == 0)
	{
		if (drive(4)) return true;
		if (path.size() < 9 || _wcsnicmp(path.c_str() + 4, L"UNC\\", 4) != 0) return false;
		start = 8;
	}
	else if (path[2] == L'.' || path[2] == L'?') return false;
	size_t slash = path.find(L'\\', start);
	return slash != std::wstring::npos && slash > start && slash + 1 < path.size();
}

bool CreationTime(HANDLE process, FILETIME& time)
{
	FILETIME exit = {}, kernel = {}, user = {};
	return GetProcessTimes(process, &time, &exit, &kernel, &user) != FALSE;
}

bool Machine(HANDLE process, USHORT& machine, std::string& error)
{
	using Fn = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
	auto fn = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
	if (fn)
	{
		USHORT p = 0, native = 0;
		if (!fn(process, &p, &native)) { error = WinError("IsWow64Process2 failed", GetLastError()); return false; }
		machine = p == IMAGE_FILE_MACHINE_UNKNOWN ? native : p;
	}
	else
	{
		SYSTEM_INFO info = {};
		GetNativeSystemInfo(&info);
		BOOL wow = FALSE;
		if (!IsWow64Process(process, &wow)) { error = WinError("IsWow64Process failed", GetLastError()); return false; }
		machine = info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL ? IMAGE_FILE_MACHINE_I386 :
			info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? (wow ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64) : IMAGE_FILE_MACHINE_UNKNOWN;
	}
	if (machine != IMAGE_FILE_MACHINE_I386 && machine != IMAGE_FILE_MACHINE_AMD64)
	{
		error = "Only x86 and x64 processes are supported";
		return false;
	}
	return true;
}

bool SameFile(const BY_HANDLE_FILE_INFORMATION& a, const BY_HANDLE_FILE_INFORMATION& b)
{
	return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow;
}

bool FindModule(HANDLE process, DWORD pid, const BY_HANDLE_FILE_INFORMATION& wanted, uintptr_t& base, DWORD& size, std::string& error)
{
	Handle snapshot;
	for (int i = 0; i != 8; ++i)
	{
		snapshot.h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (snapshot.h != INVALID_HANDLE_VALUE) break;
		snapshot.h = nullptr;
		if (GetLastError() != ERROR_BAD_LENGTH) break;
	}
	if (!snapshot.h) { error = WinError("Could not enumerate target modules", GetLastError()); return false; }
	MODULEENTRY32W entry = {};
	entry.dwSize = sizeof(entry);
	if (!Module32FirstW(snapshot.h, &entry)) { error = WinError("Could not enumerate target modules", GetLastError()); return false; }
	unsigned matches = 0;
	do
	{
		std::vector<wchar_t> path(32768);
		DWORD length = K32GetModuleFileNameExW(process, entry.hModule, path.data(), static_cast<DWORD>(path.size()));
		if (!length || length >= path.size())
		{
			error = "Could not identify every target module; module list may have changed";
			return false;
		}
		Handle file(CreateFileW(path.data(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
		BY_HANDLE_FILE_INFORMATION info = {};
		if (!file.h || !GetFileInformationByHandle(file.h, &info))
		{
			error = "Could not verify a target module's file identity";
			return false;
		}
		if (SameFile(wanted, info))
		{
			++matches;
			base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
			size = entry.modBaseSize;
		}
		entry.dwSize = sizeof(entry);
	} while (Module32NextW(snapshot.h, &entry));
	if (GetLastError() != ERROR_NO_MORE_FILES) { error = WinError("Module enumeration failed", GetLastError()); return false; }
	if (matches != 1) { error = matches ? "DLL file matches multiple loaded modules" : "DLL file is not loaded in the target"; return false; }
	return true;
}

struct Image
{
	HANDLE process;
	uintptr_t base;
	DWORD size;
	bool Read(uint64_t rva, void* buffer, size_t count) const
	{
		if (rva > size || count > static_cast<uint64_t>(size) - rva ||
			rva > (std::numeric_limits<uintptr_t>::max)() - base ||
			count > (std::numeric_limits<uintptr_t>::max)() - (base + static_cast<uintptr_t>(rva))) return false;
		SIZE_T got = 0;
		return ReadProcessMemory(process, reinterpret_cast<const void*>(base + static_cast<uintptr_t>(rva)), buffer, count, &got) && got == count;
	}
};

template<typename T> bool ReadArray(const Image& image, DWORD rva, DWORD count, std::vector<T>& result)
{
	if (count > 1048576 || static_cast<uint64_t>(count) * sizeof(T) > image.size ||
		rva > image.size || static_cast<uint64_t>(count) * sizeof(T) > image.size - rva) return false;
	result.resize(count);
	return !count || image.Read(rva, result.data(), result.size() * sizeof(T));
}

bool ResolveExport(const Image& image, USHORT machine, const char* name, uintptr_t& address, std::string& error)
{
	auto bad = [&]() { error = "Invalid, inaccessible, or unsupported target PE export data"; return false; };
	IMAGE_DOS_HEADER dos = {};
	DWORD signature = 0;
	IMAGE_FILE_HEADER file = {};
	if (!image.Read(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < sizeof(dos) ||
		!image.Read(dos.e_lfanew, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
		!image.Read(static_cast<uint64_t>(dos.e_lfanew) + sizeof(signature), &file, sizeof(file)) ||
		file.Machine != machine || !(file.Characteristics & IMAGE_FILE_DLL) || !file.NumberOfSections || file.NumberOfSections > 96) return bad();
	uint64_t opt = static_cast<uint64_t>(dos.e_lfanew) + sizeof(signature) + sizeof(file);
	IMAGE_DATA_DIRECTORY exports = {};
	DWORD imageSize = 0;
	if (machine == IMAGE_FILE_MACHINE_I386)
	{
		IMAGE_OPTIONAL_HEADER32 hdr = {};
		if (file.SizeOfOptionalHeader < sizeof(hdr) || !image.Read(opt, &hdr, sizeof(hdr)) || hdr.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC || hdr.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return bad();
		exports = hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; imageSize = hdr.SizeOfImage;
	}
	else
	{
		IMAGE_OPTIONAL_HEADER64 hdr = {};
		if (file.SizeOfOptionalHeader < sizeof(hdr) || !image.Read(opt, &hdr, sizeof(hdr)) || hdr.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || hdr.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return bad();
		exports = hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; imageSize = hdr.SizeOfImage;
	}
	if (imageSize != image.size || exports.Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
		exports.VirtualAddress > image.size || exports.Size > image.size - exports.VirtualAddress) return bad();
	uint64_t sectionsRva = opt + file.SizeOfOptionalHeader;
	std::vector<IMAGE_SECTION_HEADER> sections(file.NumberOfSections);
	if (!image.Read(sectionsRva, sections.data(), sections.size() * sizeof(sections[0]))) return bad();
	for (const auto& section : sections)
	{
		DWORD extent = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
		if (section.VirtualAddress > image.size || extent > image.size - section.VirtualAddress) return bad();
	}
	IMAGE_EXPORT_DIRECTORY dir = {};
	if (!image.Read(exports.VirtualAddress, &dir, sizeof(dir)) || !dir.NumberOfFunctions || !dir.NumberOfNames ||
		!dir.AddressOfNames || !dir.AddressOfNameOrdinals || !dir.AddressOfFunctions) return bad();
	std::vector<DWORD> names, functions;
	std::vector<WORD> ordinals;
	if (!ReadArray(image, dir.AddressOfNames, dir.NumberOfNames, names) ||
		!ReadArray(image, dir.AddressOfNameOrdinals, dir.NumberOfNames, ordinals) ||
		!ReadArray(image, dir.AddressOfFunctions, dir.NumberOfFunctions, functions)) return bad();
	unsigned matches = 0;
	DWORD result = 0;
	size_t total = 0;
	for (size_t i = 0; i < names.size(); ++i)
	{
		if (ordinals[i] >= functions.size() || names[i] >= image.size) return bad();
		std::string current;
		bool terminated = false;
		for (size_t j = 0; j < 4096; )
		{
			uint64_t rva = static_cast<uint64_t>(names[i]) + j;
			if (rva >= image.size) return bad();
			char buffer[256];
			size_t count = (std::min)(sizeof(buffer), static_cast<size_t>(image.size - rva));
			count = (std::min)(count, 4096 - j);
			count = (std::min)(count, static_cast<size_t>(4096 - ((image.base + rva) & 4095)));
			if (count > 16777216 - total || !image.Read(rva, buffer, count)) return bad();
			total += count;
			const char* end = static_cast<const char*>(std::memchr(buffer, 0, count));
			current.append(buffer, end ? static_cast<size_t>(end - buffer) : count);
			if (end) { terminated = true; break; }
			j += count;
		}
		if (!terminated) return bad();
		if (current == name) { ++matches; result = functions[ordinals[i]]; }
	}
	if (matches != 1) { error = matches ? "Export name is ambiguous" : "Export name was not found"; return false; }
	if (!result || result >= image.size) return bad();
	if (result >= exports.VirtualAddress && static_cast<uint64_t>(result) < static_cast<uint64_t>(exports.VirtualAddress) + exports.Size)
	{
		error = "Forwarded exports are not supported"; return false;
	}
	unsigned executableSections = 0;
	for (const auto& section : sections)
	{
		DWORD extent = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
		if (result >= section.VirtualAddress && result - section.VirtualAddress < extent && (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) ++executableSections;
	}
	if (executableSections != 1) return bad();
	if (result > (std::numeric_limits<uintptr_t>::max)() - image.base) return bad();
	address = image.base + result;
	return true;
}
}

struct RemoteExportCallState
{
	Handle process;
	Handle file;
	Handle thread;
	std::mutex mutex;
	std::condition_variable ready;
	bool launched = false;
	bool abandon = false;
	RemoteExportCall::State state = RemoteExportCall::State::Pending;
	DWORD exitCode = 0;
	std::string status = "Remote export is running";
};

namespace
{
void Monitor(std::shared_ptr<RemoteExportCallState> state)
{
	{
		std::unique_lock<std::mutex> lock(state->mutex);
		state->ready.wait(lock, [&] { return state->launched || state->abandon; });
		if (state->abandon) return;
	}
	HANDLE handles[] = { state->process.h, state->thread.h };
	DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
	DWORD code = 0;
	std::string status;
	bool completed = false;
	if (wait == WAIT_OBJECT_0) status = "Target process exited before completion could be confirmed";
	else if (wait == WAIT_OBJECT_0 + 1)
	{
		// ExitProcess can signal the thread before the process finishes shutting down.
		DWORD processWait = WaitForSingleObject(state->process.h, 100);
		if (processWait == WAIT_OBJECT_0) status = "Target process exited before completion could be confirmed";
		else if (processWait != WAIT_TIMEOUT) status = WinError("Could not check target process", GetLastError());
		else if (!GetExitCodeThread(state->thread.h, &code)) status = WinError("Could not read remote thread exit code", GetLastError());
		else if ((code & 0xC0000000u) == 0xC0000000u) status = "Remote thread returned an exception-like exit code; completion is indeterminate";
		else { completed = true; status = "Remote thread exited; normal return cannot be independently verified"; }
	}
	else status = WinError("Could not wait for remote thread", GetLastError());
	std::lock_guard<std::mutex> lock(state->mutex);
	state->exitCode = code;
	state->status = status;
	state->state = completed ? RemoteExportCall::State::Completed : RemoteExportCall::State::Failed;
	CloseHandle(state->thread.release());
	CloseHandle(state->process.release());
	CloseHandle(state->file.release());
}
}

RemoteExportCall::RemoteExportCall(std::shared_ptr<RemoteExportCallState> state) : state_(std::move(state)) {}
RemoteExportCall::~RemoteExportCall() = default;

std::unique_ptr<RemoteExportCall> RemoteExportCall::Start(HANDLE attachedProcess, const std::wstring& absoluteDllPath,
	const char* exportName, std::string& error)
{
	error.clear();
	if (!attachedProcess || attachedProcess == INVALID_HANDLE_VALUE || !AbsolutePath(absoluteDllPath) || !exportName || !*exportName || strnlen_s(exportName, 4096) == 4096)
	{
		error = "A real process handle, absolute DLL path, and bounded export name are required"; return nullptr;
	}
	Handle original;
	if (!DuplicateHandle(GetCurrentProcess(), attachedProcess, GetCurrentProcess(), &original.h, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{ error = WinError("Could not duplicate attached process handle", GetLastError()); return nullptr; }
	DWORD pid = GetProcessId(original.h);
	FILETIME originalTime = {}, targetTime = {};
	if (!pid || !CreationTime(original.h, originalTime)) { error = WinError("Could not identify attached process", GetLastError()); return nullptr; }
	auto state = std::make_shared<RemoteExportCallState>();
	state->process.h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid);
	if (!state->process.h) { error = WinError("Could not open target process with required rights", GetLastError()); return nullptr; }
	if (!CreationTime(state->process.h, targetTime) || CompareFileTime(&originalTime, &targetTime) != 0)
	{ error = "Could not verify target process identity"; return nullptr; }
	DWORD processWait = WaitForSingleObject(state->process.h, 0);
	if (processWait != WAIT_TIMEOUT) { error = processWait == WAIT_OBJECT_0 ? "Target process has exited" : WinError("Could not check target process", GetLastError()); return nullptr; }
	USHORT current = 0, target = 0;
	if (!Machine(GetCurrentProcess(), current, error) || !Machine(state->process.h, target, error)) return nullptr;
#if defined(_M_X64)
	if (current != IMAGE_FILE_MACHINE_AMD64)
#elif defined(_M_IX86)
	if (current != IMAGE_FILE_MACHINE_I386 || target != IMAGE_FILE_MACHINE_I386)
#else
	if (true)
#endif
	{ error = "Only native x86/x64 and x64-to-x86 invocation are supported"; return nullptr; }
	state->file.h = CreateFileW(absoluteDllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (state->file.h == INVALID_HANDLE_VALUE) state->file.h = nullptr;
	BY_HANDLE_FILE_INFORMATION wanted = {};
	if (!state->file.h || GetFileType(state->file.h) != FILE_TYPE_DISK || !GetFileInformationByHandle(state->file.h, &wanted) ||
		(wanted.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (!wanted.nFileIndexHigh && !wanted.nFileIndexLow))
	{ error = "Could not lock and identify the DLL file"; return nullptr; }
	uintptr_t base = 0, address = 0;
	DWORD size = 0;
	if (!FindModule(state->process.h, pid, wanted, base, size, error) || !ResolveExport({ state->process.h, base, size }, target, exportName, address, error)) return nullptr;
	MEMORY_BASIC_INFORMATION memory = {};
	if (VirtualQueryEx(state->process.h, reinterpret_cast<const void*>(address), &memory, sizeof(memory)) != sizeof(memory) ||
		memory.State != MEM_COMMIT || memory.Type != MEM_IMAGE || reinterpret_cast<uintptr_t>(memory.AllocationBase) != base ||
		(memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
		!(memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
	{ error = "Export is not in executable memory belonging to the target image"; return nullptr; }
	processWait = WaitForSingleObject(state->process.h, 0);
	if (processWait != WAIT_TIMEOUT) { error = processWait == WAIT_OBJECT_0 ? "Target process has exited" : WinError("Could not check target process", GetLastError()); return nullptr; }
	std::unique_ptr<RemoteExportCall> call(new RemoteExportCall(state));
	try { std::thread(Monitor, state).detach(); }
	catch (const std::system_error& exception) { error = std::string("Could not start completion monitor: ") + exception.what(); return nullptr; }
	HANDLE remote = CreateRemoteThread(state->process.h, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), nullptr, 0, nullptr);
	DWORD threadError = remote ? ERROR_SUCCESS : GetLastError();
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		state->thread.h = remote;
		state->launched = remote != nullptr;
		state->abandon = remote == nullptr;
	}
	state->ready.notify_one();
	if (!remote) { error = WinError("Could not create remote thread", threadError); return nullptr; }
	return call;
}

RemoteExportCall::State RemoteExportCall::Poll(DWORD& exitCode, std::string& status)
{
	std::lock_guard<std::mutex> lock(state_->mutex);
	status = state_->status;
	if (state_->state == State::Completed) exitCode = state_->exitCode;
	return state_->state;
}
