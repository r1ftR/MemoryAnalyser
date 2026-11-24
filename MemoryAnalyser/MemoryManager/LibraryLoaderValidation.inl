#pragma once

namespace
{
bool ProcessMachine(HANDLE process, USHORT& machine, std::string& error)
{
	using IsWow64Process2Fn = BOOL (WINAPI*)(HANDLE, USHORT*, USHORT*);
	auto fn = reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
	if (fn)
	{
		USHORT processMachine = 0, nativeMachine = 0;
		if (!fn(process, &processMachine, &nativeMachine))
		{
			error = WinError("IsWow64Process2 failed", GetLastError());
			return false;
		}
		machine = processMachine == IMAGE_FILE_MACHINE_UNKNOWN ? nativeMachine : processMachine;
	}
	else
	{
		SYSTEM_INFO info = {};
		GetNativeSystemInfo(&info);
		BOOL wow64 = FALSE;
		if (!IsWow64Process(process, &wow64))
		{
			error = WinError("IsWow64Process failed", GetLastError());
			return false;
		}
		if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			machine = IMAGE_FILE_MACHINE_I386;
		else if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
			machine = wow64 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64;
		else
			machine = IMAGE_FILE_MACHINE_UNKNOWN;
	}
	if (machine != IMAGE_FILE_MACHINE_I386 && machine != IMAGE_FILE_MACHINE_AMD64)
	{
		error = "Only x86 and x64 processes are supported";
		return false;
	}
	return true;
}

bool IsAbsolutePath(const std::wstring& path)
{
	if (path.empty() || path.find(L'\0') != std::wstring::npos) return false;
	// Accept drive-rooted and UNC paths, including their extended-length forms.
	if (path.size() >= 3 && ((path[0] >= L'A' && path[0] <= L'Z') ||
		(path[0] >= L'a' && path[0] <= L'z')) && path[1] == L':' && path[2] == L'\\') return true;
	if (path.size() < 5 || path[0] != L'\\' || path[1] != L'\\') return false;
	if (path.compare(0, 4, L"\\\\?\\") == 0)
	{
		if (path.size() >= 7 && ((path[4] >= L'A' && path[4] <= L'Z') ||
			(path[4] >= L'a' && path[4] <= L'z')) && path[5] == L':' && path[6] == L'\\') return true;
		if (path.size() < 9 || _wcsnicmp(path.c_str() + 4, L"UNC\\", 4) != 0) return false;
		const size_t slash = path.find(L'\\', 8);
		return slash != std::wstring::npos && slash > 8 && slash + 1 < path.size();
	}
	if (path[2] == L'.' || path[2] == L'?') return false;
	const size_t slash = path.find(L'\\', 2);
	return slash != std::wstring::npos && slash > 2 && slash + 1 < path.size();
}

std::string OpenedFilePath(HANDLE file)
{
	DWORD length = GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED);
	if (!length)
		return WinError("Could not resolve opened DLL path", GetLastError());
	std::vector<wchar_t> path(length);
	DWORD written = GetFinalPathNameByHandleW(file, path.data(), length, FILE_NAME_NORMALIZED);
	if (!written)
		return WinError("Could not resolve opened DLL path", GetLastError());
	if (written >= length)
		return "Opened DLL path changed while resolving it";
	const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), static_cast<int>(written), nullptr, 0, nullptr, nullptr);
	if (!bytes)
		return WinError("Could not convert opened DLL path", GetLastError());
	std::string result(static_cast<size_t>(bytes), '\0');
	if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), static_cast<int>(written), result.data(), bytes, nullptr, nullptr))
		return WinError("Could not convert opened DLL path", GetLastError());
	return "Opened DLL: " + result;
}

bool ValidateDll(HANDLE file, USHORT machine, std::string& error)
{
	BY_HANDLE_FILE_INFORMATION info = {};
	LARGE_INTEGER length = {};
	if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &info) ||
		(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !GetFileSizeEx(file, &length))
	{
		error = "DLL path must refer to a readable regular file";
		return false;
	}
	IMAGE_DOS_HEADER dos = {};
	DWORD signature = 0;
	IMAGE_FILE_HEADER header = {};
	WORD magic = 0;
	if (length.QuadPart < static_cast<LONGLONG>(sizeof(dos)) || !ReadAt(file, 0, &dos, sizeof(dos)) ||
		dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
		static_cast<LONGLONG>(dos.e_lfanew) + static_cast<LONGLONG>(sizeof(signature) + sizeof(header)) > length.QuadPart ||
		!ReadAt(file, dos.e_lfanew, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
		!ReadAt(file, static_cast<LONGLONG>(dos.e_lfanew) + sizeof(signature), &header, sizeof(header)) ||
		header.SizeOfOptionalHeader < sizeof(magic) ||
		static_cast<LONGLONG>(dos.e_lfanew) + static_cast<LONGLONG>(sizeof(signature) + sizeof(header)) + header.SizeOfOptionalHeader +
			static_cast<LONGLONG>(header.NumberOfSections) * static_cast<LONGLONG>(sizeof(IMAGE_SECTION_HEADER)) > length.QuadPart ||
		!ReadAt(file, static_cast<LONGLONG>(dos.e_lfanew) + sizeof(signature) + sizeof(header), &magic, sizeof(magic)))
	{
		error = "DLL file has invalid or truncated PE headers";
		return false;
	}
	if (!(header.Characteristics & IMAGE_FILE_DLL))
	{
		error = "PE file is not a DLL";
		return false;
	}
	if (header.Machine != machine || magic != (machine == IMAGE_FILE_MACHINE_I386 ? IMAGE_NT_OPTIONAL_HDR32_MAGIC : IMAGE_NT_OPTIONAL_HDR64_MAGIC))
	{
		char details[160];
		std::snprintf(details, sizeof(details), "DLL architecture does not match the target process: target %s (0x%04X), DLL machine 0x%04X, PE magic 0x%04X. ",
			machine == IMAGE_FILE_MACHINE_I386 ? "x86" : "x64", static_cast<unsigned>(machine),
			static_cast<unsigned>(header.Machine), static_cast<unsigned>(magic));
		error = std::string(details) + OpenedFilePath(file);
		return false;
	}
	if (header.SizeOfOptionalHeader < (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64)))
	{
		error = "DLL file has invalid or truncated PE headers";
		return false;
	}
	return true;
}

bool PrepareLoad(HANDLE attachedProcess, const std::wstring& absolutePath, Handle& original, Handle& target, Handle& file,
	DWORD& pid, USHORT& currentMachine, USHORT& targetMachine, std::string& error)
{
	if (!attachedProcess || attachedProcess == INVALID_HANDLE_VALUE || !IsAbsolutePath(absolutePath))
	{
		error = "A real process handle and absolute DLL path are required";
		return false;
	}
	HANDLE duplicate = nullptr;
	if (!DuplicateHandle(GetCurrentProcess(), attachedProcess, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
	{
		error = WinError("Could not duplicate attached process handle", GetLastError());
		return false;
	}
	original.value = duplicate;
	pid = GetProcessId(original.value);
	FILETIME originalTime = {}, reopenedTime = {};
	if (!pid || !CreationTime(original.value, originalTime))
	{
		error = WinError("Could not identify attached process", GetLastError());
		return false;
	}
	target.value = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid);
	if (!target.value)
	{
		error = WinError("Could not open target process with required rights", GetLastError());
		return false;
	}
	if (!CreationTime(target.value, reopenedTime))
	{
		error = WinError("Could not verify target process identity", GetLastError());
		return false;
	}
	if (CompareFileTime(&originalTime, &reopenedTime) != 0)
	{
		error = "The process ID was reused; target identity changed";
		return false;
	}
	DWORD wait = WaitForSingleObject(target.value, 0);
	if (wait != WAIT_TIMEOUT)
	{
		error = wait == WAIT_OBJECT_0 ? "Target process has exited" : WinError("Could not check target process", GetLastError());
		return false;
	}
	if (!ProcessMachine(GetCurrentProcess(), currentMachine, error) || !ProcessMachine(target.value, targetMachine, error)) return false;
#if defined(_M_IX86)
	if (currentMachine != IMAGE_FILE_MACHINE_I386)
#elif defined(_M_X64)
	if (currentMachine != IMAGE_FILE_MACHINE_AMD64)
#else
	if (true)
#endif
	{
		error = "The current binary must be native x86 or x64";
		return false;
	}
	if (currentMachine != targetMachine &&
		!(currentMachine == IMAGE_FILE_MACHINE_AMD64 && targetMachine == IMAGE_FILE_MACHINE_I386))
	{
		error = "Only x64-to-x86 helper loading and same-architecture loading are supported";
		return false;
	}
	file.value = CreateFileW(absolutePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file.value == INVALID_HANDLE_VALUE) file.value = nullptr;
	if (!file.value)
	{
		error = WinError("Could not open DLL file", GetLastError());
		return false;
	}
	if (!ValidateDll(file.value, targetMachine, error)) return false;
	return true;
}
}
