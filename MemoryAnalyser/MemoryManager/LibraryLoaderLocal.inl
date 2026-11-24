#pragma once

struct LibraryLoaderVerification
{
	HANDLE process = nullptr;
	HANDLE file = nullptr;
	DWORD exitCode = 0;
	bool matched = false;
	bool allocationFailed = false;
	std::string status;
	~LibraryLoaderVerification()
	{
		if (process) CloseHandle(process);
		if (file) CloseHandle(file);
	}
};

namespace
{
bool SameFile(HANDLE left, HANDLE right)
{
	BY_HANDLE_FILE_INFORMATION a = {}, b = {};
	return GetFileInformationByHandle(left, &a) && GetFileInformationByHandle(right, &b) &&
		a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow;
}

HANDLE OpenModuleFileMatching(HANDLE expected, const wchar_t* path)
{
	HANDLE file = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
#if defined(_M_IX86)
	// WOW64 snapshots can expose System32 aliases as well as physical paths.
	// Prefer the normal x86 interpretation; try physical only against the held identity.
	if (file != INVALID_HANDLE_VALUE && SameFile(expected, file)) return file;
	BOOL wow64 = FALSE;
	if (!IsWow64Process(GetCurrentProcess(), &wow64) || !wow64) return file;
	PVOID previous = nullptr;
	if (!Wow64DisableWow64FsRedirection(&previous)) return file;
	if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
	file = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
#else
	(void)expected;
#endif
	DWORD code = GetLastError();
#if defined(_M_IX86)
	if (wow64 && !Wow64RevertWow64FsRedirection(previous))
	{
		code = GetLastError();
		if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
		file = INVALID_HANDLE_VALUE;
	}
#endif
	SetLastError(code);
	return file;
}

bool GetRemoteModulePath(HANDLE process, HMODULE module, std::wstring& path, std::string& error)
{
	using GetModulePathFn = DWORD (WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);
	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	auto getModulePath = kernel ? reinterpret_cast<GetModulePathFn>(GetProcAddress(kernel, "K32GetModuleFileNameExW")) : nullptr;
	if (!getModulePath)
	{
		error = "Unicode target module path query is unavailable";
		return false;
	}
	std::vector<wchar_t> buffer(32768);
	DWORD length = getModulePath(process, module, buffer.data(), static_cast<DWORD>(buffer.size()));
	if (!length)
	{
		error = WinError("Could not query Unicode target module path", GetLastError());
		return false;
	}
	if (length >= buffer.size() - 1)
	{
		error = "Unicode target module path is truncated or too long to verify";
		return false;
	}
	path.assign(buffer.data(), length);
	return true;
}

DWORD WINAPI VerifyLoadedModule(void* argument)
{
	std::unique_ptr<std::shared_ptr<LibraryLoaderVerification>> owner(
		static_cast<std::shared_ptr<LibraryLoaderVerification>*>(argument));
	LibraryLoaderVerification& verification = **owner;
	try
	{
		DWORD pid = GetProcessId(verification.process);
		if (!pid)
		{
			verification.status = WinError("Could not identify target for module verification", GetLastError());
			return 0;
		}
		HANDLE raw = INVALID_HANDLE_VALUE;
		for (int attempt = 0; attempt < 8; ++attempt)
		{
			raw = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
			if (raw != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
		}
		Handle snapshot(raw);
		if (!snapshot.value)
		{
			verification.status = WinError("Could not enumerate target modules", GetLastError());
			return 0;
		}
		BY_HANDLE_FILE_INFORMATION expected = {};
		if (!GetFileInformationByHandle(verification.file, &expected))
		{
			verification.status = WinError("Could not identify the opened DLL", GetLastError());
			return 0;
		}
		MODULEENTRY32W module = {};
		module.dwSize = sizeof(module);
		if (!Module32FirstW(snapshot.value, &module))
		{
			verification.status = WinError("Could not enumerate target modules", GetLastError());
			return 0;
		}
		unsigned matches = 0, candidates = 0;
		bool inaccessible = false;
		std::string identificationError;
		do
		{
			if (static_cast<DWORD>(reinterpret_cast<uintptr_t>(module.modBaseAddr)) != verification.exitCode) continue;
			++candidates;
			std::wstring path;
			std::string pathError;
			if (!GetRemoteModulePath(verification.process, module.hModule, path, pathError))
			{
				inaccessible = true;
				if (identificationError.empty()) identificationError = pathError;
				continue;
			}
			Handle candidate(OpenModuleFileMatching(verification.file, path.c_str()));
			BY_HANDLE_FILE_INFORMATION actual = {};
			if (!candidate.value || !GetFileInformationByHandle(candidate.value, &actual))
			{
				inaccessible = true;
				if (identificationError.empty()) identificationError = WinError("Could not identify target module file", GetLastError());
			}
			else if (expected.dwVolumeSerialNumber == actual.dwVolumeSerialNumber &&
				expected.nFileIndexHigh == actual.nFileIndexHigh && expected.nFileIndexLow == actual.nFileIndexLow) ++matches;
		} while (Module32NextW(snapshot.value, &module));
		DWORD code = GetLastError();
		if (code != ERROR_NO_MORE_FILES)
			verification.status = WinError("Target module enumeration failed", code);
		else if (inaccessible)
			verification.status = "Could not identify every module with the returned low 32-bit base" +
				(identificationError.empty() ? std::string() : ": " + identificationError);
		else if (candidates > 1)
			verification.status = "Multiple modules share the returned low 32-bit base";
		else if (matches != 1)
			verification.status = "No module matched the opened DLL and returned low 32-bit base";
		else
		{
			verification.matched = true;
			verification.status = "A target module matched the opened DLL and returned low 32-bit base";
		}
	}
	catch (const std::bad_alloc&)
	{
		verification.matched = false;
		verification.allocationFailed = true;
	}
	return 0;
}

bool ResolveRemoteLoader(HANDLE process, DWORD pid, LPTHREAD_START_ROUTINE& entry, std::string& error)
{
	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	FARPROC function = kernel ? GetProcAddress(kernel, "LoadLibraryW") : nullptr;
	HMODULE owner = nullptr;
	if (!function || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
		reinterpret_cast<LPCWSTR>(function), &owner))
	{
		error = WinError("Could not resolve the local LoadLibraryW owner", GetLastError());
		return false;
	}
	struct ModuleGuard { HMODULE module; ~ModuleGuard() { FreeLibrary(module); } } guard{ owner };
	std::vector<wchar_t> path(32768);
	DWORD length = GetModuleFileNameW(owner, path.data(), static_cast<DWORD>(path.size()));
	if (!length || length >= path.size())
	{
		error = WinError("Could not obtain LoadLibraryW owner path", GetLastError());
		return false;
	}
	Handle localFile(CreateFileW(path.data(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (!localFile.value)
	{
		error = WinError("Could not open LoadLibraryW owner", GetLastError());
		return false;
	}
	const uintptr_t base = reinterpret_cast<uintptr_t>(owner);
	const uintptr_t address = reinterpret_cast<uintptr_t>(function);
	if (address < base)
	{
		error = "Invalid local LoadLibraryW offset";
		return false;
	}
	const uintptr_t offset = address - base;
	HANDLE rawSnapshot = INVALID_HANDLE_VALUE;
	for (int attempt = 0; attempt < 8; ++attempt)
	{
		rawSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (rawSnapshot != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
	}
	Handle snapshot(rawSnapshot);
	if (!snapshot.value)
	{
		error = WinError("Could not enumerate target modules", GetLastError());
		return false;
	}
	MODULEENTRY32W module = {};
	module.dwSize = sizeof(module);
	if (!Module32FirstW(snapshot.value, &module))
	{
		error = WinError("Could not enumerate target modules", GetLastError());
		return false;
	}
	std::string identificationError;
	do
	{
		std::wstring modulePath;
		std::string pathError;
		if (!GetRemoteModulePath(process, module.hModule, modulePath, pathError))
		{
			if (identificationError.empty()) identificationError = pathError;
			continue;
		}
		Handle targetFile(OpenModuleFileMatching(localFile.value, modulePath.c_str()));
		if (!targetFile.value && identificationError.empty())
			identificationError = WinError("Could not identify a target module file", GetLastError());
		if (targetFile.value && SameFile(localFile.value, targetFile.value))
		{
			const uintptr_t targetBase = reinterpret_cast<uintptr_t>(module.modBaseAddr);
			if (offset >= module.modBaseSize || offset > (std::numeric_limits<uintptr_t>::max)() - targetBase)
			{
				error = "LoadLibraryW offset is outside the target module";
				return false;
			}
			entry = reinterpret_cast<LPTHREAD_START_ROUTINE>(targetBase + offset);
			return true;
		}
	} while (Module32NextW(snapshot.value, &module));
	DWORD code = GetLastError();
	error = code == ERROR_NO_MORE_FILES ? "The target does not contain an identifiable local LoadLibraryW owner module" :
		WinError("Target module enumeration failed", code);
	if (code == ERROR_NO_MORE_FILES && !identificationError.empty()) error += ": " + identificationError;
	return false;
}

struct Cleanup
{
	HANDLE process;
	HANDLE thread;
	HANDLE file;
	void* remotePath;
};

DWORD WINAPI CleanupWhenFinished(void* argument)
{
	std::unique_ptr<Cleanup> cleanup(static_cast<Cleanup*>(argument));
	Handle process(cleanup->process), thread(cleanup->thread), file(cleanup->file);
	HANDLE handles[] = { thread.value, process.value };
	if (WaitForMultipleObjects(2, handles, FALSE, INFINITE) == WAIT_OBJECT_0)
		VirtualFreeEx(process.value, cleanup->remotePath, 0, MEM_RELEASE);
	return 0;
}
}

struct LibraryLoaderLocalState
{
	using State = LibraryLoader::State;
	static std::unique_ptr<LibraryLoaderLocalState> Start(Handle& target, Handle& file, DWORD pid,
		const std::wstring& absolutePath, std::string& error);
	State Poll(std::string& status);
	~LibraryLoaderLocalState();
	HANDLE process = nullptr;
	HANDLE thread = nullptr;
	HANDLE file = nullptr;
	HANDLE verificationThread = nullptr;
	std::shared_ptr<LibraryLoaderVerification> verification;
	void* remotePath = nullptr;
	ULONGLONG started = 0;
	State state = State::Pending;
	std::string result;
	std::string cleanupError;
};

std::unique_ptr<LibraryLoaderLocalState> LibraryLoaderLocalState::Start(Handle& target, Handle& file, DWORD pid,
	const std::wstring& absolutePath, std::string& error)
{
	LPTHREAD_START_ROUTINE entry = nullptr;
	if (!ResolveRemoteLoader(target.value, pid, entry, error)) return nullptr;
	DWORD wait = WaitForSingleObject(target.value, 0);
	if (wait != WAIT_TIMEOUT)
	{
		error = wait == WAIT_OBJECT_0 ? "Target process exited during setup" : WinError("Could not check target process", GetLastError());
		return nullptr;
	}
	if (absolutePath.size() > ((std::numeric_limits<SIZE_T>::max)() / sizeof(wchar_t)) - 1)
	{
		error = "DLL path is too long";
		return nullptr;
	}
	std::unique_ptr<LibraryLoaderLocalState> loader(new LibraryLoaderLocalState());
	SIZE_T bytes = (absolutePath.size() + 1) * sizeof(wchar_t);
	void* remote = VirtualAllocEx(target.value, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remote)
	{
		error = WinError("Could not allocate target path buffer", GetLastError());
		return nullptr;
	}
	SIZE_T written = 0;
	BOOL writeOk = WriteProcessMemory(target.value, remote, absolutePath.c_str(), bytes, &written);
	if (!writeOk || written != bytes)
	{
		DWORD code = writeOk ? ERROR_PARTIAL_COPY : GetLastError();
		VirtualFreeEx(target.value, remote, 0, MEM_RELEASE);
		error = WinError("Could not write complete target path", code);
		return nullptr;
	}
	Handle remoteThread(CreateRemoteThread(target.value, nullptr, 0, entry, remote, 0, nullptr));
	if (!remoteThread.value)
	{
		DWORD code = GetLastError();
		VirtualFreeEx(target.value, remote, 0, MEM_RELEASE);
		error = WinError("Could not create remote loader thread", code);
		return nullptr;
	}
	loader->process = target.release();
	loader->thread = remoteThread.release();
	loader->remotePath = remote;
	loader->file = file.release();
	loader->started = GetTickCount64();
	return loader;
}

LibraryLoaderLocalState::State LibraryLoaderLocalState::Poll(std::string& status)
{
	if (state != State::Pending)
	{
		status = result;
		return state;
	}
	HANDLE handles[] = { process, verificationThread ? verificationThread : thread };
	DWORD wait = WaitForMultipleObjects(2, handles, FALSE, 0);
	if (wait == WAIT_OBJECT_0)
	{
		DWORD code = 0;
		result = GetExitCodeProcess(process, &code) ? "Target process exited with code " + std::to_string(code) + "; load outcome unknown" :
			WinError("Target exited; could not obtain exit code; load outcome unknown", GetLastError());
		state = State::Failed;
		remotePath = nullptr;
	}
	else if (wait == WAIT_OBJECT_0 + 1 && !verificationThread)
	{
		DWORD code = 0;
		if (!GetExitCodeThread(thread, &code))
		{
			result = WinError("Could not obtain loader thread exit code; outcome unknown", GetLastError());
			state = State::Failed;
		}
		else
		{
			verification = std::make_shared<LibraryLoaderVerification>();
			verification->exitCode = code;
			if (!DuplicateHandle(GetCurrentProcess(), process, GetCurrentProcess(), &verification->process, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
				!DuplicateHandle(GetCurrentProcess(), file, GetCurrentProcess(), &verification->file, 0, FALSE, DUPLICATE_SAME_ACCESS))
			{
				result = WinError("Could not start module verification; outcome unknown", GetLastError());
				state = State::Failed;
			}
			else
			{
				auto workerState = std::make_unique<std::shared_ptr<LibraryLoaderVerification>>(verification);
				verificationThread = CreateThread(nullptr, 0, VerifyLoadedModule, workerState.get(), 0, nullptr);
				if (verificationThread) workerState.release();
				else
				{
					result = WinError("Could not start module verification; outcome unknown", GetLastError());
					state = State::Failed;
				}
			}
		}
		if (remotePath && !VirtualFreeEx(process, remotePath, 0, MEM_RELEASE))
			cleanupError = WinError("Could not release target path buffer", GetLastError());
		else remotePath = nullptr;
		if (state == State::Pending)
		{
			status = GetTickCount64() - started >= kTimeoutMs ? "Timed out; module verification pending, outcome unknown" : "Loader thread completed; module verification pending";
			if (!cleanupError.empty()) status += "; " + cleanupError;
			return state;
		}
	}
	else if (wait == WAIT_OBJECT_0 + 1)
	{
		// Check again after the snapshot: the PID must still denote the held process.
		wait = WaitForSingleObject(process, 0);
		if (wait != WAIT_TIMEOUT)
		{
			if (wait == WAIT_OBJECT_0)
			{
				DWORD code = 0;
				result = GetExitCodeProcess(process, &code) ? "Target process exited with code " + std::to_string(code) + "; load outcome unknown" :
					WinError("Target exited; could not obtain exit code; load outcome unknown", GetLastError());
			}
			else result = WinError("Could not check target process; outcome unknown", GetLastError());
			state = State::Failed;
		}
		else if (verification->allocationFailed)
		{
			result = "Module verification ran out of memory; load outcome unknown";
			state = State::Failed;
		}
		else if (!verification->matched)
		{
			result = (verification->status.empty() ? "Module verification failed" : verification->status) + "; load outcome unknown";
			state = State::Failed;
		}
		else
		{
			result = verification->status + "; a coincident exception or concurrent module change cannot be excluded";
			if (verification->exitCode == 0)
				result += "; a zero return is ambiguous on x64";
			state = State::ModuleObserved;
		}
		result += "; thread exit code " + std::to_string(verification->exitCode);
	}
	else if (wait == WAIT_TIMEOUT)
	{
		status = GetTickCount64() - started >= kTimeoutMs ? "Timed out; load outcome unknown, operation still pending" :
			(verificationThread ? "Module verification pending" : "Loader thread pending");
		return state;
	}
	else
	{
		status = WinError("Could not wait for target or operation; outcome unknown", GetLastError());
		return state;
	}
	if (file) { CloseHandle(file); file = nullptr; }
	if (!cleanupError.empty()) result += "; " + cleanupError;
	status = result;
	return state;
}

LibraryLoaderLocalState::~LibraryLoaderLocalState()
{
	if (remotePath && process && thread)
	{
		HANDLE handles[] = { thread, process };
		DWORD wait = WaitForMultipleObjects(2, handles, FALSE, 0);
		if (wait == WAIT_OBJECT_0)
			VirtualFreeEx(process, remotePath, 0, MEM_RELEASE);
		else if (wait != WAIT_OBJECT_0 + 1)
		{
			Cleanup* cleanup = new (std::nothrow) Cleanup{ process, thread, file, remotePath };
			if (cleanup)
			{
				HANDLE worker = CreateThread(nullptr, 0, CleanupWhenFinished, cleanup, 0, nullptr);
				if (worker)
				{
					CloseHandle(worker);
					process = thread = file = nullptr;
				}
				else delete cleanup;
			}
			// If cleanup cannot be scheduled, leave the buffer allocated rather than race the thread.
		}
	}
	if (verificationThread) CloseHandle(verificationThread);
	if (thread) CloseHandle(thread);
	if (process) CloseHandle(process);
	if (file) CloseHandle(file);
}
