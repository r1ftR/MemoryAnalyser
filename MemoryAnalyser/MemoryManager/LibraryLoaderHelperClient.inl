#pragma once

struct LibraryLoaderHelperState
{
	using State = LibraryLoader::State;
#if defined(_M_X64)
	static std::unique_ptr<LibraryLoaderHelperState> Start(HANDLE target, HANDLE selectedFile, std::string& error);
#endif
	State Poll(std::string& status);
	HANDLE process = nullptr;
	HANDLE output = nullptr;
	library_loader_ipc::Response response = {};
	DWORD received = 0;
	bool accepted = false;
	bool jobConstrained = false;
	ULONGLONG started = 0;
	State state = State::Pending;
	std::string result;
	~LibraryLoaderHelperState()
	{
		// Closing IPC is not cancellation: the helper owns the remote operation.
		if (output) CloseHandle(output);
		if (process) CloseHandle(process);
	}
};

#if defined(_M_X64)
std::unique_ptr<LibraryLoaderHelperState> LibraryLoaderHelperState::Start(HANDLE target, HANDLE selectedFile, std::string& error)
{
	std::vector<wchar_t> executable(32768);
	DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
	if (!length || length >= executable.size())
	{
		error = WinError("Could not locate the current executable", GetLastError());
		return nullptr;
	}
	std::wstring helperPath(executable.data(), length);
	const size_t separator = helperPath.find_last_of(L'\\');
	if (separator == std::wstring::npos)
	{
		error = "The current executable has no absolute directory";
		return nullptr;
	}
	helperPath.resize(separator + 1);
	helperPath += L"MemoryAnalyserLoader32.exe";
	Handle helperFile(CreateFileW(helperPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (!helperFile.value)
	{
		error = WinError("Could not open MemoryAnalyserLoader32.exe beside the current executable", GetLastError());
		return nullptr;
	}
	// Validate the helper PE machine (it is an executable, not a DLL).
	IMAGE_DOS_HEADER dos = {};
	DWORD signature = 0;
	IMAGE_FILE_HEADER header = {};
	WORD magic = 0;
	if (!ReadAt(helperFile.value, 0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
		dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
		!ReadAt(helperFile.value, dos.e_lfanew, &signature, sizeof(signature)) || signature != IMAGE_NT_SIGNATURE ||
		!ReadAt(helperFile.value, static_cast<LONGLONG>(dos.e_lfanew) + sizeof(signature), &header, sizeof(header)) ||
		header.Machine != IMAGE_FILE_MACHINE_I386 || (header.Characteristics & IMAGE_FILE_DLL) ||
		header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32) ||
		!ReadAt(helperFile.value, static_cast<LONGLONG>(dos.e_lfanew) + sizeof(signature) + sizeof(header), &magic, sizeof(magic)) ||
		magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		error = "MemoryAnalyserLoader32.exe must be a valid x86 executable";
		return nullptr;
	}

	auto helper = std::make_unique<LibraryLoaderHelperState>();
	library_loader_ipc::Request request = {};
	FILETIME creation = {};
	BY_HANDLE_FILE_INFORMATION info = {};
	request.pid = GetProcessId(target);
	if (!request.pid || !CreationTime(target, creation) || !GetFileInformationByHandle(selectedFile, &info))
	{
		error = WinError("Could not identify helper target or selected DLL", GetLastError());
		return nullptr;
	}
	request.creationLow = creation.dwLowDateTime;
	request.creationHigh = creation.dwHighDateTime;
	request.volume = info.dwVolumeSerialNumber;
	request.fileHigh = info.nFileIndexHigh;
	request.fileLow = info.nFileIndexLow;

	// Only private duplicates are inheritable; the allowlist excludes unrelated handles.
	Handle childTarget, childFile, childInput, parentInput, parentOutput, childOutput;
	if (!DuplicateHandle(GetCurrentProcess(), target, GetCurrentProcess(), &childTarget.value, 0, TRUE, DUPLICATE_SAME_ACCESS) ||
		!DuplicateHandle(GetCurrentProcess(), selectedFile, GetCurrentProcess(), &childFile.value, 0, TRUE, DUPLICATE_SAME_ACCESS))
	{
		error = WinError("Could not duplicate private helper handles", GetLastError());
		return nullptr;
	}
	SECURITY_ATTRIBUTES security = { sizeof(security), nullptr, TRUE };
	if (!CreatePipe(&childInput.value, &parentInput.value, &security, library_loader_ipc::PipeCapacity) ||
		!CreatePipe(&parentOutput.value, &childOutput.value, &security, library_loader_ipc::PipeCapacity) ||
		!SetHandleInformation(parentInput.value, HANDLE_FLAG_INHERIT, 0) ||
		!SetHandleInformation(parentOutput.value, HANDLE_FLAG_INHERIT, 0))
	{
		error = WinError("Could not create private helper pipes", GetLastError());
		return nullptr;
	}
	HANDLE inherited[] = { childInput.value, childOutput.value, childTarget.value, childFile.value };
	for (HANDLE handle : inherited)
	{
		if (reinterpret_cast<uintptr_t>(handle) > MAXDWORD)
		{
			error = "A private helper handle cannot be represented by x86";
			return nullptr;
		}
	}
	SIZE_T attributeBytes = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
	if (!attributeBytes)
	{
		error = WinError("Could not size helper handle allowlist", GetLastError());
		return nullptr;
	}
	std::vector<unsigned char> storage(attributeBytes);
	auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
	if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributeBytes))
	{
		error = WinError("Could not initialize helper handle allowlist", GetLastError());
		return nullptr;
	}
	struct AttributeGuard { LPPROC_THREAD_ATTRIBUTE_LIST value; ~AttributeGuard() { DeleteProcThreadAttributeList(value); } } guard{ attributes };
	if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr))
	{
		error = WinError("Could not configure helper handle allowlist", GetLastError());
		return nullptr;
	}
	std::wstring command = L"\"" + helperPath + L"\" --library-loader-helper-v1";
	for (HANDLE handle : inherited) command += L" " + std::to_wstring(reinterpret_cast<uintptr_t>(handle));
	STARTUPINFOEXW startup = {};
	startup.StartupInfo.cb = sizeof(startup);
	startup.lpAttributeList = attributes;
	PROCESS_INFORMATION child = {};
	BOOL inJob = FALSE;
	if (!IsProcessInJob(GetCurrentProcess(), nullptr, &inJob))
	{
		error = WinError("Could not check helper job lifetime", GetLastError());
		return nullptr;
	}
	DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED;
	if (inJob) flags |= CREATE_BREAKAWAY_FROM_JOB;
	BOOL launched = CreateProcessW(helperPath.c_str(), command.data(), nullptr, nullptr, TRUE, flags, nullptr, nullptr, &startup.StartupInfo, &child);
	if (!launched && inJob && GetLastError() == ERROR_ACCESS_DENIED)
	{
		// Restrictive host jobs may forbid breakaway. Losing this helper cannot
		// release its allocation in the target; report that lifetime limitation.
		command = L"\"" + helperPath + L"\" --library-loader-helper-v1";
		for (HANDLE handle : inherited) command += L" " + std::to_wstring(reinterpret_cast<uintptr_t>(handle));
		flags &= ~CREATE_BREAKAWAY_FROM_JOB;
		launched = CreateProcessW(helperPath.c_str(), command.data(), nullptr, nullptr, TRUE, flags, nullptr, nullptr, &startup.StartupInfo, &child);
	}
	if (!launched)
	{
		error = WinError("Could not launch x86 helper (no elevation is attempted)", GetLastError());
		return nullptr;
	}
	Handle helperProcess(child.hProcess), helperThread(child.hThread);
	// Never terminate a helper after it may have created a remote thread.
	BOOL childInJob = FALSE;
	if (!IsProcessInJob(helperProcess.value, nullptr, &childInJob))
	{
		error = WinError("Could not check helper lifetime", GetLastError());
		TerminateProcess(helperProcess.value, ERROR_PROCESS_ABORTED);
		return nullptr;
	}
	helper->jobConstrained = childInJob != FALSE;
	DWORD written = 0;
	// One small request fits the empty pipe even while the helper is suspended.
	if (!WriteFile(parentInput.value, &request, sizeof(request), &written, nullptr) || written != sizeof(request))
	{
		error = WinError("Could not send complete helper request", written ? ERROR_PARTIAL_COPY : GetLastError());
		TerminateProcess(helperProcess.value, ERROR_PROCESS_ABORTED);
		return nullptr;
	}
	if (ResumeThread(helperThread.value) == static_cast<DWORD>(-1))
	{
		error = WinError("Could not resume x86 helper", GetLastError());
		TerminateProcess(helperProcess.value, ERROR_PROCESS_ABORTED);
		return nullptr;
	}
	helper->process = helperProcess.release();
	helper->output = parentOutput.release();
	helper->started = GetTickCount64();
	return helper;
}
#endif

LibraryLoaderHelperState::State LibraryLoaderHelperState::Poll(std::string& status)
{
	if (state != State::Pending)
	{
		status = result;
		return state;
	}
	using library_loader_ipc::Code;
	auto failed = [&](const std::string& reason)
	{
		state = State::Failed;
		result = reason + "; load outcome unknown; the remote operation may still be running";
		if (jobConstrained) result += "; job shutdown may have killed the helper, leaving its remote buffer allocated until target exit";
		status = result;
		return state;
	};
	// At most two fixed-size records, never a blocking read or helper wait.
	for (unsigned packet = 0; packet < 2; ++packet)
	{
		DWORD available = 0;
		if (!PeekNamedPipe(output, nullptr, 0, nullptr, &available, nullptr))
			return failed(WinError("x86 helper disconnected or pipe failed", GetLastError()));
		if (!available) break;
		DWORD bytes = (std::min)(available, static_cast<DWORD>(sizeof(response)) - received);
		DWORD read = 0;
		if (!ReadFile(output, reinterpret_cast<unsigned char*>(&response) + received, bytes, &read, nullptr) || !read)
			return failed(WinError("Could not read x86 helper response", GetLastError()));
		received += read;
		if (received != sizeof(response)) break;
		const auto& response = this->response;
		if (response.magic != library_loader_ipc::Magic || response.version != library_loader_ipc::Version ||
			!response.length || response.length > library_loader_ipc::MaxStatus ||
			(response.code != Code::Pending && response.code != Code::ModuleObserved && response.code != Code::Failed) ||
			std::char_traits<char>::find(response.text, response.length, '\0'))
			return failed("Invalid x86 helper status record");
		if (response.code == Code::Pending)
		{
			if (accepted) return failed("Duplicate x86 helper acceptance");
			accepted = true;
		}
		else
		{
			if (response.code == Code::ModuleObserved && !accepted)
				return failed("Unaccepted x86 helper result");
			state = response.code == Code::ModuleObserved ? State::ModuleObserved : State::Failed;
			result.assign(response.text, response.length);
			status = result;
			return state;
		}
		received = 0;
	}
	DWORD remaining = 0;
	if (!PeekNamedPipe(output, nullptr, 0, nullptr, &remaining, nullptr))
		return failed(WinError("x86 helper disconnected or pipe failed", GetLastError()));
	DWORD wait = WaitForSingleObject(process, 0);
	if (wait == WAIT_FAILED) return failed(WinError("Could not check x86 helper", GetLastError()));
	if (wait == WAIT_OBJECT_0 && !remaining)
	{
		DWORD code = 0;
		return failed(GetExitCodeProcess(process, &code) ?
			"x86 helper exited without a complete result; exit code " + std::to_string(code) :
			WinError("x86 helper exited without a result", GetLastError()));
	}
	status = GetTickCount64() - started >= kTimeoutMs ? "Timed out; x86 helper operation still pending, load outcome unknown" :
		(accepted ? "x86 helper loader operation pending" : "x86 helper startup pending");
	if (jobConstrained) status += "; helper is job-constrained: host shutdown may interrupt cleanup and leave the remote buffer allocated";
	return state;
}
