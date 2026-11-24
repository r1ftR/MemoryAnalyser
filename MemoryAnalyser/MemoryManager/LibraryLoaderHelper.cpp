#include "LibraryLoader.h"
#include "LibraryLoaderProtocol.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <limits>

#if !defined(_M_IX86)
#error MemoryAnalyserLoader32.exe must be compiled for Win32/x86.
#endif

namespace
{
using namespace library_loader_ipc;

bool ParseHandle(const wchar_t* text, HANDLE& handle)
{
	if (!text || !*text) return false;
	std::uint64_t value = 0;
	for (const wchar_t* p = text; *p; ++p)
	{
		if (*p < L'0' || *p > L'9') return false;
		value = value * 10 + static_cast<unsigned>(*p - L'0');
		if (value >= (std::numeric_limits<std::uint32_t>::max)()) return false;
	}
	if (!value) return false;
	handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
	DWORD flags = 0;
	return GetHandleInformation(handle, &flags) && (flags & HANDLE_FLAG_INHERIT) &&
		SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
}

void Send(HANDLE output, Code code, const char* text, std::size_t length)
{
	Response response = {};
	response.code = code;
	std::size_t bounded = (std::min)(length, MaxStatus);
	// Do not cut a UTF-8 sequence at the wire-size boundary.
	if (bounded < length)
		while (bounded && (static_cast<unsigned char>(text[bounded]) & 0xC0) == 0x80) --bounded;
	if (!bounded)
	{
		text = "No helper status was available; load outcome unknown";
		bounded = std::strlen(text);
	}
	response.length = static_cast<std::uint32_t>(bounded);
	std::memcpy(response.text, text, bounded);
	DWORD written = 0;
	// Only acceptance and one terminal record are ever sent. Together they fit
	// the empty response pipe; a dead parent is not needed to finish cleanup.
	WriteFile(output, &response, sizeof(response), &written, nullptr);
}

void Send(HANDLE output, Code code, const std::string& text)
{
	Send(output, code, text.data(), text.size());
}

bool RequestIdentity(HANDLE input, HANDLE process, HANDLE file, std::string& error)
{
	Request request = {};
	DWORD total = 0;
	while (total < sizeof(request))
	{
		DWORD read = 0;
		if (!ReadFile(input, reinterpret_cast<unsigned char*>(&request) + total, sizeof(request) - total, &read, nullptr) || !read)
		{
			error = Error("Could not read complete helper request");
			return false;
		}
		total += read;
	}
	if (request.magic != Magic || request.version != Version)
	{
		error = "Invalid helper request protocol";
		return false;
	}
	FILETIME creation = {}, exit = {}, kernel = {}, user = {};
	DWORD pid = GetProcessId(process);
	if (!pid || !GetProcessTimes(process, &creation, &exit, &kernel, &user))
	{
		error = Error("Inherited target process handle could not be verified");
		return false;
	}
	if (pid != request.pid || creation.dwLowDateTime != request.creationLow || creation.dwHighDateTime != request.creationHigh)
	{
		error = "Inherited target process identity does not match the request";
		return false;
	}
	DWORD wait = WaitForSingleObject(process, 0);
	if (wait != WAIT_TIMEOUT)
	{
		error = wait == WAIT_OBJECT_0 ? "Inherited target process has exited" : Error("Could not check inherited target process");
		return false;
	}
	BY_HANDLE_FILE_INFORMATION info = {};
	if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &info))
	{
		error = Error("Inherited selected DLL handle could not be verified");
		return false;
	}
	if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || info.dwVolumeSerialNumber != request.volume ||
		info.nFileIndexHigh != request.fileHigh || info.nFileIndexLow != request.fileLow)
	{
		error = "Inherited selected DLL identity does not match the request";
		return false;
	}
	return true;
}
}

int wmain(int argc, wchar_t** argv)
{
	if (argc != 6 || std::wcscmp(argv[1], L"--library-loader-helper-v1") != 0) return ERROR_INVALID_PARAMETER;
	Handle input, output, process, file;
	if (!ParseHandle(argv[2], input.value) || !ParseHandle(argv[3], output.value) ||
		!ParseHandle(argv[4], process.value) || !ParseHandle(argv[5], file.value)) return ERROR_INVALID_HANDLE;
	if (input.value == output.value || input.value == process.value || input.value == file.value ||
		output.value == process.value || output.value == file.value || process.value == file.value ||
		GetFileType(input.value) != FILE_TYPE_PIPE || GetFileType(output.value) != FILE_TYPE_PIPE) return ERROR_INVALID_HANDLE;

	try
	{
		std::string error;
		BOOL inJob = FALSE;
		if (!IsProcessInJob(GetCurrentProcess(), nullptr, &inJob))
		{
			error = Error("Could not check helper job lifetime");
			Send(output.value, Code::Failed, error);
			return ERROR_ACCESS_DENIED;
		}
		if (!RequestIdentity(input.value, process.value, file.value, error))
		{
			Send(output.value, Code::Failed, error);
			return ERROR_INVALID_DATA;
		}
		std::wstring path;
		if (!TargetPath(file.value, path, error))
		{
			Send(output.value, Code::Failed, error);
			return ERROR_INVALID_DATA;
		}
		auto loader = LibraryLoader::Start(process.value, path, error);
		if (!loader)
		{
			Send(output.value, Code::Failed, error);
			return ERROR_DLL_INIT_FAILED;
		}
		const char* accepted = inJob ? "x86 helper accepted; job shutdown may interrupt cleanup and leave the remote buffer allocated" :
			"x86 helper accepted the remote loader operation";
		Send(output.value, Code::Pending, accepted, std::strlen(accepted));
		bool reportedUnknown = false;
		for (;;)
		{
			LibraryLoader::State state = LibraryLoader::State::Pending;
			std::string status;
			try
			{
				state = loader->Poll(status);
			}
			catch (...)
			{
				// Keep the owner alive even if reporting/verification runs out of
				// memory. Destroying it and exiting could kill deferred cleanup.
				if (!reportedUnknown)
				{
					const char unknown[] = "x86 helper verification failed unexpectedly; load outcome unknown; cleanup continues";
					Send(output.value, Code::Failed, unknown, sizeof(unknown) - 1);
					reportedUnknown = true;
				}
			}
			if (state != LibraryLoader::State::Pending)
			{
				loader.reset();
				if (!reportedUnknown)
					Send(output.value, state == LibraryLoader::State::ModuleObserved ? Code::ModuleObserved : Code::Failed, status);
				return ERROR_SUCCESS;
			}
			// Timeouts and broken pipes do not cancel a possibly running thread.
			Sleep(50);
		}
	}
	catch (...)
	{
		const char unknown[] = "x86 helper setup failed unexpectedly; load outcome unknown";
		Send(output.value, Code::Failed, unknown, sizeof(unknown) - 1);
		return ERROR_NOT_ENOUGH_MEMORY;
	}
}
