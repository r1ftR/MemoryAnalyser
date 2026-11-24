#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace library_loader_ipc
{
constexpr std::uint32_t Magic = 0x314C4C4D;
constexpr std::uint32_t Version = 1;
constexpr std::size_t MaxStatus = 1024;
constexpr DWORD PipeCapacity = 4096;
enum class Code : std::uint32_t { Pending = 1, ModuleObserved = 2, Failed = 3 };

// Fixed-width, zero-initialized wire records have identical x86/x64 layouts.
struct Request
{
	std::uint32_t magic = Magic;
	std::uint32_t version = Version;
	std::uint32_t pid = 0;
	std::uint32_t creationLow = 0;
	std::uint32_t creationHigh = 0;
	std::uint32_t volume = 0;
	std::uint32_t fileHigh = 0;
	std::uint32_t fileLow = 0;
};
struct Response
{
	std::uint32_t magic = Magic;
	std::uint32_t version = Version;
	Code code = Code::Failed;
	std::uint32_t length = 0;
	char text[MaxStatus] = {};
};
static_assert(sizeof(Request) == 32, "IPC request layout changed");
static_assert(sizeof(Response) == 1040, "IPC response layout changed");
static_assert(2 * sizeof(Response) < PipeCapacity, "Both responses must fit without a reader");

inline std::string Error(const char* operation, DWORD code = GetLastError())
{
	return std::string(operation) + " (Windows error " + std::to_string(code) + ")";
}

struct Handle
{
	HANDLE value = nullptr;
	explicit Handle(HANDLE h = nullptr) : value(h == INVALID_HANDLE_VALUE ? nullptr : h) {}
	~Handle() { if (value) CloseHandle(value); }
	Handle(const Handle&) = delete;
	Handle& operator=(const Handle&) = delete;
};

inline bool FinalPath(HANDLE file, std::wstring& path, std::string& error)
{
	DWORD length = GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	if (!length || length > 32768)
	{
		error = length ? "Resolved DLL path exceeds the Windows path limit" : Error("Could not resolve selected file path");
		return false;
	}
	std::vector<wchar_t> buffer(length);
	DWORD written = GetFinalPathNameByHandleW(file, buffer.data(), length, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
	if (!written || written >= length)
	{
		error = written ? "Selected file path changed during resolution" : Error("Could not resolve selected file path");
		return false;
	}
	path.assign(buffer.data(), written);
	return true;
}

inline bool SameFile(HANDLE a, HANDLE b)
{
	BY_HANDLE_FILE_INFORMATION left = {}, right = {};
	return GetFileInformationByHandle(a, &left) && GetFileInformationByHandle(b, &right) &&
		left.dwVolumeSerialNumber == right.dwVolumeSerialNumber &&
		left.nFileIndexHigh == right.nFileIndexHigh && left.nFileIndexLow == right.nFileIndexLow;
}

// Use the opened physical file, not the caller's possibly redirected/reparse path.
// Sysnative is resolved by both the helper and the x86 target to native System32.
inline bool TargetPath(HANDLE file, std::wstring& path, std::string& error)
{
	if (!FinalPath(file, path, error)) return false;
	std::vector<wchar_t> windows(32768);
	UINT length = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
	if (!length || length >= windows.size())
	{
		error = Error("Could not resolve the Windows directory");
		return false;
	}
	Handle directory(CreateFileW(windows.data(), FILE_READ_ATTRIBUTES,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
	std::wstring root;
	if (!directory.value || !FinalPath(directory.value, root, error))
	{
		if (!directory.value) error = Error("Could not open the Windows directory");
		return false;
	}
	if (!root.empty() && root.back() == L'\\') root.pop_back();
	const std::wstring native = root + L"\\System32\\";
	if (path.size() >= native.size() && _wcsnicmp(path.c_str(), native.c_str(), native.size()) == 0)
		path = root + L"\\Sysnative\\" + path.substr(native.size());
	Handle reopened(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
	if (!reopened.value)
	{
		error = Error("Could not reopen selected DLL in the helper/target x86 namespace");
		return false;
	}
	if (!SameFile(file, reopened.value))
	{
		error = "DLL path resolves to a different file in the helper/target x86 namespace; load refused";
		return false;
	}
	return true;
}
}
