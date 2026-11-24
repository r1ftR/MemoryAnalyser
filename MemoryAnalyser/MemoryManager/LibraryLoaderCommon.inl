#pragma once

namespace
{
constexpr ULONGLONG kTimeoutMs = 30000;

struct Handle
{
	HANDLE value = nullptr;
	explicit Handle(HANDLE h = nullptr) : value(h == INVALID_HANDLE_VALUE ? nullptr : h) {}
	~Handle() { if (value) CloseHandle(value); }
	Handle(const Handle&) = delete;
	Handle& operator=(const Handle&) = delete;
	HANDLE release() { HANDLE h = value; value = nullptr; return h; }
};

std::string WinError(const char* operation, DWORD code)
{
	return std::string(operation) + " (Windows error " + std::to_string(code) + ")";
}

bool ReadAt(HANDLE file, LONGLONG offset, void* data, DWORD size)
{
	LARGE_INTEGER pos = {};
	pos.QuadPart = offset;
	DWORD read = 0;
	return SetFilePointerEx(file, pos, nullptr, FILE_BEGIN) && ReadFile(file, data, size, &read, nullptr) && read == size;
}

bool CreationTime(HANDLE process, FILETIME& creation)
{
	FILETIME exit = {}, kernel = {}, user = {};
	return GetProcessTimes(process, &creation, &exit, &kernel, &user) != FALSE;
}

}
