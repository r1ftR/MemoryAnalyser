#pragma once

#include <Windows.h>
#include <memory>
#include <string>

struct RemoteExportCallState;

// Invokes an already-loaded DLL export as a remote thread.
// Poll and destruction must not race. Destroying the object does not cancel the call.
class RemoteExportCall
{
public:
	// The export must take no arguments and return DWORD using WINAPI. A real process
	// handle with query rights and an absolute path to the loaded DLL are required.
	// The target must keep its module loaded throughout the call. File identity is
	// checked against the module's current path, not its original mapped file object.
	static std::unique_ptr<RemoteExportCall> Start(HANDLE attachedProcess, const std::wstring& absoluteDllPath,
		const char* exportName, std::string& error);

	enum class State { Pending, Completed, Failed };
	// Completed means the thread was observed signaled and the process remained
	// alive during a short grace period, not proof of a normal function return.
	// Windows cannot distinguish a return from arbitrary thread termination. Exit
	// codes with both high bits set are conservatively reported as Failed, even
	// though a successful export could return one. exitCode changes only on Completed.
	// Concurrent unload/replacement of the target module cannot be ruled out.
	State Poll(DWORD& exitCode, std::string& status);
	~RemoteExportCall();
	RemoteExportCall(const RemoteExportCall&) = delete;
	RemoteExportCall& operator=(const RemoteExportCall&) = delete;

private:
	explicit RemoteExportCall(std::shared_ptr<RemoteExportCallState> state);
	std::shared_ptr<RemoteExportCallState> state_;
};
