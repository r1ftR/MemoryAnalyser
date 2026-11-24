#pragma once

#include <Windows.h>
#include <memory>
#include <string>

struct LibraryLoaderLocalState;
struct LibraryLoaderHelperState;

// Owns one remote LoadLibraryW operation. Poll and destruction must not race.
class LibraryLoader
{
public:
	// attachedProcess must be a real handle with process query rights, not a pseudo-handle.
	// x64-to-x86 uses MemoryAnalyserLoader32.exe beside the current executable.
	static std::unique_ptr<LibraryLoader> Start(HANDLE attachedProcess, const std::wstring& absolutePath, std::string& error);

	// Failed includes indeterminate outcomes (including helper loss); inspect status.
	// A timeout remains Pending. ModuleObserved means a module and exit code match,
	// but cannot prove that the thread did not terminate with a coincident code or
	// that this load caused the module to appear.
	enum class State { Pending, ModuleObserved, Failed };
	State Poll(std::string& status);
	~LibraryLoader();

	LibraryLoader(const LibraryLoader&) = delete;
	LibraryLoader& operator=(const LibraryLoader&) = delete;

private:
	LibraryLoader() = default;
	std::unique_ptr<LibraryLoaderHelperState> helper;
	std::unique_ptr<LibraryLoaderLocalState> local;
};
