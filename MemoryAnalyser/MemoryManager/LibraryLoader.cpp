#include "LibraryLoader.h"
#include "LibraryLoaderProtocol.h"

#include <TlHelp32.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <new>
#include <vector>

#include "LibraryLoaderCommon.inl"
#include "LibraryLoaderValidation.inl"
#include "LibraryLoaderLocal.inl"
#include "LibraryLoaderHelperClient.inl"

std::unique_ptr<LibraryLoader> LibraryLoader::Start(HANDLE attachedProcess, const std::wstring& absolutePath, std::string& error)
{
	error.clear();
	Handle original, target, file;
	DWORD pid = 0;
	USHORT currentMachine = 0, targetMachine = 0;
	if (!PrepareLoad(attachedProcess, absolutePath, original, target, file, pid, currentMachine, targetMachine, error)) return nullptr;
	auto loader = std::unique_ptr<LibraryLoader>(new LibraryLoader());
#if defined(_M_X64)
	if (currentMachine != targetMachine)
	{
		loader->helper = LibraryLoaderHelperState::Start(target.value, file.value, error);
		if (!loader->helper) return nullptr;
		return loader;
	}
#endif
	loader->local = LibraryLoaderLocalState::Start(target, file, pid, absolutePath, error);
	if (!loader->local) return nullptr;
	return loader;
}

LibraryLoader::State LibraryLoader::Poll(std::string& status)
{
	return helper ? helper->Poll(status) : local->Poll(status);
}

LibraryLoader::~LibraryLoader() = default;