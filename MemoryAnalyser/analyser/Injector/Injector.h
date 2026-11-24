#pragma once

#include <functional>
#include <memory>
#include <string>

class LibraryLoader;
class MemoryManager;

namespace analyser
{
struct AttachState;

class Injector
{
public:
	Injector();
	~Injector();

	void Render(const AttachState& attach, MemoryManager* memory);
	void Poll(MemoryManager* memory, const std::function<bool()>& refreshModules);
	void OnDetach();
	void OnShutdown();

private:
	char libraryPath[131072] = {};
	std::string libraryStatus = "Select a DLL to load into the attached process.";
	std::unique_ptr<LibraryLoader> libraryLoad;
	bool libraryLoadMatchesAttachment = false;
	std::string libraryLoadTarget;
};
}
