#pragma once

#include "HookTarget.h"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

class LibraryLoader;
class MemoryManager;
class RemoteExportCall;

namespace analyser { class TableStore; }

namespace analyser::hooking
{
class HookPanel
{
public:
	HookPanel();
	~HookPanel();

	HookPanel(const HookPanel&) = delete;
	HookPanel& operator=(const HookPanel&) = delete;

	void Select(const HookTarget& target);
	void Render(MemoryManager* memory, TableStore& store);
	void Poll(MemoryManager* memory);
	void OnDetach();
	void OnShutdown();

private:
	enum class HookPhase { NotStarted, Starting, StartReturned, Stopping, StopReturned, Unknown };

	struct BuildNotification
	{
		std::wstring session;
		std::wstring targetPath;
		std::wstring configuration;
		std::wstring platform;
		std::shared_ptr<void> fileGuard;
	};

	void GenerateAndLaunch(MemoryManager* memory, TableStore& store, bool additional = false);
	bool PrepareHookStatus(unsigned long action);
	void OpenSolution();
	void ResetSession();
	void RunBuildListener(std::wstring projectDirectory, std::wstring expectedPlatform);
	void SetStatus(std::string status);
	std::string GetStatus() const;

	std::optional<HookTarget> selectedTarget;
	std::optional<HookTarget> sessionTarget;
	std::optional<BuildNotification> pendingBuild;
	std::shared_ptr<void> builtDllGuard;
	std::shared_ptr<void> hookStatusView;
	std::shared_ptr<void> sessionProcess;
	bool targetExited = false;
	std::vector<HookTarget> attemptedTargets;
	unsigned long long exportDeadline = 0;
	bool callCompleted = false;
	unsigned long callExitCode = 0;
	char outputDirectory[32768] = {};
	char visualStudioPath[32768] = {};
	int selectedProject = 0;
	std::wstring solutionPath;
	std::wstring projectDirectory;
	std::wstring sessionId;
	std::wstring pipeName;
	std::wstring loadedDllPath;
	mutable std::mutex stateMutex;
	std::string status;
	std::thread buildListener;
	std::mutex listenerMutex;
	std::condition_variable listenerCondition;
	bool listenerReady = false;
	bool listenerFailed = false;
	std::atomic<bool> stopRequested{ false };
	std::atomic<bool> detached{ false };
	std::atomic<bool> autoInject{ true };
	bool confirmation = false;
	bool projectGenerated = false;
	bool buildProcessed = false;
	bool loadAttempted = false;
	bool dllObserved = false;
	bool shutdown = false;
	HookPhase hookPhase = HookPhase::NotStarted;
	std::unique_ptr<LibraryLoader> libraryLoad;
	std::unique_ptr<RemoteExportCall> exportCall;
};
}