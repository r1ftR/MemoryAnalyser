#pragma once

#include "../app/AppModule.h"
#include "AnalyserState.h"
#include "Injector/Injector.h"
#include "Hooking/HookPanel.h"
#include "StructTable/StructTable.h"
#include "Disasm/DisasmView.h"
#include "Disasm/Pe.h"
#include "Disasm/StaticRefsView.h"
#include "Disasm/Symbols.h"
#include "Disasm/TraceView.h"
#include "../MemoryManager/MemoryManager.h"
#include "../MemoryManager/ProcessDebugger.h"

#include <memory>
#include <vector>

class MemoryManager;

namespace analyser
{
// Plugs the memory analyser into the ImGuiBaseWinDx base.
class AnalyserModule final : public app::AppModule
{
public:
	AnalyserModule();
	~AnalyserModule() override;

	void ConfigureWindow(platform::WindowConfig& config) override;
	void RenderTabs(ui::UiState& ui) override;
	void OnFrame(ui::UiState& ui) override;
	unsigned BackgroundFrameIntervalMs() const override { return 100; }
	void OnShutdown() override;

private:
	void RenderAttachSection();
	void RefreshModules();
	void RenderStructSection();
	void HandleAttachRequests();
	void Rendertables();
	void RenderDisasmSection();
	void RenderDisasmViews();
	void ClearDisasm();
	void RenderTraceViews();
	void RenderStaticRefsViews();
	void HandleSymbolRequests();
	void ApplySavedLabels();
	void RenderSavedFunctions(bool forHooking);
	void RefreshSavedFunctions();
	bool ResolveSavedFunction(const SavedFunction& saved, hooking::HookTarget& target, std::string& error);
	bool PersistStore();

	AnalyserState state;
	TableStore store;
	std::unique_ptr<MemoryManager> memory;
	Injector injector;
	hooking::HookPanel hookPanel;
	std::vector<std::unique_ptr<StructTable>> tables;
	int nextTableId = 0;
	std::vector<std::unique_ptr<DisasmView>> disasmViews;
	int nextDisasmId = 0;
	std::vector<ModuleInfo> modules;
	std::vector<disasm::PeSection> sections;
	std::unique_ptr<disasm::SymbolResolver> symbols;
	std::unique_ptr<ProcessDebugger> debugger;
	std::vector<std::unique_ptr<TraceView>> traceViews;
	int nextTraceId = 0;
	std::vector<std::unique_ptr<StaticRefsView>> staticRefsViews;
	int nextStaticRefsId = 0;
};
}
