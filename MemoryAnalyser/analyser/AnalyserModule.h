#pragma once

#include "../app/AppModule.h"
#include "AnalyserState.h"
#include "StructTable/StructTable.h"

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
	void OnShutdown() override;

private:
	void RenderAttachSection();
	void RenderStructSection();
	void HandleAttachRequests();
	void Rendertables();

	AnalyserState state;
	TableStore store;
	std::unique_ptr<MemoryManager> memory;
	std::vector<std::unique_ptr<StructTable>> tables;
	int nextTableId = 0;
};
}
