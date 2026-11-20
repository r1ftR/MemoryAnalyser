#pragma once

#include <string>
#include <vector>

namespace ui
{
struct FeatureOption
{
	std::string name;
	bool enabled = false;
	unsigned int toggleKey = 0;
	bool waitingForKey = false;
};

struct UiState
{
	bool showMainPanel = true;
	bool exitRequested = false;
	FeatureOption menuToggle{ "Menu toggle", true, 0x2D, false };

	// Add your own features in app/Application.cpp (see RegisterFeatures).
	std::vector<FeatureOption> features;
};
}

