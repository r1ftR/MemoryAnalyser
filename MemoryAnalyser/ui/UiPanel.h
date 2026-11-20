#pragma once

#include "UiState.h"

namespace ui
{
class UiPanel
{
public:
	virtual ~UiPanel() = default;

	virtual void Render(UiState& state) = 0;
};
}

