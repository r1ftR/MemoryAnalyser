#pragma once

#include <Windows.h>

namespace app
{
class AppModule;

int Run(HINSTANCE instance);

// Runs the base with project code plugged in through an AppModule.
int Run(HINSTANCE instance, AppModule& module);
}
