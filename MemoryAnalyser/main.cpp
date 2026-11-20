#include "app/Application.h"
#include "analyser/AnalyserModule.h"

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int)
{
	analyser::AnalyserModule module;
	return app::Run(instance, module);
}

