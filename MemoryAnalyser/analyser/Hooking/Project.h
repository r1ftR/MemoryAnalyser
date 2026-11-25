#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace analyser::hooking
{
	struct ProjectSpec
	{
		std::wstring directory;
		std::wstring moduleName;
		std::uint64_t rva;
        bool x64;
        std::wstring sessionId;
        std::wstring pipeName;
        std::wstring modulePath;
        std::uint32_t volumeSerial = 0;
        std::uint64_t fileId = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t fileLastWrite = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t imageTimestamp = 0;
        std::uint32_t imageChecksum = 0;
        std::uint16_t imageMachine = 0;
        std::array<std::uint8_t, 16> originalBytes{};
    };

    bool GenerateProject(const ProjectSpec&, std::wstring& solutionPath, std::string& error);
    bool ReconnectProject(const ProjectSpec&, std::wstring& solutionPath, std::string& error);
    bool FindVisualStudio2026(std::wstring& executable, std::string& error);
    bool OpenVisualStudio(const std::wstring& executable, const std::wstring& solutionPath, std::string& error);
}
