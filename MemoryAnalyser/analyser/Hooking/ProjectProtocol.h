#pragma once

#include <cstdint>

namespace analyser::hooking::protocol
{
	// Little-endian, followed by session, absolute DLL path, configuration and
	// platform as UTF-16LE code units (no terminators). Do not rely on packing.
	constexpr std::uint32_t Magic = 0x4B4F4F48; // HOOK
	constexpr std::uint32_t Version = 1;
	constexpr std::uint32_t HeaderBytes = 24;
	constexpr std::uint32_t MaxPayloadCodeUnits = 32768;
	struct Header
	{
		std::uint32_t magic;
		std::uint32_t version;
		std::uint32_t sessionLength;
		std::uint32_t pathLength;
		std::uint32_t configurationLength;
		std::uint32_t platformLength;
	};
	static_assert(sizeof(Header) == HeaderBytes, "Unexpected protocol header size");

	constexpr std::uint32_t StatusMagic = 0x48535432;
	struct HookStatus
	{
		std::uint32_t magic;
		std::uint32_t version;
		std::uint32_t processId;
		std::uint32_t action; // 1 = start, 2 = stop
		std::uint32_t result;
		std::uint32_t stage;
		std::int32_t minHookStatus;
		volatile long completed;
	};
	static_assert(sizeof(HookStatus) == 32, "Unexpected lifecycle status size");
}
