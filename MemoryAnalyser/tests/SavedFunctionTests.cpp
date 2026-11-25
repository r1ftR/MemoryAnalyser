#include "../analyser/Storage/TableStore.h"

#include <Windows.h>
#include <cstdio>
#include <fstream>
#include <iterator>

namespace
{
bool Check(bool condition, const char* message)
{
	if (!condition) std::fprintf(stderr, "%s\n", message);
	return condition;
}
}

int main()
{
	using namespace analyser;
	wchar_t executable[MAX_PATH]{};
	if (!GetModuleFileNameW(nullptr, executable, MAX_PATH)) return 1;
	const std::wstring path = std::wstring(executable) + L".records";
	struct Cleanup
	{
		std::wstring path;
		~Cleanup() { DeleteFileW(path.c_str()); DeleteFileW((path + L".pending").c_str()); }
	} cleanup{ path };
	DeleteFileW(path.c_str());
	TableStore store(path);
	if (!Check(store.Load(), "A missing registry should load successfully")) return 1;

	SavedFunction function;
	auto& target = function.target;
	target.name = "Same name\n[with delimiters]";
	target.moduleName = "fixture.dll";
	target.modulePath = L"C:\\modules\\\u6A21\u5757.dll";
	target.rva = 0x1234;
	target.x64 = true;
	target.imageMachine = IMAGE_FILE_MACHINE_AMD64;
	target.imageSize = 0x10000;
	target.imageTimestamp = 123456;
	target.imageChecksum = 654321;
	target.fileId = 987654321;
	target.volumeSerial = 123;
	target.fileSize = 0x8000;
	target.fileLastWrite = 555;
	target.address = 0x7ff01234;
	target.processId = 4321;
	target.processCreation = 999;
	for (size_t i = 0; i < target.originalBytes.size(); ++i) target.originalBytes[i] = static_cast<uint8_t>(i * 17);
	function.locatorSpec = "module:fixture.dll+1234";
	store.UpsertFunction(function);
	if (!Check(store.AddFunctionProject(target, L"C:\\hooks\\\u6D4B\u8BD5\\Hook.sln"), "Project association failed") ||
		!Check(store.AddFunctionProject(target, L"c:\\HOOKS\\\u6D4B\u8BD5\\hook.sln"), "Case-insensitive project association failed") ||
		!Check(store.Functions()[0].projects.size() == 1, "Duplicate project path was added")) return 1;

	auto renamed = function;
	renamed.target.name = "Renamed";
	renamed.target.address += 0x100000;
	++renamed.target.processId;
	++renamed.target.processCreation;
	store.UpsertFunction(renamed);
	if (!Check(store.Functions().size() == 1 && store.Functions()[0].projects.size() == 1,
		"Display name or process identity changed the durable key or lost projects")) return 1;
	auto otherModule = function;
	otherModule.target.modulePath = L"C:\\other\\fixture.dll";
	store.UpsertFunction(otherModule);
	auto otherRva = function;
	++otherRva.target.rva;
	store.UpsertFunction(otherRva);
	auto otherVersion = function;
	++otherVersion.target.imageTimestamp;
	store.UpsertFunction(otherVersion);
	if (!Check(store.Functions().size() == 4, "Path, RVA, or PE version identities collided")) return 1;
	if (!Check(store.ReplaceFunctionProject(target, 0, L"D:\\moved\\Hook.sln"), "Project relinking failed") ||
		!Check(!store.ReplaceFunctionProject(target, 3, L"D:\\invalid\\Hook.sln"), "Invalid project index was accepted") ||
		!Check(!store.AddFunctionProject(target, L""), "Empty project path was accepted")) return 1;
	store.UpsertLocator({ "Legacy locator", "rva|fixture.dll|1234" });
	if (!Check(store.Save(), "Registry save failed")) return 1;

	TableStore reloaded(path);
	if (!Check(reloaded.Load(), "Registry reload failed")) return 1;
	const auto* saved = static_cast<const TableStore&>(reloaded).FindFunction(target);
	if (!Check(saved && reloaded.Functions().size() == 4, "Registry round-trip lost function identities") ||
		!Check(saved->target.name == "Renamed" && saved->target.originalBytes == target.originalBytes &&
			saved->target.modulePath == target.modulePath && saved->target.fileId == target.fileId &&
			saved->projects == std::vector<std::wstring>{ L"D:\\moved\\Hook.sln" } && saved->locatorSpec == function.locatorSpec,
			"Registry round-trip lost validation metadata, Unicode paths, or projects") ||
		!Check(!saved->target.address && !saved->target.processId && !saved->target.processCreation,
			"Ephemeral process identity was persisted") ||
		!Check(reloaded.Locators().size() == 1 && reloaded.Locators()[0].name == "Legacy locator",
			"Legacy locator round-trip regressed") ||
		!Check(reloaded.Functions()[1].target.name == function.target.name,
			"Encoded display-name delimiters failed to round-trip")) return 1;

	std::ifstream input(path);
	std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	input.close();
	const size_t bytes = text.find("bytes=");
	if (!Check(bytes != std::string::npos, "Serialized original bytes are missing")) return 1;
	text.erase(bytes, text.find('\n', bytes) - bytes + 1);
	std::ofstream output(path, std::ios::trunc);
	output << text;
	output.close();
	if (!Check(!reloaded.Load() && !reloaded.LastError().empty() && reloaded.Functions().empty(),
		"An incomplete validation snapshot was accepted")) return 1;

	TableStore unwritable(path + L"\\missing\\records.txt");
	if (!Check(!unwritable.Save() && !unwritable.LastError().empty(), "Save failure was not reported")) return 1;
	std::puts("Saved function registry tests passed");
	return 0;
}
