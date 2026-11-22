# Copilot Instructions

## Project Guidelines
- MemoryManager is a separate subsystem/repo; all memory functionality must stay in it. It may be extended with general, reusable process/module/memory functionality, but never analyser- or GUI-specific code.
- ImGuiBaseWinDx may be changed only to add generic, reusable GUI functionality.
- Keep code in clean ownership blocks:
  - ImGuiBaseWinDx (app/, platform/, ui/, third_party/, main.cpp): generic overlay/UI only. Project code plugs in via app::AppModule.
  - MemoryManager/: reusable memory functionality only (MemoryManager, ProcessDebugger, PatternScanner).
  - analyser/: all MemoryAnalyser-specific code (state, parsing, formatting, struct viewer, disassembly, symbols, function trace, static resolver/signatures/xrefs, attach UI). Only analyser/Disasm/Disassembler.cpp includes Zydis.


