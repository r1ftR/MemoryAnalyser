# Copilot Instructions

## Project Guidelines
- MemoryManager is a separate subsystem/repo; all memory functionality must stay in it and the app must only use its public API without modifying it.
- Keep code in clean ownership blocks:
  - ImGuiBaseWinDx (app/, platform/, ui/, third_party/, main.cpp): generic overlay/UI only. Project code plugs in via app::AppModule.
  - MemoryManager/: reusable memory functionality only.
  - analyser/: all MemoryAnalyser-specific code (state, parsing, formatting, struct viewer, attach UI).


