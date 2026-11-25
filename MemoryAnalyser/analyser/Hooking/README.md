# Hook project workflow

1. Attach to a process and scan a function through **Disassembly > Find static refs at Address**,
   or the function's **Find static references** context action. Successfully validated
   module-backed functions are saved automatically in `tables.txt` beside the analyser executable.
2. Select the saved function in the **Hooking** dropdown, or right-click the report's
   **Target** text and choose **Create hook...**. Saved functions are keyed by module
   identity and RVA, not just their name. Selection resolves and validates the current
   process address; a saved address is never used as a live process address.
3. Confirm the exact function entry, then create or open its project. Visual Studio 2026
   with C++ tools is discovered explicitly. The executable field provides an explicit
   alternative installation; the Windows `.sln` association is not used.
4. Edit `Hook.cpp` to supply the real function declaration, calling convention and detour.
   The template intentionally does not compile until this is done. Build in Visual Studio;
   the solution exposes the selected target architecture and restores MinHook v1.3.4 sources.
5. A fresh successful build notifies the analyser. With automatic injection enabled,
   the analyser revalidates the target, injects the DLL, then calls `StartHook` outside
   `DllMain`. Activation requires both a completed call and a session-bound target acknowledgement.
   **Stop hook** similarly requires acknowledgement of successful disabling.

## Saved references and projects

Saved references can be reopened from Disassembly: resolving their locator starts a fresh
static references scan rather than displaying a stale report. Legacy saved locators remain
available. Trace rows show the current absolute address plus a validated module-relative
address when a saved function matches; failed resolution is identified rather than hidden.

Each saved function defaults to its existing hook solution, including after analyser restart.
**Add another project** deliberately creates an additional solution in an empty directory.
**Relink selected project...** repairs a moved solution after validating its identity.
A changed module build is a different function identity and cannot silently reuse old boilerplate.
Older projects without `Hook.identity` are not automatically converted or overwritten: preserve
or port their edited detour into an explicitly added compatible project.

Reconnecting updates only `HookSession.h` and `HookSession.props`. `Hook.cpp`, `.vcxproj`,
and other user edits remain untouched. Reload project changes in Visual Studio when prompted
and rebuild before injection. `Hook.identity` records the generation target; do not edit it
or remove the generated acknowledgement wrappers. Successful builds without a new link do
not notify, and the analyser accepts only the first matching build per session. A build is
held while automatic injection is disabled; enabling it triggers fresh target revalidation.

## Lifetime and limitations

Stop retains the DLL, target module and trampoline for callbacks already in flight; it does
not unload them. A new session can begin before loading or after confirmed stopping. The same
function cannot be loaded again in the same tracked process instance; restart the target to
rebuild/re-run it. Detaching does not erase an active or uncertain session. Reattaching to the
same process instance restores stop controls, but never authorizes a fresh injection implicitly.

Timeout, process exit, invalid status or IPC loss produces an unknown outcome, never a
success-shaped fallback. Session identifiers and same-user local IPC are not cryptographic
authentication. File/module/byte checks are not atomic and cannot prove the function ABI or
entry point. Use this workflow only on processes you own or are authorized to instrument.
