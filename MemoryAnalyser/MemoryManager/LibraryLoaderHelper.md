# x86 library-loader helper

`LibraryLoader::Start`, `Poll`, and `State` are unchanged. Same-architecture
operations run locally. An x64 caller loading an x86 target starts
`MemoryAnalyserLoader32.exe` from the caller executable's directory. The helper
reuses the same-architecture loader; x86-to-x64 loading remains unsupported.

## Build wiring

- The application still compiles only `MemoryManager\LibraryLoader.cpp`.
- Build a separate **Win32/x86 executable** from
  `MemoryManager\LibraryLoaderHelper.cpp` and `MemoryManager\LibraryLoader.cpp`.
- Both use `MemoryManager\LibraryLoaderProtocol.h`. `LibraryLoader.cpp` includes
  `LibraryLoaderCommon.inl`, `LibraryLoaderValidation.inl`, `LibraryLoaderLocal.inl`,
  and `LibraryLoaderHelperClient.inl`; keep these alongside it and do not compile
  them separately. There are no external libraries.
- Use C++17 or newer, Windows SDK, exception handling, Unicode, and the console
  subsystem (`wmain`). Embed an **asInvoker** manifest; never request elevation.
  The parent uses `CREATE_NO_WINDOW`.
- Name the executable `MemoryAnalyserLoader32.exe` and copy it beside each
  application executable, including deployed builds. Do not compile the helper
  entry point into the application. The helper source intentionally rejects x64.

For a direct x86 developer-command-prompt build (choose an existing output folder):

```bat
cl /nologo /std:c++17 /EHsc /W4 /DUNICODE /D_UNICODE /Fo"output\\" /Fe"output\MemoryAnalyserLoader32.exe" MemoryManager\LibraryLoaderHelper.cpp MemoryManager\LibraryLoader.cpp /link /SUBSYSTEM:CONSOLE /MANIFEST:EMBED
```

## Ownership and protocol

Two inherited anonymous pipes carry a fixed 32-byte identity request and at most
one acceptance plus one terminal 1040-byte status record. Parent `Poll` peeks
before bounded reads and uses zero-time process waits. Neither destruction nor
detaching waits for, cancels, or terminates a running helper. A 30-second timeout
remains `Pending`; missing/invalid/truncated output or helper death is `Failed`
with an explicitly unknown load outcome, not evidence that the DLL did not load.

`STARTUPINFOEX` explicitly allowlists only the request reader, response writer,
verified target-process duplicate, and locked selected-file duplicate. The
helper verifies inherited process PID **and creation time**, checks file identity,
then invokes `LibraryLoader::Start` with that process handle, not a PID. No IPC
names, global rendezvous, shell launching, or elevation are used.

The helper derives a normalized physical path from the inherited selected file,
uses `Sysnative` for native `System32` files, and verifies that reopening the
x86-visible path matches the inherited file. Toolhelp enumerates module bases;
full Unicode module paths are queried separately from the held process with
`K32GetModuleFileNameExW`, because Toolhelp paths can be lossy or truncated.
Those paths are checked using normal WOW64 interpretation first and physical-file
interpretation second, always against the held file identity. A failed or truncated
path query fails closed; module verification reports an unknown outcome. Toolhelp
itself can fail to enumerate a process containing an extended-length module path;
that remains an unknown outcome, not proof the load failed. Redirection is disabled
only around one file-attribute open, never around DLL loading.

## Lifetime and limitations

The helper remains alive after IPC disconnect or ordinary parent exit until the
remote thread/target finishes and module verification/cleanup completes. It does
not depend on an open parent handle or a parent background cleanup thread. If
job breakaway is prohibited, it retries ordinary allowlisted creation and
reports that its lifetime is **job-constrained** while pending. Killing that job
can kill the helper: the remote operation may continue, its result becomes
unknown, and its path buffer may remain allocated until target exit. Helper
termination never frees a still-running remote thread's buffer. A permanently
blocked remote thread can intentionally keep an unconstrained helper alive
indefinitely. OS termination/crash can prevent eventual cleanup.

The normal Windows loader still governs target search paths, dependencies,
policy, and `DllMain`. Module observation is not proof that this invocation
caused the module to load. File locking prevents ordinary write/delete changes,
but cannot guarantee against hostile namespace/reparse or filesystem changes;
identity/path resolution failures are rejected where detectable. Keep the
helper beside the application in a trusted directory and deploy both together.

Validation: strict MSVC `/W4 /WX` compilation for x86 helper and x64 loader;
end-to-end x64-to-x86 loading in a restrictive host job, plus same-x86 and
same-x64 module-observation smoke checks. Delayed-DLL checks also verified
nonblocking `Poll`/detach, helper completion after detach, and helper-crash
reporting as unknown while the target safely finished loading the DLL.
