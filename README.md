# IronVeil

A lightweight x64 PE protector / packer written in C++17 and MASM. 

This is mostly a learning project and a base to work up from. It's definitely not the best or unbreakable like commercial solutions (VMP / Themida), but it's a solid foundation for experimenting with Windows internals, binary protection, and evasive stub techniques.

---

## What it does

- **Section Encryption**: Encrypts target sections (`.text`, optional `.rdata`) with 256-bit ChaCha20.
- **Freestanding Stub**: Custom unpacker stub without MSVC CRT dependencies (`/NODEFAULTLIB`).
- **Indirect Syscalls**: Uses TartarusGate / Halo's Gate style neighbor scanning to get SSNs even if ntdll is hooked by user-mode EDRs/debuggers, then jumps to a syscall gadget inside `ntdll.dll`.
- **Polymorphic IAT Thunking**: Instead of pointing the real IAT directly to system DLLs, it routes imports through dynamic jump thunks in `.text1` with rotating arithmetic operations (`xor`, `sub`, `add`) and scratch register variations (`r10`, `r11`, `rax`).
- **Decoy Imports**: Injects a realistic import table (`kernel32`, `vcruntime140`, `ucrtbase`) to make static PE analysis look normal.
- **Anti-Debug & Telemetry**:
  - PEB checks (`BeingDebugged`, `NtGlobalFlag`, heap flags)
  - Hardware breakpoint detection (`DR0`-`DR3`, `DR7`) via `RtlCaptureContext`
  - Kernel debug object queries via indirect syscalls (`ProcessDebugPort`, `ProcessDebugFlags`, `ProcessDebugObjectHandle`)
  - `ThreadHideFromDebugger`
  - `RDTSC` timing delta checks
  - Direct `KUSER_SHARED_DATA` dereference (`0x7FFE02D4` / `0x7FFE02D5`)
  - Entrypoint breakpoint watchdog
  - Key poisoning: detected tampering modifies the key canary silently so decryption fails into garbage code rather than calling a noisy `ExitProcess`.
- **Prologue Slicing**: Slices initial stack adjustment instructions (`sub rsp, imm`) at OEP, executes them inside the stub, and leaves the on-disk OEP filled with `0xCC` traps.
- **Anti-Dump**: Neutralizes section names and wipes import/debug data directories in memory prior to jumping to OEP.
- **IronVM (SDK)**: Small custom bytecode virtual machine included for protecting critical logic/license routines.

---

## Building

Requires Visual Studio (2019 or 2022) with C++ Desktop tools and CMake:

```cmd
mkdir build
cd build
cmake -A x64 ..
cmake --build . --config Release
```

Binaries will be output to `bin/Release/`:
- `IronVeil.exe` (Protector CLI)
- `IronVeilStub.dll` (Unpacker payload)
- `TestTarget.exe` (Sample target)

---

## Usage

```cmd
IronVeil.exe <input.exe> [output.exe] [options]
```

### Options

- `--encrypt-rdata`: Also encrypts the `.rdata` section.
- `--no-antidebug`: Disables runtime anti-debug checks.
- `--no-relocs`: Skips base relocation processing.
- `--no-pdata`: Disables exception directory dynamic registration.
- `--section-name <str>`: Custom name for the injected stub section (defaults to `.text1`).

Example:
```cmd
IronVeil.exe target.exe target_protected.exe
```

---

## Notes

This is intended as an educational proof-of-concept / research base. There's always room to improve (adding full control-flow flattening, expanding VM handlers, handling more relocation types, etc.). PRs and suggestions are welcome.
