#pragma once

#include "DynamicResolver.hpp"

namespace IronVeil {

    class AntiDebug {
    public:
        static bool PerformAllChecks(const ResolvedApis& apis, uint32_t flags) {
            if ((flags & ANTIDEBUG_HOOK_TAMPER) && CheckHookTampering(apis))
                return true;

            if ((flags & ANTIDEBUG_SYSCALL_HOOKS) && CheckSyscallHooks(apis))
                return true;

            if ((flags & ANTIDEBUG_NETWORK_HOOKS) && CheckNetworkHooks())
                return true;

            if ((flags & ANTIDEBUG_VM_MEMORY_HOOKS) && CheckMemoryHooks(apis))
                return true;

            if ((flags & ANTIDEBUG_PEB) && CheckPeb())
                return true;

            if ((flags & ANTIDEBUG_KUSER_SHARED) && CheckKUserSharedData())
                return true;

            if ((flags & ANTIDEBUG_NTAPI) && CheckNtApi(apis))
                return true;

            if ((flags & ANTIDEBUG_KERNEL_DEBUGGER) && CheckKernelDebugger(apis))
                return true;

            if ((flags & ANTIDEBUG_HARDWARE_BP) && CheckHardwareBreakpoints(apis))
                return true;

            if ((flags & ANTIDEBUG_TIMING_RDTSC) && CheckTiming())
                return true;

            if (flags & ANTIDEBUG_THREAD_CLOAK) {
                CloakCurrentThread(apis);
            }

            return false;
        }

        static bool IsAddressInModule(uintptr_t addr, HMODULE hMod) {
            if (!hMod || !addr) return false;
            auto* base = reinterpret_cast<const uint8_t*>(hMod);
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
            uintptr_t modStart = reinterpret_cast<uintptr_t>(base);
            uintptr_t modEnd = modStart + nt->OptionalHeader.SizeOfImage;
            return (addr >= modStart && addr < modEnd);
        }

        static bool IsFunctionHooked(const void* pFunc) {
            if (!pFunc) return false;
            const auto* b = static_cast<const uint8_t*>(pFunc);

            if (b[0] == 0xE9 || b[0] == 0xEB || b[0] == 0xCC || b[0] == 0xE8)
                return true;

            if (b[0] == 0xCD && b[1] == 0x03)
                return true;

            if (b[0] == 0x48 && (b[1] == 0xB8 || b[1] == 0xBA || b[1] == 0xB9 || b[1] == 0xBB))
                return true;

            if (b[0] == 0x49 && (b[1] == 0xBA || b[1] == 0xBB || b[1] == 0xB8 || b[1] == 0xB9))
                return true;

            if (b[0] == 0x68)
                return true;

            if (b[0] == 0x0F && b[1] == 0x0B)
                return true;

            if ((b[0] == 0xFF && b[1] == 0x25) || (b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x25)) {
                size_t dispOffset = (b[0] == 0x48) ? 3 : 2;
                size_t instrLen = (b[0] == 0x48) ? 7 : 6;
                int32_t disp = *reinterpret_cast<const int32_t*>(b + dispOffset);
                const auto* pTargetSlot = reinterpret_cast<const uintptr_t*>(b + instrLen + disp);
                uintptr_t target = *pTargetSlot;

                HMODULE hKb = DynamicResolver::FindModuleByHash(HashDJB2CaseInsensitive("kernelbase.dll"));
                HMODULE hK32 = DynamicResolver::FindModuleByHash(HashDJB2CaseInsensitive("kernel32.dll"));
                HMODULE hNt = DynamicResolver::FindModuleByHash(HashDJB2CaseInsensitive("ntdll.dll"));

                if (!IsAddressInModule(target, hKb) && !IsAddressInModule(target, hK32) && !IsAddressInModule(target, hNt)) {
                    return true;
                }
            }

            return false;
        }

        static bool CheckHookTampering(const ResolvedApis& apis) {
            const void* targets[] = {
                reinterpret_cast<const void*>(apis.NtQueryInformationProcess),
                reinterpret_cast<const void*>(apis.NtSetInformationThread),
                reinterpret_cast<const void*>(apis.NtQuerySystemInformation),
                reinterpret_cast<const void*>(apis.NtProtectVirtualMemory),
                reinterpret_cast<const void*>(apis.NtAllocateVirtualMemory),
                reinterpret_cast<const void*>(apis.VirtualProtect),
                reinterpret_cast<const void*>(apis.VirtualAlloc),
                reinterpret_cast<const void*>(apis.VirtualQuery),
                reinterpret_cast<const void*>(apis.LoadLibraryA),
                reinterpret_cast<const void*>(apis.GetProcAddress),
                reinterpret_cast<const void*>(apis.pNtOpenProcess),
                reinterpret_cast<const void*>(apis.pNtCreateThreadEx),
                reinterpret_cast<const void*>(apis.pNtTerminateProcess),
                reinterpret_cast<const void*>(apis.pNtReadVirtualMemory),
                reinterpret_cast<const void*>(apis.pNtWriteVirtualMemory),
                reinterpret_cast<const void*>(apis.pLdrLoadDll),
                reinterpret_cast<const void*>(apis.pLdrGetProcedureAddress)
            };

            for (const auto* target : targets) {
                if (target && IsFunctionHooked(target))
                    return true;
            }

            return false;
        }

        static bool CheckSyscallHooks(const ResolvedApis& apis) {
            auto isSyscallTampered = [](const void* pFunc) -> bool {
                if (!pFunc) return false;
                const auto* b = static_cast<const uint8_t*>(pFunc);
                if (b[0] != 0x4C || b[1] != 0x8B || b[2] != 0xD1 || b[3] != 0xB8)
                    return true;
                return false;
            };

            const void* syscallTargets[] = {
                reinterpret_cast<const void*>(apis.NtQueryInformationProcess),
                reinterpret_cast<const void*>(apis.NtSetInformationThread),
                reinterpret_cast<const void*>(apis.NtQuerySystemInformation),
                reinterpret_cast<const void*>(apis.NtProtectVirtualMemory),
                reinterpret_cast<const void*>(apis.NtAllocateVirtualMemory),
                reinterpret_cast<const void*>(apis.pNtOpenProcess),
                reinterpret_cast<const void*>(apis.pNtTerminateProcess),
                reinterpret_cast<const void*>(apis.pNtReadVirtualMemory),
                reinterpret_cast<const void*>(apis.pNtWriteVirtualMemory)
            };

            for (const auto* target : syscallTargets) {
                if (target && isSyscallTampered(target))
                    return true;
            }

            return false;
        }

        static bool CheckNetworkHooks() {
            HMODULE hWininet = DynamicResolver::FindModuleByHash(HashDJB2CaseInsensitive("wininet.dll"));
            if (hWininet) {
                FARPROC pInternetOpenA = DynamicResolver::FindExportByHash(hWininet, HashDJB2("InternetOpenA"));
                FARPROC pInternetOpenW = DynamicResolver::FindExportByHash(hWininet, HashDJB2("InternetOpenW"));
                FARPROC pHttpOpenRequestA = DynamicResolver::FindExportByHash(hWininet, HashDJB2("HttpOpenRequestA"));
                FARPROC pHttpSendRequestA = DynamicResolver::FindExportByHash(hWininet, HashDJB2("HttpSendRequestA"));
                FARPROC pInternetReadFile = DynamicResolver::FindExportByHash(hWininet, HashDJB2("InternetReadFile"));

                if (IsFunctionHooked(reinterpret_cast<const void*>(pInternetOpenA))) return true;
                if (IsFunctionHooked(reinterpret_cast<const void*>(pInternetOpenW))) return true;
                if (IsFunctionHooked(reinterpret_cast<const void*>(pHttpOpenRequestA))) return true;
                if (IsFunctionHooked(reinterpret_cast<const void*>(pHttpSendRequestA))) return true;
                if (IsFunctionHooked(reinterpret_cast<const void*>(pInternetReadFile))) return true;
            }

            HMODULE hWs2 = DynamicResolver::FindModuleByHash(HashDJB2CaseInsensitive("ws2_32.dll"));
            if (hWs2) {
                FARPROC pConnect = DynamicResolver::FindExportByHash(hWs2, HashDJB2("connect"));
                FARPROC pSend = DynamicResolver::FindExportByHash(hWs2, HashDJB2("send"));
                FARPROC pRecv = DynamicResolver::FindExportByHash(hWs2, HashDJB2("recv"));

                if (IsFunctionHooked(reinterpret_cast<const void*>(pConnect))) return true;
                if (IsFunctionHooked(reinterpret_cast<const void*>(pSend))) return true;
                if (IsFunctionHooked(reinterpret_cast<const void*>(pRecv))) return true;
            }

            return false;
        }

        static bool CheckMemoryHooks(const ResolvedApis& apis) {
            if (!apis.VirtualQuery)
                return false;

            const void* targets[] = {
                reinterpret_cast<const void*>(apis.VirtualProtect),
                reinterpret_cast<const void*>(apis.VirtualAlloc),
                reinterpret_cast<const void*>(apis.NtQueryInformationProcess)
            };

            for (const auto* target : targets) {
                if (!target) continue;
                MEMORY_BASIC_INFORMATION mbi = { 0 };
                if (apis.VirtualQuery(target, &mbi, sizeof(mbi))) {
                    if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_READWRITE)
                        return true;
                }
            }

            return false;
        }

        static bool CheckKUserSharedData() {
            const auto* kuser = reinterpret_cast<const uint8_t*>(0x7FFE0000);
            uint8_t kdFlags = kuser[0x2D4];
            if (kdFlags & 0x01) {
                return true;
            }
            return false;
        }

        struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
            BOOLEAN KernelDebuggerEnabled;
            BOOLEAN KernelDebuggerNotPresent;
        };

        static bool CheckKernelDebugger(const ResolvedApis& apis) {
            if (!apis.NtQuerySystemInformation)
                return false;

            SYSTEM_KERNEL_DEBUGGER_INFORMATION info = { 0, 0 };
            ULONG retLen = 0;
            NTSTATUS status = apis.NtQuerySystemInformation(35, &info, sizeof(info), &retLen);
            if (status == 0) {
                if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent)
                    return true;
            }
            return false;
        }

        static bool CheckPeb() {
            auto* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
            if (!peb)
                return false;

            if (peb[2] != 0)
                return true;

            uint32_t ntGlobalFlag = *reinterpret_cast<uint32_t*>(peb + 0xBC);
            if (ntGlobalFlag & 0x70)
                return true;

            auto* processHeap = *reinterpret_cast<uint8_t**>(peb + 0x30);
            if (processHeap) {
                uint32_t flags = *reinterpret_cast<uint32_t*>(processHeap + 0x70);
                uint32_t forceFlags = *reinterpret_cast<uint32_t*>(processHeap + 0x74);

                if ((flags & ~0x00000002) != 0 && forceFlags != 0) {
                    if (forceFlags != 0)
                        return true;
                }
            }

            return false;
        }

        static bool CheckNtApi(const ResolvedApis& apis) {
            if (!apis.NtQueryInformationProcess || !apis.GetCurrentProcess)
                return false;

            HANDLE hProcess = apis.GetCurrentProcess();

            uint64_t debugPort = 0;
            NTSTATUS status = apis.NtQueryInformationProcess(
                hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
            if (status == 0 && debugPort != 0)
                return true;

            uint32_t debugFlags = 1;
            status = apis.NtQueryInformationProcess(
                hProcess, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), nullptr);
            if (status == 0 && debugFlags == 0)
                return true;

            HANDLE debugObject = nullptr;
            status = apis.NtQueryInformationProcess(
                hProcess, ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), nullptr);
            if (status == 0 && debugObject != nullptr)
                return true;

            return false;
        }

        static bool CheckHardwareBreakpoints(const ResolvedApis& apis) {
            if (!apis.GetThreadContext || !apis.GetCurrentThread)
                return false;

            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (apis.GetThreadContext(apis.GetCurrentThread(), &ctx)) {
                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || (ctx.Dr7 & 0x55) != 0) {
                    if (apis.SetThreadContext) {
                        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr6 = ctx.Dr7 = 0;
                        apis.SetThreadContext(apis.GetCurrentThread(), &ctx);
                    }
                    return true;
                }
            }
            return false;
        }

        static bool CheckTiming() {
            uint64_t start = __rdtsc();
            volatile int dummy = 0;
            for (int i = 0; i < 100; ++i) {
                dummy += i;
            }
            uint64_t delta1 = __rdtsc() - start;

            start = __rdtsc();
            for (int i = 0; i < 100; ++i) {
                dummy ^= i;
            }
            uint64_t delta2 = __rdtsc() - start;

            if (delta1 > 500000 || delta2 > 500000)
                return true;

            return false;
        }

        static void CloakCurrentThread(const ResolvedApis& apis) {
            if (apis.NtSetInformationThread && apis.GetCurrentThread) {
                apis.NtSetInformationThread(apis.GetCurrentThread(), ThreadHideFromDebugger, nullptr, 0);
            }
        }
    };

}
