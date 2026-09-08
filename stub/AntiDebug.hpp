#pragma once

#include "DynamicResolver.hpp"
#include "SyscallEngine.hpp"

namespace IronVeil {

    class AntiDebug {
    public:
        static bool PerformAllChecks(const ResolvedApis& apis, const SyscallContext& sysCtx, uint32_t flags) {
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

            if ((flags & ANTIDEBUG_NTAPI) && CheckNtApi(apis, sysCtx))
                return true;

            if ((flags & ANTIDEBUG_KERNEL_DEBUGGER) && CheckKernelDebugger(apis, sysCtx))
                return true;

            if ((flags & ANTIDEBUG_HARDWARE_BP) && CheckHardwareBreakpoints(apis))
                return true;

            if ((flags & ANTIDEBUG_TIMING_RDTSC) && CheckTiming())
                return true;

            if ((flags & ANTIDEBUG_HYPERVISOR) && CheckHypervisor())
                return true;

            if (flags & ANTIDEBUG_THREAD_CLOAK) {
                CloakCurrentThread(apis, sysCtx);
            }

            if (flags & ANTIDEBUG_PROCESS_DACL) {
                HardenProcessDacl(apis);
            }

            return false;
        }

        static bool PerformAllChecks(const ResolvedApis& apis, uint32_t flags) {
            SyscallContext sysCtx = { 0 };
            SyscallEngine::Initialize(sysCtx);
            return PerformAllChecks(apis, sysCtx, flags);
        }


        static bool IsFunctionHooked(const void* pFunc) {
            if (!pFunc) return false;
            const auto* b = static_cast<const uint8_t*>(pFunc);

            if (b[0] == 0xE9 || b[0] == 0xCC)
                return true;

            if (b[0] == 0xCD && b[1] == 0x03)
                return true;

            if (b[0] == 0x48 && b[1] == 0xB8) {
                if (b[10] == 0xFF && (b[11] == 0xE0 || b[11] == 0xE1))
                    return true;
            }

            if (b[0] == 0x49 && b[1] == 0xBA) {
                if (b[10] == 0x41 && b[11] == 0xFF && (b[12] == 0xE2 || b[12] == 0xE3))
                    return true;
            }

            if ((b[0] == 0xFF && b[1] == 0x25) || (b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x25)) {
                size_t dispOffset = (b[0] == 0x48) ? 3 : 2;
                size_t instrLen = (b[0] == 0x48) ? 7 : 6;
                int32_t disp = *reinterpret_cast<const int32_t*>(b + dispOffset);
                const auto* pTargetSlot = reinterpret_cast<const uintptr_t*>(b + instrLen + disp);
                uintptr_t target = *pTargetSlot;

                if (!DynamicResolver::IsAddressInAnyModule(target)) {
                    return true;
                }
            }

            return false;
        }

        static bool CheckHookTampering(const ResolvedApis& apis) {
            #define CHK_PTR(fn) if (IsFunctionHooked(reinterpret_cast<const void*>(fn))) return true;
            CHK_PTR(apis.NtQueryInformationProcess);
            CHK_PTR(apis.NtSetInformationThread);
            CHK_PTR(apis.NtQuerySystemInformation);
            CHK_PTR(apis.NtProtectVirtualMemory);
            CHK_PTR(apis.NtAllocateVirtualMemory);
            CHK_PTR(apis.VirtualProtect);
            CHK_PTR(apis.VirtualAlloc);
            CHK_PTR(apis.VirtualQuery);
            CHK_PTR(apis.LoadLibraryA);
            CHK_PTR(apis.GetProcAddress);
            CHK_PTR(apis.pNtOpenProcess);
            CHK_PTR(apis.pNtCreateThreadEx);
            CHK_PTR(apis.pNtTerminateProcess);
            CHK_PTR(apis.pNtReadVirtualMemory);
            CHK_PTR(apis.pNtWriteVirtualMemory);
            CHK_PTR(apis.pLdrLoadDll);
            CHK_PTR(apis.pLdrGetProcedureAddress);
            #undef CHK_PTR
            return false;
        }

        static bool CheckSyscallHooks(const ResolvedApis& apis) {
            auto isHooked = [](const void* p) -> bool {
                if (!p) return false;
                const auto* b = static_cast<const uint8_t*>(p);
                return (b[0] == 0xE9 || b[0] == 0xCC || (b[0] == 0xFF && b[1] == 0x25));
            };

            #define CHK_SC(fn) if (isHooked(reinterpret_cast<const void*>(fn))) return true;
            CHK_SC(apis.NtQueryInformationProcess);
            CHK_SC(apis.NtSetInformationThread);
            CHK_SC(apis.NtQuerySystemInformation);
            CHK_SC(apis.NtProtectVirtualMemory);
            CHK_SC(apis.NtAllocateVirtualMemory);
            CHK_SC(apis.pNtOpenProcess);
            CHK_SC(apis.pNtTerminateProcess);
            CHK_SC(apis.pNtReadVirtualMemory);
            CHK_SC(apis.pNtWriteVirtualMemory);
            #undef CHK_SC
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
            bool kdEnabled = (kuser[0x2D4] & 0x01) != 0;
            bool kdNotPresent = (kuser[0x2D5] & 0x01) != 0;
            return (kdEnabled && !kdNotPresent);
        }

        struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
            BOOLEAN KernelDebuggerEnabled;
            BOOLEAN KernelDebuggerNotPresent;
        };

        static bool CheckKernelDebugger(const ResolvedApis& apis, const SyscallContext& sysCtx) {
            SYSTEM_KERNEL_DEBUGGER_INFORMATION info = { 0, 0 };
            ULONG retLen = 0;
            NTSTATUS status = -1;
            if (sysCtx.initialized) {
                status = sysCtx.NtQuerySystemInformation(35, &info, sizeof(info), &retLen);
            }
            if (status != 0 && apis.NtQuerySystemInformation) {
                status = apis.NtQuerySystemInformation(35, &info, sizeof(info), &retLen);
            }
            if (status == 0) {
                if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent)
                    return true;
            }
            return false;
        }

        static bool CheckKernelDebugger(const ResolvedApis& apis) {
            SyscallContext sysCtx = { 0 };
            SyscallEngine::Initialize(sysCtx);
            return CheckKernelDebugger(apis, sysCtx);
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

                if (forceFlags != 0 || (flags & 0x40000060) != 0)
                    return true;
            }

            return false;
        }

        static bool CheckNtApi(const ResolvedApis& apis, const SyscallContext& sysCtx) {
            HANDLE hProcess = apis.GetCurrentProcess ? apis.GetCurrentProcess() : reinterpret_cast<HANDLE>(-1);

            uint64_t debugPort = 0;
            NTSTATUS status = -1;
            if (sysCtx.initialized) {
                status = sysCtx.NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
            }
            if (status != 0 && apis.NtQueryInformationProcess) {
                status = apis.NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
            }
            if (status == 0 && debugPort != 0)
                return true;

            uint32_t debugFlags = 1;
            status = -1;
            if (sysCtx.initialized) {
                status = sysCtx.NtQueryInformationProcess(hProcess, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), nullptr);
            }
            if (status != 0 && apis.NtQueryInformationProcess) {
                status = apis.NtQueryInformationProcess(hProcess, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), nullptr);
            }
            if (status == 0 && debugFlags == 0)
                return true;

            HANDLE debugObject = nullptr;
            status = -1;
            if (sysCtx.initialized) {
                status = sysCtx.NtQueryInformationProcess(hProcess, ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), nullptr);
            }
            if (status != 0 && apis.NtQueryInformationProcess) {
                status = apis.NtQueryInformationProcess(hProcess, ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), nullptr);
            }
            if (status == 0 && debugObject != nullptr)
                return true;

            return false;
        }

        static bool CheckNtApi(const ResolvedApis& apis) {
            SyscallContext sysCtx = { 0 };
            SyscallEngine::Initialize(sysCtx);
            return CheckNtApi(apis, sysCtx);
        }

        static bool CheckHardwareBreakpoints(const ResolvedApis& apis) {
            alignas(16) CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (apis.RtlCaptureContext) {
                apis.RtlCaptureContext(&ctx);
                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 || (ctx.Dr7 & 0x55) != 0) {
                    if (apis.SetThreadContext && apis.GetCurrentThread) {
                        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = ctx.Dr6 = ctx.Dr7 = 0;
                        apis.SetThreadContext(apis.GetCurrentThread(), &ctx);
                    }
                    return true;
                }
            }

            if (apis.GetThreadContext && apis.GetCurrentThread) {
                alignas(16) CONTEXT fallbackCtx = { 0 };
                fallbackCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (apis.GetThreadContext(apis.GetCurrentThread(), &fallbackCtx)) {
                    if (fallbackCtx.Dr0 != 0 || fallbackCtx.Dr1 != 0 || fallbackCtx.Dr2 != 0 || fallbackCtx.Dr3 != 0 || (fallbackCtx.Dr7 & 0x55) != 0) {
                        if (apis.SetThreadContext) {
                            fallbackCtx.Dr0 = fallbackCtx.Dr1 = fallbackCtx.Dr2 = fallbackCtx.Dr3 = fallbackCtx.Dr6 = fallbackCtx.Dr7 = 0;
                            apis.SetThreadContext(apis.GetCurrentThread(), &fallbackCtx);
                        }
                        return true;
                    }
                }
            }
            return false;
        }

        static bool CheckTiming() {
            uint64_t minDelta = 0xFFFFFFFFFFFFFFFFULL;
            volatile uint64_t hash = 0xCBF29CE484222325ULL;

            for (int sample = 0; sample < 10; ++sample) {
                unsigned int aux = 0;
                _mm_lfence();
                uint64_t t1 = __rdtscp(&aux);
                for (int i = 0; i < 32; ++i) {
                    hash = (hash ^ (i * 0x5A)) * 0x100000001B3ULL;
                }
                _mm_lfence();
                uint64_t t2 = __rdtscp(&aux);
                uint64_t delta = (t2 > t1) ? (t2 - t1) : 0;
                if (delta < minDelta) {
                    minDelta = delta;
                }
            }

            if (minDelta > 250000 || hash == 0) return true;

            uint32_t tick1 = *reinterpret_cast<volatile uint32_t*>(0x7FFE0320);
            for (volatile int k = 0; k < 5000; ++k);
            uint32_t tick2 = *reinterpret_cast<volatile uint32_t*>(0x7FFE0320);
            if ((tick2 - tick1) > 200) return true;

            return false;
        }

        static bool CheckHypervisor() {
            int cpuInfo[4] = { 0 };
            __cpuid(cpuInfo, 1);
            if ((cpuInfo[2] & (1 << 31)) != 0) {
                __cpuid(cpuInfo, 0x40000000);
                char vendor[13] = { 0 };
                *reinterpret_cast<int*>(vendor + 0) = cpuInfo[1];
                *reinterpret_cast<int*>(vendor + 4) = cpuInfo[2];
                *reinterpret_cast<int*>(vendor + 8) = cpuInfo[3];
                vendor[12] = '\0';

                constexpr uint32_t HASH_VMWARE = HashDJB2("VMwareVMware");
                constexpr uint32_t HASH_VBOX   = HashDJB2("VBoxVBoxVBox");
                constexpr uint32_t HASH_KVM    = HashDJB2("KVMKVMKVM");
                constexpr uint32_t HASH_XEN    = HashDJB2("XenVMMXenVMM");

                uint32_t vHash = HashDJB2(vendor);
                if (vHash == HASH_VMWARE || vHash == HASH_VBOX || vHash == HASH_KVM || vHash == HASH_XEN) {
                    return true;
                }
            }
            return false;
        }

        static void CloakCurrentThread(const ResolvedApis& apis, const SyscallContext& sysCtx) {
            HANDLE hThread = apis.GetCurrentThread ? apis.GetCurrentThread() : reinterpret_cast<HANDLE>(-2);
            if (sysCtx.initialized) {
                sysCtx.NtSetInformationThread(hThread, ThreadHideFromDebugger, nullptr, 0);
            } else if (apis.NtSetInformationThread) {
                apis.NtSetInformationThread(hThread, ThreadHideFromDebugger, nullptr, 0);
            }
        }

        static void CloakCurrentThread(const ResolvedApis& apis) {
            SyscallContext sysCtx = { 0 };
            SyscallEngine::Initialize(sysCtx);
            CloakCurrentThread(apis, sysCtx);
        }

        static void HardenProcessDacl(const ResolvedApis& apis) {
            constexpr uint32_t HASH_ADVAPI32 = HashDJB2CaseInsensitive("advapi32.dll");
            HMODULE hAdvapi = DynamicResolver::FindModuleByHash(HASH_ADVAPI32);
            if (!hAdvapi && apis.LoadLibraryA) {
                hAdvapi = apis.LoadLibraryA("advapi32.dll");
            }
            if (!hAdvapi) return;

            using t_ConvertStringSD = BOOL(WINAPI*)(LPCSTR, DWORD, PSECURITY_DESCRIPTOR*, PULONG);
            using t_SetKernelObjectSecurity = BOOL(WINAPI*)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
            using t_LocalFree = HLOCAL(WINAPI*)(HLOCAL);

            auto fnConvert = reinterpret_cast<t_ConvertStringSD>(
                DynamicResolver::FindExportByHash(hAdvapi, HashDJB2("ConvertStringSecurityDescriptorToSecurityDescriptorA")));
            auto fnSetSec = reinterpret_cast<t_SetKernelObjectSecurity>(
                DynamicResolver::FindExportByHash(hAdvapi, HashDJB2("SetKernelObjectSecurity")));

            constexpr uint32_t HASH_KERNEL32 = HashDJB2CaseInsensitive("kernel32.dll");
            HMODULE hKernel32 = DynamicResolver::FindModuleByHash(HASH_KERNEL32);
            auto fnLocalFree = hKernel32 ? reinterpret_cast<t_LocalFree>(
                DynamicResolver::FindExportByHash(hKernel32, HashDJB2("LocalFree"))) : nullptr;

            if (fnConvert && fnSetSec && apis.GetCurrentProcess) {
                PSECURITY_DESCRIPTOR pSD = nullptr;
                if (fnConvert("D:(D;;0x0010;;;WD)(D;;0x0020;;;WD)(A;;GA;;;OW)", 1, &pSD, nullptr)) {
                    fnSetSec(apis.GetCurrentProcess(), DACL_SECURITY_INFORMATION, pSD);
                    if (fnLocalFree && pSD) {
                        fnLocalFree(pSD);
                    }
                }
            }
        }
    };

}
