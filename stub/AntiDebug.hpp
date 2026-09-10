#pragma once

#include "DynamicResolver.hpp"
#include "SyscallEngine.hpp"

namespace IronVeil {

    class AntiDebug {
    public:
        static uint32_t GetIntegrityMask(uint32_t flags, const SyscallContext& sysCtx, const ResolvedApis& apis, const void* entryPoint = nullptr) {
            uint32_t mask = 0;

            if (flags & ANTIDEBUG_PEB) {
                auto* peb = DynamicResolver::GetPeb();
                if (peb) {
                    if (peb[2] != 0) {
                        mask |= 0x01;
                    }

                    size_t ntGlobalFlagOffset = sizeof(void*) * 23 + 4;
                    uint32_t ntGlobalFlag = *reinterpret_cast<const uint32_t*>(peb + ntGlobalFlagOffset);
                    if (ntGlobalFlag & 0x70) {
                        mask |= 0x02;
                    }

                    auto* processHeap = *reinterpret_cast<uint8_t**>(peb + 0x18);
                    if (processHeap) {
                        uint32_t heapFlags = *reinterpret_cast<const uint32_t*>(processHeap + 0x70);
                        uint32_t heapForceFlags = *reinterpret_cast<const uint32_t*>(processHeap + 0x74);
                        if ((heapFlags & ~0x02u) != 0 || heapForceFlags != 0) {
                            mask |= 0x04;
                        }
                    }
                }
            }

            if (flags & ANTIDEBUG_HARDWARE_BP) {
                if (apis.RtlCaptureContext) {
                    CONTEXT ctxRecord = { 0 };
                    ctxRecord.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    apis.RtlCaptureContext(&ctxRecord);

                    if (ctxRecord.Dr0 != 0 || ctxRecord.Dr1 != 0 || 
                        ctxRecord.Dr2 != 0 || ctxRecord.Dr3 != 0 || 
                        (ctxRecord.Dr7 & 0xFF) != 0) {
                        mask |= 0x08;
                    }
                }
            }

            if (flags & ANTIDEBUG_PROCESS_INFO) {
                HANDLE hProc = apis.GetCurrentProcess ? apis.GetCurrentProcess() : reinterpret_cast<HANDLE>(-1);

                uintptr_t debugPort = 0;
                NTSTATUS stPort = SyscallEngine::QueryProcessInfo(
                    sysCtx, apis, hProc, ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
                if (stPort == 0 && debugPort != 0) {
                    mask |= 0x10;
                }

                uint32_t debugFlags = 0xFFFFFFFF;
                NTSTATUS stFlags = SyscallEngine::QueryProcessInfo(
                    sysCtx, apis, hProc, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), nullptr);
                if (stFlags == 0 && debugFlags == 0) {
                    mask |= 0x20;
                }

                HANDLE debugObj = nullptr;
                NTSTATUS stObj = SyscallEngine::QueryProcessInfo(
                    sysCtx, apis, hProc, ProcessDebugObjectHandle, &debugObj, sizeof(debugObj), nullptr);
                if (stObj == 0 && debugObj != nullptr) {
                    mask |= 0x40;
                }
            }

            if (flags & ANTIDEBUG_THREAD_HIDE) {
                HANDLE hThread = apis.GetCurrentThread ? apis.GetCurrentThread() : reinterpret_cast<HANDLE>(-2);
                SyscallEngine::SetThreadInfo(sysCtx, apis, hThread, ThreadHideFromDebugger, nullptr, 0);
            }

            if (flags & ANTIDEBUG_TIMING) {
                uint64_t t1 = __rdtsc();
                volatile uint32_t dummy = 0;
                for (int k = 0; k < 64; ++k) {
                    dummy = ((dummy ^ k) * 0x5BD1E995u) ^ (dummy >> 5);
                }
                uint64_t t2 = __rdtsc();
                if ((t2 - t1) > 200000ULL) {
                    mask |= 0x80;
                }
            }

            if (flags & ANTIDEBUG_HOOK_SCAN) {
                HMODULE hNtdll = DynamicResolver::FindModuleByHash(HASH_NTDLL_DLL);
                if (hNtdll) {
                    auto* pNtProtect = reinterpret_cast<const uint8_t*>(
                        DynamicResolver::FindExportByHash(hNtdll, HASH_NTPROTECTVIRTUALMEMORY));
                    if (pNtProtect && (pNtProtect[0] == 0xCC || pNtProtect[0] == 0xE9)) {
                        mask |= 0x100;
                    }

                    auto* pNtQip = reinterpret_cast<const uint8_t*>(
                        DynamicResolver::FindExportByHash(hNtdll, HASH_NTQUERYINFORMATIONPROCESS));
                    if (pNtQip && (pNtQip[0] == 0xCC || pNtQip[0] == 0xE9)) {
                        mask |= 0x200;
                    }
                }
            }

            if (flags & ANTIDEBUG_KUSER) {
                const volatile uint8_t* pKdEnabled = reinterpret_cast<const volatile uint8_t*>(0x7FFE02D4);
                const volatile uint8_t* pKdNotPresent = reinterpret_cast<const volatile uint8_t*>(0x7FFE02D5);
                if (*pKdEnabled != 0 || *pKdNotPresent == 0) {
                    mask |= 0x400;
                }
            }

            if ((flags & ANTIDEBUG_ENTRY_INTEGRITY) && entryPoint) {
                const auto* pEp = reinterpret_cast<const uint8_t*>(entryPoint);
                if (*pEp == 0xCC || (pEp[0] == 0xCD && pEp[1] == 0x03)) {
                    mask |= 0x800;
                }
            }

            return mask;
        }
    };

}
