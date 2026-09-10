#pragma once

#include "DynamicResolver.hpp"

extern "C" NTSTATUS SyscallInvoke(
    uint32_t ssn,
    const void* gadget,
    void* arg1,
    void* arg2,
    void* arg3,
    void* arg4,
    void* arg5,
    void* arg6
);

namespace IronVeil {

    struct SyscallContext {
        bool initialized;
        const void* syscallGadget;
        uint32_t ssnNtProtect;
        uint32_t ssnNtAllocate;
        uint32_t ssnNtQueryInfoProcess;
        uint32_t ssnNtSetInfoThread;
    };

    class SyscallEngine {
    private:
        static uint32_t ExtractSSN(const uint8_t* pFunc) {
            if (!pFunc) return 0;

            if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
                return *reinterpret_cast<const uint32_t*>(pFunc + 4);
            }

            for (int idx = 1; idx <= 32; ++idx) {
                const uint8_t* pDown = pFunc + (idx * 0x20);
                if (pDown[0] == 0x4C && pDown[1] == 0x8B && pDown[2] == 0xD1 && pDown[3] == 0xB8) {
                    uint32_t neighborSsn = *reinterpret_cast<const uint32_t*>(pDown + 4);
                    return neighborSsn - static_cast<uint32_t>(idx);
                }
                const uint8_t* pUp = pFunc - (idx * 0x20);
                if (pUp[0] == 0x4C && pUp[1] == 0x8B && pUp[2] == 0xD1 && pUp[3] == 0xB8) {
                    uint32_t neighborSsn = *reinterpret_cast<const uint32_t*>(pUp + 4);
                    return neighborSsn + static_cast<uint32_t>(idx);
                }
            }
            return 0;
        }

        static const void* FindSyscallGadget(const uint8_t* pStart) {
            if (!pStart) return nullptr;
            for (size_t i = 0; i < 64; ++i) {
                if (pStart[i] == 0x0F && pStart[i + 1] == 0x05 && pStart[i + 2] == 0xC3) {
                    return pStart + i;
                }
            }
            return nullptr;
        }

    public:
        static bool Initialize(SyscallContext& ctx) {
            ctx.initialized = false;
            ctx.syscallGadget = nullptr;
            ctx.ssnNtProtect = 0;
            ctx.ssnNtAllocate = 0;
            ctx.ssnNtQueryInfoProcess = 0;
            ctx.ssnNtSetInfoThread = 0;

            HMODULE hNtdll = DynamicResolver::FindModuleByHash(HASH_NTDLL_DLL);
            if (!hNtdll)
                return false;

            auto* pNtProtect = reinterpret_cast<const uint8_t*>(
                DynamicResolver::FindExportByHash(hNtdll, HASH_NTPROTECTVIRTUALMEMORY));
            if (pNtProtect) {
                ctx.ssnNtProtect = ExtractSSN(pNtProtect);
                ctx.syscallGadget = FindSyscallGadget(pNtProtect);
            }

            auto* pNtAlloc = reinterpret_cast<const uint8_t*>(
                DynamicResolver::FindExportByHash(hNtdll, HASH_NTALLOCATEVIRTUALMEMORY));
            if (pNtAlloc) {
                ctx.ssnNtAllocate = ExtractSSN(pNtAlloc);
                if (!ctx.syscallGadget) {
                    ctx.syscallGadget = FindSyscallGadget(pNtAlloc);
                }
            }

            auto* pNtQip = reinterpret_cast<const uint8_t*>(
                DynamicResolver::FindExportByHash(hNtdll, HASH_NTQUERYINFORMATIONPROCESS));
            if (pNtQip) {
                ctx.ssnNtQueryInfoProcess = ExtractSSN(pNtQip);
                if (!ctx.syscallGadget) {
                    ctx.syscallGadget = FindSyscallGadget(pNtQip);
                }
            }

            auto* pNtSit = reinterpret_cast<const uint8_t*>(
                DynamicResolver::FindExportByHash(hNtdll, HASH_NTSETINFORMATIONTHREAD));
            if (pNtSit) {
                ctx.ssnNtSetInfoThread = ExtractSSN(pNtSit);
                if (!ctx.syscallGadget) {
                    ctx.syscallGadget = FindSyscallGadget(pNtSit);
                }
            }

            ctx.initialized = (ctx.syscallGadget != nullptr && ctx.ssnNtProtect != 0);
            return ctx.initialized;
        }

        static bool ProtectMemory(const SyscallContext& ctx, const ResolvedApis& apis, 
                                  void* address, size_t size, DWORD newProtect, PDWORD oldProtect) {
            if (ctx.initialized && ctx.ssnNtProtect && ctx.syscallGadget) {
                PVOID base = address;
                SIZE_T regionSize = size;
                ULONG oldP = 0;
                HANDLE hProc = apis.GetCurrentProcess ? apis.GetCurrentProcess() : reinterpret_cast<HANDLE>(-1);

                NTSTATUS st = SyscallInvoke(
                    ctx.ssnNtProtect,
                    ctx.syscallGadget,
                    hProc,
                    &base,
                    &regionSize,
                    reinterpret_cast<void*>(static_cast<uintptr_t>(newProtect)),
                    &oldP,
                    nullptr
                );

                if (st >= 0) {
                    if (oldProtect) *oldProtect = static_cast<DWORD>(oldP);
                    return true;
                }
            }

            if (apis.NtProtectVirtualMemory) {
                PVOID base = address;
                SIZE_T regionSize = size;
                ULONG oldP = 0;
                HANDLE hProc = apis.GetCurrentProcess ? apis.GetCurrentProcess() : reinterpret_cast<HANDLE>(-1);
                NTSTATUS st = apis.NtProtectVirtualMemory(hProc, &base, &regionSize, newProtect, &oldP);
                if (st >= 0) {
                    if (oldProtect) *oldProtect = static_cast<DWORD>(oldP);
                    return true;
                }
            }

            if (apis.VirtualProtect) {
                DWORD op = 0;
                BOOL ret = apis.VirtualProtect(address, size, newProtect, &op);
                if (ret) {
                    if (oldProtect) *oldProtect = op;
                    return true;
                }
            }

            return false;
        }

        static NTSTATUS QueryProcessInfo(const SyscallContext& ctx, const ResolvedApis& apis,
                                         HANDLE hProcess, ULONG infoClass, PVOID buffer, ULONG length, PULONG retLen) {
            if (ctx.initialized && ctx.ssnNtQueryInfoProcess && ctx.syscallGadget) {
                return SyscallInvoke(
                    ctx.ssnNtQueryInfoProcess,
                    ctx.syscallGadget,
                    hProcess,
                    reinterpret_cast<void*>(static_cast<uintptr_t>(infoClass)),
                    buffer,
                    reinterpret_cast<void*>(static_cast<uintptr_t>(length)),
                    retLen,
                    nullptr
                );
            }
            if (apis.NtQueryInformationProcess) {
                return apis.NtQueryInformationProcess(hProcess, infoClass, buffer, length, retLen);
            }
            return static_cast<NTSTATUS>(0xC0000001);
        }

        static NTSTATUS SetThreadInfo(const SyscallContext& ctx, const ResolvedApis& apis,
                                      HANDLE hThread, ULONG infoClass, PVOID buffer, ULONG length) {
            if (ctx.initialized && ctx.ssnNtSetInfoThread && ctx.syscallGadget) {
                return SyscallInvoke(
                    ctx.ssnNtSetInfoThread,
                    ctx.syscallGadget,
                    hThread,
                    reinterpret_cast<void*>(static_cast<uintptr_t>(infoClass)),
                    buffer,
                    reinterpret_cast<void*>(static_cast<uintptr_t>(length)),
                    nullptr,
                    nullptr
                );
            }
            if (apis.NtSetInformationThread) {
                return apis.NtSetInformationThread(hThread, infoClass, buffer, length);
            }
            return static_cast<NTSTATUS>(0xC0000001);
        }
    };

}

