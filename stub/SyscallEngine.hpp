#pragma once

#include "DynamicResolver.hpp"

extern "C" NTSTATUS SyscallInvoke(uint32_t ssn, uintptr_t gadget, ...);

namespace IronVeil {

    struct SyscallContext {
        uintptr_t ntdllBase;
        uintptr_t codeStart;
        uintptr_t codeEnd;
        uintptr_t syscallGadget;
        int32_t   stride;
        bool initialized;

        int32_t GetSsnByHash(uint32_t zwHash) const {
            HMODULE hNtdll = reinterpret_cast<HMODULE>(ntdllBase);
            if (!hNtdll) {
                constexpr uint32_t HASH_NTDLL = HashDJB2CaseInsensitive("ntdll.dll");
                hNtdll = DynamicResolver::FindModuleByHash(HASH_NTDLL);
                if (!hNtdll) return -1;
            }

            FARPROC pProc = DynamicResolver::FindExportByHash(hNtdll, zwHash);
            if (!pProc) return -1;

            const uint8_t* pFunc = reinterpret_cast<const uint8_t*>(pProc);

            if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
                return *reinterpret_cast<const int32_t*>(pFunc + 4);
            }

            int32_t s = (stride > 0) ? stride : 32;
            constexpr int32_t MAX_STEPS = 64;

            for (int32_t step = 1; step <= MAX_STEPS; ++step) {
                const uint8_t* pDown = pFunc + (step * s);
                if (codeEnd == 0 || (reinterpret_cast<uintptr_t>(pDown) + 32 <= codeEnd)) {
                    if (pDown[0] == 0x4C && pDown[1] == 0x8B && pDown[2] == 0xD1 && pDown[3] == 0xB8) {
                        int32_t neighborSsn = *reinterpret_cast<const int32_t*>(pDown + 4);
                        return neighborSsn - step;
                    }
                }

                const uint8_t* pUp = pFunc - (step * s);
                if (codeStart == 0 || (reinterpret_cast<uintptr_t>(pUp) >= codeStart)) {
                    if (pUp[0] == 0x4C && pUp[1] == 0x8B && pUp[2] == 0xD1 && pUp[3] == 0xB8) {
                        int32_t neighborSsn = *reinterpret_cast<const int32_t*>(pUp + 4);
                        return neighborSsn + step;
                    }
                }
            }

            int32_t altStride = (s == 32) ? 16 : 32;
            for (int32_t step = 1; step <= MAX_STEPS; ++step) {
                const uint8_t* pDown = pFunc + (step * altStride);
                if (codeEnd == 0 || (reinterpret_cast<uintptr_t>(pDown) + 32 <= codeEnd)) {
                    if (pDown[0] == 0x4C && pDown[1] == 0x8B && pDown[2] == 0xD1 && pDown[3] == 0xB8) {
                        int32_t neighborSsn = *reinterpret_cast<const int32_t*>(pDown + 4);
                        return neighborSsn - step;
                    }
                }

                const uint8_t* pUp = pFunc - (step * altStride);
                if (codeStart == 0 || (reinterpret_cast<uintptr_t>(pUp) >= codeStart)) {
                    if (pUp[0] == 0x4C && pUp[1] == 0x8B && pUp[2] == 0xD1 && pUp[3] == 0xB8) {
                        int32_t neighborSsn = *reinterpret_cast<const int32_t*>(pUp + 4);
                        return neighborSsn + step;
                    }
                }
            }

            return -1;
        }

        uintptr_t EnsureGadget() const {
            if (syscallGadget != 0) return syscallGadget;
            HMODULE hNtdll = reinterpret_cast<HMODULE>(ntdllBase);
            if (!hNtdll) {
                constexpr uint32_t HASH_NTDLL = HashDJB2CaseInsensitive("ntdll.dll");
                hNtdll = DynamicResolver::FindModuleByHash(HASH_NTDLL);
                if (!hNtdll) return 0;
            }

            constexpr uint32_t KNOWN_ZW_HASHES[] = {
                HashDJB2("ZwProtectVirtualMemory"),
                HashDJB2("ZwQueryInformationProcess"),
                HashDJB2("ZwAllocateVirtualMemory"),
                HashDJB2("ZwClose"),
                HashDJB2("ZwSetInformationThread")
            };

            for (uint32_t h : KNOWN_ZW_HASHES) {
                FARPROC p = DynamicResolver::FindExportByHash(hNtdll, h);
                if (p) {
                    const uint8_t* pBytes = reinterpret_cast<const uint8_t*>(p);
                    for (size_t k = 0; k < 32; ++k) {
                        if (pBytes[k] == 0x0F && pBytes[k + 1] == 0x05 && pBytes[k + 2] == 0xC3) {
                            return reinterpret_cast<uintptr_t>(pBytes + k);
                        }
                    }
                }
            }
            return 0;
        }

        NTSTATUS NtProtectVirtualMemory(HANDLE hProcess, PVOID* pBase, PSIZE_T pSize, ULONG newProtect, PULONG pOldProtect) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwProtectVirtualMemory");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            uintptr_t gadget = EnsureGadget();
            return SyscallInvoke(static_cast<uint32_t>(ssn), gadget, hProcess, pBase, pSize, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(newProtect)), pOldProtect);
        }

        NTSTATUS NtQueryInformationProcess(HANDLE hProcess, ULONG infoClass, PVOID pInfo, ULONG infoLen, PULONG pRetLen) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwQueryInformationProcess");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            uintptr_t gadget = EnsureGadget();
            return SyscallInvoke(static_cast<uint32_t>(ssn), gadget, hProcess, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoClass)), 
                                 pInfo, reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoLen)), pRetLen);
        }

        NTSTATUS NtSetInformationThread(HANDLE hThread, ULONG infoClass, PVOID pInfo, ULONG infoLen) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwSetInformationThread");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            uintptr_t gadget = EnsureGadget();
            return SyscallInvoke(static_cast<uint32_t>(ssn), gadget, hThread, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoClass)), 
                                 pInfo, reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoLen)));
        }

        NTSTATUS NtQuerySystemInformation(ULONG infoClass, PVOID pInfo, ULONG infoLen, PULONG pRetLen) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwQuerySystemInformation");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            uintptr_t gadget = EnsureGadget();
            return SyscallInvoke(static_cast<uint32_t>(ssn), gadget, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoClass)), 
                                 pInfo, reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoLen)), pRetLen);
        }

        NTSTATUS NtAllocateVirtualMemory(HANDLE hProcess, PVOID* pBase, ULONG_PTR zeroBits, PSIZE_T pSize, ULONG allocType, ULONG protect) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwAllocateVirtualMemory");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            uintptr_t gadget = EnsureGadget();
            return SyscallInvoke(static_cast<uint32_t>(ssn), gadget, hProcess, pBase, 
                                 reinterpret_cast<PVOID>(zeroBits), pSize, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(allocType)), 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(protect)));
        }
    };

    class SyscallEngine {
    public:
        static bool Initialize(SyscallContext& ctx) {
            ctx.ntdllBase = 0;
            ctx.codeStart = 0;
            ctx.codeEnd = 0;
            ctx.syscallGadget = 0;
            ctx.stride = 32;
            ctx.initialized = false;

            constexpr uint32_t HASH_NTDLL = HashDJB2CaseInsensitive("ntdll.dll");
            HMODULE hNtdll = DynamicResolver::FindModuleByHash(HASH_NTDLL);
            if (!hNtdll) return false;

            ctx.ntdllBase = reinterpret_cast<uintptr_t>(hNtdll);
            auto* base = reinterpret_cast<uint8_t*>(hNtdll);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

            ctx.codeStart = ctx.ntdllBase + nt->OptionalHeader.BaseOfCode;
            ctx.codeEnd = ctx.codeStart + nt->OptionalHeader.SizeOfCode;

            constexpr uint32_t KNOWN_ZW_HASHES[] = {
                HashDJB2("ZwProtectVirtualMemory"),
                HashDJB2("ZwQueryInformationProcess"),
                HashDJB2("ZwAllocateVirtualMemory"),
                HashDJB2("ZwClose"),
                HashDJB2("ZwSetInformationThread")
            };

            for (uint32_t h : KNOWN_ZW_HASHES) {
                FARPROC p = DynamicResolver::FindExportByHash(hNtdll, h);
                if (p) {
                    const uint8_t* pBytes = reinterpret_cast<const uint8_t*>(p);
                    if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1 && pBytes[3] == 0xB8) {
                        for (int32_t delta = 16; delta <= 64; delta += 8) {
                            if (pBytes[delta] == 0x4C && pBytes[delta + 1] == 0x8B && 
                                pBytes[delta + 2] == 0xD1 && pBytes[delta + 3] == 0xB8) {
                                ctx.stride = delta;
                                break;
                            }
                        }
                        break;
                    }
                }
            }

            ctx.syscallGadget = ctx.EnsureGadget();
            if (ctx.syscallGadget == 0) {
                auto* sec = IMAGE_FIRST_SECTION(nt);
                for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
                    if ((sec[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
                        const uint8_t* pSec = base + sec[s].VirtualAddress;
                        size_t secLen = sec[s].Misc.VirtualSize;
                        for (size_t i = 0; i + 3 < secLen; ++i) {
                            if (pSec[i] == 0x0F && pSec[i + 1] == 0x05 && pSec[i + 2] == 0xC3) {
                                ctx.syscallGadget = reinterpret_cast<uintptr_t>(pSec + i);
                                break;
                            }
                        }
                        if (ctx.syscallGadget != 0) break;
                    }
                }
            }

            ctx.initialized = (ctx.syscallGadget != 0);
            return ctx.initialized;
        }

        static bool ProtectMemory(const SyscallContext& ctx, const ResolvedApis& apis, 
                                  void* address, size_t size, DWORD newProtect, PDWORD oldProtect) {
            if (ctx.initialized || ctx.ntdllBase != 0) {
                PVOID base = address;
                SIZE_T regionSize = size;
                ULONG oldP = 0;
                NTSTATUS status = ctx.NtProtectVirtualMemory(apis.GetCurrentProcess ? apis.GetCurrentProcess() : reinterpret_cast<HANDLE>(-1),
                                                             &base, &regionSize, newProtect, &oldP);
                if (status >= 0) {
                    if (oldProtect) *oldProtect = static_cast<DWORD>(oldP);
                    return true;
                }
            }
            if (apis.VirtualProtect) {
                DWORD op = 0;
                BOOL ret = apis.VirtualProtect(address, size, newProtect, &op);
                if (oldProtect) *oldProtect = op;
                return ret != FALSE;
            }
            return false;
        }
    };

}
