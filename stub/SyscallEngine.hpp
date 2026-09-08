#pragma once

#include "DynamicResolver.hpp"

extern "C" NTSTATUS SyscallInvoke(uint32_t ssn, uintptr_t gadget, ...);

namespace IronVeil {

    struct SyscallExportEntry {
        uint32_t rva;
        uint32_t hash;
        uint32_t ssn;
    };

    struct SyscallContext {
        static constexpr size_t MAX_SYSCALL_ENTRIES = 256;
        SyscallExportEntry entries[MAX_SYSCALL_ENTRIES];
        size_t count;
        uintptr_t ntdllBase;
        uintptr_t syscallGadget;
        bool initialized;

        int32_t GetSsnByHash(uint32_t zwHash) const {
            for (size_t i = 0; i < count; ++i) {
                if (entries[i].hash == zwHash) {
                    return static_cast<int32_t>(entries[i].ssn);
                }
            }
            return -1;
        }

        NTSTATUS NtProtectVirtualMemory(HANDLE hProcess, PVOID* pBase, PSIZE_T pSize, ULONG newProtect, PULONG pOldProtect) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwProtectVirtualMemory");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            return SyscallInvoke(static_cast<uint32_t>(ssn), syscallGadget, hProcess, pBase, pSize, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(newProtect)), pOldProtect);
        }

        NTSTATUS NtQueryInformationProcess(HANDLE hProcess, ULONG infoClass, PVOID pInfo, ULONG infoLen, PULONG pRetLen) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwQueryInformationProcess");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            return SyscallInvoke(static_cast<uint32_t>(ssn), syscallGadget, hProcess, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoClass)), 
                                 pInfo, reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoLen)), pRetLen);
        }

        NTSTATUS NtSetInformationThread(HANDLE hThread, ULONG infoClass, PVOID pInfo, ULONG infoLen) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwSetInformationThread");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            return SyscallInvoke(static_cast<uint32_t>(ssn), syscallGadget, hThread, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoClass)), 
                                 pInfo, reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoLen)));
        }

        NTSTATUS NtQuerySystemInformation(ULONG infoClass, PVOID pInfo, ULONG infoLen, PULONG pRetLen) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwQuerySystemInformation");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            return SyscallInvoke(static_cast<uint32_t>(ssn), syscallGadget, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoClass)), 
                                 pInfo, reinterpret_cast<PVOID>(static_cast<uintptr_t>(infoLen)), pRetLen);
        }

        NTSTATUS NtAllocateVirtualMemory(HANDLE hProcess, PVOID* pBase, ULONG_PTR zeroBits, PSIZE_T pSize, ULONG allocType, ULONG protect) const {
            constexpr uint32_t HASH_ZW = HashDJB2("ZwAllocateVirtualMemory");
            int32_t ssn = GetSsnByHash(HASH_ZW);
            if (ssn < 0) return 0xC0000001;
            return SyscallInvoke(static_cast<uint32_t>(ssn), syscallGadget, hProcess, pBase, 
                                 reinterpret_cast<PVOID>(zeroBits), pSize, 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(allocType)), 
                                 reinterpret_cast<PVOID>(static_cast<uintptr_t>(protect)));
        }
    };

    class SyscallEngine {
    public:
        static bool Initialize(SyscallContext& ctx) {
            ctx.count = 0;
            ctx.ntdllBase = 0;
            ctx.syscallGadget = 0;
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

            auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (expDir.VirtualAddress == 0) return false;

            auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + expDir.VirtualAddress);
            auto* names = reinterpret_cast<uint32_t*>(base + exports->AddressOfNames);
            auto* ordinals = reinterpret_cast<uint16_t*>(base + exports->AddressOfNameOrdinals);
            auto* functions = reinterpret_cast<uint32_t*>(base + exports->AddressOfFunctions);

            for (uint32_t i = 0; i < exports->NumberOfNames && ctx.count < SyscallContext::MAX_SYSCALL_ENTRIES; ++i) {
                const char* name = reinterpret_cast<const char*>(base + names[i]);
                if (name[0] == 'Z' && name[1] == 'w') {
                    uint16_t ord = ordinals[i];
                    uint32_t funcRva = functions[ord];
                    if (funcRva != 0) {
                        ctx.entries[ctx.count].rva = funcRva;
                        ctx.entries[ctx.count].hash = HashDJB2(name);
                        ctx.entries[ctx.count].ssn = 0;
                        ctx.count++;
                    }
                }
            }

            for (size_t i = 0; i < ctx.count; ++i) {
                for (size_t j = i + 1; j < ctx.count; ++j) {
                    if (ctx.entries[i].rva > ctx.entries[j].rva) {
                        SyscallExportEntry temp = ctx.entries[i];
                        ctx.entries[i] = ctx.entries[j];
                        ctx.entries[j] = temp;
                    }
                }
            }

            for (size_t i = 0; i < ctx.count; ++i) {
                ctx.entries[i].ssn = static_cast<uint32_t>(i);
            }

            for (size_t i = 0; i < ctx.count; ++i) {
                const uint8_t* pCode = base + ctx.entries[i].rva;
                for (size_t k = 0; k < 32; ++k) {
                    if (pCode[k] == 0x0F && pCode[k + 1] == 0x05 && pCode[k + 2] == 0xC3) {
                        ctx.syscallGadget = reinterpret_cast<uintptr_t>(pCode + k);
                        break;
                    }
                }
                if (ctx.syscallGadget != 0) break;
            }

            ctx.initialized = (ctx.count > 0);
            return ctx.initialized;
        }

        static bool ProtectMemory(const SyscallContext& ctx, const ResolvedApis& apis, 
                                  void* address, size_t size, DWORD newProtect, PDWORD oldProtect) {
            if (ctx.initialized) {
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
