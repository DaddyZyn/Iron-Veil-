#pragma once

#include "../include/Common.hpp"
#include <intrin.h>

namespace IronVeil {

    struct UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    };

    #ifndef ProcessDebugPort
    constexpr uint32_t ProcessDebugPort = 7;
    #endif
    #ifndef ProcessDebugFlags
    constexpr uint32_t ProcessDebugFlags = 31;
    #endif
    #ifndef ProcessDebugObjectHandle
    constexpr uint32_t ProcessDebugObjectHandle = 30;
    #endif
    #ifndef ThreadHideFromDebugger
    constexpr uint32_t ThreadHideFromDebugger = 17;
    #endif

    using t_NtQueryInformationProcess = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    using t_NtSetInformationThread = NTSTATUS(NTAPI*)(
        HANDLE ThreadHandle,
        ULONG ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength
    );

    using t_VirtualProtect = BOOL(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    using t_VirtualAlloc = LPVOID(WINAPI*)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    using t_VirtualQuery = SIZE_T(WINAPI*)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
    using t_LoadLibraryA = HMODULE(WINAPI*)(LPCSTR lpLibFileName);
    using t_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
    using t_ExitProcess = void(WINAPI*)(UINT uExitCode);
    using t_GetCurrentProcess = HANDLE(WINAPI*)();
    using t_GetCurrentThread = HANDLE(WINAPI*)();
    using t_GetThreadContext = BOOL(WINAPI*)(HANDLE hThread, LPCONTEXT lpContext);
    using t_SetThreadContext = BOOL(WINAPI*)(HANDLE hThread, const CONTEXT* lpContext);
    using t_FlushInstructionCache = BOOL(WINAPI*)(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize);
    using t_NtQuerySystemInformation = NTSTATUS(NTAPI*)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );

    using t_NtProtectVirtualMemory = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    using t_NtAllocateVirtualMemory = NTSTATUS(NTAPI*)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    using t_PIMAGE_TLS_CALLBACK = void(NTAPI*)(PVOID DllHandle, DWORD Reason, PVOID Reserved);
    using t_RtlAddFunctionTable = BOOLEAN(NTAPI*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
    using t_AddVectoredExceptionHandler = PVOID(WINAPI*)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
    using t_RemoveVectoredExceptionHandler = ULONG(WINAPI*)(PVOID Handle);
    using t_RtlCaptureContext = void(WINAPI*)(PCONTEXT ContextRecord);

    struct ResolvedApis {
        t_VirtualProtect VirtualProtect = nullptr;
        t_VirtualAlloc VirtualAlloc = nullptr;
        t_VirtualQuery VirtualQuery = nullptr;
        t_LoadLibraryA LoadLibraryA = nullptr;
        t_GetProcAddress GetProcAddress = nullptr;
        t_ExitProcess ExitProcess = nullptr;
        t_RtlAddFunctionTable RtlAddFunctionTable = nullptr;
        t_AddVectoredExceptionHandler AddVectoredExceptionHandler = nullptr;
        t_RemoveVectoredExceptionHandler RemoveVectoredExceptionHandler = nullptr;
        t_GetCurrentProcess GetCurrentProcess = nullptr;
        t_GetCurrentThread GetCurrentThread = nullptr;
        t_GetThreadContext GetThreadContext = nullptr;
        t_SetThreadContext SetThreadContext = nullptr;
        t_FlushInstructionCache FlushInstructionCache = nullptr;
        t_NtQueryInformationProcess NtQueryInformationProcess = nullptr;
        t_NtSetInformationThread NtSetInformationThread = nullptr;
        t_NtQuerySystemInformation NtQuerySystemInformation = nullptr;
        t_NtProtectVirtualMemory NtProtectVirtualMemory = nullptr;
        t_NtAllocateVirtualMemory NtAllocateVirtualMemory = nullptr;
        t_RtlCaptureContext RtlCaptureContext = nullptr;

        FARPROC pNtOpenProcess = nullptr;
        FARPROC pNtCreateThreadEx = nullptr;
        FARPROC pNtTerminateProcess = nullptr;
        FARPROC pNtReadVirtualMemory = nullptr;
        FARPROC pNtWriteVirtualMemory = nullptr;
        FARPROC pLdrLoadDll = nullptr;
        FARPROC pLdrGetProcedureAddress = nullptr;
    };

    class DynamicResolver {
    public:
        static uintptr_t GetImageBase() {
            auto* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
            return *reinterpret_cast<uintptr_t*>(peb + 0x10);
        }

        static HMODULE FindModuleByHash(uint32_t nameHash) {
            auto* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
            auto* ldr = *reinterpret_cast<uint8_t**>(peb + 0x18);
            auto* head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x20);

            for (auto* curr = head->Flink; curr != head; curr = curr->Flink) {
                auto* entry = reinterpret_cast<uint8_t*>(curr) - 0x10;
                auto* baseAddress = *reinterpret_cast<HMODULE*>(entry + 0x30);
                auto* baseDllName = reinterpret_cast<UNICODE_STRING*>(entry + 0x58);

                if (baseDllName && baseDllName->Buffer) {
                    char ansiName[128];
                    USHORT len = baseDllName->Length / 2;
                    if (len > 127) len = 127;
                    for (USHORT i = 0; i < len; ++i) {
                        ansiName[i] = static_cast<char>(baseDllName->Buffer[i]);
                    }
                    ansiName[len] = '\0';

                    if (HashDJB2CaseInsensitive(ansiName) == nameHash) {
                        return baseAddress;
                    }
                }
            }
            return nullptr;
        }

        static bool IsAddressInAnyModule(uintptr_t addr) {
            if (!addr)
                return false;
            auto* peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
            if (!peb)
                return false;
            auto* ldr = *reinterpret_cast<uint8_t**>(peb + 0x18);
            if (!ldr)
                return false;
            auto* head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x20);
            if (!head)
                return false;

            for (auto* curr = head->Flink; curr && curr != head; curr = curr->Flink) {
                auto* entry = reinterpret_cast<uint8_t*>(curr) - 0x10;
                uintptr_t base = *reinterpret_cast<uintptr_t*>(entry + 0x30);
                uint32_t sizeOfImage = *reinterpret_cast<uint32_t*>(entry + 0x40);
                if (base && sizeOfImage) {
                    if (addr >= base && addr < base + sizeOfImage) {
                        return true;
                    }
                }
            }
            return false;
        }

        static FARPROC FindExportByOrdinal(HMODULE hMod, uint16_t ordinal, int depth = 0) {
            if (!hMod || depth > 5)
                return nullptr;

            auto* base = reinterpret_cast<uint8_t*>(hMod);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return nullptr;

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return nullptr;

            auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (expDir.VirtualAddress == 0)
                return nullptr;

            auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + expDir.VirtualAddress);
            if (ordinal < exports->Base || ordinal >= exports->Base + exports->NumberOfFunctions)
                return nullptr;

            auto* functions = reinterpret_cast<uint32_t*>(base + exports->AddressOfFunctions);
            uint32_t funcRva = functions[ordinal - exports->Base];
            if (funcRva == 0)
                return nullptr;

            if (funcRva >= expDir.VirtualAddress && funcRva < expDir.VirtualAddress + expDir.Size) {
                const char* forwarder = reinterpret_cast<const char*>(base + funcRva);
                return ResolveForwarder(forwarder, depth + 1);
            }

            return reinterpret_cast<FARPROC>(base + funcRva);
        }

        static FARPROC ResolveForwarder(const char* forwarder, int depth = 0) {
            if (!forwarder || depth > 5)
                return nullptr;

            const char* dot = nullptr;
            for (const char* p = forwarder; *p; ++p) {
                if (*p == '.') {
                    dot = p;
                    break;
                }
            }
            if (!dot)
                return nullptr;

            size_t modLen = static_cast<size_t>(dot - forwarder);
            if (modLen == 0 || modLen >= 60)
                return nullptr;

            char modName[64];
            for (size_t i = 0; i < modLen; ++i) {
                modName[i] = forwarder[i];
            }
            modName[modLen] = '\0';

            char modWithDll[64];
            for (size_t i = 0; i < modLen; ++i) {
                modWithDll[i] = modName[i];
            }
            modWithDll[modLen] = '.';
            modWithDll[modLen + 1] = 'd';
            modWithDll[modLen + 2] = 'l';
            modWithDll[modLen + 3] = 'l';
            modWithDll[modLen + 4] = '\0';

            HMODULE targetMod = FindModuleByHash(HashDJB2CaseInsensitive(modWithDll));
            if (!targetMod) {
                targetMod = FindModuleByHash(HashDJB2CaseInsensitive(modName));
            }

            const char* funcPart = dot + 1;
            if (*funcPart == '\0')
                return nullptr;

            if (targetMod) {
                if (*funcPart == '#') {
                    uint16_t ord = 0;
                    for (const char* p = funcPart + 1; *p >= '0' && *p <= '9'; ++p) {
                        ord = ord * 10 + static_cast<uint16_t>(*p - '0');
                    }
                    return FindExportByOrdinal(targetMod, ord, depth);
                } else {
                    return FindExportByHash(targetMod, HashDJB2(funcPart), depth);
                }
            }

            if (*funcPart != '#') {
                uint32_t fHash = HashDJB2(funcPart);
                HMODULE hKb = FindModuleByHash(HashDJB2CaseInsensitive("kernelbase.dll"));
                if (hKb) {
                    FARPROC p = FindExportByHash(hKb, fHash, depth);
                    if (p) return p;
                }
                HMODULE hNt = FindModuleByHash(HashDJB2CaseInsensitive("ntdll.dll"));
                if (hNt) {
                    FARPROC p = FindExportByHash(hNt, fHash, depth);
                    if (p) return p;
                }
                HMODULE hK32 = FindModuleByHash(HashDJB2CaseInsensitive("kernel32.dll"));
                if (hK32) {
                    FARPROC p = FindExportByHash(hK32, fHash, depth);
                    if (p) return p;
                }
            }

            return nullptr;
        }

        static FARPROC FindExportByHash(HMODULE hMod, uint32_t funcHash, int depth = 0) {
            if (!hMod || depth > 5)
                return nullptr;

            auto* base = reinterpret_cast<uint8_t*>(hMod);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return nullptr;

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return nullptr;

            auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (expDir.VirtualAddress == 0)
                return nullptr;

            auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + expDir.VirtualAddress);
            auto* names = reinterpret_cast<uint32_t*>(base + exports->AddressOfNames);
            auto* ordinals = reinterpret_cast<uint16_t*>(base + exports->AddressOfNameOrdinals);
            auto* functions = reinterpret_cast<uint32_t*>(base + exports->AddressOfFunctions);

            for (uint32_t i = 0; i < exports->NumberOfNames; ++i) {
                const char* name = reinterpret_cast<const char*>(base + names[i]);
                if (HashDJB2(name) == funcHash) {
                    uint16_t ord = ordinals[i];
                    uint32_t funcRva = functions[ord];
                    if (funcRva == 0)
                        return nullptr;

                    if (funcRva >= expDir.VirtualAddress && funcRva < expDir.VirtualAddress + expDir.Size) {
                        const char* forwarder = reinterpret_cast<const char*>(base + funcRva);
                        return ResolveForwarder(forwarder, depth + 1);
                    }

                    return reinterpret_cast<FARPROC>(base + funcRva);
                }
            }

            return nullptr;
        }

        static bool ResolveAll(ResolvedApis& outApis) {
            constexpr uint32_t HASH_KERNELBASE = HashDJB2CaseInsensitive("kernelbase.dll");
            constexpr uint32_t HASH_KERNEL32   = HashDJB2CaseInsensitive("kernel32.dll");
            constexpr uint32_t HASH_NTDLL      = HashDJB2CaseInsensitive("ntdll.dll");

            HMODULE hKernelBase = FindModuleByHash(HASH_KERNELBASE);
            HMODULE hKernel32 = FindModuleByHash(HASH_KERNEL32);
            HMODULE hKMod = hKernelBase ? hKernelBase : hKernel32;
            HMODULE hNtdll = FindModuleByHash(HASH_NTDLL);

            if (!hKMod || !hNtdll)
                return false;

            auto resolveK = [&](uint32_t hash) -> FARPROC {
                FARPROC p = FindExportByHash(hKMod, hash);
                if (!p && hKernel32 && hKernel32 != hKMod) {
                    p = FindExportByHash(hKernel32, hash);
                }
                return p;
            };

            outApis.VirtualProtect = reinterpret_cast<t_VirtualProtect>(
                resolveK(HashDJB2("VirtualProtect")));
            outApis.VirtualAlloc = reinterpret_cast<t_VirtualAlloc>(
                resolveK(HashDJB2("VirtualAlloc")));
            outApis.VirtualQuery = reinterpret_cast<t_VirtualQuery>(
                resolveK(HashDJB2("VirtualQuery")));
            outApis.LoadLibraryA = reinterpret_cast<t_LoadLibraryA>(
                resolveK(HashDJB2("LoadLibraryA")));
            outApis.GetProcAddress = reinterpret_cast<t_GetProcAddress>(
                resolveK(HashDJB2("GetProcAddress")));
            outApis.ExitProcess = reinterpret_cast<t_ExitProcess>(
                resolveK(HashDJB2("ExitProcess")));
            outApis.GetCurrentProcess = reinterpret_cast<t_GetCurrentProcess>(
                resolveK(HashDJB2("GetCurrentProcess")));
            outApis.GetCurrentThread = reinterpret_cast<t_GetCurrentThread>(
                resolveK(HashDJB2("GetCurrentThread")));
            outApis.GetThreadContext = reinterpret_cast<t_GetThreadContext>(
                resolveK(HashDJB2("GetThreadContext")));
            outApis.SetThreadContext = reinterpret_cast<t_SetThreadContext>(
                resolveK(HashDJB2("SetThreadContext")));
            outApis.FlushInstructionCache = reinterpret_cast<t_FlushInstructionCache>(
                resolveK(HashDJB2("FlushInstructionCache")));

            outApis.AddVectoredExceptionHandler = reinterpret_cast<t_AddVectoredExceptionHandler>(
                resolveK(HashDJB2("AddVectoredExceptionHandler")));
            if (!outApis.AddVectoredExceptionHandler) {
                outApis.AddVectoredExceptionHandler = reinterpret_cast<t_AddVectoredExceptionHandler>(
                    FindExportByHash(hNtdll, HashDJB2("RtlAddVectoredExceptionHandler")));
            }

            outApis.RemoveVectoredExceptionHandler = reinterpret_cast<t_RemoveVectoredExceptionHandler>(
                resolveK(HashDJB2("RemoveVectoredExceptionHandler")));
            if (!outApis.RemoveVectoredExceptionHandler) {
                outApis.RemoveVectoredExceptionHandler = reinterpret_cast<t_RemoveVectoredExceptionHandler>(
                    FindExportByHash(hNtdll, HashDJB2("RtlRemoveVectoredExceptionHandler")));
            }

            outApis.RtlAddFunctionTable = reinterpret_cast<t_RtlAddFunctionTable>(
                FindExportByHash(hNtdll, HashDJB2("RtlAddFunctionTable")));
            if (!outApis.RtlAddFunctionTable) {
                outApis.RtlAddFunctionTable = reinterpret_cast<t_RtlAddFunctionTable>(
                    resolveK(HashDJB2("RtlAddFunctionTable")));
            }

            outApis.RtlCaptureContext = reinterpret_cast<t_RtlCaptureContext>(
                FindExportByHash(hNtdll, HashDJB2("RtlCaptureContext")));
            if (!outApis.RtlCaptureContext) {
                outApis.RtlCaptureContext = reinterpret_cast<t_RtlCaptureContext>(
                    resolveK(HashDJB2("RtlCaptureContext")));
            }

            outApis.NtQueryInformationProcess = reinterpret_cast<t_NtQueryInformationProcess>(
                FindExportByHash(hNtdll, HashDJB2("NtQueryInformationProcess")));
            outApis.NtSetInformationThread = reinterpret_cast<t_NtSetInformationThread>(
                FindExportByHash(hNtdll, HashDJB2("NtSetInformationThread")));
            outApis.NtQuerySystemInformation = reinterpret_cast<t_NtQuerySystemInformation>(
                FindExportByHash(hNtdll, HashDJB2("NtQuerySystemInformation")));
            outApis.NtProtectVirtualMemory = reinterpret_cast<t_NtProtectVirtualMemory>(
                FindExportByHash(hNtdll, HashDJB2("NtProtectVirtualMemory")));
            outApis.NtAllocateVirtualMemory = reinterpret_cast<t_NtAllocateVirtualMemory>(
                FindExportByHash(hNtdll, HashDJB2("NtAllocateVirtualMemory")));

            outApis.pNtOpenProcess = FindExportByHash(hNtdll, HashDJB2("NtOpenProcess"));
            outApis.pNtCreateThreadEx = FindExportByHash(hNtdll, HashDJB2("NtCreateThreadEx"));
            outApis.pNtTerminateProcess = FindExportByHash(hNtdll, HashDJB2("NtTerminateProcess"));
            outApis.pNtReadVirtualMemory = FindExportByHash(hNtdll, HashDJB2("NtReadVirtualMemory"));
            outApis.pNtWriteVirtualMemory = FindExportByHash(hNtdll, HashDJB2("NtWriteVirtualMemory"));
            outApis.pLdrLoadDll = FindExportByHash(hNtdll, HashDJB2("LdrLoadDll"));
            outApis.pLdrGetProcedureAddress = FindExportByHash(hNtdll, HashDJB2("LdrGetProcedureAddress"));

            return (outApis.VirtualProtect && outApis.LoadLibraryA && outApis.GetProcAddress && outApis.ExitProcess);
        }
    };

}
