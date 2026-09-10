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
        t_LoadLibraryA LoadLibraryA = nullptr;
        t_GetProcAddress GetProcAddress = nullptr;
        t_ExitProcess ExitProcess = nullptr;
        t_GetCurrentProcess GetCurrentProcess = nullptr;
        t_GetCurrentThread GetCurrentThread = nullptr;
        t_FlushInstructionCache FlushInstructionCache = nullptr;
        t_RtlAddFunctionTable RtlAddFunctionTable = nullptr;
        t_NtProtectVirtualMemory NtProtectVirtualMemory = nullptr;
        t_NtQueryInformationProcess NtQueryInformationProcess = nullptr;
        t_NtSetInformationThread NtSetInformationThread = nullptr;
        t_RtlCaptureContext RtlCaptureContext = nullptr;
        t_AddVectoredExceptionHandler RtlAddVectoredExceptionHandler = nullptr;
        t_RemoveVectoredExceptionHandler RtlRemoveVectoredExceptionHandler = nullptr;
    };

    class DynamicResolver {
    public:
        __forceinline static uint8_t* GetPeb() {
            return reinterpret_cast<uint8_t*>(__readgsqword(0x60));
        }

        static uintptr_t GetImageBase() {
            auto* peb = GetPeb();
            if (!peb) return 0;
            return *reinterpret_cast<uintptr_t*>(peb + 0x10);
        }

        static HMODULE FindModuleByHash(uint32_t nameHash) {
            auto* peb = GetPeb();
            if (!peb) return nullptr;
            auto* ldr = *reinterpret_cast<uint8_t**>(peb + sizeof(void*) * 3);
            if (!ldr) return nullptr;
            auto* head = reinterpret_cast<LIST_ENTRY*>(ldr + sizeof(void*) * 2);

            for (auto* curr = head->Flink; curr && curr != head; curr = curr->Flink) {
                auto* entry = reinterpret_cast<uint8_t*>(curr);
                auto* baseAddress = *reinterpret_cast<HMODULE*>(entry + sizeof(void*) * 6);
                auto* baseDllName = reinterpret_cast<UNICODE_STRING*>(entry + sizeof(void*) * 11);

                if (baseDllName && baseDllName->Buffer) {
                    char ansiName[128];
                    USHORT len = baseDllName->Length / 2;
                    if (len > 127) len = 127;
                    for (USHORT i = 0; i < len; ++i) {
                        ansiName[i] = static_cast<char>(baseDllName->Buffer[i]);
                    }
                    ansiName[len] = '\0';

                    if (HashApiCaseInsensitive(ansiName) == nameHash) {
                        return baseAddress;
                    }
                }
            }
            return nullptr;
        }

        static bool IsAddressInAnyModule(uintptr_t addr) {
            if (!addr)
                return false;
            auto* peb = GetPeb();
            if (!peb)
                return false;
            auto* ldr = *reinterpret_cast<uint8_t**>(peb + sizeof(void*) * 3);
            if (!ldr)
                return false;
            auto* head = reinterpret_cast<LIST_ENTRY*>(ldr + sizeof(void*) * 2);
            if (!head)
                return false;

            for (auto* curr = head->Flink; curr && curr != head; curr = curr->Flink) {
                auto* entry = reinterpret_cast<uint8_t*>(curr);
                uintptr_t base = *reinterpret_cast<uintptr_t*>(entry + sizeof(void*) * 6);
                uint32_t sizeOfImage = *reinterpret_cast<uint32_t*>(entry + sizeof(void*) * 8);
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

            volatile size_t lfaShift = 0x1E;
            size_t lfaOff = lfaShift * 2; // 0x3C
            int32_t ntOff = *reinterpret_cast<const int32_t*>(base + lfaOff);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + ntOff);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return nullptr;

            volatile size_t expDirShift = 7;
            size_t expDirOff = (1 << expDirShift) | 0x08; // 0x88
            auto* pExpDir = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(reinterpret_cast<const uint8_t*>(nt) + expDirOff);
            uint32_t expDirVa = pExpDir->VirtualAddress;
            uint32_t expDirSz = pExpDir->Size;
            if (expDirVa == 0)
                return nullptr;

            const auto* pExpBytes = base + expDirVa;
            volatile size_t offBase = (1 << 4);            // 0x10
            volatile size_t offNumFuncs = (1 << 4) | 0x04; // 0x14
            volatile size_t offFuncs = (1 << 4) | 0x0C;    // 0x1C

            uint32_t expBase = *reinterpret_cast<const uint32_t*>(pExpBytes + offBase);
            uint32_t expNumFuncs = *reinterpret_cast<const uint32_t*>(pExpBytes + offNumFuncs);
            if (ordinal < expBase || ordinal >= expBase + expNumFuncs)
                return nullptr;

            auto* functions = reinterpret_cast<const uint32_t*>(base + *reinterpret_cast<const uint32_t*>(pExpBytes + offFuncs));
            uint32_t funcRva = functions[ordinal - expBase];
            if (funcRva == 0)
                return nullptr;

            if (funcRva >= expDirVa && funcRva < expDirVa + expDirSz) {
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

            HMODULE targetMod = FindModuleByHash(HashApiCaseInsensitive(modWithDll));
            if (!targetMod) {
                targetMod = FindModuleByHash(HashApiCaseInsensitive(modName));
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
                    return FindExportByHash(targetMod, HashApi(funcPart), depth);
                }
            }

            if (*funcPart != '#') {
                uint32_t fHash = HashApi(funcPart);
                HMODULE hKb = FindModuleByHash(HASH_KERNELBASE_DLL);
                if (hKb) {
                    FARPROC p = FindExportByHash(hKb, fHash, depth);
                    if (p) return p;
                }
                HMODULE hNt = FindModuleByHash(HASH_NTDLL_DLL);
                if (hNt) {
                    FARPROC p = FindExportByHash(hNt, fHash, depth);
                    if (p) return p;
                }
                HMODULE hK32 = FindModuleByHash(HASH_KERNEL32_DLL);
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

            volatile size_t lfaShift = 0x1E;
            size_t lfaOff = lfaShift * 2; // 0x3C
            int32_t ntOff = *reinterpret_cast<const int32_t*>(base + lfaOff);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + ntOff);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return nullptr;

            volatile size_t expDirShift = 7;
            size_t expDirOff = (1 << expDirShift) | 0x08; // 0x88
            auto* pExpDir = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(reinterpret_cast<const uint8_t*>(nt) + expDirOff);
            uint32_t expDirVa = pExpDir->VirtualAddress;
            uint32_t expDirSz = pExpDir->Size;
            if (expDirVa == 0)
                return nullptr;

            const auto* pExpBytes = base + expDirVa;
            volatile size_t offNames = (1 << 5);           // 0x20
            volatile size_t offOrds  = (1 << 5) | 4;       // 0x24
            volatile size_t offFuncs = (1 << 4) | 0x0C;    // 0x1C
            volatile size_t offNumNames = (1 << 4) | 0x08; // 0x18

            uint32_t expNumNames = *reinterpret_cast<const uint32_t*>(pExpBytes + offNumNames);
            auto* names = reinterpret_cast<const uint32_t*>(base + *reinterpret_cast<const uint32_t*>(pExpBytes + offNames));
            auto* ordinals = reinterpret_cast<const uint16_t*>(base + *reinterpret_cast<const uint32_t*>(pExpBytes + offOrds));
            auto* functions = reinterpret_cast<const uint32_t*>(base + *reinterpret_cast<const uint32_t*>(pExpBytes + offFuncs));

            for (uint32_t i = 0; i < expNumNames; ++i) {
                const char* name = reinterpret_cast<const char*>(base + names[i]);
                if (HashApi(name) == funcHash) {
                    uint16_t ord = ordinals[i];
                    uint32_t funcRva = functions[ord];
                    if (funcRva == 0)
                        return nullptr;

                    if (funcRva >= expDirVa && funcRva < expDirVa + expDirSz) {
                        const char* forwarder = reinterpret_cast<const char*>(base + funcRva);
                        return ResolveForwarder(forwarder, depth + 1);
                    }

                    return reinterpret_cast<FARPROC>(base + funcRva);
                }
            }

            return nullptr;
        }

        static bool ResolveAll(ResolvedApis& outApis) {
            HMODULE hKernelBase = FindModuleByHash(HASH_KERNELBASE_DLL);
            HMODULE hKernel32 = FindModuleByHash(HASH_KERNEL32_DLL);
            HMODULE hKMod = hKernelBase ? hKernelBase : hKernel32;
            HMODULE hNtdll = FindModuleByHash(HASH_NTDLL_DLL);

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
                resolveK(HASH_VIRTUALPROTECT));
            outApis.LoadLibraryA = reinterpret_cast<t_LoadLibraryA>(
                resolveK(HASH_LOADLIBRARYA));
            outApis.GetProcAddress = reinterpret_cast<t_GetProcAddress>(
                resolveK(HASH_GETPROCADDRESS));
            outApis.ExitProcess = reinterpret_cast<t_ExitProcess>(
                resolveK(HASH_EXITPROCESS));
            outApis.GetCurrentProcess = reinterpret_cast<t_GetCurrentProcess>(
                resolveK(HASH_GETCURRENTPROCESS));
            outApis.FlushInstructionCache = reinterpret_cast<t_FlushInstructionCache>(
                resolveK(HASH_FLUSHINSTRUCTIONCACHE));

            outApis.RtlAddFunctionTable = reinterpret_cast<t_RtlAddFunctionTable>(
                FindExportByHash(hNtdll, HASH_RTLADDFUNCTIONTABLE));
            if (!outApis.RtlAddFunctionTable) {
                outApis.RtlAddFunctionTable = reinterpret_cast<t_RtlAddFunctionTable>(
                    resolveK(HASH_RTLADDFUNCTIONTABLE));
            }

            outApis.GetCurrentThread = reinterpret_cast<t_GetCurrentThread>(
                resolveK(HASH_GETCURRENTTHREAD));

            outApis.NtProtectVirtualMemory = reinterpret_cast<t_NtProtectVirtualMemory>(
                FindExportByHash(hNtdll, HASH_NTPROTECTVIRTUALMEMORY));
            outApis.NtQueryInformationProcess = reinterpret_cast<t_NtQueryInformationProcess>(
                FindExportByHash(hNtdll, HASH_NTQUERYINFORMATIONPROCESS));
            outApis.NtSetInformationThread = reinterpret_cast<t_NtSetInformationThread>(
                FindExportByHash(hNtdll, HASH_NTSETINFORMATIONTHREAD));
            outApis.RtlCaptureContext = reinterpret_cast<t_RtlCaptureContext>(
                FindExportByHash(hNtdll, HASH_RTLCAPTURECONTEXT));

            outApis.RtlAddVectoredExceptionHandler = reinterpret_cast<t_AddVectoredExceptionHandler>(
                FindExportByHash(hNtdll, HASH_RTLADDVECTOREDEXCEPTIONHANDLER));
            outApis.RtlRemoveVectoredExceptionHandler = reinterpret_cast<t_RemoveVectoredExceptionHandler>(
                FindExportByHash(hNtdll, HASH_RTLREMOVEVECTOREDEXCEPTIONHANDLER));

            return (outApis.VirtualProtect && outApis.LoadLibraryA && outApis.GetProcAddress && outApis.ExitProcess);
        }
    };

}
