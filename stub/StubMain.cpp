#include "DynamicResolver.hpp"
#include "AntiDebug.hpp"
#include "../include/Encryptor.hpp"
#define IRONVEIL_FREESTANDING 1
#include "../include/IronVM.hpp"

extern "C" {
    #pragma function(memset)
    void* memset(void* dest, int c, size_t count) {
        auto* p = static_cast<unsigned char*>(dest);
        while (count--) *p++ = static_cast<unsigned char>(c);
        return dest;
    }

    #pragma function(memcpy)
    void* memcpy(void* dest, const void* src, size_t count) {
        auto* d = static_cast<unsigned char*>(dest);
        const auto* s = static_cast<const unsigned char*>(src);
        while (count--) *d++ = *s++;
        return dest;
    }
}

namespace IronVeil {

    __declspec(noinline) static void SecureZero(void* ptr, size_t len) {
        volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
        while (len--) *p++ = 0;
    }





    extern "C" void StubEntryPoint();

    extern "C" bool StubMainWorker(DispatchInfo* outDispatch) {
        if (!outDispatch)
            return false;

        uint64_t startTsc = __rdtsc();
        uintptr_t imageBase = DynamicResolver::GetImageBase();
        if (!imageBase)
            return false;

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(imageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        auto* sections = IMAGE_FIRST_SECTION(nt);
        uint32_t workerRva = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&StubMainWorker) - imageBase);
        IMAGE_SECTION_HEADER* guardSec = nullptr;
        StubConfig* config = nullptr;
        for (uint16_t s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
            if (workerRva >= sections[s].VirtualAddress &&
                workerRva < sections[s].VirtualAddress + sections[s].Misc.VirtualSize) {
                guardSec = &sections[s];
                config = reinterpret_cast<StubConfig*>(imageBase + guardSec->VirtualAddress);
                break;
            }
        }
        if (!config || !guardSec)
            return false;

        ResolvedApis apis;
        if (!DynamicResolver::ResolveAll(apis))
            return false;

        SyscallContext sysCtx = { 0 };
        SyscallEngine::Initialize(sysCtx);

        DWORD cfgOldProtect = 0;
        SyscallEngine::ProtectMemory(sysCtx, apis, config, sizeof(StubConfig), PAGE_READWRITE, &cfgOldProtect);
        config->fnVirtualProtect = reinterpret_cast<uintptr_t>(apis.VirtualProtect);
        config->fnFlushInstructionCache = reinterpret_cast<uintptr_t>(apis.FlushInstructionCache);

        uint32_t integrityMask = AntiDebug::GetIntegrityMask(config->antiDebugFlags, sysCtx, apis, reinterpret_cast<const void*>(&StubEntryPoint));
        uint64_t effectiveCanary = config->keyCanary ^ (static_cast<uint64_t>(integrityMask) * 0x5851F42D4C957F2DULL);

        if (config->vmBytecodeRva && config->vmBytecodeSize) {
            const uint8_t* pVmCode = reinterpret_cast<const uint8_t*>(imageBase + config->vmBytecodeRva);
            uint64_t vmVal = VM::VirtualMachine::Execute(pVmCode, config->vmBytecodeSize, config->vmKey, effectiveCanary);
            if (vmVal != 0) {
                effectiveCanary = vmVal;
            }
        }

        uint8_t sessionKey[32];
        UnblindKey(config->blindedKey, effectiveCanary, sessionKey);

        for (uint32_t i = 0; i < config->sectionCount; ++i) {
            const auto& sec = config->sections[i];
            uint8_t* pSection = reinterpret_cast<uint8_t*>(imageBase + sec.virtualAddress);

            DWORD oldProtect = 0;
            if (SyscallEngine::ProtectMemory(sysCtx, apis, pSection, sec.virtualSize, PAGE_READWRITE, &oldProtect)) {
                if (sec.payloadSize > 0 && sec.payloadOffset > 0) {
                    const uint8_t* pPayload = reinterpret_cast<const uint8_t*>(config) + sec.payloadOffset;
                    ChaCha20::Process(sessionKey, sec.nonce, 0, pPayload, pSection, sec.payloadSize);
                } else {
                    ChaCha20::CryptInPlace(sessionKey, sec.nonce, 0, 
                                           pSection, sec.rawSize);
                }

                if (i == 0) {
                    if (config->stolenLen == 0) {
                        if (config->originalEntryPoint >= sec.virtualAddress &&
                            config->originalEntryPoint + sizeof(config->originalEpBytes) <= sec.virtualAddress + sec.virtualSize) {
                            memcpy(pSection + (config->originalEntryPoint - sec.virtualAddress),
                                   config->originalEpBytes, sizeof(config->originalEpBytes));
                        }
                    }

                    if (config->textHash != 0) {
                        uint64_t currentHash = HashFNV1a64(pSection, sec.rawSize);
                        if (currentHash != config->textHash) {
                            SecureZero(sessionKey, sizeof(sessionKey));
                            apis.ExitProcess(0);
                            return false;
                        }
                    }
                }
            }
        }

        if (config->relocTableRva && config->relocTableSize && config->originalImageBase) {
            intptr_t delta = static_cast<intptr_t>(imageBase) - static_cast<intptr_t>(config->originalImageBase);
            if (delta != 0) {
                uint8_t* encRelocs = reinterpret_cast<uint8_t*>(imageBase + config->relocTableRva);
                DWORD oldProtect = 0;
                if (SyscallEngine::ProtectMemory(sysCtx, apis, encRelocs, config->relocTableSize, PAGE_READWRITE, &oldProtect)) {
                    ChaCha20::CryptInPlace(sessionKey, config->relocsNonce, 0,
                                           encRelocs, config->relocTableSize);

                    size_t relocOffset = 0;
                    while (relocOffset + sizeof(IMAGE_BASE_RELOCATION) <= config->relocTableSize) {
                        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(encRelocs + relocOffset);
                        if (block->SizeOfBlock == 0 || block->SizeOfBlock > config->relocTableSize - relocOffset)
                            break;

                        size_t entryCount = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
                        auto* entries = reinterpret_cast<uint16_t*>(encRelocs + relocOffset + sizeof(IMAGE_BASE_RELOCATION));

                        uint8_t* pPage = reinterpret_cast<uint8_t*>(imageBase + block->VirtualAddress);
                        DWORD pageOldProtect = 0;
                        bool pageUnprotected = SyscallEngine::ProtectMemory(sysCtx, apis, pPage, 4096, PAGE_READWRITE, &pageOldProtect);

                        for (size_t k = 0; k < entryCount; ++k) {
                            uint16_t entry = entries[k];
                            uint8_t type = static_cast<uint8_t>(entry >> 12);
                            uint16_t offset = entry & 0x0FFF;

                            if (type == IMAGE_REL_BASED_DIR64) {
                                auto* pPatch = reinterpret_cast<uint64_t*>(pPage + offset);
                                *pPatch += delta;
                            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                                auto* pPatch = reinterpret_cast<uint32_t*>(pPage + offset);
                                *pPatch += static_cast<uint32_t>(delta);
                            }
                        }

                        if (pageUnprotected) {
                            SyscallEngine::ProtectMemory(sysCtx, apis, pPage, 4096, pageOldProtect, &pageOldProtect);
                        }

                        relocOffset += block->SizeOfBlock;
                    }

                    SecureZero(encRelocs, config->relocTableSize);
                }
            }
        }

        if (config->encryptedImportsRva && config->encryptedImportsSize) {
            uint8_t* encImports = reinterpret_cast<uint8_t*>(imageBase + config->encryptedImportsRva);

            DWORD oldProtect = 0;
            if (SyscallEngine::ProtectMemory(sysCtx, apis, encImports, config->encryptedImportsSize, PAGE_READWRITE, &oldProtect)) {
                ChaCha20::CryptInPlace(sessionKey, config->importsNonce, 0,
                                       encImports, config->encryptedImportsSize);

                size_t offset = 0;
                uint32_t thunkIndex = 0;

                DWORD thunkOldProtect = 0;
                uint8_t* pThunkBase = nullptr;
                if (config->thunkPoolRva != 0 && config->thunkPoolSize != 0) {
                    pThunkBase = reinterpret_cast<uint8_t*>(imageBase + config->thunkPoolRva);
                    SyscallEngine::ProtectMemory(sysCtx, apis, pThunkBase, config->thunkPoolSize, PAGE_READWRITE, &thunkOldProtect);
                }

                if (config->encryptedImportsSize >= sizeof(uint32_t)) {
                    uint32_t moduleCount = *reinterpret_cast<uint32_t*>(encImports + offset);
                    offset += sizeof(uint32_t);

                    for (uint32_t m = 0; m < moduleCount && offset < config->encryptedImportsSize; ++m) {
                        uint32_t nameLen = *reinterpret_cast<uint32_t*>(encImports + offset);
                        offset += sizeof(uint32_t);

                        if (offset + nameLen > config->encryptedImportsSize)
                            break;

                        const char* modName = reinterpret_cast<const char*>(encImports + offset);
                        offset += nameLen + 1;

                        HMODULE hMod = apis.LoadLibraryA(modName);

                        uint32_t funcCount = *reinterpret_cast<uint32_t*>(encImports + offset);
                        offset += sizeof(uint32_t);

                        for (uint32_t f = 0; f < funcCount && offset < config->encryptedImportsSize; ++f) {
                            uint32_t iatRva = *reinterpret_cast<uint32_t*>(encImports + offset);
                            offset += sizeof(uint32_t);

                            uint8_t isOrdinal = encImports[offset++];
                            uint16_t ordinal = *reinterpret_cast<uint16_t*>(encImports + offset);
                            offset += sizeof(uint16_t);

                            uint16_t fNameLen = *reinterpret_cast<uint16_t*>(encImports + offset);
                            offset += sizeof(uint16_t);

                            const char* funcName = nullptr;
                            if (!isOrdinal && fNameLen > 0) {
                                funcName = reinterpret_cast<const char*>(encImports + offset);
                                offset += fNameLen + 1;
                            }

                            if (hMod) {
                                FARPROC pFunc = nullptr;
                                if (isOrdinal) {
                                    pFunc = apis.GetProcAddress(hMod, reinterpret_cast<LPCSTR>(static_cast<uintptr_t>(ordinal)));
                                } else if (funcName) {
                                    pFunc = apis.GetProcAddress(hMod, funcName);
                                }

                                if (pFunc) {
                                    auto* iatEntry = reinterpret_cast<uintptr_t*>(imageBase + iatRva);
                                    DWORD iatOld = 0;
                                    SyscallEngine::ProtectMemory(sysCtx, apis, iatEntry, sizeof(uintptr_t), PAGE_READWRITE, &iatOld);

                                    bool isCode = false;
                                    auto* modBase = reinterpret_cast<const uint8_t*>(hMod);
                                    auto* modDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(modBase);
                                    if (modDos && modDos->e_magic == IMAGE_DOS_SIGNATURE) {
                                        auto* modNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(modBase + modDos->e_lfanew);
                                        if (modNt && modNt->Signature == IMAGE_NT_SIGNATURE) {
                                            uint32_t fRva = static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(pFunc) - modBase);
                                            auto* modSecs = IMAGE_FIRST_SECTION(modNt);
                                            for (uint16_t s = 0; s < modNt->FileHeader.NumberOfSections; ++s) {
                                                if (fRva >= modSecs[s].VirtualAddress && fRva < modSecs[s].VirtualAddress + modSecs[s].Misc.VirtualSize) {
                                                    isCode = (modSecs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                                                    break;
                                                }
                                            }
                                        }
                                    }

                                    if (isCode && pThunkBase && (thunkIndex * 32 + 32) <= config->thunkPoolSize) {
                                        uint8_t* pThunk = pThunkBase + (thunkIndex * 32);

                                        uint64_t rawTarget = reinterpret_cast<uint64_t>(pFunc);
                                        uint64_t thunkKey = 0x5851F42D4C957F2DULL ^ (static_cast<uint64_t>(thunkIndex) * 0x9E3779B97F4A7C15ULL);

                                        uint32_t mode = thunkIndex % 4;
                                        if (mode == 0) {
                                            uint64_t encTarget = rawTarget ^ thunkKey;
                                            pThunk[0] = 0x49; pThunk[1] = 0xBA;
                                            *reinterpret_cast<uint64_t*>(pThunk + 2) = encTarget;
                                            pThunk[10] = 0x48; pThunk[11] = 0xB8;
                                            *reinterpret_cast<uint64_t*>(pThunk + 12) = thunkKey;
                                            pThunk[20] = 0x49; pThunk[21] = 0x31; pThunk[22] = 0xC2;
                                            pThunk[23] = 0x41; pThunk[24] = 0xFF; pThunk[25] = 0xE2;
                                            pThunk[26] = 0x48; pThunk[27] = 0x8D; pThunk[28] = 0x64; pThunk[29] = 0x24; pThunk[30] = 0x00;
                                            pThunk[31] = 0x90;
                                        } else if (mode == 1) {
                                            uint64_t encTarget = rawTarget ^ thunkKey;
                                            pThunk[0] = 0x49; pThunk[1] = 0xBB;
                                            *reinterpret_cast<uint64_t*>(pThunk + 2) = encTarget;
                                            pThunk[10] = 0x48; pThunk[11] = 0xB8;
                                            *reinterpret_cast<uint64_t*>(pThunk + 12) = thunkKey;
                                            pThunk[20] = 0x49; pThunk[21] = 0x31; pThunk[22] = 0xC3;
                                            pThunk[23] = 0x41; pThunk[24] = 0xFF; pThunk[25] = 0xE3;
                                            pThunk[26] = 0xF8; pThunk[27] = 0xFC;
                                            pThunk[28] = 0x48; pThunk[29] = 0x85; pThunk[30] = 0xC0;
                                            pThunk[31] = 0x90;
                                        } else if (mode == 2) {
                                            uint64_t encTarget = rawTarget + thunkKey;
                                            pThunk[0] = 0x49; pThunk[1] = 0xBA;
                                            *reinterpret_cast<uint64_t*>(pThunk + 2) = encTarget;
                                            pThunk[10] = 0x48; pThunk[11] = 0xB8;
                                            *reinterpret_cast<uint64_t*>(pThunk + 12) = thunkKey;
                                            pThunk[20] = 0x49; pThunk[21] = 0x29; pThunk[22] = 0xC2;
                                            pThunk[23] = 0x41; pThunk[24] = 0xFF; pThunk[25] = 0xE2;
                                            pThunk[26] = 0x0F; pThunk[27] = 0x1F; pThunk[28] = 0x44; pThunk[29] = 0x00; pThunk[30] = 0x00;
                                            pThunk[31] = 0x90;
                                        } else {
                                            uint64_t encTarget = rawTarget - thunkKey;
                                            pThunk[0] = 0x49; pThunk[1] = 0xBB;
                                            *reinterpret_cast<uint64_t*>(pThunk + 2) = encTarget;
                                            pThunk[10] = 0x48; pThunk[11] = 0xB8;
                                            *reinterpret_cast<uint64_t*>(pThunk + 12) = thunkKey;
                                            pThunk[20] = 0x49; pThunk[21] = 0x01; pThunk[22] = 0xC3;
                                            pThunk[23] = 0x41; pThunk[24] = 0xFF; pThunk[25] = 0xE3;
                                            pThunk[26] = 0x66; pThunk[27] = 0x0F; pThunk[28] = 0x1F; pThunk[29] = 0x44; pThunk[30] = 0x00; pThunk[31] = 0x00;
                                        }

                                        *iatEntry = reinterpret_cast<uintptr_t>(pThunk);
                                        thunkIndex++;
                                    } else {
                                        *iatEntry = reinterpret_cast<uintptr_t>(pFunc);
                                    }

                                    SyscallEngine::ProtectMemory(sysCtx, apis, iatEntry, sizeof(uintptr_t), iatOld, &iatOld);
                                }
                            }
                        }
                    }
                }

                if (pThunkBase && config->thunkPoolSize) {
                    SyscallEngine::ProtectMemory(sysCtx, apis, pThunkBase, config->thunkPoolSize, PAGE_EXECUTE_READ, &thunkOldProtect);
                    if (apis.FlushInstructionCache && apis.GetCurrentProcess) {
                        apis.FlushInstructionCache(apis.GetCurrentProcess(), pThunkBase, config->thunkPoolSize);
                    }
                }

                SecureZero(encImports, config->encryptedImportsSize);
            }
        }

        if (config->tlsCallbacksRva && config->tlsCallbackCount) {
            uint32_t tlsDataSize = config->tlsCallbackCount * sizeof(uint32_t);
            uint8_t* encTls = reinterpret_cast<uint8_t*>(imageBase + config->tlsCallbacksRva);
            DWORD oldProtect = 0;
            if (SyscallEngine::ProtectMemory(sysCtx, apis, encTls, tlsDataSize, PAGE_READWRITE, &oldProtect)) {
                ChaCha20::CryptInPlace(sessionKey, config->tlsNonce, 0,
                                       encTls, tlsDataSize);

                const auto* cbRvas = reinterpret_cast<const uint32_t*>(encTls);
                for (uint32_t c = 0; c < config->tlsCallbackCount; ++c) {
                    if (cbRvas[c] != 0) {
                        auto cbFunc = reinterpret_cast<t_PIMAGE_TLS_CALLBACK>(imageBase + cbRvas[c]);
                        cbFunc(reinterpret_cast<PVOID>(imageBase), DLL_PROCESS_ATTACH, nullptr);
                    }
                }

                SecureZero(encTls, tlsDataSize);
            }
        }

        if (config->pdataRva && config->pdataSize && config->pdataEntryCount) {
            uint8_t* encPdata = reinterpret_cast<uint8_t*>(imageBase + config->pdataRva);
            DWORD oldProtect = 0;
            if (SyscallEngine::ProtectMemory(sysCtx, apis, encPdata, config->pdataSize, PAGE_READWRITE, &oldProtect)) {
                ChaCha20::CryptInPlace(sessionKey, config->pdataNonce, 0,
                                       encPdata, config->pdataSize);
                if (apis.RtlAddFunctionTable) {
                    apis.RtlAddFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(encPdata),
                                             config->pdataEntryCount,
                                             imageBase);
                }
                SyscallEngine::ProtectMemory(sysCtx, apis, encPdata, config->pdataSize, PAGE_READONLY, &oldProtect);
            }
        }

        for (uint32_t i = 0; i < config->sectionCount; ++i) {
            const auto& sec = config->sections[i];
            uint8_t* pSection = reinterpret_cast<uint8_t*>(imageBase + sec.virtualAddress);

            DWORD oldProtect = 0;
            SyscallEngine::ProtectMemory(sysCtx, apis, pSection, sec.virtualSize, sec.originalProtect, &oldProtect);

            if (apis.FlushInstructionCache && apis.GetCurrentProcess) {
                apis.FlushInstructionCache(apis.GetCurrentProcess(), pSection, sec.virtualSize);
            }
        }

        uintptr_t realOep = imageBase + config->originalEntryPoint;

        if (config->textHash != 0 && config->sectionCount > 0) {
            const auto& sec0 = config->sections[0];
            const auto* pSection0 = reinterpret_cast<const uint8_t*>(imageBase + sec0.virtualAddress);
            uint64_t finalHash = HashFNV1a64(pSection0, sec0.rawSize);
            if (finalHash != config->textHash) {
                SecureZero(sessionKey, sizeof(sessionKey));
                apis.ExitProcess(0);
                return false;
            }
        }

        SecureZero(sessionKey, sizeof(sessionKey));

        SecureZero(config->blindedKey, sizeof(config->blindedKey));
        memset(config->importsNonce, 0, sizeof(config->importsNonce));
        memset(config->relocsNonce, 0, sizeof(config->relocsNonce));
        memset(config->tlsNonce, 0, sizeof(config->tlsNonce));
        memset(config->pdataNonce, 0, sizeof(config->pdataNonce));
        config->keyCanary = 0;
        config->textHash = 0;

        DWORD hdrOldProtect = 0;
        if (SyscallEngine::ProtectMemory(sysCtx, apis, reinterpret_cast<void*>(imageBase), 4096, PAGE_READWRITE, &hdrOldProtect)) {
            auto* pSecHeaders = IMAGE_FIRST_SECTION(nt);
            for (uint16_t s = 0; s < nt->FileHeader.NumberOfSections; ++s) {
                memset(pSecHeaders[s].Name, 0, sizeof(pSecHeaders[s].Name));
            }
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;

            SyscallEngine::ProtectMemory(sysCtx, apis, reinterpret_cast<void*>(imageBase), 4096, hdrOldProtect, &hdrOldProtect);
        }

        uintptr_t targetOep = imageBase + (config->stolenLen > 0 ? config->stolenOep : config->originalEntryPoint);
        uint64_t stackAdjust = config->stolenLen > 0 ? config->stolenStackAdjust : 0;

        outDispatch->targetOep = targetOep;
        outDispatch->stackAdjust = stackAdjust;
        outDispatch->useVeh = 0;

        return true;
    }

}
