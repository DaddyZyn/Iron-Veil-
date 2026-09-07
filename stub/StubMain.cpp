#include "DynamicResolver.hpp"
#include "AntiDebug.hpp"
#include "../include/Encryptor.hpp"

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

    extern "C" __declspec(dllexport) uintptr_t StubMainWorker() {
        uintptr_t imageBase = DynamicResolver::GetImageBase();
        if (!imageBase)
            return 0;

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;

        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(imageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return 0;

        uint32_t epRva = nt->OptionalHeader.AddressOfEntryPoint;
        auto* sections = IMAGE_FIRST_SECTION(nt);
        IMAGE_SECTION_HEADER* guardSec = nullptr;

        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (epRva >= sections[i].VirtualAddress && 
                epRva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
                guardSec = &sections[i];
                break;
            }
        }

        if (!guardSec)
            return 0;

        auto* config = reinterpret_cast<StubConfig*>(imageBase + guardSec->VirtualAddress);
        if (config->magic != STUB_MAGIC || config->version != STUB_VERSION)
            return 0;

        ResolvedApis apis;
        if (!DynamicResolver::ResolveAll(apis))
            return 0;

        if (AntiDebug::PerformAllChecks(apis, config->antiDebugFlags)) {
            apis.ExitProcess(0);
            return 0;
        }

        for (uint32_t i = 0; i < config->sectionCount; ++i) {
            const auto& sec = config->sections[i];
            uint8_t* pSection = reinterpret_cast<uint8_t*>(imageBase + sec.virtualAddress);

            DWORD oldProtect = 0;
            if (apis.VirtualProtect(pSection, sec.virtualSize, PAGE_READWRITE, &oldProtect)) {
                ChaCha20::CryptInPlace(config->encryptionKey, sec.nonce, 0, 
                                       pSection, sec.rawSize);
            }
        }

        if (config->relocTableRva && config->relocTableSize && config->originalImageBase) {
            intptr_t delta = static_cast<intptr_t>(imageBase) - static_cast<intptr_t>(config->originalImageBase);
            if (delta != 0) {
                uint8_t* encRelocs = reinterpret_cast<uint8_t*>(imageBase + config->relocTableRva);
                DWORD oldProtect = 0;
                if (apis.VirtualProtect(encRelocs, config->relocTableSize, PAGE_READWRITE, &oldProtect)) {
                    ChaCha20::CryptInPlace(config->encryptionKey, config->relocsNonce, 0,
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
                        bool pageUnprotected = apis.VirtualProtect(pPage, 4096, PAGE_READWRITE, &pageOldProtect) != FALSE;

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
                            apis.VirtualProtect(pPage, 4096, pageOldProtect, &pageOldProtect);
                        }

                        relocOffset += block->SizeOfBlock;
                    }

                    memset(encRelocs, 0, config->relocTableSize);
                    apis.VirtualProtect(encRelocs, config->relocTableSize, PAGE_NOACCESS, &oldProtect);
                }
            }
        }

        if (config->encryptedImportsRva && config->encryptedImportsSize) {
            uint8_t* encImports = reinterpret_cast<uint8_t*>(imageBase + config->encryptedImportsRva);

            DWORD oldProtect = 0;
            if (apis.VirtualProtect(encImports, config->encryptedImportsSize, PAGE_READWRITE, &oldProtect)) {
                ChaCha20::CryptInPlace(config->encryptionKey, config->importsNonce, 0,
                                       encImports, config->encryptedImportsSize);

                size_t offset = 0;
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
                                    apis.VirtualProtect(iatEntry, sizeof(uintptr_t), PAGE_READWRITE, &iatOld);
                                    *iatEntry = reinterpret_cast<uintptr_t>(pFunc);
                                    apis.VirtualProtect(iatEntry, sizeof(uintptr_t), iatOld, &iatOld);
                                }
                            }
                        }
                    }
                }

                memset(encImports, 0, config->encryptedImportsSize);
                apis.VirtualProtect(encImports, config->encryptedImportsSize, PAGE_NOACCESS, &oldProtect);
            }
        }

        if (config->tlsCallbacksRva && config->tlsCallbackCount) {
            uint32_t tlsDataSize = config->tlsCallbackCount * sizeof(uint32_t);
            uint8_t* encTls = reinterpret_cast<uint8_t*>(imageBase + config->tlsCallbacksRva);
            DWORD oldProtect = 0;
            if (apis.VirtualProtect(encTls, tlsDataSize, PAGE_READWRITE, &oldProtect)) {
                ChaCha20::CryptInPlace(config->encryptionKey, config->tlsNonce, 0,
                                       encTls, tlsDataSize);

                const auto* cbRvas = reinterpret_cast<const uint32_t*>(encTls);
                for (uint32_t c = 0; c < config->tlsCallbackCount; ++c) {
                    if (cbRvas[c] != 0) {
                        auto cbFunc = reinterpret_cast<t_PIMAGE_TLS_CALLBACK>(imageBase + cbRvas[c]);
                        cbFunc(reinterpret_cast<PVOID>(imageBase), DLL_PROCESS_ATTACH, nullptr);
                    }
                }

                memset(encTls, 0, tlsDataSize);
                apis.VirtualProtect(encTls, tlsDataSize, PAGE_NOACCESS, &oldProtect);
            }
        }

        if (config->pdataRva && config->pdataSize && config->pdataEntryCount) {
            uint8_t* encPdata = reinterpret_cast<uint8_t*>(imageBase + config->pdataRva);
            DWORD oldProtect = 0;
            if (apis.VirtualProtect(encPdata, config->pdataSize, PAGE_READWRITE, &oldProtect)) {
                ChaCha20::CryptInPlace(config->encryptionKey, config->pdataNonce, 0,
                                       encPdata, config->pdataSize);
                if (apis.RtlAddFunctionTable) {
                    apis.RtlAddFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(encPdata),
                                             config->pdataEntryCount,
                                             imageBase);
                }
                apis.VirtualProtect(encPdata, config->pdataSize, PAGE_READONLY, &oldProtect);
            }
        }

        for (uint32_t i = 0; i < config->sectionCount; ++i) {
            const auto& sec = config->sections[i];
            uint8_t* pSection = reinterpret_cast<uint8_t*>(imageBase + sec.virtualAddress);

            DWORD oldProtect = 0;
            apis.VirtualProtect(pSection, sec.virtualSize, sec.originalProtect, &oldProtect);

            if (apis.FlushInstructionCache && apis.GetCurrentProcess) {
                apis.FlushInstructionCache(apis.GetCurrentProcess(), pSection, sec.virtualSize);
            }
        }

        if (config->textHash != 0 && config->sectionCount > 0) {
            const auto& firstSec = config->sections[0];
            uint8_t* pText = reinterpret_cast<uint8_t*>(imageBase + firstSec.virtualAddress);
            uint64_t currentHash = HashFNV1a64(pText, firstSec.rawSize);
            if (currentHash != config->textHash) {
                apis.ExitProcess(0);
                return 0;
            }
        }

        uintptr_t realOep = imageBase + config->originalEntryPoint;

        if (config->antiDebugFlags & ANTIDEBUG_ANTI_DUMP) {
            auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);
            if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE && dosHeader->e_lfanew > 0) {
                auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(imageBase + dosHeader->e_lfanew);
                DWORD oldP = 0;
                if (apis.VirtualProtect(reinterpret_cast<LPVOID>(imageBase), 4096, PAGE_READWRITE, &oldP)) {
                    dosHeader->e_magic = 0;
                    ntHeaders->Signature = 0;
                    ntHeaders->FileHeader.NumberOfSections = 0;
                    auto* secHeaders = IMAGE_FIRST_SECTION(ntHeaders);
                    for (uint16_t s = 0; s < config->sectionCount; ++s) {
                        memset(secHeaders[s].Name, 0, 8);
                        secHeaders[s].PointerToRawData = 0;
                        secHeaders[s].SizeOfRawData = 0;
                    }
                    apis.VirtualProtect(reinterpret_cast<LPVOID>(imageBase), 4096, oldP, &oldP);
                }
            }
        }

        DWORD cfgOldProtect = 0;
        if (apis.VirtualProtect(config, sizeof(StubConfig), PAGE_READWRITE, &cfgOldProtect)) {
            memset(config->encryptionKey, 0, sizeof(config->encryptionKey));
            memset(config->importsNonce, 0, sizeof(config->importsNonce));
            memset(config->relocsNonce, 0, sizeof(config->relocsNonce));
            memset(config->tlsNonce, 0, sizeof(config->tlsNonce));
            memset(config->pdataNonce, 0, sizeof(config->pdataNonce));
            config->magic = 0;
            config->version = 0;
            config->originalEntryPoint = 0;
            config->textHash = 0;
            memset(config->sections, 0, sizeof(config->sections));
            memset(config, 0, sizeof(StubConfig));
            apis.VirtualProtect(config, sizeof(StubConfig), PAGE_NOACCESS, &cfgOldProtect);
        }

        return realOep;
    }

}
