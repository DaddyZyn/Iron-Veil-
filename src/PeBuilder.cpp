#include "../include/PeBuilder.hpp"
#include <cstring>

namespace IronVeil {

    PeBuilder::PeBuilder(PeParser& parser, const ProtectorOptions& options)
        : m_parser(parser), m_options(options) {}

    bool PeBuilder::SerializeImports(const std::vector<ImportedModule>& imports, std::vector<uint8_t>& outBlob) {
        outBlob.clear();

        auto write32 = [&](uint32_t v) {
            const auto* p = reinterpret_cast<const uint8_t*>(&v);
            outBlob.insert(outBlob.end(), p, p + 4);
        };

        auto write16 = [&](uint16_t v) {
            const auto* p = reinterpret_cast<const uint8_t*>(&v);
            outBlob.insert(outBlob.end(), p, p + 2);
        };

        auto write8 = [&](uint8_t v) {
            outBlob.push_back(v);
        };

        auto writeStr = [&](const std::string& s) {
            outBlob.insert(outBlob.end(), s.begin(), s.end());
            outBlob.push_back(0);
        };

        uint32_t modCount = static_cast<uint32_t>(imports.size());
        write32(modCount);

        for (const auto& mod : imports) {
            write32(static_cast<uint32_t>(mod.moduleName.size()));
            writeStr(mod.moduleName);

            write32(static_cast<uint32_t>(mod.functions.size()));
            for (const auto& fn : mod.functions) {
                write32(fn.iatRva);
                write8(fn.isOrdinal ? 1 : 0);
                write16(fn.ordinal);
                write16(static_cast<uint16_t>(fn.name.size()));
                if (!fn.isOrdinal && !fn.name.empty()) {
                    writeStr(fn.name);
                }
            }
        }

        return true;
    }

    bool PeBuilder::CreateStubPayload(const std::vector<uint8_t>& stubCode, 
                                     const StubConfig& config, 
                                     const std::vector<uint8_t>& encryptedImports,
                                     const std::vector<uint8_t>& encryptedRelocs,
                                     const std::vector<uint8_t>& encryptedTls,
                                     const std::vector<uint8_t>& encryptedPdata,
                                     uint32_t stubCodeAlignedSize,
                                     std::vector<uint8_t>& outPayload,
                                     uint32_t& outConfigOffsetInPayload) {
        outPayload.clear();
        outConfigOffsetInPayload = 0;

        const auto* cfgBytes = reinterpret_cast<const uint8_t*>(&config);
        outPayload.insert(outPayload.end(), cfgBytes, cfgBytes + sizeof(StubConfig));

        outPayload.insert(outPayload.end(), stubCode.begin(), stubCode.end());

        if (outPayload.size() < stubCodeAlignedSize) {
            outPayload.resize(stubCodeAlignedSize, 0);
        }

        outPayload.insert(outPayload.end(), encryptedImports.begin(), encryptedImports.end());

        while (outPayload.size() % 16 != 0) outPayload.push_back(0);
        outPayload.insert(outPayload.end(), encryptedRelocs.begin(), encryptedRelocs.end());

        while (outPayload.size() % 16 != 0) outPayload.push_back(0);
        outPayload.insert(outPayload.end(), encryptedTls.begin(), encryptedTls.end());

        while (outPayload.size() % 16 != 0) outPayload.push_back(0);
        outPayload.insert(outPayload.end(), encryptedPdata.begin(), encryptedPdata.end());

        return true;
    }

    bool PeBuilder::Build(std::vector<uint8_t>& outProtectedPe) {
        auto* nt = m_parser.GetNtHeaders();
        if (!nt)
            return false;

        auto& rawBuffer = m_parser.GetBuffer();

        std::vector<ImportedModule> imports;
        if (!m_parser.ParseImports(imports)) {
            std::cerr << "[-] Failed to parse imports from PE." << std::endl;
            return false;
        }

        std::cout << "[+] Extracted " << imports.size() << " imported modules." << std::endl;

        std::vector<uint8_t> importBlob;
        SerializeImports(imports, importBlob);

        std::vector<uint8_t> relocBlob;
        if (m_options.handleRelocations) {
            m_parser.ExtractRelocations(relocBlob);
            if (!relocBlob.empty()) {
                std::cout << "[+] Extracted " << relocBlob.size() << " bytes of base relocations." << std::endl;
            }
        }

        std::vector<uint32_t> tlsCallbacks;
        std::vector<uint8_t> tlsBlob;
        if (m_options.handleTlsCallbacks) {
            m_parser.ExtractTlsCallbacks(tlsCallbacks);
            if (!tlsCallbacks.empty()) {
                std::cout << "[+] Extracted " << tlsCallbacks.size() << " TLS callbacks." << std::endl;
                tlsBlob.resize(tlsCallbacks.size() * sizeof(uint32_t));
                memcpy(tlsBlob.data(), tlsCallbacks.data(), tlsBlob.size());

                const auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                if (tlsDir.VirtualAddress != 0) {
                    uint32_t tlsOffset = m_parser.RvaToOffset(tlsDir.VirtualAddress);
                    if (tlsOffset != 0 && tlsOffset + sizeof(IMAGE_TLS_DIRECTORY64) <= rawBuffer.size()) {
                        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(rawBuffer.data() + tlsOffset);
                        tls->AddressOfCallBacks = 0;
                    }
                }
            }
        }

        std::vector<uint8_t> pdataBlob;
        uint32_t pdataEntryCount = 0;
        if (m_options.sanitizePdata) {
            const auto& pdataDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (pdataDir.VirtualAddress != 0 && pdataDir.Size >= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) {
                uint32_t pdataOffset = m_parser.RvaToOffset(pdataDir.VirtualAddress);
                if (pdataOffset != 0 && pdataOffset + pdataDir.Size <= rawBuffer.size()) {
                    pdataBlob.assign(rawBuffer.data() + pdataOffset, rawBuffer.data() + pdataOffset + pdataDir.Size);
                    pdataEntryCount = pdataDir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
                    std::cout << "[+] Extracted " << pdataEntryCount << " runtime function unwind entries (.pdata)." << std::endl;
                    memset(rawBuffer.data() + pdataOffset, 0, pdataDir.Size);
                }
            }
        }

        uint8_t encKey[32] = { 0 };
        uint8_t encNonce[12] = { 0 };
        CryptoUtils::GenerateRandomBytes(encKey, sizeof(encKey));
        CryptoUtils::GenerateRandomBytes(encNonce, sizeof(encNonce));

        std::vector<uint8_t> encImportBlob(importBlob.size());
        ChaCha20::Process(encKey, encNonce, 0, importBlob.data(), encImportBlob.data(), importBlob.size());

        std::vector<uint8_t> encRelocBlob(relocBlob.size());
        if (!relocBlob.empty()) {
            ChaCha20::Process(encKey, encNonce, 50, relocBlob.data(), encRelocBlob.data(), relocBlob.size());
        }

        std::vector<uint8_t> encTlsBlob(tlsBlob.size());
        if (!tlsBlob.empty()) {
            ChaCha20::Process(encKey, encNonce, 60, tlsBlob.data(), encTlsBlob.data(), tlsBlob.size());
        }

        std::vector<uint8_t> encPdataBlob(pdataBlob.size());
        if (!pdataBlob.empty()) {
            ChaCha20::Process(encKey, encNonce, 70, pdataBlob.data(), encPdataBlob.data(), pdataBlob.size());
        }

        StubConfig config = { 0 };
        config.magic = STUB_MAGIC;
        config.version = STUB_VERSION;
        config.originalEntryPoint = nt->OptionalHeader.AddressOfEntryPoint;
        config.originalImageBase = nt->OptionalHeader.ImageBase;
        memcpy(config.encryptionKey, encKey, 32);
        memcpy(config.encryptionNonce, encNonce, 12);
        config.antiDebugFlags = m_options.antiDebugFlags;

        auto* sections = m_parser.GetSectionHeaders();
        uint32_t protectedCount = 0;

        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            auto& sec = sections[i];
            char secName[9] = { 0 };
            memcpy(secName, sec.Name, 8);

            bool shouldEncrypt = false;
            if (m_options.encryptTextSection && (sec.Characteristics & IMAGE_SCN_CNT_CODE || strcmp(secName, ".text") == 0)) {
                shouldEncrypt = true;
            } else if (m_options.encryptRdataSection && strcmp(secName, ".rdata") == 0) {
                shouldEncrypt = true;
            }

            if (shouldEncrypt && protectedCount < 16) {
                auto& secInfo = config.sections[protectedCount];
                secInfo.virtualAddress = sec.VirtualAddress;
                secInfo.virtualSize = sec.Misc.VirtualSize;
                secInfo.rawSize = sec.SizeOfRawData;
                secInfo.characteristics = sec.Characteristics;

                DWORD origProtect = PAGE_READONLY;
                if (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    origProtect = (sec.Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
                } else if (sec.Characteristics & IMAGE_SCN_MEM_WRITE) {
                    origProtect = PAGE_READWRITE;
                }
                secInfo.originalProtect = origProtect;

                if (protectedCount == 0) {
                    uint8_t* pRawCode = rawBuffer.data() + sec.PointerToRawData;
                    config.textHash = HashFNV1a64(pRawCode, sec.SizeOfRawData);
                }

                std::cout << "[+] Encrypting section: " << secName << " (" << sec.SizeOfRawData / 1024 << " KB)..." << std::endl;
                ChaCha20::CryptInPlace(encKey, encNonce, 1 + protectedCount, 
                                       rawBuffer.data() + sec.PointerToRawData, sec.SizeOfRawData);

                sec.Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
                sec.Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;

                protectedCount++;
            }
        }

        config.sectionCount = protectedCount;

        if (m_options.stripImports) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
        }

        if (m_options.handleRelocations && !relocBlob.empty()) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
        }

        if (m_options.sanitizePdata && !pdataBlob.empty()) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = 0;
        }

        if (m_options.wipeDebugDirectory) {
            const auto& debugDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            if (debugDir.VirtualAddress != 0 && debugDir.Size != 0) {
                uint32_t debugOffset = m_parser.RvaToOffset(debugDir.VirtualAddress);
                if (debugOffset != 0 && debugOffset + debugDir.Size <= rawBuffer.size()) {
                    auto* dbgEntry = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(rawBuffer.data() + debugOffset);
                    if (dbgEntry->PointerToRawData != 0 && dbgEntry->PointerToRawData + dbgEntry->SizeOfData <= rawBuffer.size()) {
                        memset(rawBuffer.data() + dbgEntry->PointerToRawData, 0, dbgEntry->SizeOfData);
                    }
                    memset(rawBuffer.data() + debugOffset, 0, debugDir.Size);
                }
            }
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
        }

        nt->OptionalHeader.DllCharacteristics &= ~0x4000;

        std::vector<uint8_t> stubCode;
        uint32_t stubEpOffsetInText = 0;

        PeParser stubDll;
        if (stubDll.Load("IronVeilStub.dll") || stubDll.Load("bin/Release/IronVeilStub.dll")) {
            auto* stubNt = stubDll.GetNtHeaders();
            auto* textSec = stubDll.GetSectionByName(".text");
            if (stubNt && textSec) {
                const auto& dllBuf = stubDll.GetBuffer();
                stubCode.assign(dllBuf.data() + textSec->PointerToRawData, 
                                dllBuf.data() + textSec->PointerToRawData + textSec->SizeOfRawData);
                
                uint32_t stubEpRva = stubNt->OptionalHeader.AddressOfEntryPoint;
                if (stubEpRva >= textSec->VirtualAddress) {
                    stubEpOffsetInText = stubEpRva - textSec->VirtualAddress;
                }
                std::cout << "[+] Extracted stub code (" << stubCode.size() << " bytes), StubEntryPoint offset: 0x" 
                          << std::hex << stubEpOffsetInText << std::dec << std::endl;
            }
        }

        if (stubCode.empty()) {
            std::cerr << "[-] Error: Failed to extract stub code from IronVeilStub.dll." << std::endl;
            return false;
        }

        auto* lastSec = &sections[nt->FileHeader.NumberOfSections - 1];
        uint32_t guardVa = AlignUp(lastSec->VirtualAddress + lastSec->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
        uint32_t guardRawOffset = AlignUp(static_cast<uint32_t>(rawBuffer.size()), nt->OptionalHeader.FileAlignment);

        uint32_t stubCodeAlignedSize = AlignUp(static_cast<uint32_t>(sizeof(StubConfig) + stubCode.size()), nt->OptionalHeader.SectionAlignment);

        config.encryptedImportsRva = guardVa + stubCodeAlignedSize;
        config.encryptedImportsSize = static_cast<uint32_t>(encImportBlob.size());

        uint32_t currentOffset = stubCodeAlignedSize + static_cast<uint32_t>(encImportBlob.size());
        while (currentOffset % 16 != 0) currentOffset++;

        if (!encRelocBlob.empty()) {
            config.relocTableRva = guardVa + currentOffset;
            config.relocTableSize = static_cast<uint32_t>(encRelocBlob.size());
            currentOffset += static_cast<uint32_t>(encRelocBlob.size());
            while (currentOffset % 16 != 0) currentOffset++;
        }

        if (!encTlsBlob.empty()) {
            config.tlsCallbacksRva = guardVa + currentOffset;
            config.tlsCallbackCount = static_cast<uint32_t>(tlsCallbacks.size());
            currentOffset += static_cast<uint32_t>(encTlsBlob.size());
            while (currentOffset % 16 != 0) currentOffset++;
        }

        if (!encPdataBlob.empty()) {
            config.pdataRva = guardVa + currentOffset;
            config.pdataSize = static_cast<uint32_t>(encPdataBlob.size());
            config.pdataEntryCount = pdataEntryCount;
            currentOffset += static_cast<uint32_t>(encPdataBlob.size());
            while (currentOffset % 16 != 0) currentOffset++;
        }

        uint32_t cfgOffset = 0;
        std::vector<uint8_t> guardPayload;
        CreateStubPayload(stubCode, config, encImportBlob, encRelocBlob, encTlsBlob, encPdataBlob, stubCodeAlignedSize, guardPayload, cfgOffset);

        uint32_t guardRawSize = AlignUp(static_cast<uint32_t>(guardPayload.size()), nt->OptionalHeader.FileAlignment);
        uint32_t guardVirtualSize = AlignUp(static_cast<uint32_t>(guardPayload.size()), nt->OptionalHeader.SectionAlignment);

        guardPayload.resize(guardRawSize, 0);

        if (nt->FileHeader.NumberOfSections >= 96) {
            std::cerr << "[-] Error: Maximum section count reached." << std::endl;
            return false;
        }

        IMAGE_SECTION_HEADER newSec = { 0 };
        strncpy_s(reinterpret_cast<char*>(newSec.Name), 8, m_options.sectionName.c_str(), 8);
        newSec.VirtualAddress = guardVa;
        newSec.Misc.VirtualSize = guardVirtualSize;
        newSec.PointerToRawData = guardRawOffset;
        newSec.SizeOfRawData = guardRawSize;
        newSec.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

        size_t secHeaderOffset = reinterpret_cast<uint8_t*>(&sections[nt->FileHeader.NumberOfSections]) - rawBuffer.data();
        if (secHeaderOffset + sizeof(IMAGE_SECTION_HEADER) > nt->OptionalHeader.SizeOfHeaders) {
            std::cerr << "[-] Error: Not enough space in headers for new section header." << std::endl;
            return false;
        }

        memcpy(rawBuffer.data() + secHeaderOffset, &newSec, sizeof(IMAGE_SECTION_HEADER));
        nt->FileHeader.NumberOfSections++;

        nt->OptionalHeader.AddressOfEntryPoint = guardVa + sizeof(StubConfig) + stubEpOffsetInText;
        nt->OptionalHeader.SizeOfImage = guardVa + guardVirtualSize;

        if (rawBuffer.size() < guardRawOffset) {
            rawBuffer.resize(guardRawOffset, 0);
        }
        rawBuffer.insert(rawBuffer.end(), guardPayload.begin(), guardPayload.end());

        outProtectedPe = rawBuffer;
        std::cout << "[+] Protection build successful! New EntryPoint: 0x" << std::hex << nt->OptionalHeader.AddressOfEntryPoint << std::dec << std::endl;
        return true;
    }

}
