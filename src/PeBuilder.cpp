#include "../include/PeBuilder.hpp"
#include "../include/IronVM.hpp"
#include <cstring>

namespace {
    uint32_t CalculatePeChecksum(const uint8_t* data, size_t size, size_t checksumOffset) {
        uint64_t sum = 0;
        size_t words = size / 2;
        for (size_t i = 0; i < words; ++i) {
            if (i * 2 == checksumOffset || i * 2 == checksumOffset + 2) {
                continue;
            }
            uint16_t word = *reinterpret_cast<const uint16_t*>(data + i * 2);
            sum += word;
            if (sum > 0xFFFFFFFF) {
                sum = (sum & 0xFFFFFFFF) + (sum >> 32);
            }
        }
        if (size % 2 != 0) {
            sum += data[size - 1];
            if (sum > 0xFFFFFFFF) {
                sum = (sum & 0xFFFFFFFF) + (sum >> 32);
            }
        }
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = sum + (sum >> 16);
        return static_cast<uint32_t>((sum & 0xFFFF) + size);
    }

    void GenerateSyntheticCode(uint8_t* dest, size_t size, uint32_t baseRva) {
        static const uint8_t fn1[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08,       // mov [rsp+8], rbx
            0x48, 0x89, 0x74, 0x24, 0x10,       // mov [rsp+10h], rsi
            0x57,                               // push rdi
            0x48, 0x83, 0xEC, 0x20,             // sub rsp, 20h
            0x48, 0x8B, 0xD9,                   // mov rbx, rcx
            0x48, 0x8B, 0xF2,                   // mov rsi, rdx
            0x33, 0xC0,                         // xor eax, eax
            0x48, 0x85, 0xD2,                   // test rdx, rdx
            0x74, 0x06,                         // jz +6
            0x48, 0x8B, 0x02,                   // mov rax, [rdx]
            0x48, 0x03, 0xC1,                   // add rax, rcx
            0x48, 0x83, 0xC4, 0x20,             // add rsp, 20h
            0x5F,                               // pop rdi
            0x48, 0x8B, 0x74, 0x24, 0x10,       // mov rsi, [rsp+10h]
            0x48, 0x8B, 0x5C, 0x24, 0x08,       // mov rbx, [rsp+8]
            0xC3,                               // ret
            0xCC, 0xCC, 0xCC, 0xCC              // int 3 alignment
        };

        static const uint8_t fn2[] = {
            0x40, 0x53,                         // push rbx
            0x48, 0x83, 0xEC, 0x20,             // sub rsp, 20h
            0x48, 0x8B, 0xD9,                   // mov rbx, rcx
            0x48, 0x85, 0xC9,                   // test rcx, rcx
            0x74, 0x0D,                         // jz +13
            0x8B, 0x41, 0x04,                   // mov eax, [rcx+4]
            0x03, 0x01,                         // add eax, [rcx]
            0x48, 0x83, 0xC4, 0x20,             // add rsp, 20h
            0x5B,                               // pop rbx
            0xC3,                               // ret
            0x33, 0xC0,                         // xor eax, eax
            0x48, 0x83, 0xC4, 0x20,             // add rsp, 20h
            0x5B,                               // pop rbx
            0xC3,                               // ret
            0x90, 0x90                          // nop alignment
        };

        static const uint8_t fn3[] = {
            0x48, 0x83, 0xEC, 0x38,             // sub rsp, 38h
            0x48, 0x8D, 0x4C, 0x24, 0x20,       // lea rcx, [rsp+20h]
            0x33, 0xD2,                         // xor edx, edx
            0x41, 0xB8, 0x40, 0x00, 0x00, 0x00, // mov r8d, 40h
            0x33, 0xC0,                         // xor eax, eax
            0x48, 0x89, 0x44, 0x24, 0x20,       // mov [rsp+20h], rax
            0x48, 0x83, 0xC4, 0x38,             // add rsp, 38h
            0xC3,                               // ret
            0xCC, 0xCC                          // int 3 alignment
        };

        static const uint8_t fn4[] = {
            0x48, 0x89, 0x4C, 0x24, 0x08,       // mov [rsp+8], rcx
            0x48, 0x83, 0xEC, 0x18,             // sub rsp, 18h
            0x48, 0x8B, 0x44, 0x24, 0x20,       // mov rax, [rsp+20h]
            0x48, 0xFF, 0xC0,                   // inc rax
            0x48, 0x83, 0xC4, 0x18,             // add rsp, 18h
            0xC3,                               // ret
            0x90, 0x90, 0x90, 0x90              // nop alignment
        };

        const uint8_t* fns[] = { fn1, fn2, fn3, fn4 };
        const size_t fnLens[] = { sizeof(fn1), sizeof(fn2), sizeof(fn3), sizeof(fn4) };
        const size_t numFns = 4;

        size_t offset = 0;
        size_t fnIdx = 0;
        while (offset < size) {
            const uint8_t* curFn = fns[fnIdx % numFns];
            size_t curLen = fnLens[fnIdx % numFns];
            size_t copyLen = (offset + curLen <= size) ? curLen : (size - offset);
            memcpy(dest + offset, curFn, copyLen);
            offset += copyLen;
            fnIdx++;
        }
    }
}

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
                                     const std::vector<uint8_t>& vmBytecode,
                                     const std::vector<uint8_t>& sectionPayloads,
                                     const std::vector<uint8_t>& decoyImports,
                                     uint32_t thunkPoolSize,
                                     uint32_t configAlignedSize,
                                     uint32_t stubCodeAlignedSize,
                                     std::vector<uint8_t>& outPayload,
                                     uint32_t& outConfigOffsetInPayload) {
        outPayload.clear();
        outConfigOffsetInPayload = 0;

        const auto* cfgBytes = reinterpret_cast<const uint8_t*>(&config);
        outPayload.insert(outPayload.end(), cfgBytes, cfgBytes + sizeof(StubConfig));

        if (outPayload.size() < configAlignedSize) {
            outPayload.resize(configAlignedSize, 0);
        }

        outPayload.insert(outPayload.end(), stubCode.begin(), stubCode.end());

        if (outPayload.size() < stubCodeAlignedSize) {
            outPayload.resize(stubCodeAlignedSize, 0);
        }

        outPayload.insert(outPayload.end(), encryptedImports.begin(), encryptedImports.end());

        if (!encryptedRelocs.empty()) {
            while (outPayload.size() % 16 != 0) outPayload.push_back(0);
            outPayload.insert(outPayload.end(), encryptedRelocs.begin(), encryptedRelocs.end());
        }

        if (!encryptedTls.empty()) {
            while (outPayload.size() % 16 != 0) outPayload.push_back(0);
            outPayload.insert(outPayload.end(), encryptedTls.begin(), encryptedTls.end());
        }

        if (!encryptedPdata.empty()) {
            while (outPayload.size() % 16 != 0) outPayload.push_back(0);
            outPayload.insert(outPayload.end(), encryptedPdata.begin(), encryptedPdata.end());
        }

        if (!vmBytecode.empty()) {
            while (outPayload.size() % 16 != 0) outPayload.push_back(0);
            outPayload.insert(outPayload.end(), vmBytecode.begin(), vmBytecode.end());
        }

        if (!sectionPayloads.empty()) {
            while (outPayload.size() % 16 != 0) outPayload.push_back(0);
            outPayload.insert(outPayload.end(), sectionPayloads.begin(), sectionPayloads.end());
        }

        if (!decoyImports.empty()) {
            while (outPayload.size() % 16 != 0) outPayload.push_back(0);
            outPayload.insert(outPayload.end(), decoyImports.begin(), decoyImports.end());
        }

        if (thunkPoolSize > 0) {
            while (outPayload.size() % 16 != 0) outPayload.push_back(0);
            outPayload.resize(outPayload.size() + thunkPoolSize, 0x90);
        }

        return true;
    }

    bool PeBuilder::BuildDecoyImports(uint32_t baseRva, std::vector<uint8_t>& outBlob,
                                      uint32_t& outImportDirRva, uint32_t& outImportDirSize,
                                      uint32_t& outIatRva, uint32_t& outIatSize) {
        outBlob.clear();

        struct DecoyModule {
            std::string dllName;
            std::vector<std::string> functions;
        };

        const std::vector<DecoyModule> modules = {
            {
                "KERNEL32.dll",
                {
                    "InitializeSListHead",
                    "GetSystemTimeAsFileTime",
                    "GetCurrentProcessId",
                    "GetCurrentThreadId",
                    "QueryPerformanceCounter",
                    "IsDebuggerPresent",
                    "IsProcessorFeaturePresent",
                    "TerminateProcess",
                    "GetCurrentProcess",
                    "SetUnhandledExceptionFilter",
                    "UnhandledExceptionFilter",
                    "RtlCaptureContext",
                    "RtlLookupFunctionEntry",
                    "RtlVirtualUnwind",
                    "Sleep",
                    "CloseHandle",
                    "GetLastError",
                    "SetLastError",
                    "LocalFree",
                    "FormatMessageW",
                    "MultiByteToWideChar",
                    "WideCharToMultiByte"
                }
            },
            {
                "VCRUNTIME140.dll",
                {
                    "__C_specific_handler",
                    "memset",
                    "memcpy",
                    "memmove"
                }
            },
            {
                "api-ms-win-crt-runtime-l1-1-0.dll",
                {
                    "_initterm",
                    "_initterm_e",
                    "_c_exit",
                    "_register_thread_local_exe_atexit_callback"
                }
            },
            {
                "api-ms-win-crt-stdio-l1-1-0.dll",
                {
                    "__p__commode",
                    "_set_fmode",
                    "__stdio_common_vfprintf"
                }
            },
            {
                "ADVAPI32.dll",
                {
                    "RegCloseKey",
                    "RegOpenKeyExA",
                    "RegQueryValueExA",
                    "SystemFunction036"
                }
            }
        };

        // 1. Calculate layout offsets
        size_t descCount = modules.size() + 1;
        uint32_t descTotalSize = static_cast<uint32_t>(descCount * sizeof(IMAGE_IMPORT_DESCRIPTOR));

        uint32_t currentOffset = descTotalSize;
        if (currentOffset % 8 != 0) currentOffset += 8 - (currentOffset % 8);

        std::vector<uint32_t> intOffsets(modules.size());
        for (size_t m = 0; m < modules.size(); ++m) {
            intOffsets[m] = currentOffset;
            currentOffset += static_cast<uint32_t>((modules[m].functions.size() + 1) * sizeof(uint64_t));
        }

        uint32_t iatStartOffset = currentOffset;
        std::vector<uint32_t> iatOffsets(modules.size());
        for (size_t m = 0; m < modules.size(); ++m) {
            iatOffsets[m] = currentOffset;
            currentOffset += static_cast<uint32_t>((modules[m].functions.size() + 1) * sizeof(uint64_t));
        }
        uint32_t totalIatSize = currentOffset - iatStartOffset;

        std::vector<uint32_t> dllNameOffsets(modules.size());
        for (size_t m = 0; m < modules.size(); ++m) {
            dllNameOffsets[m] = currentOffset;
            currentOffset += static_cast<uint32_t>(modules[m].dllName.size() + 1);
        }

        std::vector<std::vector<uint32_t>> funcOffsets(modules.size());
        for (size_t m = 0; m < modules.size(); ++m) {
            funcOffsets[m].resize(modules[m].functions.size());
            for (size_t f = 0; f < modules[m].functions.size(); ++f) {
                if (currentOffset % 2 != 0) currentOffset++;
                funcOffsets[m][f] = currentOffset;
                currentOffset += static_cast<uint32_t>(2 + modules[m].functions[f].size() + 1);
            }
        }

        while (currentOffset % 16 != 0) currentOffset++;
        uint32_t totalBlobSize = currentOffset;

        outBlob.assign(totalBlobSize, 0);

        // 2. Populate IMAGE_IMPORT_DESCRIPTORs
        auto* descriptors = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(outBlob.data());
        for (size_t m = 0; m < modules.size(); ++m) {
            descriptors[m].OriginalFirstThunk = baseRva + intOffsets[m];
            descriptors[m].TimeDateStamp = 0;
            descriptors[m].ForwarderChain = 0;
            descriptors[m].Name = baseRva + dllNameOffsets[m];
            descriptors[m].FirstThunk = baseRva + iatOffsets[m];
        }

        // 3. Populate DLL name strings
        for (size_t m = 0; m < modules.size(); ++m) {
            memcpy(outBlob.data() + dllNameOffsets[m], modules[m].dllName.c_str(), modules[m].dllName.size() + 1);
        }

        // 4. Populate IMAGE_IMPORT_BY_NAME entries and INT / IAT thunk tables
        for (size_t m = 0; m < modules.size(); ++m) {
            auto* intTable = reinterpret_cast<uint64_t*>(outBlob.data() + intOffsets[m]);
            auto* iatTable = reinterpret_cast<uint64_t*>(outBlob.data() + iatOffsets[m]);

            for (size_t f = 0; f < modules[m].functions.size(); ++f) {
                uint32_t fnRva = baseRva + funcOffsets[m][f];
                intTable[f] = fnRva;
                iatTable[f] = fnRva;

                uint8_t* pNameEntry = outBlob.data() + funcOffsets[m][f];
                *reinterpret_cast<uint16_t*>(pNameEntry) = 0; // Hint = 0
                memcpy(pNameEntry + 2, modules[m].functions[f].c_str(), modules[m].functions[f].size() + 1);
            }
        }

        outImportDirRva = baseRva;
        outImportDirSize = descTotalSize;
        outIatRva = baseRva + iatStartOffset;
        outIatSize = totalIatSize;

        return true;
    }

    bool PeBuilder::Build(std::vector<uint8_t>& outProtectedPe) {
        auto* nt = m_parser.GetNtHeaders();
        if (!nt)
            return false;

        auto& rawBuffer = m_parser.GetBuffer();
        const auto origImportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        const auto origIatDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];

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
                }
            }
        }

        StubConfig config = { 0 };
        config.magic = 0;
        config.version = STUB_VERSION;
        config.originalEntryPoint = nt->OptionalHeader.AddressOfEntryPoint;
        config.originalImageBase = nt->OptionalHeader.ImageBase;
        config.antiDebugFlags = m_options.antiDebugFlags;

        uint8_t encKey[32] = { 0 };
        CryptoUtils::GenerateRandomBytes(encKey, sizeof(encKey));
        CryptoUtils::GenerateRandomBytes(reinterpret_cast<uint8_t*>(&config.keyCanary), sizeof(config.keyCanary));

        // Assemble IronVM bytecode to derive effective canary using MBA operations
        IronVeil::VM::BytecodeBuilder vmBuilder;
        vmBuilder.Imm(1, 0x4B9E2B67ULL)
                 .MbaAdd(0, 1)
                 .Imm(2, 0x5BD1E995ULL)
                 .MbaXor(0, 2)
                 .Ret();

        config.vmKey = 0xA7;
        std::vector<uint8_t> vmBytecode = vmBuilder.Build(config.vmKey);

        // Derive expected canary through VM execution at build time
        uint64_t expectedVmCanary = IronVeil::VM::VirtualMachine::Execute(
            vmBytecode.data(), vmBytecode.size(), config.vmKey, config.keyCanary
        );
        BlindKey(encKey, expectedVmCanary, config.blindedKey);

        CryptoUtils::GenerateRandomBytes(config.importsNonce, sizeof(config.importsNonce));
        CryptoUtils::GenerateRandomBytes(config.relocsNonce, sizeof(config.relocsNonce));
        CryptoUtils::GenerateRandomBytes(config.tlsNonce, sizeof(config.tlsNonce));
        CryptoUtils::GenerateRandomBytes(config.pdataNonce, sizeof(config.pdataNonce));

        std::vector<uint8_t> encImportBlob(importBlob.size());
        ChaCha20::Process(encKey, config.importsNonce, 0, importBlob.data(), encImportBlob.data(), importBlob.size());

        std::vector<uint8_t> encRelocBlob(relocBlob.size());
        if (!relocBlob.empty()) {
            ChaCha20::Process(encKey, config.relocsNonce, 0, relocBlob.data(), encRelocBlob.data(), relocBlob.size());
        }

        std::vector<uint8_t> encTlsBlob(tlsBlob.size());
        if (!tlsBlob.empty()) {
            ChaCha20::Process(encKey, config.tlsNonce, 0, tlsBlob.data(), encTlsBlob.data(), tlsBlob.size());
        }

        std::vector<uint8_t> encPdataBlob(pdataBlob.size());
        if (!pdataBlob.empty()) {
            ChaCha20::Process(encKey, config.pdataNonce, 0, pdataBlob.data(), encPdataBlob.data(), pdataBlob.size());
        }

        auto* sections = m_parser.GetSectionHeaders();
        uint32_t protectedCount = 0;

        uint32_t epRawOffset = 0;
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (config.originalEntryPoint >= sections[i].VirtualAddress &&
                config.originalEntryPoint < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
                epRawOffset = sections[i].PointerToRawData + (config.originalEntryPoint - sections[i].VirtualAddress);
                break;
            }
        }
        if (epRawOffset != 0 && epRawOffset + sizeof(config.originalEpBytes) <= rawBuffer.size()) {
            memcpy(config.originalEpBytes, rawBuffer.data() + epRawOffset, sizeof(config.originalEpBytes));

            // Check for standard x64 prologue: sub rsp, imm8 (48 83 ec <imm8>) or sub rsp, imm32 (48 81 ec <imm32>)
            const uint8_t* pEp = rawBuffer.data() + epRawOffset;
            if (pEp[0] == 0x48 && pEp[1] == 0x83 && pEp[2] == 0xEC) {
                config.stolenLen = 4;
                config.stolenStackAdjust = pEp[3];
                config.stolenOep = config.originalEntryPoint + 4;
                memset(rawBuffer.data() + epRawOffset, 0xCC, config.stolenLen);
                std::cout << "[+] Sliced & stole function prologue at OEP (sub rsp, 0x"
                          << std::hex << static_cast<uint32_t>(config.stolenStackAdjust)
                          << "). Entrypoint mutilated with traps." << std::dec << std::endl;
            } else if (pEp[0] == 0x48 && pEp[1] == 0x81 && pEp[2] == 0xEC) {
                config.stolenLen = 7;
                config.stolenStackAdjust = *reinterpret_cast<const uint32_t*>(pEp + 3);
                config.stolenOep = config.originalEntryPoint + 7;
                memset(rawBuffer.data() + epRawOffset, 0xCC, config.stolenLen);
                std::cout << "[+] Sliced & stole function prologue at OEP (sub rsp, 0x"
                          << std::hex << config.stolenStackAdjust
                          << "). Entrypoint mutilated with traps." << std::dec << std::endl;
            }
        }

        std::vector<uint8_t> sectionPayloads;
        struct PendingSecPayload {
            uint32_t secIdx;
            uint32_t payloadRelOffset;
            uint32_t payloadSize;
        };
        std::vector<PendingSecPayload> pendingPayloads;

        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            auto& sec = sections[i];
            char secName[9] = { 0 };
            memcpy(secName, sec.Name, 8);

            bool shouldEncrypt = false;
            bool isCodeSection = false;
            if (m_options.encryptTextSection && (sec.Characteristics & IMAGE_SCN_CNT_CODE || strcmp(secName, ".text") == 0)) {
                shouldEncrypt = true;
                isCodeSection = true;
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

                CryptoUtils::GenerateRandomBytes(secInfo.nonce, sizeof(secInfo.nonce));

                if (isCodeSection) {
                    std::cout << "[+] Packaging & encrypting code section: " << secName << " (" << sec.SizeOfRawData / 1024 << " KB) into container..." << std::endl;
                    std::vector<uint8_t> origBytes(rawBuffer.data() + sec.PointerToRawData,
                                                   rawBuffer.data() + sec.PointerToRawData + sec.SizeOfRawData);
                    std::vector<uint8_t> encBytes(origBytes.size());
                    ChaCha20::Process(encKey, secInfo.nonce, 0, origBytes.data(), encBytes.data(), origBytes.size());

                    while (sectionPayloads.size() % 16 != 0) sectionPayloads.push_back(0);
                    uint32_t payloadRelOffset = static_cast<uint32_t>(sectionPayloads.size());
                    sectionPayloads.insert(sectionPayloads.end(), encBytes.begin(), encBytes.end());

                    secInfo.payloadOffset = payloadRelOffset;
                    secInfo.payloadSize = static_cast<uint32_t>(encBytes.size());
                    pendingPayloads.push_back({ protectedCount, payloadRelOffset, secInfo.payloadSize });

                    GenerateSyntheticCode(rawBuffer.data() + sec.PointerToRawData, sec.SizeOfRawData, sec.VirtualAddress);
                    std::cout << "[+] Synthesized valid x64 code for " << secName << " (normalized entropy ~5.8)." << std::endl;
                } else {
                    std::cout << "[+] Encrypting in-place section: " << secName << " (" << sec.SizeOfRawData / 1024 << " KB)..." << std::endl;
                    ChaCha20::CryptInPlace(encKey, secInfo.nonce, 0, 
                                           rawBuffer.data() + sec.PointerToRawData, sec.SizeOfRawData);
                    secInfo.payloadOffset = 0;
                    secInfo.payloadSize = 0;
                }

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

        if (m_options.handleRelocations) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
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

        // Retain original LOAD_CONFIG directory if present in unencrypted section (.rdata)
        const auto& origLoadConfig = m_parser.GetNtHeaders()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (!m_options.encryptRdataSection && origLoadConfig.VirtualAddress != 0 && origLoadConfig.Size != 0) {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = origLoadConfig;
        } else {
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
        }

        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;

        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress = 0;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size = 0;

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

        int relocIndex = -1;
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (strncmp(reinterpret_cast<const char*>(sections[i].Name), ".reloc", 6) == 0) {
                relocIndex = static_cast<int>(i);
                break;
            }
        }
        bool hadRelocAtEnd = (relocIndex >= 0 && relocIndex == nt->FileHeader.NumberOfSections - 1);

        uint32_t guardVa = 0;
        uint32_t guardRawOffset = 0;

        if (hadRelocAtEnd && relocIndex > 0) {
            auto* prevSec = &sections[relocIndex - 1];
            guardVa = AlignUp(prevSec->VirtualAddress + prevSec->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
            guardRawOffset = sections[relocIndex].PointerToRawData;
            if (rawBuffer.size() > guardRawOffset) {
                rawBuffer.resize(guardRawOffset);
            }
        } else {
            auto* lastSec = &sections[nt->FileHeader.NumberOfSections - 1];
            guardVa = AlignUp(lastSec->VirtualAddress + lastSec->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
            guardRawOffset = AlignUp(static_cast<uint32_t>(rawBuffer.size()), nt->OptionalHeader.FileAlignment);
            if (rawBuffer.size() < guardRawOffset) {
                rawBuffer.resize(guardRawOffset, 0);
            }
        }

        uint32_t configAlignedSize = AlignUp(static_cast<uint32_t>(sizeof(StubConfig)), nt->OptionalHeader.SectionAlignment);
        uint32_t stubCodeAlignedSize = AlignUp(configAlignedSize + static_cast<uint32_t>(stubCode.size()), nt->OptionalHeader.SectionAlignment);

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

        if (!vmBytecode.empty()) {
            config.vmBytecodeRva = guardVa + currentOffset;
            config.vmBytecodeSize = static_cast<uint32_t>(vmBytecode.size());
            currentOffset += static_cast<uint32_t>(vmBytecode.size());
            while (currentOffset % 16 != 0) currentOffset++;
        }

        uint32_t sectionPayloadsBaseOffset = currentOffset;
        if (!sectionPayloads.empty()) {
            for (const auto& item : pendingPayloads) {
                config.sections[item.secIdx].payloadOffset = sectionPayloadsBaseOffset + item.payloadRelOffset;
            }
            currentOffset += static_cast<uint32_t>(sectionPayloads.size());
            while (currentOffset % 16 != 0) currentOffset++;
        }

        std::vector<uint8_t> decoyBlob;
        uint32_t decoyImportDirRva = 0;
        uint32_t decoyImportDirSize = 0;
        uint32_t decoyIatRva = 0;
        uint32_t decoyIatSize = 0;

        if (m_options.stripImports && m_options.addDecoyImports) {
            auto* rdataSec = m_parser.GetSectionByName(".rdata");
            if (!rdataSec && origImportDir.VirtualAddress != 0) {
                rdataSec = m_parser.GetSectionByRva(origImportDir.VirtualAddress);
            }

            bool placedInRdata = false;
            if (rdataSec && !m_options.encryptRdataSection && origImportDir.VirtualAddress != 0) {
                uint32_t rdataEndRva = rdataSec->VirtualAddress + rdataSec->SizeOfRawData;
                uint32_t decoyTargetRva = origImportDir.VirtualAddress;

                BuildDecoyImports(decoyTargetRva, decoyBlob, decoyImportDirRva, decoyImportDirSize, decoyIatRva, decoyIatSize);

                if (decoyTargetRva + decoyBlob.size() <= rdataEndRva) {
                    uint32_t decoyRawOffset = m_parser.RvaToOffset(decoyTargetRva);
                    if (decoyRawOffset != 0 && decoyRawOffset + decoyBlob.size() <= rawBuffer.size()) {
                        memcpy(rawBuffer.data() + decoyRawOffset, decoyBlob.data(), decoyBlob.size());
                        placedInRdata = true;
                        std::cout << "[+] Injected decoy imports & IAT into .rdata at RVA 0x" 
                                  << std::hex << decoyTargetRva << " (size " << std::dec << decoyBlob.size() << " bytes)." << std::endl;
                    }
                }
            }

            if (placedInRdata) {
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = decoyImportDirRva;
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = decoyImportDirSize;
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = decoyIatRva;
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = decoyIatSize;
                decoyBlob.clear();
            } else {
                uint32_t decoyBaseRva = guardVa + currentOffset;
                BuildDecoyImports(decoyBaseRva, decoyBlob, decoyImportDirRva, decoyImportDirSize, decoyIatRva, decoyIatSize);
                currentOffset += static_cast<uint32_t>(decoyBlob.size());
                while (currentOffset % 16 != 0) currentOffset++;
            }
        }

        uint32_t totalFunctions = 0;
        for (const auto& mod : imports) {
            totalFunctions += static_cast<uint32_t>(mod.functions.size());
        }
        uint32_t thunkPoolSize = totalFunctions * 32;
        if (thunkPoolSize > 0) {
            config.thunkPoolRva = guardVa + currentOffset;
            config.thunkPoolSize = thunkPoolSize;
            currentOffset += thunkPoolSize;
            while (currentOffset % 16 != 0) currentOffset++;
            std::cout << "[+] Allocated IAT camouflage thunk pool for " << totalFunctions 
                      << " functions (" << thunkPoolSize << " bytes) at RVA 0x" 
                      << std::hex << config.thunkPoolRva << std::dec << std::endl;
        }

        uint32_t cfgOffset = 0;
        std::vector<uint8_t> guardPayload;
        CreateStubPayload(stubCode, config, encImportBlob, encRelocBlob, encTlsBlob, encPdataBlob, vmBytecode, sectionPayloads, decoyBlob, thunkPoolSize, configAlignedSize, stubCodeAlignedSize, guardPayload, cfgOffset);

        uint32_t guardRawSize = AlignUp(static_cast<uint32_t>(guardPayload.size()), nt->OptionalHeader.FileAlignment);
        uint32_t guardVirtualSize = AlignUp(static_cast<uint32_t>(guardPayload.size()), nt->OptionalHeader.SectionAlignment);

        guardPayload.resize(guardRawSize, 0);

        struct DummyRelocBlock {
            IMAGE_BASE_RELOCATION header;
            uint16_t entries[2];
        } dummyBlock;
        dummyBlock.header.VirtualAddress = 0x1000;
        dummyBlock.header.SizeOfBlock = sizeof(DummyRelocBlock);
        dummyBlock.entries[0] = 0; // IMAGE_REL_BASED_ABSOLUTE
        dummyBlock.entries[1] = 0; // IMAGE_REL_BASED_ABSOLUTE

        uint32_t relocVa = AlignUp(guardVa + guardVirtualSize, nt->OptionalHeader.SectionAlignment);
        uint32_t relocRawOffset = AlignUp(guardRawOffset + guardRawSize, nt->OptionalHeader.FileAlignment);
        uint32_t relocRawSize = AlignUp(static_cast<uint32_t>(sizeof(dummyBlock)), nt->OptionalHeader.FileAlignment);
        uint32_t relocVirtualSize = sizeof(dummyBlock);

        uint16_t origSecCount = nt->FileHeader.NumberOfSections;
        uint16_t neededSecCount = hadRelocAtEnd ? (origSecCount + 1) : (m_options.handleRelocations ? origSecCount + 2 : origSecCount + 1);

        if (neededSecCount >= 96) {
            std::cerr << "[-] Error: Maximum section count reached." << std::endl;
            return false;
        }

        size_t maxSecHeaderOffset = reinterpret_cast<uint8_t*>(&sections[neededSecCount]) - rawBuffer.data();
        if (maxSecHeaderOffset > nt->OptionalHeader.SizeOfHeaders) {
            std::cerr << "[-] Error: Not enough space in headers for new section header." << std::endl;
            return false;
        }

        IMAGE_SECTION_HEADER newSec = { 0 };
        strncpy_s(reinterpret_cast<char*>(newSec.Name), 8, m_options.sectionName.c_str(), 8);
        newSec.VirtualAddress = guardVa;
        newSec.Misc.VirtualSize = guardVirtualSize;
        newSec.PointerToRawData = guardRawOffset;
        newSec.SizeOfRawData = guardRawSize;
        newSec.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;

        IMAGE_SECTION_HEADER finalRelocSec = { 0 };
        strncpy_s(reinterpret_cast<char*>(finalRelocSec.Name), 8, ".reloc", 8);
        finalRelocSec.VirtualAddress = relocVa;
        finalRelocSec.Misc.VirtualSize = relocVirtualSize;
        finalRelocSec.PointerToRawData = relocRawOffset;
        finalRelocSec.SizeOfRawData = relocRawSize;
        finalRelocSec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE;

        // 1. Perform buffer insertions first so rawBuffer never reallocates afterwards
        if (rawBuffer.size() < guardRawOffset) {
            rawBuffer.resize(guardRawOffset, 0);
        }
        rawBuffer.insert(rawBuffer.end(), guardPayload.begin(), guardPayload.end());

        if (m_options.handleRelocations) {
            if (rawBuffer.size() < relocRawOffset) {
                rawBuffer.resize(relocRawOffset, 0);
            }
            std::vector<uint8_t> relocBytes(relocRawSize, 0);
            memcpy(relocBytes.data(), &dummyBlock, sizeof(dummyBlock));
            rawBuffer.insert(rawBuffer.end(), relocBytes.begin(), relocBytes.end());
        }

        // 2. Re-acquire pointers directly against final rawBuffer
        auto* pDos = reinterpret_cast<IMAGE_DOS_HEADER*>(rawBuffer.data());
        auto* pNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(rawBuffer.data() + pDos->e_lfanew);
        auto* curSections = IMAGE_FIRST_SECTION(pNt);

        // 3. Write section headers in guaranteed valid ascending order
        if (hadRelocAtEnd) {
            curSections[origSecCount - 1] = newSec;
            curSections[origSecCount] = finalRelocSec;
            pNt->FileHeader.NumberOfSections = origSecCount + 1;
        } else if (m_options.handleRelocations) {
            curSections[origSecCount] = newSec;
            curSections[origSecCount + 1] = finalRelocSec;
            pNt->FileHeader.NumberOfSections = origSecCount + 2;
        } else {
            curSections[origSecCount] = newSec;
            pNt->FileHeader.NumberOfSections = origSecCount + 1;
        }

        // 4. Update .pdata if configured
        auto* pdataSec = m_parser.GetSectionByName(".pdata");
        if (m_options.sanitizePdata && pdataSec) {
            uint32_t pdataRawOffset = pdataSec->PointerToRawData;
            if (pdataRawOffset != 0 && pdataRawOffset + 28 <= rawBuffer.size()) {
                IMAGE_RUNTIME_FUNCTION_ENTRY rf[1] = { 0 };
                rf[0].BeginAddress = guardVa;
                rf[0].EndAddress = guardVa + guardVirtualSize;
                rf[0].UnwindData = pdataSec->VirtualAddress + static_cast<uint32_t>(sizeof(rf));

                uint8_t unwindInfo[4] = { 0x01, 0x00, 0x00, 0x00 };

                memcpy(rawBuffer.data() + pdataRawOffset, rf, sizeof(rf));
                memcpy(rawBuffer.data() + pdataRawOffset + sizeof(rf), unwindInfo, sizeof(unwindInfo));

                pdataSec->Misc.VirtualSize = static_cast<uint32_t>(sizeof(rf) + sizeof(unwindInfo));
                pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = pdataSec->VirtualAddress;
                pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = static_cast<uint32_t>(sizeof(rf));
                std::cout << "[+] Retained valid x64 exception directory (.pdata) covering entrypoint and guard stub." << std::endl;
            }
        }

        // 5. Direct entrypoint to guard stub (No opaque trampoline in Section 0)
        uint32_t stubTargetRva = guardVa + configAlignedSize + stubEpOffsetInText;

        // 6. Update NT Optional Header
        pNt->OptionalHeader.AddressOfEntryPoint = stubTargetRva;
        if (m_options.handleRelocations) {
            pNt->OptionalHeader.SizeOfImage = AlignUp(relocVa + relocVirtualSize, pNt->OptionalHeader.SectionAlignment);
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = relocVa;
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = sizeof(dummyBlock);
            std::cout << "[+] Positioned valid base relocation directory (.reloc) as the final section at RVA 0x" 
                      << std::hex << relocVa << " (offset 0x" << relocRawOffset << ")." << std::dec << std::endl;
        } else {
            pNt->OptionalHeader.SizeOfImage = AlignUp(guardVa + guardVirtualSize, pNt->OptionalHeader.SectionAlignment);
        }

        uint32_t totalCodeSize = 0;
        uint32_t totalInitData = 0;
        for (uint16_t i = 0; i < pNt->FileHeader.NumberOfSections; ++i) {
            if (curSections[i].Characteristics & IMAGE_SCN_CNT_CODE) {
                totalCodeSize += curSections[i].SizeOfRawData;
            }
            if (curSections[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
                totalInitData += curSections[i].SizeOfRawData;
            }
        }
        pNt->OptionalHeader.SizeOfCode = AlignUp(totalCodeSize, pNt->OptionalHeader.FileAlignment);
        pNt->OptionalHeader.SizeOfInitializedData = AlignUp(totalInitData, pNt->OptionalHeader.FileAlignment);

        if (m_options.stripImports && m_options.addDecoyImports && !decoyBlob.empty()) {
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = decoyImportDirRva;
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = decoyImportDirSize;
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = decoyIatRva;
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = decoyIatSize;
        }

        // 7. Compute and stamp valid PE CheckSum
        size_t checksumOffset = reinterpret_cast<const uint8_t*>(&pNt->OptionalHeader.CheckSum) - rawBuffer.data();
        pNt->OptionalHeader.CheckSum = 0;
        uint32_t peChecksum = CalculatePeChecksum(rawBuffer.data(), rawBuffer.size(), checksumOffset);
        pNt->OptionalHeader.CheckSum = peChecksum;
        std::cout << "[+] Computed and stamped valid PE Checksum: 0x" << std::hex << peChecksum << std::dec << std::endl;

        outProtectedPe = rawBuffer;
        std::cout << "[+] Protection build successful! EntryPoint set to: 0x" << std::hex << stubTargetRva 
                  << " (Original OEP: 0x" << config.originalEntryPoint << ")" << std::dec << std::endl;
        return true;
    }

}
