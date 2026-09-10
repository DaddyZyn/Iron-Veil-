#pragma once

#include "Common.hpp"
#include "PeParser.hpp"
#include "Encryptor.hpp"

namespace IronVeil {

    struct ProtectorOptions {
        bool encryptTextSection = true;
        bool encryptRdataSection = false;
        bool sanitizePdata = true;
        bool wipeDebugDirectory = true;
        bool stripImports = true;
        bool addDecoyImports = true;
        bool handleRelocations = true;
        bool handleTlsCallbacks = true;
        uint32_t antiDebugFlags = ANTIDEBUG_ALL;
        std::string sectionName = ".text1";
    };

    class PeBuilder {
    public:
        PeBuilder(PeParser& parser, const ProtectorOptions& options = {});

        bool Build(std::vector<uint8_t>& outProtectedPe);

    private:
        bool SerializeImports(const std::vector<ImportedModule>& imports, std::vector<uint8_t>& outBlob);
        bool CreateStubPayload(const std::vector<uint8_t>& stubCode, 
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
                               uint32_t& outConfigOffsetInPayload);

        bool BuildDecoyImports(uint32_t baseRva, std::vector<uint8_t>& outBlob,
                               uint32_t& outImportDirRva, uint32_t& outImportDirSize,
                               uint32_t& outIatRva, uint32_t& outIatSize);

        uint32_t AlignUp(uint32_t value, uint32_t alignment) const {
            return (value + alignment - 1) & ~(alignment - 1);
        }

        PeParser& m_parser;
        ProtectorOptions m_options;
    };

}
