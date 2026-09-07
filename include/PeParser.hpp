#pragma once

#include "Common.hpp"

namespace IronVeil {

    struct ImportedFunction {
        std::string name;
        uint16_t ordinal = 0;
        bool isOrdinal = false;
        uint32_t iatRva = 0;
    };

    struct ImportedModule {
        std::string moduleName;
        std::vector<ImportedFunction> functions;
    };

    class PeParser {
    public:
        PeParser() = default;

        bool Load(const std::string& filePath);
        bool Save(const std::string& filePath, const std::vector<uint8_t>& buffer);

        IMAGE_DOS_HEADER* GetDosHeader();
        IMAGE_NT_HEADERS64* GetNtHeaders();
        IMAGE_SECTION_HEADER* GetSectionHeaders();
        uint16_t GetSectionCount() const;

        uint32_t RvaToOffset(uint32_t rva) const;
        uint32_t OffsetToRva(uint32_t offset) const;
        IMAGE_SECTION_HEADER* GetSectionByRva(uint32_t rva);
        IMAGE_SECTION_HEADER* GetSectionByName(const std::string& name);

        bool ParseImports(std::vector<ImportedModule>& outImports);
        bool ExtractRelocations(std::vector<uint8_t>& outRelocData);
        bool ExtractTlsCallbacks(std::vector<uint32_t>& outCallbackRvas);

        std::vector<uint8_t>& GetBuffer() { return m_buffer; }
        const std::vector<uint8_t>& GetBuffer() const { return m_buffer; }
        size_t GetSize() const { return m_buffer.size(); }

    private:
        std::vector<uint8_t> m_buffer;
        bool m_isValid = false;
    };

}
