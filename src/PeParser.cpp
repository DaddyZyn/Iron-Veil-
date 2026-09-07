#include "../include/PeParser.hpp"

namespace IronVeil {

    bool PeParser::Load(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open())
            return false;

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        m_buffer.resize(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(m_buffer.data()), size))
            return false;

        auto* dos = GetDosHeader();
        if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        auto* nt = GetNtHeaders();
        if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
            return false;

        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return false;

        m_isValid = true;
        return true;
    }

    bool PeParser::Save(const std::string& filePath, const std::vector<uint8_t>& buffer) {
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open())
            return false;

        file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        return file.good();
    }

    IMAGE_DOS_HEADER* PeParser::GetDosHeader() {
        if (m_buffer.size() < sizeof(IMAGE_DOS_HEADER))
            return nullptr;
        return reinterpret_cast<IMAGE_DOS_HEADER*>(m_buffer.data());
    }

    IMAGE_NT_HEADERS64* PeParser::GetNtHeaders() {
        auto* dos = GetDosHeader();
        if (!dos || dos->e_lfanew <= 0)
            return nullptr;

        if (m_buffer.size() < static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64))
            return nullptr;

        return reinterpret_cast<IMAGE_NT_HEADERS64*>(m_buffer.data() + dos->e_lfanew);
    }

    IMAGE_SECTION_HEADER* PeParser::GetSectionHeaders() {
        auto* nt = GetNtHeaders();
        if (!nt)
            return nullptr;

        return IMAGE_FIRST_SECTION(nt);
    }

    uint16_t PeParser::GetSectionCount() const {
        auto* nt = const_cast<PeParser*>(this)->GetNtHeaders();
        return nt ? nt->FileHeader.NumberOfSections : 0;
    }

    uint32_t PeParser::RvaToOffset(uint32_t rva) const {
        auto* pThis = const_cast<PeParser*>(this);
        auto* nt = pThis->GetNtHeaders();
        if (!nt)
            return 0;

        auto* sections = pThis->GetSectionHeaders();
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& sec = sections[i];
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.Misc.VirtualSize) {
                return (rva - sec.VirtualAddress) + sec.PointerToRawData;
            }
        }

        if (rva < nt->OptionalHeader.SizeOfHeaders)
            return rva;

        return 0;
    }

    uint32_t PeParser::OffsetToRva(uint32_t offset) const {
        auto* pThis = const_cast<PeParser*>(this);
        auto* nt = pThis->GetNtHeaders();
        if (!nt)
            return 0;

        auto* sections = pThis->GetSectionHeaders();
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& sec = sections[i];
            if (offset >= sec.PointerToRawData && offset < sec.PointerToRawData + sec.SizeOfRawData) {
                return (offset - sec.PointerToRawData) + sec.VirtualAddress;
            }
        }

        if (offset < nt->OptionalHeader.SizeOfHeaders)
            return offset;

        return 0;
    }

    IMAGE_SECTION_HEADER* PeParser::GetSectionByRva(uint32_t rva) {
        auto* nt = GetNtHeaders();
        if (!nt)
            return nullptr;

        auto* sections = GetSectionHeaders();
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (rva >= sections[i].VirtualAddress && rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
                return &sections[i];
            }
        }
        return nullptr;
    }

    IMAGE_SECTION_HEADER* PeParser::GetSectionByName(const std::string& name) {
        auto* nt = GetNtHeaders();
        if (!nt)
            return nullptr;

        auto* sections = GetSectionHeaders();
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            char secName[9] = { 0 };
            memcpy(secName, sections[i].Name, 8);
            if (name == secName) {
                return &sections[i];
            }
        }
        return nullptr;
    }

    bool PeParser::ParseImports(std::vector<ImportedModule>& outImports) {
        auto* nt = GetNtHeaders();
        if (!nt)
            return false;

        const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0 || importDir.Size == 0)
            return true;

        uint32_t importOffset = RvaToOffset(importDir.VirtualAddress);
        if (importOffset == 0 || importOffset >= m_buffer.size())
            return false;

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(m_buffer.data() + importOffset);

        while (desc->Name != 0 && desc->FirstThunk != 0) {
            uint32_t nameOffset = RvaToOffset(desc->Name);
            if (nameOffset == 0 || nameOffset >= m_buffer.size())
                break;

            std::string modName = reinterpret_cast<const char*>(m_buffer.data() + nameOffset);
            ImportedModule mod;
            mod.moduleName = modName;

            uint32_t thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            uint32_t iatRva = desc->FirstThunk;

            uint32_t thunkOffset = RvaToOffset(thunkRva);

            if (thunkOffset != 0 && thunkOffset < m_buffer.size()) {
                auto* thunkData = reinterpret_cast<IMAGE_THUNK_DATA64*>(m_buffer.data() + thunkOffset);

                while (thunkData->u1.AddressOfData != 0) {
                    ImportedFunction fn;
                    fn.iatRva = iatRva;

                    if (IMAGE_SNAP_BY_ORDINAL64(thunkData->u1.Ordinal)) {
                        fn.isOrdinal = true;
                        fn.ordinal = static_cast<uint16_t>(IMAGE_ORDINAL64(thunkData->u1.Ordinal));
                    } else {
                        fn.isOrdinal = false;
                        uint32_t ibnOffset = RvaToOffset(static_cast<uint32_t>(thunkData->u1.AddressOfData));
                        if (ibnOffset != 0 && ibnOffset + sizeof(WORD) < m_buffer.size()) {
                            auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(m_buffer.data() + ibnOffset);
                            fn.name = reinterpret_cast<const char*>(ibn->Name);
                            fn.ordinal = ibn->Hint;
                        }
                    }

                    mod.functions.push_back(fn);

                    thunkData++;
                    iatRva += sizeof(IMAGE_THUNK_DATA64);
                }
            }

            outImports.push_back(mod);
            desc++;
        }

        return true;
    }

    bool PeParser::ExtractRelocations(std::vector<uint8_t>& outRelocData) {
        outRelocData.clear();
        auto* nt = GetNtHeaders();
        if (!nt)
            return false;

        const auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.VirtualAddress == 0 || relocDir.Size == 0)
            return true;

        uint32_t relocOffset = RvaToOffset(relocDir.VirtualAddress);
        if (relocOffset == 0 || relocOffset + relocDir.Size > m_buffer.size())
            return false;

        outRelocData.assign(m_buffer.data() + relocOffset, m_buffer.data() + relocOffset + relocDir.Size);
        return true;
    }

    bool PeParser::ExtractTlsCallbacks(std::vector<uint32_t>& outCallbackRvas) {
        outCallbackRvas.clear();
        auto* nt = GetNtHeaders();
        if (!nt)
            return false;

        const auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0)
            return true;

        uint32_t tlsOffset = RvaToOffset(tlsDir.VirtualAddress);
        if (tlsOffset == 0 || tlsOffset + sizeof(IMAGE_TLS_DIRECTORY64) > m_buffer.size())
            return false;

        auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(m_buffer.data() + tlsOffset);
        if (!tls->AddressOfCallBacks)
            return true;

        uint64_t imageBase = nt->OptionalHeader.ImageBase;
        if (tls->AddressOfCallBacks < imageBase)
            return false;

        uint32_t cbArrayRva = static_cast<uint32_t>(tls->AddressOfCallBacks - imageBase);
        uint32_t cbArrayOffset = RvaToOffset(cbArrayRva);
        if (cbArrayOffset == 0 || cbArrayOffset >= m_buffer.size())
            return false;

        const auto* cbPtr = reinterpret_cast<const uint64_t*>(m_buffer.data() + cbArrayOffset);
        while (reinterpret_cast<const uint8_t*>(cbPtr) + sizeof(uint64_t) <= m_buffer.data() + m_buffer.size()) {
            if (*cbPtr == 0)
                break;
            if (*cbPtr >= imageBase) {
                outCallbackRvas.push_back(static_cast<uint32_t>(*cbPtr - imageBase));
            }
            cbPtr++;
        }

        return true;
    }

}
