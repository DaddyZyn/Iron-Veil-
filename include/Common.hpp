#pragma once

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <memory>
#include <algorithm>

namespace IronVeil {

    constexpr uint32_t STUB_VERSION = 2;

    enum AntiDebugFlags : uint32_t {
        ANTIDEBUG_NONE               = 0,
        ANTIDEBUG_PEB                = (1 << 0),
        ANTIDEBUG_HARDWARE_BP        = (1 << 1),
        ANTIDEBUG_PROCESS_INFO       = (1 << 2),
        ANTIDEBUG_THREAD_HIDE        = (1 << 3),
        ANTIDEBUG_TIMING             = (1 << 4),
        ANTIDEBUG_HOOK_SCAN          = (1 << 5),
        ANTIDEBUG_KUSER              = (1 << 6),
        ANTIDEBUG_ENTRY_INTEGRITY    = (1 << 7),
        ANTIDEBUG_ALL                = 0xFFu
    };

    #pragma pack(push, 1)
    struct ProtectedSectionInfo {
        uint32_t virtualAddress;
        uint32_t virtualSize;
        uint32_t rawSize;
        uint32_t originalProtect;
        uint32_t characteristics;
        uint8_t  nonce[12];
        uint32_t payloadOffset;
        uint32_t payloadSize;
    };

    struct StubConfig {
        uint32_t magic;
        uint32_t version;
        uint32_t originalEntryPoint;
        uint8_t  originalEpBytes[16];
        uint64_t originalImageBase;
        uint32_t sectionCount;
        uint32_t encryptedImportsRva;
        uint32_t encryptedImportsSize;
        uint32_t relocTableRva;
        uint32_t relocTableSize;
        uint32_t tlsCallbacksRva;
        uint32_t tlsCallbackCount;
        uint32_t pdataRva;
        uint32_t pdataSize;
        uint32_t pdataEntryCount;
        uint64_t textHash;
        uint8_t  blindedKey[32];
        uint64_t keyCanary;
        uint8_t  importsNonce[12];
        uint8_t  relocsNonce[12];
        uint8_t  tlsNonce[12];
        uint8_t  pdataNonce[12];
        uint32_t antiDebugFlags;
        ProtectedSectionInfo sections[16];
        uintptr_t fnVirtualProtect;
        uintptr_t fnFlushInstructionCache;
        uint32_t  stolenLen;
        uint32_t  stolenOep;
        uint64_t  stolenStackAdjust;
        uint32_t  vmBytecodeRva;
        uint32_t  vmBytecodeSize;
        uint32_t  thunkPoolRva;
        uint32_t  thunkPoolSize;
        uint8_t   vmKey;
        uint8_t   reserved[7];
    };
    #pragma pack(pop)

    struct DispatchInfo {
        uintptr_t targetOep;
        uint64_t  stackAdjust;
        uint64_t  useVeh;
    };

    inline void BlindKey(const uint8_t* inKey, uint64_t canary, uint8_t* outBlindedKey) {
        const auto* in64 = reinterpret_cast<const uint64_t*>(inKey);
        auto* out64 = reinterpret_cast<uint64_t*>(outBlindedKey);
        out64[0] = in64[0] ^ canary ^ 0x3F3E3D3C3B3A3938ULL;
        out64[1] = in64[1] ^ (canary * 0x5851F42D4C957F2DULL + 1) ^ 0x7F7E7D7C7B7A7978ULL;
        out64[2] = in64[2] ^ (canary * 0x14057B7EF767814FULL + 3) ^ 0xBFBEBDBCBBBAB9B8ULL;
        out64[3] = in64[3] ^ (canary * 0x9E3779B97F4A7C15ULL + 5) ^ 0xFFFEFDFCFBFAF9F8ULL;
    }

    inline void UnblindKey(const uint8_t* inBlindedKey, uint64_t canary, uint8_t* outKey) {
        const auto* in64 = reinterpret_cast<const uint64_t*>(inBlindedKey);
        auto* out64 = reinterpret_cast<uint64_t*>(outKey);
        out64[0] = in64[0] ^ canary ^ 0x3F3E3D3C3B3A3938ULL;
        out64[1] = in64[1] ^ (canary * 0x5851F42D4C957F2DULL + 1) ^ 0x7F7E7D7C7B7A7978ULL;
        out64[2] = in64[2] ^ (canary * 0x14057B7EF767814FULL + 3) ^ 0xBFBEBDBCBBBAB9B8ULL;
        out64[3] = in64[3] ^ (canary * 0x9E3779B97F4A7C15ULL + 5) ^ 0xFFFEFDFCFBFAF9F8ULL;
    }

    constexpr uint32_t HashApi(const char* str, uint32_t h = 0x4B9E2B67u) {
        return (!*str) ? h : HashApi(str + 1, (((h ^ static_cast<uint8_t>(*str)) * 0x5BD1E995u) ^ (h >> 15)));
    }

    constexpr uint32_t HashApiCaseInsensitive(const char* str, uint32_t h = 0x4B9E2B67u) {
        return (!*str) ? h : HashApiCaseInsensitive(str + 1, (((h ^ static_cast<uint8_t>(
            (*str >= 'A' && *str <= 'Z') ? (*str + 32) : *str
        )) * 0x5BD1E995u) ^ (h >> 15)));
    }

    constexpr uint32_t HASH_NTDLL_DLL                           = 0x1d118a95u;
    constexpr uint32_t HASH_KERNEL32_DLL                        = 0x37cf1638u;
    constexpr uint32_t HASH_KERNELBASE_DLL                      = 0xb40d1c98u;

    constexpr uint32_t HASH_VIRTUALPROTECT                      = 0x4b2061a7u;
    constexpr uint32_t HASH_LOADLIBRARYA                        = 0x074dc1fbu;
    constexpr uint32_t HASH_GETPROCADDRESS                      = 0xaee0ac7eu;
    constexpr uint32_t HASH_EXITPROCESS                         = 0x8598dab3u;
    constexpr uint32_t HASH_GETCURRENTPROCESS                   = 0x49e8e5c8u;
    constexpr uint32_t HASH_FLUSHINSTRUCTIONCACHE               = 0xf32e945du;
    constexpr uint32_t HASH_RTLADDFUNCTIONTABLE                 = 0x8ff0c6bbu;
    constexpr uint32_t HASH_NTPROTECTVIRTUALMEMORY              = 0xdab35511u;
    constexpr uint32_t HASH_NTQUERYINFORMATIONPROCESS          = 0x152bb40du;
    constexpr uint32_t HASH_NTSETINFORMATIONTHREAD              = 0x5bd0f120u;
    constexpr uint32_t HASH_NTALLOCATEVIRTUALMEMORY             = 0x4fff86cbu;
    constexpr uint32_t HASH_RTLCAPTURECONTEXT                   = 0x7277bfd7u;
    constexpr uint32_t HASH_GETCURRENTTHREAD                    = 0x61ca9e61u;
    constexpr uint32_t HASH_RTLADDVECTOREDEXCEPTIONHANDLER      = 0x80910531u;
    constexpr uint32_t HASH_RTLREMOVEVECTOREDEXCEPTIONHANDLER   = 0x4054d9e9u;

    inline uint64_t HashFNV1a64(const void* data, size_t size) {
        const auto* ptr = static_cast<const uint8_t*>(data);
        uint64_t h = 0xA24BAED4963EE407ULL;
        for (size_t i = 0; i < size; ++i) {
            h ^= static_cast<uint64_t>(ptr[i]);
            h = (h ^ (h >> 27)) * 0x4CF5AD432745937FULL;
        }
        h ^= h >> 33;
        h *= 0xC2B2AE3D27D4EB4FULL;
        h ^= h >> 29;
        return h;
    }

}
