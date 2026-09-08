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

    constexpr uint32_t STUB_MAGIC = 0x4C494556;
    constexpr uint32_t STUB_VERSION = 2;

    enum AntiDebugFlags : uint32_t {
        ANTIDEBUG_NONE               = 0,
        ANTIDEBUG_PEB                = (1 << 0),
        ANTIDEBUG_NTAPI              = (1 << 1),
        ANTIDEBUG_HARDWARE_BP        = (1 << 2),
        ANTIDEBUG_TIMING_RDTSC       = (1 << 3),
        ANTIDEBUG_THREAD_CLOAK       = (1 << 4),
        ANTIDEBUG_INTEGRITY_WATCHDOG = (1 << 5),
        ANTIDEBUG_HOOK_TAMPER        = (1 << 6),
        ANTIDEBUG_KUSER_SHARED       = (1 << 7),
        ANTIDEBUG_KERNEL_DEBUGGER    = (1 << 8),
        ANTIDEBUG_SYSCALL_HOOKS      = (1 << 9),
        ANTIDEBUG_NETWORK_HOOKS      = (1 << 10),
        ANTIDEBUG_VM_MEMORY_HOOKS    = (1 << 11),
        ANTIDEBUG_ANTI_DUMP          = (1 << 12),
        ANTIDEBUG_HYPERVISOR         = (1 << 13),
        ANTIDEBUG_PROCESS_DACL       = (1 << 14),
        ANTIDEBUG_ALL                = 0x7FFF
    };

    #pragma pack(push, 1)
    struct ProtectedSectionInfo {
        uint32_t virtualAddress;
        uint32_t virtualSize;
        uint32_t rawSize;
        uint32_t originalProtect;
        uint32_t characteristics;
        uint8_t  nonce[12];
    };

    struct StubConfig {
        uint32_t magic;
        uint32_t version;
        uint32_t originalEntryPoint;
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
        uintptr_t vehActivePages[4];
        uint32_t  vehRingHead;
        uint8_t   vehPageDecrypted[256];
    };
    #pragma pack(pop)

    inline void BlindKey(const uint8_t* inKey, uint64_t canary, uint8_t* outBlindedKey) {
        const auto* in64 = reinterpret_cast<const uint64_t*>(inKey);
        auto* out64 = reinterpret_cast<uint64_t*>(outBlindedKey);
        volatile uint64_t kMask = 0x5A335A335A335A33ULL;
        for (int q = 0; q < 4; ++q) {
            uint64_t qCanary = (canary << (q * 8)) | (canary >> (64 - (q * 8)));
            out64[q] = in64[q] ^ qCanary ^ (kMask + (q * 0x1111111111111111ULL));
        }
    }

    inline void UnblindKey(const uint8_t* inBlindedKey, uint64_t canary, uint8_t* outKey) {
        const auto* in64 = reinterpret_cast<const uint64_t*>(inBlindedKey);
        auto* out64 = reinterpret_cast<uint64_t*>(outKey);
        volatile uint64_t kMask = 0x5A335A335A335A33ULL;
        for (int q = 0; q < 4; ++q) {
            uint64_t qCanary = (canary << (q * 8)) | (canary >> (64 - (q * 8)));
            out64[q] = in64[q] ^ qCanary ^ (kMask + (q * 0x1111111111111111ULL));
        }
    }

    constexpr uint32_t HASH_SEED = 0x7B92A415;

    constexpr uint32_t HashDJB2(const char* str, uint32_t h = HASH_SEED) {
        return (!*str) ? h : HashDJB2(str + 1, (((h << 5) | (h >> 27)) ^ static_cast<uint8_t>(*str)));
    }

    constexpr uint32_t HashDJB2CaseInsensitive(const char* str, uint32_t h = HASH_SEED) {
        return (!*str) ? h : HashDJB2CaseInsensitive(str + 1, (((h << 5) | (h >> 27)) ^ static_cast<uint8_t>(
            (*str >= 'A' && *str <= 'Z') ? (*str + 32) : *str
        )));
    }

    inline uint32_t HashDJB2Runtime(const char* str, uint32_t h = HASH_SEED) {
        while (char c = *str++) {
            h = ((h << 5) | (h >> 27)) ^ static_cast<uint8_t>(c);
        }
        return h;
    }

    inline uint32_t HashDJB2CaseInsensitiveRuntime(const char* str, uint32_t h = HASH_SEED) {
        while (char c = *str++) {
            uint8_t b = (c >= 'A' && c <= 'Z') ? static_cast<uint8_t>(c + 32) : static_cast<uint8_t>(c);
            h = ((h << 5) | (h >> 27)) ^ b;
        }
        return h;
    }

    inline uint64_t HashFNV1a64(const void* data, size_t size) {
        const auto* ptr = static_cast<const uint8_t*>(data);
        uint64_t h = 0x9E3779B97F4A7C15ULL;
        const uint64_t mult = 0x5851F42D4C957F2DULL;
        for (size_t i = 0; i < size; ++i) {
            h ^= ptr[i];
            h *= mult;
        }
        return h;
    }

}
