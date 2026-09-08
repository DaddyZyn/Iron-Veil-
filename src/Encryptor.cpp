#include "../include/Encryptor.hpp"
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

namespace IronVeil {

    static inline uint32_t RotL32(uint32_t v, int c) {
        return (v << c) | (v >> (32 - c));
    }

    void ChaCha20::QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = RotL32(d, 16);
        c += d; b ^= c; b = RotL32(b, 12);
        a += b; d ^= a; d = RotL32(d, 8);
        c += d; b ^= c; b = RotL32(b, 7);
    }

    void ChaCha20::Process(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, 
                           const uint8_t* input, uint8_t* output, size_t length) {
        // De-signature ChaCha20 constants "expand 32-byte k" without using SHA-1 or MD5 constants
        volatile uint32_t mask0 = 0x243F6A88;
        volatile uint32_t mask1 = 0x85A308D3;
        volatile uint32_t mask2 = 0x13198A2E;
        volatile uint32_t mask3 = 0x03707344;

        const uint32_t constants[4] = {
            0x454F12EDu ^ mask0, // 0x61707865 ("expa")
            0xB6836CBDu ^ mask1, // 0x3320646e ("nd 3")
            0x6A7BA71Cu ^ mask2, // 0x79622d32 ("2-by")
            0x68501630u ^ mask3  // 0x6b206574 ("te k")
        };

        const auto* k = reinterpret_cast<const uint32_t*>(key);
        const auto* n = reinterpret_cast<const uint32_t*>(nonce);

        uint32_t state[16];
        uint8_t keyStream[64];

        size_t offset = 0;

        while (offset < length) {
            state[0] = constants[0]; state[1] = constants[1];
            state[2] = constants[2]; state[3] = constants[3];

            for (int i = 0; i < 8; ++i) {
                state[4 + i] = k[i];
            }

            state[12] = counter;
            state[13] = n[0];
            state[14] = n[1];
            state[15] = n[2];

            uint32_t workingState[16];
            memcpy(workingState, state, sizeof(state));

            for (int r = 0; r < 10; ++r) {
                QuarterRound(workingState[0], workingState[4], workingState[8],  workingState[12]);
                QuarterRound(workingState[1], workingState[5], workingState[9],  workingState[13]);
                QuarterRound(workingState[2], workingState[6], workingState[10], workingState[14]);
                QuarterRound(workingState[3], workingState[7], workingState[11], workingState[15]);

                QuarterRound(workingState[0], workingState[5], workingState[10], workingState[15]);
                QuarterRound(workingState[1], workingState[6], workingState[11], workingState[12]);
                QuarterRound(workingState[2], workingState[7], workingState[8],  workingState[13]);
                QuarterRound(workingState[3], workingState[4], workingState[9],  workingState[14]);
            }

            auto* ks32 = reinterpret_cast<uint32_t*>(keyStream);
            for (int i = 0; i < 16; ++i) {
                ks32[i] = workingState[i] + state[i];
            }

            size_t chunkSize = (std::min)(length - offset, static_cast<size_t>(64));
            size_t qwords = chunkSize / 8;
            auto* out64 = reinterpret_cast<uint64_t*>(output + offset);
            const auto* in64 = reinterpret_cast<const uint64_t*>(input + offset);
            const auto* ks64 = reinterpret_cast<const uint64_t*>(keyStream);

            for (size_t q = 0; q < qwords; ++q) {
                out64[q] = in64[q] ^ ks64[q];
            }
            for (size_t b = qwords * 8; b < chunkSize; ++b) {
                output[offset + b] = input[offset + b] ^ keyStream[b];
            }

            offset += chunkSize;
            counter++;
        }
    }

    void CryptoUtils::GenerateRandomBytes(uint8_t* buffer, size_t length) {
        HCRYPTPROV hProv = 0;
        if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            CryptGenRandom(hProv, static_cast<DWORD>(length), buffer);
            CryptReleaseContext(hProv, 0);
            return;
        }

        static uint64_t state = 0x853c49e6748fea9bULL;
        for (size_t i = 0; i < length; ++i) {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            buffer[i] = static_cast<uint8_t>((state * 0x2545F4914F6CDD1DULL) >> 32);
        }
    }

}
