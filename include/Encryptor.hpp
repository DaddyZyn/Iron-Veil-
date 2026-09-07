#pragma once

#include "Common.hpp"

namespace IronVeil {

    class ChaCha20 {
    public:
        static void Process(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, 
                            const uint8_t* input, uint8_t* output, size_t length);

        static void CryptInPlace(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                                 uint8_t* data, size_t length) {
            Process(key, nonce, counter, data, data, length);
        }

    private:
        static void QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
    };

    class CryptoUtils {
    public:
        static void GenerateRandomBytes(uint8_t* buffer, size_t length);
    };

}
