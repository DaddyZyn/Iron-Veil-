#pragma once

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <array>
#include <utility>
#include <intrin.h>

namespace IronVeil {

    template <size_t N, uint8_t K>
    class EphemeralString {
    public:
        constexpr EphemeralString(const char(&str)[N]) {
            for (size_t i = 0; i < N; ++i) {
                m_data[i] = static_cast<uint8_t>(str[i] ^ (K + i * 7));
            }
        }

        ~EphemeralString() {
            Wipe();
        }

        EphemeralString(const EphemeralString& other) {
            for (size_t i = 0; i < N; ++i) m_data[i] = other.m_data[i];
            m_decrypted = false;
        }

        EphemeralString& operator=(const EphemeralString& other) {
            if (this != &other) {
                Wipe();
                for (size_t i = 0; i < N; ++i) m_data[i] = other.m_data[i];
                m_decrypted = false;
            }
            return *this;
        }

        const char* c_str() const {
            DecryptInternal();
            return reinterpret_cast<const char*>(m_buffer);
        }

        operator std::string() const {
            DecryptInternal();
            std::string s(reinterpret_cast<const char*>(m_buffer), N > 0 ? N - 1 : 0);
            return s;
        }

        size_t length() const {
            return N > 0 ? N - 1 : 0;
        }

    private:
        void DecryptInternal() const {
            if (!m_decrypted) {
                for (size_t i = 0; i < N; ++i) {
                    m_buffer[i] = static_cast<uint8_t>(m_data[i] ^ (K + i * 7));
                }
                m_decrypted = true;
            }
        }

        void Wipe() const {
            if (m_decrypted) {
                volatile uint8_t* p = m_buffer;
                for (size_t i = 0; i < N; ++i) p[i] = static_cast<uint8_t>(i ^ 0xA5);
                for (size_t i = 0; i < N; ++i) p[i] = 0;
                m_decrypted = false;
            }
        }

        uint8_t m_data[N] = { 0 };
        mutable uint8_t m_buffer[N] = { 0 };
        mutable bool m_decrypted = false;
    };

    template <size_t N, uint16_t K>
    class EphemeralWideString {
    public:
        constexpr EphemeralWideString(const wchar_t(&str)[N]) {
            for (size_t i = 0; i < N; ++i) {
                m_data[i] = static_cast<uint16_t>(str[i] ^ (K + i * 11));
            }
        }

        ~EphemeralWideString() {
            Wipe();
        }

        const wchar_t* c_str() const {
            DecryptInternal();
            return reinterpret_cast<const wchar_t*>(m_buffer);
        }

        operator std::wstring() const {
            DecryptInternal();
            return std::wstring(reinterpret_cast<const wchar_t*>(m_buffer), N > 0 ? N - 1 : 0);
        }

    private:
        void DecryptInternal() const {
            if (!m_decrypted) {
                for (size_t i = 0; i < N; ++i) {
                    m_buffer[i] = static_cast<uint16_t>(m_data[i] ^ (K + i * 11));
                }
                m_decrypted = true;
            }
        }

        void Wipe() const {
            if (m_decrypted) {
                volatile uint16_t* p = m_buffer;
                for (size_t i = 0; i < N; ++i) p[i] = 0;
                m_decrypted = false;
            }
        }

        uint16_t m_data[N] = { 0 };
        mutable uint16_t m_buffer[N] = { 0 };
        mutable bool m_decrypted = false;
    };

    template <size_t N, uint8_t K1, uint8_t K2>
    class RuntimeObfuscatedString {
    public:
        constexpr RuntimeObfuscatedString(const char(&str)[N]) {
            for (size_t i = 0; i < N; ++i) {
                m_data[i] = static_cast<uint8_t>((str[i] ^ (K1 + i * 13)) + (K2 + i * 7));
            }
        }

        bool operator==(const char* str) const {
            if (!str) return false;
            for (size_t i = 0; i < N - 1; ++i) {
                if (!str[i]) return false;
                uint8_t dec = static_cast<uint8_t>((m_data[i] - (K2 + i * 7)) ^ (K1 + i * 13));
                if (static_cast<char>(dec) != str[i]) return false;
            }
            return str[N - 1] == '\0';
        }

        bool operator==(const std::string& str) const {
            if (str.length() != N - 1) return false;
            return *this == str.c_str();
        }

        bool operator!=(const char* str) const {
            return !(*this == str);
        }

        bool operator!=(const std::string& str) const {
            return !(*this == str);
        }

        uint8_t At(size_t index) const {
            if (index >= N - 1) return 0;
            return static_cast<uint8_t>((m_data[index] - (K2 + index * 7)) ^ (K1 + index * 13));
        }

        size_t length() const {
            return N > 0 ? N - 1 : 0;
        }

    private:
        uint8_t m_data[N] = { 0 };
    };

    #define IV_STR(str) (IronVeil::EphemeralString<sizeof(str), 0x6C>(str))
    #define IV_WSTR(wstr) (IronVeil::EphemeralWideString<sizeof(wstr)/sizeof(wchar_t), 0x9A>(wstr))
    #define IV_SECURE_STR(str) (IronVeil::RuntimeObfuscatedString<sizeof(str), 0x7B, 0x4D>(str))

    #define IV_JUNK_CODE() do { \
        volatile uint64_t _iv_j1 = reinterpret_cast<uint64_t>(&_iv_j1); \
        volatile uint64_t _iv_j2 = __readgsqword(0x30); \
        _iv_j1 = (_iv_j1 << 5) | (_iv_j1 >> 59); \
        _iv_j2 ^= _iv_j1; \
        if ((_iv_j1 ^ _iv_j2) == 0x1337C0DEFEEDFACEULL) { \
            __fastfail(0x42); \
        } \
    } while(0)

    #define IV_OPAQUE_BRANCH(junk_action) do { \
        volatile uint64_t _iv_op1 = __readgsqword(0x30); \
        volatile uint64_t _iv_op2 = __readgsqword(0x60); \
        if (((_iv_op1 ^ _iv_op2) & 0x01) && (((_iv_op1 ^ _iv_op2) & 0x02) == 0) && (_iv_op1 == _iv_op2)) { \
            junk_action; \
        } \
    } while(0)

    #define IV_DEAD_LOOP(iterations) do { \
        volatile uint32_t _iv_cnt = (iterations); \
        volatile uint32_t _iv_accum = 0x5A5A; \
        while (_iv_cnt > 0) { \
            _iv_accum = (_iv_accum << 3) ^ (_iv_accum >> 5) ^ _iv_cnt; \
            _iv_cnt--; \
        } \
    } while(0)

    #define IV_CALL_ENCRYPTED(funcPtr, funcSize, key, ...) \
        [&]() { \
            IronVeil::ScopedFunctionCrypt _iv_fc_guard(funcPtr, funcSize, key); \
            return __VA_ARGS__; \
        }()

    class ScopedFunctionCrypt {
    public:
        ScopedFunctionCrypt(void* funcPtr, size_t funcSize, uint8_t key = 0xAA)
            : m_ptr(funcPtr), m_size(funcSize), m_key(key) {
            if (m_ptr && m_size) {
                DWORD oldP = 0;
                if (VirtualProtect(m_ptr, m_size, PAGE_EXECUTE_READWRITE, &m_oldProtect)) {
                    Transform();
                    FlushInstructionCache(GetCurrentProcess(), m_ptr, m_size);
                }
            }
        }

        ~ScopedFunctionCrypt() {
            if (m_ptr && m_size) {
                Transform();
                DWORD dummy = 0;
                VirtualProtect(m_ptr, m_size, m_oldProtect, &dummy);
                FlushInstructionCache(GetCurrentProcess(), m_ptr, m_size);
            }
        }

    private:
        void Transform() {
            auto* p = static_cast<uint8_t*>(m_ptr);
            for (size_t i = 0; i < m_size; ++i) {
                p[i] ^= static_cast<uint8_t>(m_key + (i * 13));
            }
        }

        void* m_ptr = nullptr;
        size_t m_size = 0;
        uint8_t m_key = 0;
        DWORD m_oldProtect = 0;
    };

    class FunctionProtector {
    public:
        static void Encrypt(void* funcPtr, size_t length, uint8_t key = 0xAA) {
            if (!funcPtr || length == 0)
                return;

            DWORD oldP = 0;
            if (VirtualProtect(funcPtr, length, PAGE_EXECUTE_READWRITE, &oldP)) {
                auto* p = static_cast<uint8_t*>(funcPtr);
                for (size_t i = 0; i < length; ++i) {
                    p[i] ^= static_cast<uint8_t>(key + (i * 13));
                }
                VirtualProtect(funcPtr, length, oldP, &oldP);
                FlushInstructionCache(GetCurrentProcess(), funcPtr, length);
            }
        }

        static void Decrypt(void* funcPtr, size_t length, uint8_t key = 0xAA) {
            Encrypt(funcPtr, length, key);
        }
    };

    class LicenseShield {
    public:
        static bool CheckHttpProxy() {
            char buf[256];
            DWORD res = GetEnvironmentVariableA("HTTP_PROXY", buf, sizeof(buf));
            if (res > 0 && res < sizeof(buf))
                return true;

            res = GetEnvironmentVariableA("HTTPS_PROXY", buf, sizeof(buf));
            if (res > 0 && res < sizeof(buf))
                return true;

            res = GetEnvironmentVariableA("ALL_PROXY", buf, sizeof(buf));
            if (res > 0 && res < sizeof(buf))
                return true;

            return false;
        }

        static bool VerifyCaller(void* returnAddress) {
            if (!returnAddress)
                return false;

            HMODULE hSelf = GetModuleHandleA(nullptr);
            if (!hSelf)
                return false;

            auto* base = reinterpret_cast<const uint8_t*>(hSelf);
            auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return true;

            auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return true;

            uintptr_t caller = reinterpret_cast<uintptr_t>(returnAddress);
            uintptr_t modStart = reinterpret_cast<uintptr_t>(base);
            uintptr_t modEnd = modStart + nt->OptionalHeader.SizeOfImage;

            return (caller >= modStart && caller < modEnd);
        }

        static uint64_t HashFunction(const void* funcPtr, size_t length) {
            if (!funcPtr || length == 0)
                return 0;

            const auto* p = static_cast<const uint8_t*>(funcPtr);
            uint64_t h = 14695981039346656037ULL;
            for (size_t i = 0; i < length; ++i) {
                h ^= p[i];
                h *= 1099511628211ULL;
            }
            return h;
        }

        static bool VerifyFunctionIntegrity(const void* funcPtr, size_t length, uint64_t expectedHash) {
            if (!funcPtr || length == 0)
                return false;

            const auto* p = static_cast<const uint8_t*>(funcPtr);
            for (size_t i = 0; i < length; ++i) {
                if (p[i] == 0xCC || (p[i] == 0xCD && i + 1 < length && p[i + 1] == 0x03))
                    return false;
                if (p[i] == 0xE9 || p[i] == 0xEB)
                    return false;
                if (p[i] == 0xFF && i + 1 < length && p[i + 1] == 0x25)
                    return false;
                if (p[i] == 0x48 && i + 1 < length && p[i + 1] == 0xB8 && i + 10 < length && p[i + 10] == 0xFF && p[i + 11] == 0xE0)
                    return false;
            }

            return (HashFunction(funcPtr, length) == expectedHash);
        }

        static void SecureScramble(void* buffer, size_t length) {
            if (!buffer || length == 0)
                return;

            volatile uint8_t* p = static_cast<volatile uint8_t*>(buffer);
            for (size_t i = 0; i < length; ++i) {
                p[i] = static_cast<uint8_t>(i ^ 0xAA);
            }
            for (size_t i = 0; i < length; ++i) {
                p[i] = 0;
            }
        }
    };

}
