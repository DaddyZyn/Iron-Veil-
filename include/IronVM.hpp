#pragma once

#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <intrin.h>

namespace IronVeil {
namespace VM {

    enum VmOpcode : uint8_t {
        VM_OP_NOP        = 0x11,
        VM_OP_IMM64      = 0x22,
        VM_OP_MOV        = 0x33,
        VM_OP_ADD        = 0x44,
        VM_OP_SUB        = 0x55,
        VM_OP_XOR        = 0x66,
        VM_OP_AND        = 0x77,
        VM_OP_OR         = 0x88,
        VM_OP_SHL        = 0x91,
        VM_OP_SHR        = 0x92,
        VM_OP_ROL        = 0x93,
        VM_OP_ROR        = 0x94,
        VM_OP_MBA_ADD    = 0xA1,
        VM_OP_MBA_SUB    = 0xA2,
        VM_OP_MBA_XOR    = 0xA3,
        VM_OP_PUSH       = 0xB1,
        VM_OP_POP        = 0xB2,
        VM_OP_CMP        = 0xC1,
        VM_OP_JMP        = 0xD1,
        VM_OP_JZ         = 0xD2,
        VM_OP_JNZ        = 0xD3,
        VM_OP_READ_MEM   = 0xE1,
        VM_OP_WRITE_MEM  = 0xE2,
        VM_OP_RET        = 0xFF
    };

    struct VmContext {
        uint64_t rawRegs[8] = { 0 };
        uint64_t canaries[8] = { 
            0xA5A5A5A55A5A5A5AULL, 0x123456789ABCDEF0ULL, 
            0xFEDCBA9876543210ULL, 0x1337C0DECAFEBABFULL,
            0x4242424224242424ULL, 0x7E7E7E7E81818181ULL,
            0x99663300FFCCDDBBULL, 0x0123456789ABCDEFULL 
        };
        uint64_t stack[256] = { 0 };
        size_t sp = 0;
        size_t ip = 0;
        bool flagZero = false;
        bool flagSign = false;
        bool running = true;

        struct RegProxy {
            uint64_t& storage;
            uint64_t canary;
            operator uint64_t() const { return storage ^ canary; }
            RegProxy& operator=(uint64_t val) { storage = val ^ canary; return *this; }
            RegProxy& operator=(const RegProxy& other) { storage = (static_cast<uint64_t>(other)) ^ canary; return *this; }
            RegProxy& operator+=(uint64_t val) { storage = ((storage ^ canary) + val) ^ canary; return *this; }
            RegProxy& operator-=(uint64_t val) { storage = ((storage ^ canary) - val) ^ canary; return *this; }
            RegProxy& operator^=(uint64_t val) { storage = ((storage ^ canary) ^ val) ^ canary; return *this; }
            RegProxy& operator&=(uint64_t val) { storage = ((storage ^ canary) & val) ^ canary; return *this; }
            RegProxy& operator|=(uint64_t val) { storage = ((storage ^ canary) | val) ^ canary; return *this; }
            RegProxy& operator<<=(uint8_t shift) { storage = ((storage ^ canary) << shift) ^ canary; return *this; }
            RegProxy& operator>>=(uint8_t shift) { storage = ((storage ^ canary) >> shift) ^ canary; return *this; }
        };

        struct RegArrayProxy {
            VmContext* parent;
            RegProxy operator[](size_t idx) {
                return RegProxy{ parent->rawRegs[idx & 0x07], parent->canaries[idx & 0x07] };
            }
            uint64_t operator[](size_t idx) const {
                return parent->rawRegs[idx & 0x07] ^ parent->canaries[idx & 0x07];
            }
        };

        RegArrayProxy regs{ this };
    };

    class VirtualMachine {
    public:
        static uint64_t Execute(const uint8_t* bytecode, size_t size, uint8_t initialKey,
                                uint64_t arg0 = 0, uint64_t arg1 = 0, uint64_t arg2 = 0, uint64_t arg3 = 0) {
            if (!bytecode || size == 0)
                return 0;

            VmContext ctx;
            ctx.regs[0] = arg0;
            ctx.regs[1] = arg1;
            ctx.regs[2] = arg2;
            ctx.regs[3] = arg3;

            auto fetchByte = [&]() -> uint8_t {
                if (ctx.ip >= size) { ctx.running = false; return 0; }
                size_t curr = ctx.ip++;
                uint8_t k = static_cast<uint8_t>((initialKey * 33) + (curr * 7) + 13);
                return bytecode[curr] ^ k;
            };

            while (ctx.running && ctx.ip < size) {
                uint8_t op = fetchByte();

                switch (op) {
                case VM_OP_NOP:
                    break;

                case VM_OP_IMM64: {
                    if (ctx.ip + 9 > size) { ctx.running = false; break; }
                    uint8_t reg = fetchByte() & 0x07;
                    uint64_t imm = 0;
                    for (int k = 0; k < 8; ++k) {
                        imm |= (static_cast<uint64_t>(fetchByte()) << (k * 8));
                    }
                    ctx.regs[reg] = imm;
                    break;
                }

                case VM_OP_MOV: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    ctx.regs[dst] = ctx.regs[src];
                    break;
                }

                case VM_OP_ADD: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    ctx.regs[dst] += ctx.regs[src];
                    break;
                }

                case VM_OP_SUB: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    ctx.regs[dst] -= ctx.regs[src];
                    break;
                }

                case VM_OP_XOR: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    ctx.regs[dst] ^= ctx.regs[src];
                    break;
                }

                case VM_OP_AND: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    ctx.regs[dst] &= ctx.regs[src];
                    break;
                }

                case VM_OP_OR: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    ctx.regs[dst] |= ctx.regs[src];
                    break;
                }

                case VM_OP_SHL: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t shift = fetchByte() & 0x3F;
                    ctx.regs[dst] <<= shift;
                    break;
                }

                case VM_OP_SHR: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t shift = fetchByte() & 0x3F;
                    ctx.regs[dst] >>= shift;
                    break;
                }

                case VM_OP_ROL: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t shift = fetchByte() & 0x3F;
                    ctx.regs[dst] = _rotl64(ctx.regs[dst], shift);
                    break;
                }

                case VM_OP_ROR: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t shift = fetchByte() & 0x3F;
                    ctx.regs[dst] = _rotr64(ctx.regs[dst], shift);
                    break;
                }

                case VM_OP_MBA_ADD: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    uint64_t x = ctx.regs[dst];
                    uint64_t y = ctx.regs[src];
                    ctx.regs[dst] = (x ^ y) + ((x & y) << 1);
                    break;
                }

                case VM_OP_MBA_SUB: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    uint64_t x = ctx.regs[dst];
                    uint64_t y = ctx.regs[src];
                    ctx.regs[dst] = (x ^ y) - ((~x & y) << 1);
                    break;
                }

                case VM_OP_MBA_XOR: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    uint64_t x = ctx.regs[dst];
                    uint64_t y = ctx.regs[src];
                    ctx.regs[dst] = (x | y) - (x & y);
                    break;
                }

                case VM_OP_PUSH: {
                    if (ctx.ip + 1 > size || ctx.sp >= 256) { ctx.running = false; break; }
                    uint8_t reg = fetchByte() & 0x07;
                    ctx.stack[ctx.sp++] = ctx.regs[reg];
                    break;
                }

                case VM_OP_POP: {
                    if (ctx.ip + 1 > size || ctx.sp == 0) { ctx.running = false; break; }
                    uint8_t reg = fetchByte() & 0x07;
                    ctx.regs[reg] = ctx.stack[--ctx.sp];
                    break;
                }

                case VM_OP_CMP: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t r1 = fetchByte() & 0x07;
                    uint8_t r2 = fetchByte() & 0x07;
                    ctx.flagZero = (ctx.regs[r1] == ctx.regs[r2]);
                    ctx.flagSign = (static_cast<int64_t>(ctx.regs[r1]) < static_cast<int64_t>(ctx.regs[r2]));
                    break;
                }

                case VM_OP_JMP: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t b0 = fetchByte();
                    uint8_t b1 = fetchByte();
                    int16_t offset = static_cast<int16_t>(b0 | (b1 << 8));
                    ctx.ip += offset;
                    break;
                }

                case VM_OP_JZ: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t b0 = fetchByte();
                    uint8_t b1 = fetchByte();
                    int16_t offset = static_cast<int16_t>(b0 | (b1 << 8));
                    if (ctx.flagZero) ctx.ip += offset;
                    break;
                }

                case VM_OP_JNZ: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t b0 = fetchByte();
                    uint8_t b1 = fetchByte();
                    int16_t offset = static_cast<int16_t>(b0 | (b1 << 8));
                    if (!ctx.flagZero) ctx.ip += offset;
                    break;
                }

                case VM_OP_READ_MEM: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    uintptr_t addr = static_cast<uintptr_t>(ctx.regs[src]);
                    if (addr >= 0x10000) {
                        ctx.regs[dst] = *reinterpret_cast<const uint64_t*>(addr);
                    }
                    break;
                }

                case VM_OP_WRITE_MEM: {
                    if (ctx.ip + 2 > size) { ctx.running = false; break; }
                    uint8_t dst = fetchByte() & 0x07;
                    uint8_t src = fetchByte() & 0x07;
                    uintptr_t addr = static_cast<uintptr_t>(ctx.regs[dst]);
                    if (addr >= 0x10000) {
                        *reinterpret_cast<uint64_t*>(addr) = ctx.regs[src];
                    }
                    break;
                }

                case VM_OP_RET:
                    ctx.running = false;
                    break;

                default:
                    ctx.running = false;
                    break;
                }
            }

            return ctx.regs[0];
        }
    };

    class BytecodeBuilder {
    public:
        BytecodeBuilder& Nop() {
            m_raw.push_back(VM_OP_NOP);
            return *this;
        }

        BytecodeBuilder& Imm(uint8_t reg, uint64_t val) {
            m_raw.push_back(VM_OP_IMM64);
            m_raw.push_back(reg & 0x07);
            for (int i = 0; i < 8; ++i) {
                m_raw.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
            }
            return *this;
        }

        BytecodeBuilder& Mov(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_MOV);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& Add(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_ADD);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& Sub(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_SUB);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& Xor(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_XOR);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& And(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_AND);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& Or(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_OR);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& Shl(uint8_t dst, uint8_t shift) {
            m_raw.push_back(VM_OP_SHL);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(shift & 0x3F);
            return *this;
        }

        BytecodeBuilder& Shr(uint8_t dst, uint8_t shift) {
            m_raw.push_back(VM_OP_SHR);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(shift & 0x3F);
            return *this;
        }

        BytecodeBuilder& Rol(uint8_t dst, uint8_t shift) {
            m_raw.push_back(VM_OP_ROL);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(shift & 0x3F);
            return *this;
        }

        BytecodeBuilder& Ror(uint8_t dst, uint8_t shift) {
            m_raw.push_back(VM_OP_ROR);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(shift & 0x3F);
            return *this;
        }

        BytecodeBuilder& MbaAdd(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_MBA_ADD);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& MbaSub(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_MBA_SUB);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& MbaXor(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_MBA_XOR);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& Push(uint8_t reg) {
            m_raw.push_back(VM_OP_PUSH);
            m_raw.push_back(reg & 0x07);
            return *this;
        }

        BytecodeBuilder& Pop(uint8_t reg) {
            m_raw.push_back(VM_OP_POP);
            m_raw.push_back(reg & 0x07);
            return *this;
        }

        BytecodeBuilder& Cmp(uint8_t r1, uint8_t r2) {
            m_raw.push_back(VM_OP_CMP);
            m_raw.push_back(r1 & 0x07);
            m_raw.push_back(r2 & 0x07);
            return *this;
        }

        BytecodeBuilder& Jmp(int16_t offset) {
            m_raw.push_back(VM_OP_JMP);
            m_raw.push_back(static_cast<uint8_t>(offset & 0xFF));
            m_raw.push_back(static_cast<uint8_t>((offset >> 8) & 0xFF));
            return *this;
        }

        BytecodeBuilder& Jz(int16_t offset) {
            m_raw.push_back(VM_OP_JZ);
            m_raw.push_back(static_cast<uint8_t>(offset & 0xFF));
            m_raw.push_back(static_cast<uint8_t>((offset >> 8) & 0xFF));
            return *this;
        }

        BytecodeBuilder& Jnz(int16_t offset) {
            m_raw.push_back(VM_OP_JNZ);
            m_raw.push_back(static_cast<uint8_t>(offset & 0xFF));
            m_raw.push_back(static_cast<uint8_t>((offset >> 8) & 0xFF));
            return *this;
        }

        BytecodeBuilder& ReadMem(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_READ_MEM);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& WriteMem(uint8_t dst, uint8_t src) {
            m_raw.push_back(VM_OP_WRITE_MEM);
            m_raw.push_back(dst & 0x07);
            m_raw.push_back(src & 0x07);
            return *this;
        }

        BytecodeBuilder& Ret() {
            m_raw.push_back(VM_OP_RET);
            return *this;
        }

        std::vector<uint8_t> Build(uint8_t initialKey) const {
            std::vector<uint8_t> enc = m_raw;
            for (size_t i = 0; i < enc.size(); ++i) {
                uint8_t k = static_cast<uint8_t>((initialKey * 33) + (i * 7) + 13);
                enc[i] ^= k;
            }
            return enc;
        }

    private:
        std::vector<uint8_t> m_raw;
    };

}
}
