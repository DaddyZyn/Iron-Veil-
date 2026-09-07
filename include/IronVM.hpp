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
        VM_OP_RET        = 0xFF
    };

    struct VmContext {
        uint64_t regs[8] = { 0 };
        uint64_t stack[256] = { 0 };
        size_t sp = 0;
        size_t ip = 0;
        bool flagZero = false;
        bool flagSign = false;
        bool running = true;
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

            std::vector<uint8_t> code(bytecode, bytecode + size);
            uint8_t key = initialKey;
            for (size_t i = 0; i < size; ++i) {
                code[i] ^= key;
                key = static_cast<uint8_t>((key * 33) + 7);
            }

            while (ctx.running && ctx.ip < code.size()) {
                uint8_t op = code[ctx.ip++];

                switch (op) {
                case VM_OP_NOP:
                    break;

                case VM_OP_IMM64: {
                    if (ctx.ip + 9 > code.size()) { ctx.running = false; break; }
                    uint8_t reg = code[ctx.ip++] & 0x07;
                    uint64_t imm = 0;
                    for (int k = 0; k < 8; ++k) {
                        imm |= (static_cast<uint64_t>(code[ctx.ip++]) << (k * 8));
                    }
                    ctx.regs[reg] = imm;
                    break;
                }

                case VM_OP_MOV: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    ctx.regs[dst] = ctx.regs[src];
                    break;
                }

                case VM_OP_ADD: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    ctx.regs[dst] += ctx.regs[src];
                    break;
                }

                case VM_OP_SUB: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    ctx.regs[dst] -= ctx.regs[src];
                    break;
                }

                case VM_OP_XOR: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    ctx.regs[dst] ^= ctx.regs[src];
                    break;
                }

                case VM_OP_AND: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    ctx.regs[dst] &= ctx.regs[src];
                    break;
                }

                case VM_OP_OR: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    ctx.regs[dst] |= ctx.regs[src];
                    break;
                }

                case VM_OP_SHL: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t shift = code[ctx.ip++] & 0x3F;
                    ctx.regs[dst] <<= shift;
                    break;
                }

                case VM_OP_SHR: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t shift = code[ctx.ip++] & 0x3F;
                    ctx.regs[dst] >>= shift;
                    break;
                }

                case VM_OP_ROL: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t shift = code[ctx.ip++] & 0x3F;
                    ctx.regs[dst] = _rotl64(ctx.regs[dst], shift);
                    break;
                }

                case VM_OP_ROR: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t shift = code[ctx.ip++] & 0x3F;
                    ctx.regs[dst] = _rotr64(ctx.regs[dst], shift);
                    break;
                }

                case VM_OP_MBA_ADD: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    uint64_t x = ctx.regs[dst];
                    uint64_t y = ctx.regs[src];
                    ctx.regs[dst] = (x ^ y) + ((x & y) << 1);
                    break;
                }

                case VM_OP_MBA_SUB: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    uint64_t x = ctx.regs[dst];
                    uint64_t y = ctx.regs[src];
                    ctx.regs[dst] = (x ^ y) - ((~x & y) << 1);
                    break;
                }

                case VM_OP_MBA_XOR: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t dst = code[ctx.ip++] & 0x07;
                    uint8_t src = code[ctx.ip++] & 0x07;
                    uint64_t x = ctx.regs[dst];
                    uint64_t y = ctx.regs[src];
                    ctx.regs[dst] = (x | y) - (x & y);
                    break;
                }

                case VM_OP_PUSH: {
                    if (ctx.ip + 1 > code.size() || ctx.sp >= 256) { ctx.running = false; break; }
                    uint8_t reg = code[ctx.ip++] & 0x07;
                    ctx.stack[ctx.sp++] = ctx.regs[reg];
                    break;
                }

                case VM_OP_POP: {
                    if (ctx.ip + 1 > code.size() || ctx.sp == 0) { ctx.running = false; break; }
                    uint8_t reg = code[ctx.ip++] & 0x07;
                    ctx.regs[reg] = ctx.stack[--ctx.sp];
                    break;
                }

                case VM_OP_CMP: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    uint8_t r1 = code[ctx.ip++] & 0x07;
                    uint8_t r2 = code[ctx.ip++] & 0x07;
                    ctx.flagZero = (ctx.regs[r1] == ctx.regs[r2]);
                    ctx.flagSign = (static_cast<int64_t>(ctx.regs[r1]) < static_cast<int64_t>(ctx.regs[r2]));
                    break;
                }

                case VM_OP_JMP: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    int16_t offset = static_cast<int16_t>(code[ctx.ip] | (code[ctx.ip + 1] << 8));
                    ctx.ip += 2 + offset;
                    break;
                }

                case VM_OP_JZ: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    int16_t offset = static_cast<int16_t>(code[ctx.ip] | (code[ctx.ip + 1] << 8));
                    ctx.ip += 2;
                    if (ctx.flagZero) ctx.ip += offset;
                    break;
                }

                case VM_OP_JNZ: {
                    if (ctx.ip + 2 > code.size()) { ctx.running = false; break; }
                    int16_t offset = static_cast<int16_t>(code[ctx.ip] | (code[ctx.ip + 1] << 8));
                    ctx.ip += 2;
                    if (!ctx.flagZero) ctx.ip += offset;
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

            SecureZeroMemory(code.data(), code.size());
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

        BytecodeBuilder& Ret() {
            m_raw.push_back(VM_OP_RET);
            return *this;
        }

        std::vector<uint8_t> Build(uint8_t initialKey) const {
            std::vector<uint8_t> enc = m_raw;
            uint8_t key = initialKey;
            for (size_t i = 0; i < enc.size(); ++i) {
                enc[i] ^= key;
                key = static_cast<uint8_t>((key * 33) + 7);
            }
            return enc;
        }

    private:
        std::vector<uint8_t> m_raw;
    };

}
}
