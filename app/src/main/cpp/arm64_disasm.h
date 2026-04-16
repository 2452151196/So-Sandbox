#ifndef ARM64_DISASM_H
#define ARM64_DISASM_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t address;
    uint32_t opcode;
    char mnemonic[16];
    char operands[128];
    char comment[64];
} Arm64Insn;

// 反汇编单条指令
int arm64_disasm_one(uint32_t insn, uint64_t addr, Arm64Insn *out);

// 反汇编一段内存区域，返回反汇编的指令数量
int arm64_disasm_block(const uint8_t *code, size_t code_size, uint64_t base_addr,
                       Arm64Insn *out, int max_insns);

// 格式化单条指令为字符串
void arm64_format_insn(const Arm64Insn *insn, char *buf, size_t buf_size);

#endif // ARM64_DISASM_H
