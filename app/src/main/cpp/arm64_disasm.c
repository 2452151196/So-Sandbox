#include "arm64_disasm.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// ARM64 寄存器名
// ============================================================================

static const char *reg_name_x(int reg, int sf) {
    static const char *x_regs[] = {
        "x0","x1","x2","x3","x4","x5","x6","x7",
        "x8","x9","x10","x11","x12","x13","x14","x15",
        "x16","x17","x18","x19","x20","x21","x22","x23",
        "x24","x25","x26","x27","x28","x29","x30","xzr"
    };
    static const char *w_regs[] = {
        "w0","w1","w2","w3","w4","w5","w6","w7",
        "w8","w9","w10","w11","w12","w13","w14","w15",
        "w16","w17","w18","w19","w20","w21","w22","w23",
        "w24","w25","w26","w27","w28","w29","w30","wzr"
    };
    if (reg < 0 || reg > 31) return "???";
    return sf ? x_regs[reg] : w_regs[reg];
}

static const char *reg_name_sp(int reg, int sf) {
    if (reg == 31) return sf ? "sp" : "wsp";
    return reg_name_x(reg, sf);
}

static const char *cond_name(int cond) {
    static const char *conds[] = {
        "eq","ne","cs","cc","mi","pl","vs","vc",
        "hi","ls","ge","lt","gt","le","al","nv"
    };
    if (cond < 0 || cond > 15) return "??";
    return conds[cond];
}

static const char *shift_name(int shift) {
    static const char *shifts[] = {"lsl","lsr","asr","ror"};
    if (shift < 0 || shift > 3) return "???";
    return shifts[shift];
}

// ============================================================================
// 位域提取宏
// ============================================================================

#define BITS(v, hi, lo) (((v) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))
#define BIT(v, n) (((v) >> (n)) & 1)
#define SIGN_EXTEND(val, bits) ((int64_t)((uint64_t)(val) << (64-(bits))) >> (64-(bits)))

// ============================================================================
// 指令解码
// ============================================================================

static int decode_b_uncond(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // B: 000101 imm26
    // BL: 100101 imm26
    if (BITS(insn, 30, 26) != 0x05 && BITS(insn, 30, 26) != 0x25)
        return 0;

    int op = BIT(insn, 31);
    int64_t imm26 = BITS(insn, 25, 0);
    int64_t offset = SIGN_EXTEND(imm26, 26) * 4;
    uint64_t target = addr + offset;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", op ? "bl" : "b");
    snprintf(out->operands, sizeof(out->operands), "0x%llx", (unsigned long long)target);
    snprintf(out->comment, sizeof(out->comment), "-> 0x%llx", (unsigned long long)target);
    return 1;
}

static int decode_b_cond(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // B.cond: 01010100 imm19 0 cond
    if (BITS(insn, 31, 24) != 0x54) return 0;

    int cond = BITS(insn, 3, 0);
    int64_t imm19 = BITS(insn, 23, 5);
    int64_t offset = SIGN_EXTEND(imm19, 19) * 4;
    uint64_t target = addr + offset;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "b.%s", cond_name(cond));
    snprintf(out->operands, sizeof(out->operands), "0x%llx", (unsigned long long)target);
    return 1;
}

static int decode_cbz_cbnz(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // CBZ/CBNZ: sf 011010 op imm19 Rt
    if (BITS(insn, 30, 25) != 0x1A) return 0;

    int sf = BIT(insn, 31);
    int op = BIT(insn, 24);
    int rt = BITS(insn, 4, 0);
    int64_t imm19 = BITS(insn, 23, 5);
    int64_t offset = SIGN_EXTEND(imm19, 19) * 4;
    uint64_t target = addr + offset;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", op ? "cbnz" : "cbz");
    snprintf(out->operands, sizeof(out->operands), "%s, 0x%llx",
             reg_name_x(rt, sf), (unsigned long long)target);
    return 1;
}

static int decode_tbz_tbnz(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    if (BITS(insn, 30, 25) != 0x1B) return 0;

    int b5 = BIT(insn, 31);
    int op = BIT(insn, 24);
    int b40 = BITS(insn, 23, 19);
    int bit_pos = (b5 << 5) | b40;
    int rt = BITS(insn, 4, 0);
    int64_t imm14 = BITS(insn, 18, 5);
    int64_t offset = SIGN_EXTEND(imm14, 14) * 4;
    uint64_t target = addr + offset;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", op ? "tbnz" : "tbz");
    snprintf(out->operands, sizeof(out->operands), "%s, #%d, 0x%llx",
             reg_name_x(rt, b5), bit_pos, (unsigned long long)target);
    return 1;
}

static int decode_ret_br_blr(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // RET: 1101011 0010 11111 0000 00 Rn 00000
    // BR:  1101011 0000 11111 0000 00 Rn 00000
    // BLR: 1101011 0001 11111 0000 00 Rn 00000
    if (BITS(insn, 31, 25) != 0x6B) return 0;
    if (BITS(insn, 20, 16) != 0x1F) return 0;
    if (BITS(insn, 15, 10) != 0x00) return 0;
    if (BITS(insn, 4, 0) != 0x00) return 0;

    int opc = BITS(insn, 24, 21);
    int rn = BITS(insn, 9, 5);

    if (opc == 0) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "br");
        snprintf(out->operands, sizeof(out->operands), "%s", reg_name_x(rn, 1));
    } else if (opc == 1) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "blr");
        snprintf(out->operands, sizeof(out->operands), "%s", reg_name_x(rn, 1));
    } else if (opc == 2) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "ret");
        if (rn != 30)
            snprintf(out->operands, sizeof(out->operands), "%s", reg_name_x(rn, 1));
        else
            out->operands[0] = '\0';
    } else {
        return 0;
    }
    return 1;
}

static int decode_svc(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // SVC: 11010100 000 imm16 000 01
    if (BITS(insn, 31, 21) == 0x6A0 && BITS(insn, 4, 0) == 0x01) {
        int imm16 = BITS(insn, 20, 5);
        snprintf(out->mnemonic, sizeof(out->mnemonic), "svc");
        snprintf(out->operands, sizeof(out->operands), "#0x%x", imm16);
        return 1;
    }
    return 0;
}

static int decode_nop_hint(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // NOP: 11010101 00000011 00100000 00011111
    if (insn == 0xD503201F) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "nop");
        out->operands[0] = '\0';
        return 1;
    }
    // BRK
    if (BITS(insn, 31, 21) == 0x6A1 && BITS(insn, 4, 0) == 0x00) {
        int imm16 = BITS(insn, 20, 5);
        snprintf(out->mnemonic, sizeof(out->mnemonic), "brk");
        snprintf(out->operands, sizeof(out->operands), "#0x%x", imm16);
        return 1;
    }
    return 0;
}

// --- 数据处理 - 寄存器 ---

static int decode_add_sub_shifted(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // ADD/SUB shifted register: sf 0 op 01011 shift 0 Rm imm6 Rn Rd
    if (BITS(insn, 28, 24) != 0x0B) return 0;
    if (BIT(insn, 21)) return 0; // extended reg form

    int sf = BIT(insn, 31);
    int op = BIT(insn, 30);
    int S = BIT(insn, 29);
    int shift = BITS(insn, 23, 22);
    int rm = BITS(insn, 20, 16);
    int imm6 = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    const char *mne;
    if (S && rd == 31) {
        mne = op ? "cmp" : "cmn";
        if (imm6 == 0) {
            snprintf(out->operands, sizeof(out->operands), "%s, %s",
                     reg_name_x(rn, sf), reg_name_x(rm, sf));
        } else {
            snprintf(out->operands, sizeof(out->operands), "%s, %s, %s #%d",
                     reg_name_x(rn, sf), reg_name_x(rm, sf), shift_name(shift), imm6);
        }
    } else {
        if (op && !S && rn == 31) {
            mne = "neg";
            if (imm6 == 0) {
                snprintf(out->operands, sizeof(out->operands), "%s, %s",
                         reg_name_x(rd, sf), reg_name_x(rm, sf));
            } else {
                snprintf(out->operands, sizeof(out->operands), "%s, %s, %s #%d",
                         reg_name_x(rd, sf), reg_name_x(rm, sf), shift_name(shift), imm6);
            }
        } else {
            mne = op ? (S ? "subs" : "sub") : (S ? "adds" : "add");
            if (imm6 == 0) {
                snprintf(out->operands, sizeof(out->operands), "%s, %s, %s",
                         reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf));
            } else {
                snprintf(out->operands, sizeof(out->operands), "%s, %s, %s, %s #%d",
                         reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf),
                         shift_name(shift), imm6);
            }
        }
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    return 1;
}

static int decode_add_sub_imm(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // ADD/SUB imm: sf op S 100010 sh imm12 Rn Rd
    if (BITS(insn, 28, 23) != 0x22) return 0;

    int sf = BIT(insn, 31);
    int op = BIT(insn, 30);
    int S = BIT(insn, 29);
    int sh = BIT(insn, 22);
    int imm12 = BITS(insn, 21, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    int64_t imm = sh ? ((int64_t)imm12 << 12) : imm12;

    const char *mne;
    if (S && rd == 31) {
        mne = op ? "cmp" : "cmn";
        snprintf(out->operands, sizeof(out->operands), "%s, #0x%llx",
                 reg_name_sp(rn, sf), (unsigned long long)imm);
    } else if (!op && !S && (rn == 31 || rd == 31)) {
        // MOV alias for ADD with sp
        if (imm == 0 && (rn == 31 || rd == 31)) {
            mne = "mov";
            snprintf(out->operands, sizeof(out->operands), "%s, %s",
                     reg_name_sp(rd, sf), reg_name_sp(rn, sf));
        } else {
            mne = "add";
            snprintf(out->operands, sizeof(out->operands), "%s, %s, #0x%llx",
                     reg_name_sp(rd, sf), reg_name_sp(rn, sf), (unsigned long long)imm);
        }
    } else {
        mne = op ? (S ? "subs" : "sub") : (S ? "adds" : "add");
        snprintf(out->operands, sizeof(out->operands), "%s, %s, #0x%llx",
                 reg_name_sp(rd, sf), reg_name_sp(rn, sf), (unsigned long long)imm);
    }
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    return 1;
}

static int decode_logic_shifted(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // Logical shifted register: sf opc 01010 shift N Rm imm6 Rn Rd
    if (BITS(insn, 28, 24) != 0x0A) return 0;

    int sf = BIT(insn, 31);
    int opc = BITS(insn, 30, 29);
    int shift = BITS(insn, 23, 22);
    int N = BIT(insn, 21);
    int rm = BITS(insn, 20, 16);
    int imm6 = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    const char *mne;
    // opc: 00=AND, 01=ORR, 10=EOR, 11=ANDS
    if (N) {
        static const char *neg_mnes[] = {"bic","orn","eon","bics"};
        mne = neg_mnes[opc];
    } else {
        static const char *pos_mnes[] = {"and","orr","eor","ands"};
        mne = pos_mnes[opc];
    }

    // MOV alias: ORR Rd, XZR, Rm
    if (opc == 1 && !N && rn == 31 && imm6 == 0 && shift == 0) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "mov");
        snprintf(out->operands, sizeof(out->operands), "%s, %s",
                 reg_name_x(rd, sf), reg_name_x(rm, sf));
        return 1;
    }
    // MVN alias: ORN Rd, XZR, Rm
    if (opc == 1 && N && rn == 31 && imm6 == 0 && shift == 0) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "mvn");
        snprintf(out->operands, sizeof(out->operands), "%s, %s",
                 reg_name_x(rd, sf), reg_name_x(rm, sf));
        return 1;
    }
    // TST alias: ANDS XZR, Rn, Rm
    if (opc == 3 && !N && rd == 31) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "tst");
        if (imm6 == 0) {
            snprintf(out->operands, sizeof(out->operands), "%s, %s",
                     reg_name_x(rn, sf), reg_name_x(rm, sf));
        } else {
            snprintf(out->operands, sizeof(out->operands), "%s, %s, %s #%d",
                     reg_name_x(rn, sf), reg_name_x(rm, sf), shift_name(shift), imm6);
        }
        return 1;
    }

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    if (imm6 == 0 && shift == 0) {
        snprintf(out->operands, sizeof(out->operands), "%s, %s, %s",
                 reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf));
    } else {
        snprintf(out->operands, sizeof(out->operands), "%s, %s, %s, %s #%d",
                 reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf),
                 shift_name(shift), imm6);
    }
    return 1;
}

static int decode_movz_movn_movk(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // MOVx: sf opc 100101 hw imm16 Rd
    if (BITS(insn, 28, 23) != 0x25) return 0;

    int sf = BIT(insn, 31);
    int opc = BITS(insn, 30, 29);
    int hw = BITS(insn, 22, 21);
    int imm16 = BITS(insn, 20, 5);
    int rd = BITS(insn, 4, 0);
    int shift = hw * 16;

    const char *mne;
    switch (opc) {
        case 0: mne = "movn"; break;
        case 2: mne = "movz"; break;
        case 3: mne = "movk"; break;
        default: return 0;
    }

    // MOV alias for MOVZ with shift=0, or MOVN with certain values
    if (opc == 2 && hw == 0) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "mov");
        snprintf(out->operands, sizeof(out->operands), "%s, #0x%x",
                 reg_name_x(rd, sf), imm16);
        return 1;
    }

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    if (shift == 0) {
        snprintf(out->operands, sizeof(out->operands), "%s, #0x%x",
                 reg_name_x(rd, sf), imm16);
    } else {
        snprintf(out->operands, sizeof(out->operands), "%s, #0x%x, lsl #%d",
                 reg_name_x(rd, sf), imm16, shift);
    }
    return 1;
}

static int decode_adr_adrp(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // ADR:  0 immlo 10000 immhi Rd
    // ADRP: 1 immlo 10000 immhi Rd
    if (BITS(insn, 28, 24) != 0x10) return 0;

    int op = BIT(insn, 31);
    int immlo = BITS(insn, 30, 29);
    int immhi = BITS(insn, 23, 5);
    int rd = BITS(insn, 4, 0);

    int64_t imm = ((int64_t)immhi << 2) | immlo;
    imm = SIGN_EXTEND(imm, 21);

    uint64_t target;
    if (op) {
        // ADRP: page-aligned
        imm <<= 12;
        target = (addr & ~0xFFFULL) + imm;
        snprintf(out->mnemonic, sizeof(out->mnemonic), "adrp");
    } else {
        target = addr + imm;
        snprintf(out->mnemonic, sizeof(out->mnemonic), "adr");
    }
    snprintf(out->operands, sizeof(out->operands), "%s, 0x%llx",
             reg_name_x(rd, 1), (unsigned long long)target);
    return 1;
}

// --- Load/Store ---

static int decode_ldr_str_imm_unsigned(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // LDR/STR unsigned offset: size 11 1 01 opc imm12 Rn Rt
    if (BITS(insn, 29, 27) != 0x07) return 0;
    if (BIT(insn, 26) != 0) return 0; // exclude SIMD
    if (BITS(insn, 25, 24) != 0x01) return 0;

    int size = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int opc = BITS(insn, 23, 22);
    int imm12 = BITS(insn, 21, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    if (V) return 0; // skip SIMD for now

    int scale = size;
    int64_t offset = (int64_t)imm12 << scale;
    int is_64 = (size == 3) || (size == 2 && opc == 1);

    const char *mne;
    switch (opc) {
        case 0: mne = (size == 0) ? "strb" : (size == 1) ? "strh" : "str"; break;
        case 1: mne = (size == 0) ? "ldrb" : (size == 1) ? "ldrh" : "ldr"; break;
        case 2: mne = (size == 0) ? "ldrsb" : (size == 1) ? "ldrsh" : "ldrsw"; break;
        case 3: mne = "prfm"; break;
        default: return 0;
    }

    if (opc == 3 && size == 3) return 0; // invalid

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    if (offset == 0) {
        snprintf(out->operands, sizeof(out->operands), "%s, [%s]",
                 reg_name_x(rt, is_64), reg_name_sp(rn, 1));
    } else {
        snprintf(out->operands, sizeof(out->operands), "%s, [%s, #0x%llx]",
                 reg_name_x(rt, is_64), reg_name_sp(rn, 1), (unsigned long long)offset);
    }
    return 1;
}

static int decode_ldr_str_pre_post(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // LDR/STR pre/post index: size 11 1 00 opc 0 imm9 idx Rn Rt
    // idx: 01=post, 11=pre
    if (BITS(insn, 29, 27) != 0x07) return 0;
    if (BIT(insn, 26) != 0) return 0;
    if (BITS(insn, 25, 24) != 0x00) return 0;
    if (BIT(insn, 21) != 0) return 0;

    int size = BITS(insn, 31, 30);
    int opc = BITS(insn, 23, 22);
    int imm9 = BITS(insn, 20, 12);
    int idx = BITS(insn, 11, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    if (idx != 1 && idx != 3) return 0; // unscaled or unprivileged

    int64_t offset = SIGN_EXTEND(imm9, 9);
    int is_64 = (size == 3) || (size == 2 && opc == 1);

    const char *mne;
    switch (opc) {
        case 0: mne = (size == 0) ? "strb" : (size == 1) ? "strh" : "str"; break;
        case 1: mne = (size == 0) ? "ldrb" : (size == 1) ? "ldrh" : "ldr"; break;
        case 2: mne = (size == 0) ? "ldrsb" : (size == 1) ? "ldrsh" : "ldrsw"; break;
        default: return 0;
    }

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    if (idx == 3) { // pre-index
        snprintf(out->operands, sizeof(out->operands), "%s, [%s, #%lld]!",
                 reg_name_x(rt, is_64), reg_name_sp(rn, 1), (long long)offset);
    } else { // post-index
        snprintf(out->operands, sizeof(out->operands), "%s, [%s], #%lld",
                 reg_name_x(rt, is_64), reg_name_sp(rn, 1), (long long)offset);
    }
    return 1;
}

static int decode_ldp_stp(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // LDP/STP: opc 0 101 V 0 L imm7 Rt2 Rn Rt  (signed offset)
    // opc 0 101 V 0 L imm7 Rt2 Rn Rt
    int op2_check = BITS(insn, 29, 27);
    if (op2_check != 0x05) return 0;

    int opc = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int mode = BITS(insn, 25, 23); // 001=post, 010=signed, 011=pre
    int L = BIT(insn, 22);
    int imm7 = BITS(insn, 21, 15);
    int rt2 = BITS(insn, 14, 10);
    int rn = BITS(insn, 9, 5);
    int rt = BITS(insn, 4, 0);

    if (V) return 0; // skip SIMD

    int sf = (opc == 2) ? 1 : (opc == 0) ? 0 : 0;
    if (opc == 2) sf = 1;
    int scale = sf ? 3 : 2;
    int64_t offset = SIGN_EXTEND(imm7, 7) << scale;

    const char *mne = L ? "ldp" : "stp";
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);

    if (mode == 2) { // signed offset
        if (offset == 0) {
            snprintf(out->operands, sizeof(out->operands), "%s, %s, [%s]",
                     reg_name_x(rt, sf), reg_name_x(rt2, sf), reg_name_sp(rn, 1));
        } else {
            snprintf(out->operands, sizeof(out->operands), "%s, %s, [%s, #%lld]",
                     reg_name_x(rt, sf), reg_name_x(rt2, sf), reg_name_sp(rn, 1), (long long)offset);
        }
    } else if (mode == 3) { // pre-index
        snprintf(out->operands, sizeof(out->operands), "%s, %s, [%s, #%lld]!",
                 reg_name_x(rt, sf), reg_name_x(rt2, sf), reg_name_sp(rn, 1), (long long)offset);
    } else if (mode == 1) { // post-index
        snprintf(out->operands, sizeof(out->operands), "%s, %s, [%s], #%lld",
                 reg_name_x(rt, sf), reg_name_x(rt2, sf), reg_name_sp(rn, 1), (long long)offset);
    } else {
        return 0;
    }
    return 1;
}

static int decode_ldr_literal(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // LDR literal: opc 01 1 V 00 imm19 Rt
    if (BITS(insn, 29, 27) != 0x03) return 0;
    if (BITS(insn, 25, 24) != 0x00) return 0;

    int opc = BITS(insn, 31, 30);
    int V = BIT(insn, 26);
    int rt = BITS(insn, 4, 0);
    int64_t imm19 = BITS(insn, 23, 5);
    int64_t offset = SIGN_EXTEND(imm19, 19) * 4;
    uint64_t target = addr + offset;

    if (V) return 0; // skip SIMD

    const char *mne;
    int sf;
    if (opc == 0) { mne = "ldr"; sf = 0; }
    else if (opc == 1) { mne = "ldr"; sf = 1; }
    else if (opc == 2) { mne = "ldrsw"; sf = 1; }
    else return 0;

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    snprintf(out->operands, sizeof(out->operands), "%s, 0x%llx",
             reg_name_x(rt, sf), (unsigned long long)target);
    snprintf(out->comment, sizeof(out->comment), "literal pool");
    return 1;
}

// --- Data processing 2/3 source ---

static int decode_dp_2src(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // Data Processing 2 source: sf 0 S 11010110 Rm opcode2 Rn Rd
    if (BITS(insn, 28, 21) != 0xD6) return 0;

    int sf = BIT(insn, 31);
    int rm = BITS(insn, 20, 16);
    int opc = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    const char *mne;
    switch (opc) {
        case 2: mne = "udiv"; break;
        case 3: mne = "sdiv"; break;
        case 8: mne = "lsl"; break;
        case 9: mne = "lsr"; break;
        case 10: mne = "asr"; break;
        case 11: mne = "ror"; break;
        default: return 0;
    }

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    snprintf(out->operands, sizeof(out->operands), "%s, %s, %s",
             reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf));
    return 1;
}

static int decode_dp_3src(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // MADD/MSUB: sf 00 11011 000 Rm o0 Ra Rn Rd
    if (BITS(insn, 28, 24) != 0x1B) return 0;
    if (BITS(insn, 23, 21) != 0x00) return 0;

    int sf = BIT(insn, 31);
    int rm = BITS(insn, 20, 16);
    int o0 = BIT(insn, 15);
    int ra = BITS(insn, 14, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    if (ra == 31 && !o0) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "mul");
        snprintf(out->operands, sizeof(out->operands), "%s, %s, %s",
                 reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf));
    } else if (ra == 31 && o0) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "mneg");
        snprintf(out->operands, sizeof(out->operands), "%s, %s, %s",
                 reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf));
    } else {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", o0 ? "msub" : "madd");
        snprintf(out->operands, sizeof(out->operands), "%s, %s, %s, %s",
                 reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf), reg_name_x(ra, sf));
    }
    return 1;
}

// --- Bitfield (SBFM/UBFM/BFM) ---

static int decode_bitfield(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // sf opc 100110 N immr imms Rn Rd
    if (BITS(insn, 28, 23) != 0x26) return 0;

    int sf = BIT(insn, 31);
    int opc = BITS(insn, 30, 29);
    int immr = BITS(insn, 21, 16);
    int imms = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    int bits = sf ? 64 : 32;

    if (opc == 2) {
        // UBFM aliases
        if (imms == bits - 1) {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "lsr");
            snprintf(out->operands, sizeof(out->operands), "%s, %s, #%d",
                     reg_name_x(rd, sf), reg_name_x(rn, sf), immr);
        } else if (imms + 1 == immr) {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "lsl");
            snprintf(out->operands, sizeof(out->operands), "%s, %s, #%d",
                     reg_name_x(rd, sf), reg_name_x(rn, sf), bits - immr);
        } else if (imms == 7 && immr == 0) {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "uxtb");
            snprintf(out->operands, sizeof(out->operands), "%s, %s",
                     reg_name_x(rd, sf), reg_name_x(rn, 0));
        } else if (imms == 15 && immr == 0) {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "uxth");
            snprintf(out->operands, sizeof(out->operands), "%s, %s",
                     reg_name_x(rd, sf), reg_name_x(rn, 0));
        } else {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "ubfm");
            snprintf(out->operands, sizeof(out->operands), "%s, %s, #%d, #%d",
                     reg_name_x(rd, sf), reg_name_x(rn, sf), immr, imms);
        }
    } else if (opc == 0) {
        // SBFM aliases
        if (imms == bits - 1) {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "asr");
            snprintf(out->operands, sizeof(out->operands), "%s, %s, #%d",
                     reg_name_x(rd, sf), reg_name_x(rn, sf), immr);
        } else if (imms == 7 && immr == 0) {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "sxtb");
            snprintf(out->operands, sizeof(out->operands), "%s, %s",
                     reg_name_x(rd, sf), reg_name_x(rn, 0));
        } else if (imms == 15 && immr == 0) {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "sxth");
            snprintf(out->operands, sizeof(out->operands), "%s, %s",
                     reg_name_x(rd, sf), reg_name_x(rn, 0));
        } else if (imms == 31 && immr == 0) {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "sxtw");
            snprintf(out->operands, sizeof(out->operands), "%s, %s",
                     reg_name_x(rd, 1), reg_name_x(rn, 0));
        } else {
            snprintf(out->mnemonic, sizeof(out->mnemonic), "sbfm");
            snprintf(out->operands, sizeof(out->operands), "%s, %s, #%d, #%d",
                     reg_name_x(rd, sf), reg_name_x(rn, sf), immr, imms);
        }
    } else if (opc == 1) {
        snprintf(out->mnemonic, sizeof(out->mnemonic), "bfm");
        snprintf(out->operands, sizeof(out->operands), "%s, %s, #%d, #%d",
                 reg_name_x(rd, sf), reg_name_x(rn, sf), immr, imms);
    } else {
        return 0;
    }
    return 1;
}

// --- CSEL/CSINC/CSINV/CSNEG ---

static int decode_csel(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // sf op S 11010100 Rm cond o2 Rn Rd
    if (BITS(insn, 28, 21) != 0xD4) return 0;

    int sf = BIT(insn, 31);
    int op = BIT(insn, 30);
    int rm = BITS(insn, 20, 16);
    int cond = BITS(insn, 15, 12);
    int o2 = BIT(insn, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    const char *mne;
    if (!op && !o2) {
        mne = "csel";
    } else if (!op && o2) {
        if (rn == rm && rn != 31) { mne = "cinc"; }
        else { mne = "csinc"; }
    } else if (op && !o2) {
        mne = "csinv";
    } else {
        mne = "csneg";
    }

    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    snprintf(out->operands, sizeof(out->operands), "%s, %s, %s, %s",
             reg_name_x(rd, sf), reg_name_x(rn, sf), reg_name_x(rm, sf), cond_name(cond));
    return 1;
}

// --- Logic immediate ---

static int decode_logic_imm(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    // sf opc 100100 N immr imms Rn Rd
    if (BITS(insn, 28, 23) != 0x24) return 0;

    int sf = BIT(insn, 31);
    int opc = BITS(insn, 30, 29);
    int N = BIT(insn, 22);
    int immr = BITS(insn, 21, 16);
    int imms = BITS(insn, 15, 10);
    int rn = BITS(insn, 9, 5);
    int rd = BITS(insn, 4, 0);

    const char *mne;
    switch (opc) {
        case 0: mne = "and"; break;
        case 1: mne = "orr"; break;
        case 2: mne = "eor"; break;
        case 3: mne = "ands"; break;
        default: return 0;
    }

    // Decode bitmask immediate (simplified - show raw encoding)
    snprintf(out->mnemonic, sizeof(out->mnemonic), "%s", mne);
    snprintf(out->operands, sizeof(out->operands), "%s, %s, #<imm N=%d,r=%d,s=%d>",
             (opc == 3) ? reg_name_x(rd, sf) : reg_name_sp(rd, sf),
             reg_name_x(rn, sf), N, immr, imms);
    return 1;
}

// ============================================================================
// 主解码入口
// ============================================================================

int arm64_disasm_one(uint32_t insn, uint64_t addr, Arm64Insn *out) {
    memset(out, 0, sizeof(*out));
    out->address = addr;
    out->opcode = insn;

    // 尝试各解码器，按优先级排列
    if (decode_nop_hint(insn, addr, out)) return 1;
    if (decode_ret_br_blr(insn, addr, out)) return 1;
    if (decode_svc(insn, addr, out)) return 1;
    if (decode_b_uncond(insn, addr, out)) return 1;
    if (decode_b_cond(insn, addr, out)) return 1;
    if (decode_cbz_cbnz(insn, addr, out)) return 1;
    if (decode_tbz_tbnz(insn, addr, out)) return 1;
    if (decode_adr_adrp(insn, addr, out)) return 1;
    if (decode_movz_movn_movk(insn, addr, out)) return 1;
    if (decode_add_sub_imm(insn, addr, out)) return 1;
    if (decode_add_sub_shifted(insn, addr, out)) return 1;
    if (decode_logic_shifted(insn, addr, out)) return 1;
    if (decode_logic_imm(insn, addr, out)) return 1;
    if (decode_bitfield(insn, addr, out)) return 1;
    if (decode_csel(insn, addr, out)) return 1;
    if (decode_dp_2src(insn, addr, out)) return 1;
    if (decode_dp_3src(insn, addr, out)) return 1;
    if (decode_ldp_stp(insn, addr, out)) return 1;
    if (decode_ldr_literal(insn, addr, out)) return 1;
    if (decode_ldr_str_imm_unsigned(insn, addr, out)) return 1;
    if (decode_ldr_str_pre_post(insn, addr, out)) return 1;

    // 未知指令
    snprintf(out->mnemonic, sizeof(out->mnemonic), ".inst");
    snprintf(out->operands, sizeof(out->operands), "0x%08x", insn);
    return 0;
}

int arm64_disasm_block(const uint8_t *code, size_t code_size, uint64_t base_addr,
                       Arm64Insn *out, int max_insns) {
    int count = 0;
    size_t offset = 0;

    while (offset + 4 <= code_size && count < max_insns) {
        uint32_t insn = *(const uint32_t *)(code + offset);
        arm64_disasm_one(insn, base_addr + offset, &out[count]);
        count++;
        offset += 4;
    }
    return count;
}

void arm64_format_insn(const Arm64Insn *insn, char *buf, size_t buf_size) {
    if (insn->comment[0]) {
        snprintf(buf, buf_size, "0x%08llx:  %08x    %-8s %-40s ; %s",
                 (unsigned long long)insn->address, insn->opcode,
                 insn->mnemonic, insn->operands, insn->comment);
    } else {
        snprintf(buf, buf_size, "0x%08llx:  %08x    %-8s %s",
                 (unsigned long long)insn->address, insn->opcode,
                 insn->mnemonic, insn->operands);
    }
}
