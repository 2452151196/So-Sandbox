#include "decompiler.h"
#include <capstone/capstone.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

// ============================================================================
// 伪C生成器 - 基于Capstone cs_insn结构化数据翻译为伪C
// ============================================================================

#define MAX_LABELS 512

typedef struct {
    uint64_t addr;
    char name[32];
} Label;

static int g_label_count;
static Label g_labels[MAX_LABELS];

static const char* find_label(uint64_t addr) {
    for (int i = 0; i < g_label_count; i++) {
        if (g_labels[i].addr == addr) return g_labels[i].name;
    }
    return NULL;
}

static void add_label(uint64_t addr) {
    if (find_label(addr)) return;
    if (g_label_count >= MAX_LABELS) return;
    Label *l = &g_labels[g_label_count++];
    l->addr = addr;
    snprintf(l->name, sizeof(l->name), "loc_%llx", (unsigned long long)(addr & 0xFFFF));
}

// Capstone AArch64 寄存器ID转变量名 (使用真实寄存器名)
static const char* cs_reg_var(arm64_reg reg) {
    switch (reg) {
        case ARM64_REG_X0: return "x0";
        case ARM64_REG_X1: return "x1";
        case ARM64_REG_X2: return "x2";
        case ARM64_REG_X3: return "x3";
        case ARM64_REG_X4: return "x4";
        case ARM64_REG_X5: return "x5";
        case ARM64_REG_X6: return "x6";
        case ARM64_REG_X7: return "x7";
        case ARM64_REG_X8: return "x8";
        case ARM64_REG_X9: return "x9";
        case ARM64_REG_X10: return "x10";
        case ARM64_REG_X11: return "x11";
        case ARM64_REG_X12: return "x12";
        case ARM64_REG_X13: return "x13";
        case ARM64_REG_X14: return "x14";
        case ARM64_REG_X15: return "x15";
        case ARM64_REG_X16: return "x16";
        case ARM64_REG_X17: return "x17";
        case ARM64_REG_X19: return "x19";
        case ARM64_REG_X20: return "x20";
        case ARM64_REG_X21: return "x21";
        case ARM64_REG_X22: return "x22";
        case ARM64_REG_X23: return "x23";
        case ARM64_REG_X24: return "x24";
        case ARM64_REG_X25: return "x25";
        case ARM64_REG_X26: return "x26";
        case ARM64_REG_X27: return "x27";
        case ARM64_REG_X28: return "x28";
        case ARM64_REG_W0: return "w0";
        case ARM64_REG_W1: return "w1";
        case ARM64_REG_W2: return "w2";
        case ARM64_REG_W3: return "w3";
        case ARM64_REG_W4: return "w4";
        case ARM64_REG_W5: return "w5";
        case ARM64_REG_W6: return "w6";
        case ARM64_REG_W7: return "w7";
        case ARM64_REG_W8: return "w8";
        case ARM64_REG_W9: return "w9";
        case ARM64_REG_W10: return "w10";
        case ARM64_REG_W11: return "w11";
        case ARM64_REG_W12: return "w12";
        case ARM64_REG_W13: return "w13";
        case ARM64_REG_W14: return "w14";
        case ARM64_REG_W15: return "w15";
        case ARM64_REG_W19: return "w19";
        case ARM64_REG_W20: return "w20";
        case ARM64_REG_W21: return "w21";
        case ARM64_REG_W22: return "w22";
        case ARM64_REG_W23: return "w23";
        case ARM64_REG_W24: return "w24";
        case ARM64_REG_W25: return "w25";
        case ARM64_REG_W26: return "w26";
        case ARM64_REG_W27: return "w27";
        case ARM64_REG_W28: return "w28";
        case ARM64_REG_W29: return "w29";
        case ARM64_REG_W30: return "w30";
        case ARM64_REG_X29: return "fp";
        case ARM64_REG_X30: return "lr";
        case ARM64_REG_SP: return "sp";
        case ARM64_REG_XZR: return "0";
        case ARM64_REG_WZR: return "0";
        default: return "?";
    }
}

// 条件码 -> C运算符
static const char* cc_to_c(arm64_cc cc) {
    switch (cc) {
        case ARM64_CC_EQ: return "==";
        case ARM64_CC_NE: return "!=";
        case ARM64_CC_HS: return ">=u";
        case ARM64_CC_LO: return "<u";
        case ARM64_CC_MI: return "<0";
        case ARM64_CC_PL: return ">=0";
        case ARM64_CC_GT: return ">";
        case ARM64_CC_GE: return ">=";
        case ARM64_CC_LT: return "<";
        case ARM64_CC_LE: return "<=";
        case ARM64_CC_HI: return ">u";
        case ARM64_CC_LS: return "<=u";
        default: return "?cond";
    }
}

static int append(char *buf, size_t buf_size, int *pos, const char *fmt, ...) {
    if (*pos >= (int)buf_size - 1) return 0;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *pos, buf_size - *pos, fmt, ap);
    va_end(ap);
    if (n > 0) *pos += n;
    return n;
}

// 检查指令是否属于某个group
static int insn_in_group(cs_insn *insn, unsigned int grp) {
    cs_detail *d = insn->detail;
    if (!d) return 0;
    for (int i = 0; i < d->groups_count; i++) {
        if (d->groups[i] == grp) return 1;
    }
    return 0;
}

// 从operands字符串解析0x地址 (用于分支目标)
static uint64_t parse_imm_target(const char *op_str) {
    const char *p = op_str;
    while (*p) {
        if (p[0] == '#' && p[1] == '0' && p[2] == 'x') {
            uint64_t val = 0;
            sscanf(p + 1, "0x%llx", (unsigned long long *)&val);
            return val;
        }
        if (p[0] == '0' && p[1] == 'x') {
            uint64_t val = 0;
            sscanf(p, "0x%llx", (unsigned long long *)&val);
            return val;
        }
        p++;
    }
    return 0;
}

// ============================================================================
// 签名解析: "retType|name0:type0|name1:type1|..."
// ============================================================================

#define MAX_PARAMS 8
typedef struct {
    char ret_type[32];
    char func_name[256];
    int param_count;
    char param_names[MAX_PARAMS][64];
    char param_types[MAX_PARAMS][32];
} FuncSignature;

static void parse_signature(const char *sig_str, const char *func_name, FuncSignature *sig) {
    memset(sig, 0, sizeof(*sig));
    strcpy(sig->ret_type, "int64_t");
    if (func_name && func_name[0])
        snprintf(sig->func_name, sizeof(sig->func_name), "%s", func_name);
    else
        strcpy(sig->func_name, "sub");

    if (!sig_str || !sig_str[0]) return;

    // 解析: "retType|name0:type0|name1:type1|..."
    char buf[2048];
    strncpy(buf, sig_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(buf, "|", &saveptr);
    if (tok) {
        // 第一段: 返回类型
        if (strcmp(tok, "void") == 0) strcpy(sig->ret_type, "void");
        else if (strcmp(tok, "int") == 0) strcpy(sig->ret_type, "int32_t");
        else if (strcmp(tok, "long") == 0) strcpy(sig->ret_type, "int64_t");
        else if (strcmp(tok, "float") == 0) strcpy(sig->ret_type, "float");
        else if (strcmp(tok, "double") == 0) strcpy(sig->ret_type, "double");
        else if (strcmp(tok, "string") == 0) strcpy(sig->ret_type, "char*");
        else strncpy(sig->ret_type, tok, sizeof(sig->ret_type) - 1);
    }

    // 后续段: 参数 name:type
    while ((tok = strtok_r(NULL, "|", &saveptr)) != NULL && sig->param_count < MAX_PARAMS) {
        char *colon = strchr(tok, ':');
        int idx = sig->param_count;
        if (colon) {
            *colon = '\0';
            strncpy(sig->param_names[idx], tok, 63);
            const char *t = colon + 1;
            if (strcmp(t, "jnienv") == 0) strcpy(sig->param_types[idx], "JNIEnv*");
            else if (strcmp(t, "jobject") == 0) strcpy(sig->param_types[idx], "jobject");
            else if (strcmp(t, "javavm") == 0) strcpy(sig->param_types[idx], "JavaVM*");
            else if (strcmp(t, "long") == 0) strcpy(sig->param_types[idx], "int64_t");
            else if (strcmp(t, "int") == 0) strcpy(sig->param_types[idx], "int32_t");
            else if (strcmp(t, "float") == 0) strcpy(sig->param_types[idx], "float");
            else if (strcmp(t, "double") == 0) strcpy(sig->param_types[idx], "double");
            else if (strcmp(t, "string") == 0) strcpy(sig->param_types[idx], "char*");
            else strncpy(sig->param_types[idx], t, 31);
        } else {
            snprintf(sig->param_names[idx], 64, "arg%d", idx);
            strcpy(sig->param_types[idx], "int64_t");
        }
        sig->param_count++;
    }
}

// 构建从x0-x7到参数名的映射
static const char* g_reg_aliases[8] = {NULL};

static void build_reg_aliases(FuncSignature *sig) {
    for (int i = 0; i < 8; i++) g_reg_aliases[i] = NULL;
    for (int i = 0; i < sig->param_count && i < 8; i++) {
        g_reg_aliases[i] = sig->param_names[i];
    }
}

// 如果寄存器有别名(参数名)就用别名
static const char* cs_reg_var_aliased(arm64_reg reg) {
    int idx = -1;
    switch (reg) {
        case ARM64_REG_X0: idx = 0; break;
        case ARM64_REG_X1: idx = 1; break;
        case ARM64_REG_X2: idx = 2; break;
        case ARM64_REG_X3: idx = 3; break;
        case ARM64_REG_X4: idx = 4; break;
        case ARM64_REG_X5: idx = 5; break;
        case ARM64_REG_X6: idx = 6; break;
        case ARM64_REG_X7: idx = 7; break;
        default: break;
    }
    if (idx >= 0 && g_reg_aliases[idx]) return g_reg_aliases[idx];
    return cs_reg_var(reg);
}

// ============================================================================
// 主反编译入口
// ============================================================================

int decompile_function_ex(const uint8_t *code, size_t code_size, uint64_t base_addr,
                          const char *func_name, const char *signature,
                          char *output, size_t output_size) {
    if (code_size > 65536) code_size = 65536;

    // 解析签名
    FuncSignature sig;
    parse_signature(signature, func_name, &sig);
    build_reg_aliases(&sig);

    // Capstone反汇编
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return 0;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insns = NULL;
    size_t count = cs_disasm(handle, code, code_size, base_addr, 0, &insns);
    if (count <= 0) {
        cs_close(&handle);
        return snprintf(output, output_size, "// 反汇编失败\n");
    }

    // Pass 1: 收集分支标签
    g_label_count = 0;
    for (size_t i = 0; i < count; i++) {
        cs_insn *ins = &insns[i];
        if (insn_in_group(ins, ARM64_GRP_BRANCH_RELATIVE)) {
            uint64_t target = parse_imm_target(ins->op_str);
            if (target >= base_addr && target < base_addr + code_size) {
                add_label(target);
            }
        }
    }

    // Pass 2: 生成伪C
    int pos = 0;
    char cmp_left[64] = {0}, cmp_right[64] = {0};

    // 函数头 - 使用签名信息
    append(output, output_size, &pos,
           "// 伪C代码 - Capstone反汇编自动生成\n"
           "// 函数地址: 0x%llx, 大小: %zu bytes, 指令数: %zu\n\n",
           (unsigned long long)base_addr, code_size, count);

    // 生成函数声明
    append(output, output_size, &pos, "%s %s(", sig.ret_type, sig.func_name);
    if (sig.param_count == 0) {
        append(output, output_size, &pos, "void");
    } else {
        for (int i = 0; i < sig.param_count; i++) {
            if (i > 0) append(output, output_size, &pos, ", ");
            append(output, output_size, &pos, "%s %s", sig.param_types[i], sig.param_names[i]);
        }
    }
    append(output, output_size, &pos, ") {\n");

    for (size_t i = 0; i < count; i++) {
        cs_insn *ins = &insns[i];
        cs_detail *d = ins->detail;
        cs_arm64 *arm64 = d ? &d->arm64 : NULL;
        const char *mne = ins->mnemonic;
        const char *ops = ins->op_str;

        // 检查标签
        const char *label = find_label(ins->address);
        if (label) {
            append(output, output_size, &pos, "\n%s:\n", label);
        }

        // 跳过 prologue/epilogue 的 stp/ldp fp,lr
        if ((strcmp(mne, "stp") == 0 || strcmp(mne, "ldp") == 0) &&
            (strstr(ops, "x29") || strstr(ops, "x30")) && strstr(ops, "sp")) {
            if (strcmp(mne, "stp") == 0)
                append(output, output_size, &pos, "    // [prologue] 保存寄存器\n");
            else
                append(output, output_size, &pos, "    // [epilogue] 恢复寄存器\n");
            continue;
        }

        // --- 数据处理 ---
        if (strcmp(mne, "mov") == 0 || strcmp(mne, "movz") == 0) {
            if (arm64 && arm64->op_count >= 2) {
                const char *dst = cs_reg_var(arm64->operands[0].reg);
                if (arm64->operands[1].type == ARM64_OP_REG)
                    append(output, output_size, &pos, "    %s = %s;\n", dst, cs_reg_var(arm64->operands[1].reg));
                else if (arm64->operands[1].type == ARM64_OP_IMM)
                    append(output, output_size, &pos, "    %s = 0x%llx;\n", dst, (unsigned long long)arm64->operands[1].imm);
                else
                    append(output, output_size, &pos, "    %s = %s;  // mov\n", dst, ops);
            } else {
                append(output, output_size, &pos, "    /* mov */ %s;\n", ops);
            }
        }
        else if (strcmp(mne, "movn") == 0) {
            if (arm64 && arm64->op_count >= 2 && arm64->operands[1].type == ARM64_OP_IMM)
                append(output, output_size, &pos, "    %s = ~0x%llx;  // movn\n",
                       cs_reg_var(arm64->operands[0].reg), (unsigned long long)arm64->operands[1].imm);
        }
        else if (strcmp(mne, "movk") == 0) {
            if (arm64 && arm64->op_count >= 2 && arm64->operands[1].type == ARM64_OP_IMM) {
                int shift = arm64->operands[1].shift.value;
                append(output, output_size, &pos, "    %s |= (0x%llx << %d);  // movk\n",
                       cs_reg_var(arm64->operands[0].reg), (unsigned long long)arm64->operands[1].imm, shift);
            }
        }
        else if (strcmp(mne, "add") == 0 || strcmp(mne, "adds") == 0) {
            if (arm64 && arm64->op_count == 3) {
                const char *dst = cs_reg_var(arm64->operands[0].reg);
                const char *src1 = cs_reg_var(arm64->operands[1].reg);
                if (arm64->operands[2].type == ARM64_OP_IMM)
                    append(output, output_size, &pos, "    %s = %s + 0x%llx;\n", dst, src1, (unsigned long long)arm64->operands[2].imm);
                else if (arm64->operands[2].type == ARM64_OP_REG)
                    append(output, output_size, &pos, "    %s = %s + %s;\n", dst, src1, cs_reg_var(arm64->operands[2].reg));
                else
                    append(output, output_size, &pos, "    %s = %s + ...;\n", dst, src1);
            }
        }
        else if (strcmp(mne, "sub") == 0 || strcmp(mne, "subs") == 0) {
            if (arm64 && arm64->op_count == 3) {
                const char *dst = cs_reg_var(arm64->operands[0].reg);
                if (arm64->operands[0].reg == ARM64_REG_SP) {
                    append(output, output_size, &pos, "    // 分配栈空间: %s\n", ops);
                } else if (arm64->operands[2].type == ARM64_OP_IMM) {
                    append(output, output_size, &pos, "    %s = %s - 0x%llx;\n", dst,
                           cs_reg_var(arm64->operands[1].reg), (unsigned long long)arm64->operands[2].imm);
                } else if (arm64->operands[2].type == ARM64_OP_REG) {
                    append(output, output_size, &pos, "    %s = %s - %s;\n", dst,
                           cs_reg_var(arm64->operands[1].reg), cs_reg_var(arm64->operands[2].reg));
                }
            }
        }
        else if (strcmp(mne, "mul") == 0) {
            if (arm64 && arm64->op_count == 3)
                append(output, output_size, &pos, "    %s = %s * %s;\n",
                       cs_reg_var(arm64->operands[0].reg), cs_reg_var(arm64->operands[1].reg), cs_reg_var(arm64->operands[2].reg));
        }
        else if (strcmp(mne, "sdiv") == 0 || strcmp(mne, "udiv") == 0) {
            if (arm64 && arm64->op_count == 3)
                append(output, output_size, &pos, "    %s = %s / %s;  // %s\n",
                       cs_reg_var(arm64->operands[0].reg), cs_reg_var(arm64->operands[1].reg),
                       cs_reg_var(arm64->operands[2].reg), mne);
        }
        else if (strcmp(mne, "and") == 0 || strcmp(mne, "ands") == 0) {
            if (arm64 && arm64->op_count >= 3)
                append(output, output_size, &pos, "    %s = %s & %s;\n",
                       cs_reg_var(arm64->operands[0].reg), cs_reg_var(arm64->operands[1].reg),
                       arm64->operands[2].type == ARM64_OP_IMM ?
                       ops + (strstr(ops, "#") - ops) : cs_reg_var(arm64->operands[2].reg));
        }
        else if (strcmp(mne, "orr") == 0) {
            if (arm64 && arm64->op_count >= 3)
                append(output, output_size, &pos, "    %s = %s | %s;\n",
                       cs_reg_var(arm64->operands[0].reg), cs_reg_var(arm64->operands[1].reg),
                       arm64->operands[2].type == ARM64_OP_REG ?
                       cs_reg_var(arm64->operands[2].reg) : "...");
        }
        else if (strcmp(mne, "eor") == 0) {
            if (arm64 && arm64->op_count >= 3)
                append(output, output_size, &pos, "    %s = %s ^ %s;\n",
                       cs_reg_var(arm64->operands[0].reg), cs_reg_var(arm64->operands[1].reg),
                       arm64->operands[2].type == ARM64_OP_REG ?
                       cs_reg_var(arm64->operands[2].reg) : "...");
        }
        else if (strcmp(mne, "lsl") == 0) {
            append(output, output_size, &pos, "    /* lsl */ %s;\n", ops);
        }
        else if (strcmp(mne, "lsr") == 0) {
            append(output, output_size, &pos, "    /* lsr */ %s;\n", ops);
        }
        else if (strcmp(mne, "asr") == 0) {
            append(output, output_size, &pos, "    /* asr */ %s;\n", ops);
        }
        // --- Compare ---
        else if (strcmp(mne, "cmp") == 0) {
            if (arm64 && arm64->op_count >= 2) {
                snprintf(cmp_left, sizeof(cmp_left), "%s", cs_reg_var(arm64->operands[0].reg));
                if (arm64->operands[1].type == ARM64_OP_IMM)
                    snprintf(cmp_right, sizeof(cmp_right), "0x%llx", (unsigned long long)arm64->operands[1].imm);
                else if (arm64->operands[1].type == ARM64_OP_REG)
                    snprintf(cmp_right, sizeof(cmp_right), "%s", cs_reg_var(arm64->operands[1].reg));
            }
            append(output, output_size, &pos, "    // cmp %s\n", ops);
        }
        else if (strcmp(mne, "tst") == 0) {
            snprintf(cmp_left, sizeof(cmp_left), "(%s & %s)",
                     arm64 ? cs_reg_var(arm64->operands[0].reg) : "?",
                     arm64 && arm64->op_count >= 2 && arm64->operands[1].type == ARM64_OP_REG ?
                     cs_reg_var(arm64->operands[1].reg) : "...");
            snprintf(cmp_right, sizeof(cmp_right), "0");
        }
        // --- Branches ---
        else if (insn_in_group(ins, ARM64_GRP_BRANCH_RELATIVE) && mne[0] == 'b' && mne[1] == '.') {
            // b.cond
            arm64_cc cc = arm64 ? arm64->cc : ARM64_CC_AL;
            uint64_t target = parse_imm_target(ops);
            const char *tlabel = find_label(target);
            if (tlabel)
                append(output, output_size, &pos, "    if (%s %s %s) goto %s;\n",
                       cmp_left, cc_to_c(cc), cmp_right, tlabel);
            else
                append(output, output_size, &pos, "    if (%s %s %s) goto 0x%llx;\n",
                       cmp_left, cc_to_c(cc), cmp_right, (unsigned long long)target);
        }
        else if (strcmp(mne, "cbz") == 0) {
            uint64_t target = parse_imm_target(ops);
            const char *r = arm64 ? cs_reg_var(arm64->operands[0].reg) : "?";
            const char *tlabel = find_label(target);
            if (tlabel)
                append(output, output_size, &pos, "    if (%s == 0) goto %s;\n", r, tlabel);
            else
                append(output, output_size, &pos, "    if (%s == 0) goto 0x%llx;\n", r, (unsigned long long)target);
        }
        else if (strcmp(mne, "cbnz") == 0) {
            uint64_t target = parse_imm_target(ops);
            const char *r = arm64 ? cs_reg_var(arm64->operands[0].reg) : "?";
            const char *tlabel = find_label(target);
            if (tlabel)
                append(output, output_size, &pos, "    if (%s != 0) goto %s;\n", r, tlabel);
            else
                append(output, output_size, &pos, "    if (%s != 0) goto 0x%llx;\n", r, (unsigned long long)target);
        }
        else if (strcmp(mne, "b") == 0 && !insn_in_group(ins, ARM64_GRP_CALL)) {
            uint64_t target = parse_imm_target(ops);
            const char *tlabel = find_label(target);
            if (tlabel)
                append(output, output_size, &pos, "    goto %s;\n", tlabel);
            else
                append(output, output_size, &pos, "    goto 0x%llx; // tail call?\n", (unsigned long long)target);
        }
        else if (strcmp(mne, "bl") == 0) {
            uint64_t target = parse_imm_target(ops);
            append(output, output_size, &pos,
                   "    ret_val = sub_%llx(ret_val, arg1, arg2, arg3);\n",
                   (unsigned long long)target);
        }
        else if (strcmp(mne, "blr") == 0) {
            if (arm64 && arm64->op_count >= 1)
                append(output, output_size, &pos,
                       "    ret_val = (*%s)(ret_val, arg1, arg2, arg3);\n",
                       cs_reg_var(arm64->operands[0].reg));
        }
        else if (strcmp(mne, "br") == 0) {
            if (arm64 && arm64->op_count >= 1)
                append(output, output_size, &pos,
                       "    goto *%s;  // indirect jump\n", cs_reg_var(arm64->operands[0].reg));
        }
        // --- Load/Store ---
        else if (strcmp(mne, "ldr") == 0 || strcmp(mne, "ldrsw") == 0 ||
                 strcmp(mne, "ldrb") == 0 || strcmp(mne, "ldrh") == 0 ||
                 strcmp(mne, "ldrsb") == 0 || strcmp(mne, "ldrsh") == 0) {
            if (arm64 && arm64->op_count >= 2) {
                const char *dst = cs_reg_var(arm64->operands[0].reg);
                if (arm64->operands[1].type == ARM64_OP_MEM) {
                    arm64_op_mem *mem = &arm64->operands[1].mem;
                    const char *base = cs_reg_var(mem->base);
                    if (mem->disp != 0)
                        append(output, output_size, &pos, "    %s = *(%s + 0x%x);  // %s\n", dst, base, mem->disp, mne);
                    else
                        append(output, output_size, &pos, "    %s = *(%s);  // %s\n", dst, base, mne);
                } else {
                    append(output, output_size, &pos, "    %s = /* %s */ %s;\n", dst, mne, ops);
                }
            }
        }
        else if (strcmp(mne, "str") == 0 || strcmp(mne, "strb") == 0 || strcmp(mne, "strh") == 0) {
            if (arm64 && arm64->op_count >= 2) {
                const char *src = cs_reg_var(arm64->operands[0].reg);
                if (arm64->operands[1].type == ARM64_OP_MEM) {
                    arm64_op_mem *mem = &arm64->operands[1].mem;
                    const char *base = cs_reg_var(mem->base);
                    if (mem->disp != 0)
                        append(output, output_size, &pos, "    *(%s + 0x%x) = %s;  // %s\n", base, mem->disp, src, mne);
                    else
                        append(output, output_size, &pos, "    *(%s) = %s;  // %s\n", base, src, mne);
                }
            }
        }
        else if (strcmp(mne, "stp") == 0) {
            append(output, output_size, &pos, "    // store pair: %s\n", ops);
        }
        else if (strcmp(mne, "ldp") == 0) {
            append(output, output_size, &pos, "    // load pair: %s\n", ops);
        }
        // --- Address gen ---
        else if (strcmp(mne, "adrp") == 0) {
            if (arm64 && arm64->op_count >= 2 && arm64->operands[1].type == ARM64_OP_IMM)
                append(output, output_size, &pos, "    %s = 0x%llx;  // page addr\n",
                       cs_reg_var(arm64->operands[0].reg), (unsigned long long)arm64->operands[1].imm);
            else
                append(output, output_size, &pos, "    /* adrp */ %s;\n", ops);
        }
        else if (strcmp(mne, "adr") == 0) {
            if (arm64 && arm64->op_count >= 2 && arm64->operands[1].type == ARM64_OP_IMM)
                append(output, output_size, &pos, "    %s = 0x%llx;  // addr\n",
                       cs_reg_var(arm64->operands[0].reg), (unsigned long long)arm64->operands[1].imm);
        }
        // --- CSEL ---
        else if (strcmp(mne, "csel") == 0 || strcmp(mne, "csinc") == 0 ||
                 strcmp(mne, "csinv") == 0 || strcmp(mne, "csneg") == 0) {
            if (arm64 && arm64->op_count >= 3) {
                arm64_cc cc = arm64->cc;
                append(output, output_size, &pos, "    %s = (%s) ? %s : %s;  // %s\n",
                       cs_reg_var(arm64->operands[0].reg),
                       cc_to_c(cc),
                       cs_reg_var(arm64->operands[1].reg),
                       cs_reg_var(arm64->operands[2].reg), mne);
            }
        }
        // --- Return ---
        else if (strcmp(mne, "ret") == 0) {
            append(output, output_size, &pos, "    return ret_val;\n");
        }
        // --- NOP ---
        else if (strcmp(mne, "nop") == 0) {
            // skip
        }
        // --- SVC/BRK ---
        else if (strcmp(mne, "svc") == 0) {
            append(output, output_size, &pos, "    syscall(%s);  // x8=num\n", ops);
        }
        else if (strcmp(mne, "brk") == 0) {
            append(output, output_size, &pos, "    __breakpoint(%s);\n", ops);
        }
        // --- Extension ---
        else if (strcmp(mne, "sxtw") == 0 || strcmp(mne, "sxtb") == 0 ||
                 strcmp(mne, "sxth") == 0 || strcmp(mne, "uxtb") == 0 || strcmp(mne, "uxth") == 0) {
            if (arm64 && arm64->op_count >= 2)
                append(output, output_size, &pos, "    %s = (%s)%s;\n",
                       cs_reg_var(arm64->operands[0].reg), mne, cs_reg_var(arm64->operands[1].reg));
        }
        else if (strcmp(mne, "mvn") == 0) {
            if (arm64 && arm64->op_count >= 2)
                append(output, output_size, &pos, "    %s = ~%s;\n",
                       cs_reg_var(arm64->operands[0].reg), cs_reg_var(arm64->operands[1].reg));
        }
        else if (strcmp(mne, "neg") == 0) {
            if (arm64 && arm64->op_count >= 2)
                append(output, output_size, &pos, "    %s = -%s;\n",
                       cs_reg_var(arm64->operands[0].reg), cs_reg_var(arm64->operands[1].reg));
        }
        // --- Fallback ---
        else {
            append(output, output_size, &pos, "    /* %s %s */\n", mne, ops);
        }
    }

    append(output, output_size, &pos, "}\n");

    cs_free(insns, count);
    cs_close(&handle);
    return pos;
}

int decompile_function(const uint8_t *code, size_t code_size, uint64_t base_addr,
                       char *output, size_t output_size) {
    return decompile_function_ex(code, code_size, base_addr, NULL, NULL, output, output_size);
}
