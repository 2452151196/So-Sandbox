#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <android/log.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <capstone/capstone.h>
#include "decompiler.h"

// Keystone 架构/模式常量 (与 keystone.h 兼容)
#define KS_ARCH_ARM64 1
#define KS_MODE_ARM 1
#define KS_MODE_LITTLE_ENDIAN 0

#define TAG "NativeInvoker"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 平台检测：动态执行仅在 ARM64 真机支持
#if defined(__aarch64__) || defined(__arm64__)
    #define PLATFORM_SUPPORTS_EXECUTION 1
    #define PLATFORM_NAME "ARM64"
#else
    #define PLATFORM_SUPPORTS_EXECUTION 0
    #define PLATFORM_NAME "X86/Other"
#endif

// 全局JNI上下文 (用于注入给被调用的JNI函数)
static JavaVM *g_jvm = NULL;
static JNIEnv *g_invoke_env = NULL;

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

// ============================================================================
// 从 crash_protection.c 引入
// ============================================================================
extern void crash_protection_enter();
extern void crash_protection_leave();
extern int crash_protection_was_crash();
extern int crash_protection_get_signal();
extern sigjmp_buf* crash_protection_get_jmpbuf();
extern const char* signal_name(int sig);

// 前向声明
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_disassembleFunctionEx(
        JNIEnv *env, jclass clazz, jlong funcAddr, jlong funcSize, jstring jStringTable, jstring jPltTable, jlong baseAddress, jstring jFuncTable);

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_disassembleTextSection(
        JNIEnv *env, jclass clazz, jlong baseAddr, jlong textSize, jlong highlightFuncAddr, jlong highlightFuncSize, jstring jStringTable, jstring jPltTable);

// ============================================================================
// libffi 动态加载
// ============================================================================

// ffi类型定义 (与libffi兼容)
typedef struct _ffi_type {
    size_t size;
    unsigned short alignment;
    unsigned short type;
    struct _ffi_type **elements;
} ffi_type;

typedef enum {
    FFI_OK = 0,
    FFI_BAD_TYPEDEF,
    FFI_BAD_ABI
} ffi_status;

typedef struct {
    unsigned char abi;
    unsigned nargs;
    ffi_type **arg_types;
    ffi_type *rtype;
    unsigned bytes;
    unsigned flags;
} ffi_cif;

// libffi函数指针
typedef ffi_status (*ffi_prep_cif_fn)(ffi_cif *cif, int abi, unsigned int nargs,
                                       ffi_type *rtype, ffi_type **atypes);
typedef void (*ffi_call_fn)(ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalue);

static ffi_prep_cif_fn g_ffi_prep_cif = NULL;
static ffi_call_fn g_ffi_call = NULL;
static void *g_ffi_handle = NULL;

// libffi类型指针
static ffi_type *g_ffi_type_void = NULL;
static ffi_type *g_ffi_type_sint32 = NULL;
static ffi_type *g_ffi_type_sint64 = NULL;
static ffi_type *g_ffi_type_float = NULL;
static ffi_type *g_ffi_type_double = NULL;
static ffi_type *g_ffi_type_pointer = NULL;

static int g_ffi_available = 0;

static void try_load_libffi() {
    // 尝试多个路径
    const char *paths[] = {
        "libffi.so",
        "libffi.so.8",
        "libffi.so.7",
        "/system/lib64/libffi.so",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        g_ffi_handle = dlopen(paths[i], RTLD_NOW);
        if (g_ffi_handle) {
            LOGI("Loaded libffi from: %s", paths[i]);
            break;
        }
    }

    if (!g_ffi_handle) {
        LOGI("libffi not available, using fallback invoker");
        return;
    }

    g_ffi_prep_cif = (ffi_prep_cif_fn) dlsym(g_ffi_handle, "ffi_prep_cif");
    g_ffi_call = (ffi_call_fn) dlsym(g_ffi_handle, "ffi_call");

    g_ffi_type_void = (ffi_type*) dlsym(g_ffi_handle, "ffi_type_void");
    g_ffi_type_sint32 = (ffi_type*) dlsym(g_ffi_handle, "ffi_type_sint32");
    g_ffi_type_sint64 = (ffi_type*) dlsym(g_ffi_handle, "ffi_type_sint64");
    g_ffi_type_float = (ffi_type*) dlsym(g_ffi_handle, "ffi_type_float");
    g_ffi_type_double = (ffi_type*) dlsym(g_ffi_handle, "ffi_type_double");
    g_ffi_type_pointer = (ffi_type*) dlsym(g_ffi_handle, "ffi_type_pointer");

    if (g_ffi_prep_cif && g_ffi_call && g_ffi_type_void) {
        g_ffi_available = 1;
        LOGI("libffi fully initialized");
    } else {
        LOGI("libffi partially loaded, missing symbols");
        g_ffi_available = 0;
    }
}

// ============================================================================
// 类型映射
// ============================================================================

typedef enum {
    TYPE_VOID = 0,
    TYPE_INT,
    TYPE_LONG,
    TYPE_FLOAT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_JNIENV,   // 自动注入当前JNIEnv*
    TYPE_JOBJECT,  // 自动注入一个dummy jclass (NULL)
    TYPE_JAVAVM    // 自动注入全局JavaVM*
} ParamType;

static ParamType parse_type(const char *typeStr) {
    if (!typeStr) return TYPE_VOID;
    if (strcmp(typeStr, "int") == 0) return TYPE_INT;
    if (strcmp(typeStr, "long") == 0) return TYPE_LONG;
    if (strcmp(typeStr, "float") == 0) return TYPE_FLOAT;
    if (strcmp(typeStr, "double") == 0) return TYPE_DOUBLE;
    if (strcmp(typeStr, "string") == 0) return TYPE_STRING;
    if (strcmp(typeStr, "jnienv") == 0) return TYPE_JNIENV;
    if (strcmp(typeStr, "jobject") == 0) return TYPE_JOBJECT;
    if (strcmp(typeStr, "javavm") == 0) return TYPE_JAVAVM;
    return TYPE_VOID;
}

static ffi_type* get_ffi_type(ParamType type) {
    switch (type) {
        case TYPE_INT:    return g_ffi_type_sint32;
        case TYPE_LONG:   return g_ffi_type_sint64;
        case TYPE_FLOAT:  return g_ffi_type_float;
        case TYPE_DOUBLE: return g_ffi_type_double;
        case TYPE_STRING: return g_ffi_type_pointer;
        case TYPE_JNIENV: return g_ffi_type_pointer;
        case TYPE_JOBJECT: return g_ffi_type_pointer;
        case TYPE_JAVAVM: return g_ffi_type_pointer;
        default:          return g_ffi_type_void;
    }
}

// ============================================================================
// Fallback invoker (arm64直接调用)
// arm64 ABI: x0-x7 整型/指针参数, d0-d7 浮点参数, 返回x0或d0
// ============================================================================

typedef long (*func_0)(void);
typedef long (*func_1)(long);
typedef long (*func_2)(long, long);
typedef long (*func_3)(long, long, long);
typedef long (*func_4)(long, long, long, long);
typedef long (*func_5)(long, long, long, long, long);
typedef long (*func_6)(long, long, long, long, long, long);

typedef double (*func_d_0)(void);
typedef double (*func_d_1)(long);
typedef double (*func_d_2)(long, long);

// 将参数值转为64位整型(可存储int/long/pointer)
static long parse_value_as_long(const char *value, ParamType type) {
    if (!value) return 0;
    switch (type) {
        case TYPE_INT:    return (long) atoi(value);
        case TYPE_LONG:   return strtol(value, NULL, 0);
        case TYPE_FLOAT: {
            float f = strtof(value, NULL);
            long result;
            memcpy(&result, &f, sizeof(float));
            return result;
        }
        case TYPE_DOUBLE: {
            double d = strtod(value, NULL);
            long result;
            memcpy(&result, &d, sizeof(double));
            return result;
        }
        case TYPE_STRING:
            return (long) value; // 直接传指针
        case TYPE_JNIENV:
            return (long) g_invoke_env;  // 注入当前JNIEnv*
        case TYPE_JOBJECT:
            return 0;  // NULL
        default:
            return 0;
    }
}

static void fallback_invoke(void *func_ptr, ParamType retType, int nargs,
                            long *args, char *result, size_t result_size) {
    long ret_long = 0;
    double ret_double = 0.0;

    if (retType == TYPE_FLOAT || retType == TYPE_DOUBLE) {
        // 浮点返回
        switch (nargs) {
            case 0: ret_double = ((func_d_0)func_ptr)(); break;
            case 1: ret_double = ((func_d_1)func_ptr)(args[0]); break;
            case 2: ret_double = ((func_d_2)func_ptr)(args[0], args[1]); break;
            default:
                snprintf(result, result_size, "ERR:Fallback模式最多支持2个浮点返回参数");
                return;
        }
    } else {
        // 整型/指针返回
        switch (nargs) {
            case 0: ret_long = ((func_0)func_ptr)(); break;
            case 1: ret_long = ((func_1)func_ptr)(args[0]); break;
            case 2: ret_long = ((func_2)func_ptr)(args[0], args[1]); break;
            case 3: ret_long = ((func_3)func_ptr)(args[0], args[1], args[2]); break;
            case 4: ret_long = ((func_4)func_ptr)(args[0], args[1], args[2], args[3]); break;
            case 5: ret_long = ((func_5)func_ptr)(args[0], args[1], args[2], args[3], args[4]); break;
            case 6: ret_long = ((func_6)func_ptr)(args[0], args[1], args[2], args[3], args[4], args[5]); break;
            default:
                snprintf(result, result_size, "ERR:Fallback模式最多支持6个参数");
                return;
        }
    }

    // 格式化结果
    switch (retType) {
        case TYPE_VOID:
            snprintf(result, result_size, "OK:void (函数已执行)");
            break;
        case TYPE_INT:
            snprintf(result, result_size, "OK:%d (0x%x)", (int)ret_long, (unsigned int)ret_long);
            break;
        case TYPE_LONG:
            snprintf(result, result_size, "OK:%ld (0x%lx)", ret_long, (unsigned long)ret_long);
            break;
        case TYPE_FLOAT: {
            float f = (float)ret_double;
            snprintf(result, result_size, "OK:%f", f);
            break;
        }
        case TYPE_DOUBLE:
            snprintf(result, result_size, "OK:%f", ret_double);
            break;
        case TYPE_STRING: {
            if (ret_long == 0) {
                snprintf(result, result_size, "OK:(null)");
            } else {
                snprintf(result, result_size, "OK:%s", (const char*)ret_long);
            }
            break;
        }
        default:
            snprintf(result, result_size, "OK:0x%lx", (unsigned long)ret_long);
            break;
    }
}

// ============================================================================
// libffi 调用
// ============================================================================

static void ffi_invoke(void *func_ptr, ParamType retType, int nargs,
                       ParamType *argTypes, const char **argValues,
                       char *result, size_t result_size) {
    if (!g_ffi_available) {
        // 转为fallback
        long args[8] = {0};
        for (int i = 0; i < nargs && i < 8; i++) {
            args[i] = parse_value_as_long(argValues[i], argTypes[i]);
        }
        fallback_invoke(func_ptr, retType, nargs, args, result, result_size);
        return;
    }

    // 准备ffi类型
    ffi_type *ret_ffi_type = get_ffi_type(retType);
    ffi_type **arg_ffi_types = NULL;
    void **arg_values = NULL;

    // 参数存储
    int *int_args = NULL;
    long *long_args = NULL;
    float *float_args = NULL;
    double *double_args = NULL;
    const char **str_args = NULL;
    void **ptr_args = NULL;

    if (nargs > 0) {
        arg_ffi_types = (ffi_type**) calloc(nargs, sizeof(ffi_type*));
        arg_values = (void**) calloc(nargs, sizeof(void*));
        int_args = (int*) calloc(nargs, sizeof(int));
        long_args = (long*) calloc(nargs, sizeof(long));
        float_args = (float*) calloc(nargs, sizeof(float));
        double_args = (double*) calloc(nargs, sizeof(double));
        str_args = (const char**) calloc(nargs, sizeof(const char*));
        ptr_args = (void**) calloc(nargs, sizeof(void*));

        for (int i = 0; i < nargs; i++) {
            arg_ffi_types[i] = get_ffi_type(argTypes[i]);
            switch (argTypes[i]) {
                case TYPE_INT:
                    int_args[i] = atoi(argValues[i]);
                    arg_values[i] = &int_args[i];
                    break;
                case TYPE_LONG:
                    long_args[i] = strtol(argValues[i], NULL, 0);
                    arg_values[i] = &long_args[i];
                    break;
                case TYPE_FLOAT:
                    float_args[i] = strtof(argValues[i], NULL);
                    arg_values[i] = &float_args[i];
                    break;
                case TYPE_DOUBLE:
                    double_args[i] = strtod(argValues[i], NULL);
                    arg_values[i] = &double_args[i];
                    break;
                case TYPE_STRING:
                    str_args[i] = argValues[i];
                    arg_values[i] = &str_args[i];
                    break;
                case TYPE_JNIENV:
                    ptr_args[i] = (void*)g_invoke_env;
                    arg_values[i] = &ptr_args[i];
                    break;
                case TYPE_JOBJECT:
                    ptr_args[i] = NULL;
                    arg_values[i] = &ptr_args[i];
                    break;
                case TYPE_JAVAVM:
                    ptr_args[i] = (void*)g_jvm;
                    arg_values[i] = &ptr_args[i];
                    break;
                default:
                    arg_values[i] = NULL;
                    break;
            }
        }
    }

    // 准备cif
    ffi_cif cif;
    // FFI_DEFAULT_ABI = 0 on arm64
    ffi_status status = g_ffi_prep_cif(&cif, 0, nargs, ret_ffi_type, arg_ffi_types);
    if (status != FFI_OK) {
        snprintf(result, result_size, "ERR:ffi_prep_cif失败 (status=%d)", status);
        goto cleanup;
    }

    // 执行调用
    {
        union {
            int i;
            long l;
            float f;
            double d;
            void *p;
            char buf[8];
        } ret_val;
        memset(&ret_val, 0, sizeof(ret_val));

        g_ffi_call(&cif, (void(*)(void))func_ptr, &ret_val, arg_values);

        // 格式化结果
        switch (retType) {
            case TYPE_VOID:
                snprintf(result, result_size, "OK:void (函数已执行)");
                break;
            case TYPE_INT:
                snprintf(result, result_size, "OK:%d (0x%x)", ret_val.i, (unsigned int)ret_val.i);
                break;
            case TYPE_LONG:
                snprintf(result, result_size, "OK:%ld (0x%lx)", ret_val.l, (unsigned long)ret_val.l);
                break;
            case TYPE_FLOAT:
                snprintf(result, result_size, "OK:%f", ret_val.f);
                break;
            case TYPE_DOUBLE:
                snprintf(result, result_size, "OK:%f", ret_val.d);
                break;
            case TYPE_STRING:
                if (ret_val.p == NULL) {
                    snprintf(result, result_size, "OK:(null)");
                } else {
                    snprintf(result, result_size, "OK:%s", (const char*)ret_val.p);
                }
                break;
            default:
                snprintf(result, result_size, "OK:0x%lx", (unsigned long)ret_val.l);
                break;
        }
    }

cleanup:
    free(arg_ffi_types);
    free(arg_values);
    free(int_args);
    free(long_args);
    free(float_args);
    free(double_args);
    free(str_args);
    free(ptr_args);
}

// ============================================================================
// JNI入口: invokeFunction
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_invokeFunction(
        JNIEnv *env, jclass clazz,
        jlong funcAddr, jstring jRetType,
        jobjectArray jParamTypes, jobjectArray jParamValues) {

#if !PLATFORM_SUPPORTS_EXECUTION
    return (*env)->NewStringUTF(env, "ERR: 动态函数执行仅在 ARM64 真机支持，当前平台 (" PLATFORM_NAME ") 仅支持静态分析");
#endif

    static int ffi_loaded = 0;
    if (!ffi_loaded) {
        try_load_libffi();
        ffi_loaded = 1;
    }

    char result[2048];
    result[0] = '\0';

    // 解析返回类型
    const char *retTypeStr = (*env)->GetStringUTFChars(env, jRetType, NULL);
    ParamType retType = parse_type(retTypeStr);
    (*env)->ReleaseStringUTFChars(env, jRetType, retTypeStr);

    // 解析参数
    int nargs = 0;
    ParamType *argTypes = NULL;
    const char **argValues = NULL;
    jstring *jArgTypeStrs = NULL;
    jstring *jArgValueStrs = NULL;

    if (jParamTypes && jParamValues) {
        nargs = (*env)->GetArrayLength(env, jParamTypes);
        argTypes = (ParamType*) calloc(nargs, sizeof(ParamType));
        argValues = (const char**) calloc(nargs, sizeof(const char*));
        jArgTypeStrs = (jstring*) calloc(nargs, sizeof(jstring));
        jArgValueStrs = (jstring*) calloc(nargs, sizeof(jstring));

        for (int i = 0; i < nargs; i++) {
            jArgTypeStrs[i] = (jstring)(*env)->GetObjectArrayElement(env, jParamTypes, i);
            jArgValueStrs[i] = (jstring)(*env)->GetObjectArrayElement(env, jParamValues, i);

            const char *typeStr = (*env)->GetStringUTFChars(env, jArgTypeStrs[i], NULL);
            argTypes[i] = parse_type(typeStr);
            (*env)->ReleaseStringUTFChars(env, jArgTypeStrs[i], typeStr);

            argValues[i] = (*env)->GetStringUTFChars(env, jArgValueStrs[i], NULL);
        }
    }

    void *func_ptr = (void*)(uintptr_t)funcAddr;
    LOGI("Invoking function at %p, retType=%d, nargs=%d", func_ptr, retType, nargs);

    // 保存当前JNIEnv以便注入给被调用的JNI函数
    g_invoke_env = env;

    // 崩溃保护
    crash_protection_enter();
    int sig = sigsetjmp(*crash_protection_get_jmpbuf(), 1);
    if (sig != 0) {
        // 从崩溃中恢复
        crash_protection_leave();
        snprintf(result, sizeof(result), "ERR:函数崩溃: %s (signal %d)", signal_name(sig), sig);
        LOGE("Function crashed with signal %d (%s)", sig, signal_name(sig));
    } else {
        // 正常执行
        ffi_invoke(func_ptr, retType, nargs, argTypes, argValues, result, sizeof(result));
        crash_protection_leave();
    }

    // 释放参数
    if (jArgValueStrs) {
        for (int i = 0; i < nargs; i++) {
            if (argValues[i]) {
                (*env)->ReleaseStringUTFChars(env, jArgValueStrs[i], argValues[i]);
            }
        }
    }
    free(argTypes);
    free(argValues);
    free(jArgTypeStrs);
    free(jArgValueStrs);

    return (*env)->NewStringUTF(env, result);
}

// ============================================================================
// 交叉引用分析 (XRef)
// ============================================================================

#define MAX_XREFS 1024

typedef struct {
    uint64_t caller;  // 调用者地址
    uint64_t callee;  // 被调用者地址
    int is_call;      // 1=BL直接调用, 0=B跳转
} XRefEntry;

static XRefEntry g_xrefs[MAX_XREFS];
static int g_xref_count = 0;

// 分析单个函数的调用关系
// 返回格式: "caller|callee|type|caller|callee|type|..." (type: call/jump)
static char* analyze_function_xrefs(const uint8_t *code, size_t code_size, uint64_t base_addr,
                                    uint64_t *known_funcs, int known_count,
                                    char *out_buf, size_t out_size) {
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return NULL;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insns = NULL;
    size_t count = cs_disasm(handle, code, code_size, base_addr, 0, &insns);
    if (count <= 0) {
        cs_close(&handle);
        return NULL;
    }

    int pos = 0;
    int found = 0;

    for (size_t i = 0; i < count; i++) {
        cs_insn *ins = &insns[i];
        cs_detail *d = ins->detail;
        cs_arm64 *arm64 = d ? &d->arm64 : NULL;

        if (!arm64) continue;

        uint64_t target = 0;
        int is_call = 0;

        // BL: 直接调用 (相对跳转)
        if (strcmp(ins->mnemonic, "bl") == 0) {
            for (int j = 0; j < arm64->op_count; j++) {
                cs_arm64_op *op = &arm64->operands[j];
                if (op->type == ARM64_OP_IMM) {
                    target = op->imm;
                    is_call = 1;
                    break;
                }
            }
        }
        // BLR: 寄存器调用 (间接，无法静态确定目标)
        else if (strcmp(ins->mnemonic, "blr") == 0) {
            // 无法静态分析，跳过
        }
        // B: 无条件跳转 (可能是尾调用)
        else if (strcmp(ins->mnemonic, "b") == 0) {
            for (int j = 0; j < arm64->op_count; j++) {
                cs_arm64_op *op = &arm64->operands[j];
                if (op->type == ARM64_OP_IMM) {
                    target = op->imm;
                    is_call = 0; // 跳转，不是调用
                    break;
                }
            }
        }

        if (target == 0) continue;

        // 检查目标是否是已知函数
        for (int k = 0; k < known_count; k++) {
            // 允许小范围误差 (THUMB/ARM 切换等)
            if (llabs((int64_t)(target - known_funcs[k])) < 4) {
                if (found > 0) pos += snprintf(out_buf + pos, out_size - pos, "|");
                pos += snprintf(out_buf + pos, out_size - pos, "%llX|%llX|%s",
                                (unsigned long long)ins->address,
                                (unsigned long long)known_funcs[k],
                                is_call ? "call" : "jump");
                found++;

                // 存储到全局表
                if (g_xref_count < MAX_XREFS) {
                    g_xrefs[g_xref_count].caller = ins->address;
                    g_xrefs[g_xref_count].callee = known_funcs[k];
                    g_xrefs[g_xref_count].is_call = is_call;
                    g_xref_count++;
                }
                break;
            }
        }
    }

    cs_free(insns, count);
    cs_close(&handle);

    if (found == 0) {
        snprintf(out_buf, out_size, "none");
    }
    return out_buf;
}

// ============================================================================
// 字符串表支持: 存储地址->字符串映射
// ============================================================================

#define MAX_STRINGS 8192
typedef struct {
    uint64_t addr;
    char str[256];
} StringEntry;

static StringEntry g_string_table[MAX_STRINGS];
static int g_string_count = 0;

// ============================================================================
// PLT表支持: 存储地址->函数名映射
// ============================================================================

#define MAX_PLT 1024
typedef struct {
    uint64_t addr;      // PLT条目偏移地址
    char name[128];     // 函数名
} PltEntry;

static PltEntry g_plt_table[MAX_PLT];
static int g_plt_count = 0;

// 解析PLT表格式: "addr|name|addr|name|..."
static void parse_plt_table(const char *table_str) {
    g_plt_count = 0;
    if (!table_str || !table_str[0]) return;

    char buf[65536];
    strncpy(buf, table_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(buf, "|", &saveptr);

    while (tok && g_plt_count < MAX_PLT) {
        uint64_t addr = strtoull(tok, NULL, 16);
        tok = strtok_r(NULL, "|", &saveptr);
        if (!tok) break;

        g_plt_table[g_plt_count].addr = addr;
        strncpy(g_plt_table[g_plt_count].name, tok, 127);
        g_plt_table[g_plt_count].name[127] = '\0';
        g_plt_count++;
        tok = strtok_r(NULL, "|", &saveptr);
    }
}

// 查找PLT地址对应的函数名
static const char* find_plt_at(uint64_t addr) {
    for (int i = 0; i < g_plt_count; i++) {
        if (g_plt_table[i].addr == addr) {
            return g_plt_table[i].name;
        }
    }
    return NULL;
}

// 解析字符串表格式: "addr|str|addr|str|..."
static void parse_string_table(const char *table_str) {
    g_string_count = 0;
    if (!table_str || !table_str[0]) return;

    size_t len = strlen(table_str);
    char *buf = (char *)malloc(len + 1);
    if (!buf) return;
    memcpy(buf, table_str, len + 1);

    char *saveptr = NULL;
    char *tok = strtok_r(buf, "|", &saveptr);

    while (tok && g_string_count < MAX_STRINGS) {
        uint64_t addr = strtoull(tok, NULL, 16);
        tok = strtok_r(NULL, "|", &saveptr);
        if (!tok) break;

        g_string_table[g_string_count].addr = addr;
        strncpy(g_string_table[g_string_count].str, tok, 255);
        g_string_table[g_string_count].str[255] = '\0';
        g_string_count++;
        tok = strtok_r(NULL, "|", &saveptr);
    }
    free(buf);
}

// 查找地址对应的字符串 (精确匹配)
static const char* find_string_at(uint64_t addr) {
    for (int i = 0; i < g_string_count; i++) {
        if (g_string_table[i].addr == addr) {
            return g_string_table[i].str;
        }
    }
    return NULL;
}

// ============================================================================
// 函数表支持: 存储地址->函数名映射 (用于跳转目标解析)
// ============================================================================

#define MAX_FUNCS 16384
typedef struct {
    uint64_t addr;
    char name[128];
} FuncEntry;

static FuncEntry g_func_table[MAX_FUNCS];
static int g_func_count = 0;

static void parse_func_table(const char *table_str) {
    g_func_count = 0;
    if (!table_str || !table_str[0]) return;

    // 动态分配解析缓冲区
    size_t len = strlen(table_str);
    char *buf = (char *)malloc(len + 1);
    if (!buf) return;
    memcpy(buf, table_str, len + 1);

    char *saveptr = NULL;
    char *tok = strtok_r(buf, "|", &saveptr);

    while (tok && g_func_count < MAX_FUNCS) {
        uint64_t addr = strtoull(tok, NULL, 16);
        tok = strtok_r(NULL, "|", &saveptr);
        if (!tok) break;

        g_func_table[g_func_count].addr = addr;
        strncpy(g_func_table[g_func_count].name, tok, 127);
        g_func_table[g_func_count].name[127] = '\0';
        g_func_count++;
        tok = strtok_r(NULL, "|", &saveptr);
    }
    free(buf);
}

static const char* find_func_at(uint64_t addr) {
    for (int i = 0; i < g_func_count; i++) {
        if (g_func_table[i].addr == addr) {
            return g_func_table[i].name;
        }
    }
    return NULL;
}

// 计算指令引用的目标地址 (简化版ADRP/ADR/LDR分析)
// Capstone的imm操作数已经是计算好的绝对目标地址，直接返回即可
// 返回UINT64_MAX表示失败, 因为0是合法的ADRP目标地址(同一页)
static uint64_t calc_ref_target(cs_insn *ins, cs_arm64 *arm64) {
    if (strcmp(ins->mnemonic, "adrp") == 0 || strcmp(ins->mnemonic, "adr") == 0) {
        if (arm64->op_count >= 2) {
            cs_arm64_op *src = &arm64->operands[1];
            if (src->type == ARM64_OP_IMM) {
                return (uint64_t)src->imm;
            }
        }
    }
    return UINT64_MAX;
}

// ============================================================================
// JNI入口: disassembleFunction - 使用Capstone反汇编 (显示偏移地址)
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_disassembleFunction(
        JNIEnv *env, jclass clazz, jlong funcAddr, jlong funcSize) {
    return Java_com_example_anative_core_NativeInvoker_disassembleFunctionEx(
            env, clazz, funcAddr, funcSize, NULL, NULL, 0, NULL);
}

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_disassembleFunctionEx(
        JNIEnv *env, jclass clazz, jlong funcAddr, jlong funcSize, jstring jStringTable, jstring jPltTable, jlong baseAddress, jstring jFuncTable) {

    const uint8_t *code = (const uint8_t *)(uintptr_t)funcAddr;
    size_t size = (size_t)funcSize;
    uint64_t base = (uint64_t)baseAddress;

    if (size == 0) size = 256;
    if (size > 65536) size = 65536;

    // 解析字符串表
    const char *str_table = jStringTable ? (*env)->GetStringUTFChars(env, jStringTable, NULL) : NULL;
    parse_string_table(str_table);
    if (str_table) (*env)->ReleaseStringUTFChars(env, jStringTable, str_table);

    // 解析PLT表
    const char *plt_table = jPltTable ? (*env)->GetStringUTFChars(env, jPltTable, NULL) : NULL;
    parse_plt_table(plt_table);
    if (plt_table) (*env)->ReleaseStringUTFChars(env, jPltTable, plt_table);

    // 解析函数表
    const char *func_table = jFuncTable ? (*env)->GetStringUTFChars(env, jFuncTable, NULL) : NULL;
    parse_func_table(func_table);
    if (func_table) (*env)->ReleaseStringUTFChars(env, jFuncTable, func_table);

    // 崩溃保护
    uint8_t *code_copy = (uint8_t *)malloc(size);
    if (!code_copy) return (*env)->NewStringUTF(env, "ERR: out of memory");

    crash_protection_enter();
    int sig = sigsetjmp(*crash_protection_get_jmpbuf(), 1);
    if (sig != 0) {
        crash_protection_leave();
        free(code_copy);
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "ERR: 读取内存崩溃: %s (signal %d), 地址=0x%llX", signal_name(sig), sig, (unsigned long long)funcAddr);
        LOGE("Disassemble memory crash: %s at addr 0x%llX", signal_name(sig), (unsigned long long)funcAddr);
        return (*env)->NewStringUTF(env, errbuf);
    }
    memcpy(code_copy, code, size);
    crash_protection_leave();

    // Capstone反汇编 (使用绝对地址获取正确指令，但显示偏移)
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        free(code_copy);
        return (*env)->NewStringUTF(env, "ERR: Capstone初始化失败");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn *insns = NULL;
    size_t count = cs_disasm(handle, code_copy, size, (uint64_t)funcAddr, 0, &insns);

    if (count <= 0) {
        // 反汇编完全失败，直接显示原始字节
        size_t raw_buf_size = size * 32 + 4096;
        char *raw_buffer = (char *)calloc(1, raw_buf_size);
        if (!raw_buffer) {
            free(code_copy);
            cs_close(&handle);
            return (*env)->NewStringUTF(env, "ERR: out of memory");
        }
        int rpos = 0;
        uint64_t funcOffset_raw = (uint64_t)funcAddr - base;
        rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                        "; ARM64 Disassembly - 解析失败，显示原始字节\n"
                        "; Function Offset: 0x%llx, Size: %zu bytes\n\n",
                        (unsigned long long)funcOffset_raw, size);
        for (size_t off = 0; off + 3 < size; off += 4) {
            uint32_t word = *(uint32_t *)(code_copy + off);
            rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                            "%08llx:  .inst   0x%08x  ; %02x %02x %02x %02x\n",
                            (unsigned long long)(funcOffset_raw + off), word,
                            code_copy[off], code_copy[off+1], code_copy[off+2], code_copy[off+3]);
        }
        // 处理末尾不足4字节的情况
        size_t tail = size % 4;
        if (tail > 0) {
            size_t tail_off = size - tail;
            rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                            "%08llx:  .byte  ",
                            (unsigned long long)(funcOffset_raw + tail_off));
            for (size_t t = 0; t < tail; t++) {
                rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                                "%s0x%02x", t > 0 ? ", " : "", code_copy[tail_off + t]);
            }
            rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos, "\n");
        }
        free(code_copy);
        cs_close(&handle);
        jstring result_str = (*env)->NewStringUTF(env, raw_buffer);
        free(raw_buffer);
        return result_str;
    }
    free(code_copy);

    // 格式化输出
    size_t buf_size = count * 256 + 4096;  // 增加缓冲区用于注释
    char *buffer = (char *)calloc(1, buf_size);
    if (!buffer) {
        cs_free(insns, count);
        cs_close(&handle);
        return (*env)->NewStringUTF(env, "ERR: out of memory");
    }

    int pos = 0;
    // 计算函数偏移
    uint64_t funcOffset = (uint64_t)funcAddr - base;
    uint64_t funcEndOffset = funcOffset + size;

    pos += snprintf(buffer + pos, buf_size - pos,
                    "; ARM64 Disassembly (Capstone)\n"
                    "; Function Offset: 0x%llx, Size: %zu bytes\n"
                    "; Base: 0x%llx, Instructions: %zu\n\n",
                    (unsigned long long)funcOffset, size,
                    (unsigned long long)base, count);

    // 跟踪寄存器中的ADRP结果 (UINT64_MAX=未设置, 因为ADRP #0是合法的)
    uint64_t reg_page[32];
    for (int r = 0; r < 32; r++) reg_page[r] = UINT64_MAX;

    for (size_t i = 0; i < count && pos < (int)buf_size - 512; i++) {
        cs_insn *ins = &insns[i];
        cs_detail *d = ins->detail;
        cs_arm64 *arm64 = d ? &d->arm64 : NULL;

        // 计算当前指令的偏移地址 (用于显示)
        uint64_t insOffset = ins->address - base;

        // 格式化操作数: 对于跳转指令，显示偏移地址而非绝对地址
        // 使用Capstone指令ID精确判断，避免误匹配bfi/bic/tbl等非分支指令
        char ops_formatted[256];
        int is_branch = (ins->id == ARM64_INS_B || ins->id == ARM64_INS_BL ||
                         ins->id == ARM64_INS_ADR || ins->id == ARM64_INS_ADRP ||
                         ins->id == ARM64_INS_CBZ || ins->id == ARM64_INS_CBNZ ||
                         ins->id == ARM64_INS_TBZ || ins->id == ARM64_INS_TBNZ);

        if (is_branch && arm64) {
            // 找到跳转目标IMM (最后一个IMM就是目标地址)
            uint64_t target = 0;
            int last_imm_idx = -1;
            for (int j = 0; j < arm64->op_count; j++) {
                if (arm64->operands[j].type == ARM64_OP_IMM) {
                    last_imm_idx = j;
                }
            }
            if (last_imm_idx >= 0) {
                target = arm64->operands[last_imm_idx].imm;
            }

            if (target) {
                uint64_t targetOffset = target - base;
                const char *func_name = find_func_at(targetOffset);
                int should_synthesize_bl = (ins->id == ARM64_INS_BL && !func_name &&
                         (targetOffset < funcOffset || targetOffset >= funcEndOffset));

                if (ins->id == ARM64_INS_TBZ || ins->id == ARM64_INS_TBNZ) {
                    char *op_copy = strdup(ins->op_str);
                    char *last_comma = strrchr(op_copy, ',');
                    if (last_comma) {
                        *last_comma = '\0';
                        if (func_name)
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s, %s", op_copy, func_name);
                        else
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s, #0x%llx", op_copy, (unsigned long long)targetOffset);
                    } else {
                        if (func_name)
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s", func_name);
                        else
                            snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx", (unsigned long long)targetOffset);
                    }
                    free(op_copy);
                } else if (ins->id == ARM64_INS_CBZ || ins->id == ARM64_INS_CBNZ) {
                    char *op_copy = strdup(ins->op_str);
                    char *comma = strchr(op_copy, ',');
                    if (comma) {
                        *comma = '\0';
                        if (func_name)
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s, %s", op_copy, func_name);
                        else
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s, #0x%llx", op_copy, (unsigned long long)targetOffset);
                    } else {
                        if (func_name)
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s", func_name);
                        else
                            snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx", (unsigned long long)targetOffset);
                    }
                    free(op_copy);
                } else {
                    if (func_name)
                        snprintf(ops_formatted, sizeof(ops_formatted), "%s", func_name);
                    else if (should_synthesize_bl)
                        snprintf(ops_formatted, sizeof(ops_formatted), "sub_%llx", (unsigned long long)targetOffset);
                    else
                        snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx", (unsigned long long)targetOffset);
                }
            } else {
                strncpy(ops_formatted, ins->op_str, sizeof(ops_formatted) - 1);
                ops_formatted[sizeof(ops_formatted) - 1] = '\0';
            }
        } else {
            strncpy(ops_formatted, ins->op_str, sizeof(ops_formatted) - 1);
            ops_formatted[sizeof(ops_formatted) - 1] = '\0';
        }

        // 后处理: 将超长无符号hex转为带符号短形式
        // 例: #0xfffffffffffffffc → #-0x4, #0xfffffffffffffffe → #-0x2
        {
            char *p = ops_formatted;
            while ((p = strstr(p, "#0xffffffffffff")) != NULL) {
                char *val_start = p + 1; // 跳过'#'
                char *endptr = NULL;
                uint64_t uval = strtoull(val_start, &endptr, 16);
                int64_t sval = (int64_t)uval;
                if (sval < 0 && sval > -0x10000) {
                    // 保存后缀
                    char suffix[128] = {0};
                    if (endptr) strncpy(suffix, endptr, sizeof(suffix) - 1);
                    int off = (int)(p - ops_formatted);
                    snprintf(p, sizeof(ops_formatted) - off, "#-0x%llx%s",
                            (unsigned long long)(-sval), suffix);
                }
                p++;
            }
        }

        char line[512];
        int line_len = snprintf(line, sizeof(line),
                        "%08llx:  %-8s %s",
                        (unsigned long long)insOffset,
                        ins->mnemonic,
                        ops_formatted);

        // 检测字符串引用和PLT调用
        const char *str_comment = NULL;
        const char *plt_comment = NULL;
        const char *synthetic_comment = NULL;

        // B/BL 指令: 查找PLT表
        if (arm64 && (strcmp(ins->mnemonic, "bl") == 0 || strcmp(ins->mnemonic, "b") == 0)) {
            uint64_t target = 0;
            for (int j = 0; j < arm64->op_count; j++) {
                cs_arm64_op *op = &arm64->operands[j];
                if (op->type == ARM64_OP_IMM) {
                    target = op->imm;
                    break;
                }
            }
            if (target) {
                uint64_t targetOffset = target - base;
                plt_comment = find_plt_at(targetOffset);
                if (!plt_comment && targetOffset != insOffset &&
                        (targetOffset < funcOffset || targetOffset >= funcEndOffset)) {
                    const char *known_func = find_func_at(targetOffset);
                    if (!known_func) synthetic_comment = "auto-discovered call target";
                }
            }
        }

        if (arm64) {
            // ADRP: 记录页地址到寄存器
            if (strcmp(ins->mnemonic, "adrp") == 0 && arm64->op_count >= 2) {
                uint64_t target = calc_ref_target(ins, arm64);
                if (target != UINT64_MAX) {
                    int reg = arm64->operands[0].reg - ARM64_REG_X0;
                    if (reg >= 0 && reg < 32) reg_page[reg] = target;
                }
            }
            // ADD: 检查是否是 adrp + add 模式 (字符串地址)
            else if (strcmp(ins->mnemonic, "add") == 0 && arm64->op_count >= 3) {
                cs_arm64_op *dst = &arm64->operands[0];
                cs_arm64_op *src1 = &arm64->operands[1];
                cs_arm64_op *src2 = &arm64->operands[2];
                int src1_reg = src1->reg - ARM64_REG_X0;
                if (src2->type == ARM64_OP_IMM && src1_reg >= 0 && src1_reg < 32
                        && reg_page[src1_reg] != UINT64_MAX) {
                    uint64_t target = reg_page[src1_reg] + (uint64_t)src2->imm;
                    str_comment = find_string_at(target - base);
                    int dst_reg = dst->reg - ARM64_REG_X0;
                    if (dst_reg >= 0 && dst_reg < 32) reg_page[dst_reg] = target;
                }
            }
            // ADR: 直接地址
            else if (strcmp(ins->mnemonic, "adr") == 0) {
                uint64_t target = calc_ref_target(ins, arm64);
                if (target != UINT64_MAX) str_comment = find_string_at(target - base);
            }
            // BL/BLR: 调用后清除易失寄存器 (x0-x18 可能被callee覆盖)
            else if (ins->id == ARM64_INS_BL || ins->id == ARM64_INS_BLR) {
                for (int r = 0; r <= 18; r++) reg_page[r] = UINT64_MAX;
            }
        }

        // 追加PLT或字符串注释
        if (plt_comment) {
            // PLT函数名注释
            int pad = 36 - line_len;
            if (pad < 2) pad = 2;
            pos += snprintf(buffer + pos, buf_size - pos, "%s%*s; %s@PLT\n",
                            line, pad, "", plt_comment);
        } else if (synthetic_comment) {
            int pad = 36 - line_len;
            if (pad < 2) pad = 2;
            pos += snprintf(buffer + pos, buf_size - pos, "%s%*s; %s\n",
                            line, pad, "", synthetic_comment);
        } else if (str_comment) {
            // 字符串注释
            char short_str[64];
            if (strlen(str_comment) > 50) {
                snprintf(short_str, sizeof(short_str), "%.50s...", str_comment);
            } else {
                snprintf(short_str, sizeof(short_str), "%s", str_comment);
            }
            int pad = 36 - line_len;
            if (pad < 2) pad = 2;
            pos += snprintf(buffer + pos, buf_size - pos, "%s%*s; \"%s\"\n",
                            line, pad, "", short_str);
        } else {
            pos += snprintf(buffer + pos, buf_size - pos, "%s\n", line);
        }
    }

    jstring result_str = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    cs_free(insns, count);
    cs_close(&handle);
    return result_str;
}

// ============================================================================
// JNI入口: disassembleBytes - 从byte[]反汇编 (静态分析模式)
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_disassembleBytes(
        JNIEnv *env, jclass clazz, jbyteArray jBytes, jlong funcOffset, jlong funcSize,
        jstring jStringTable, jstring jPltTable, jstring jFuncTable) {

    jsize dataLen = (*env)->GetArrayLength(env, jBytes);
    size_t size = (size_t)funcSize;
    if (size == 0 || size > (size_t)dataLen) size = (size_t)dataLen;
    if (size > 65536) size = 65536;

    uint8_t *code = (uint8_t *)malloc(size);
    if (!code) return (*env)->NewStringUTF(env, "ERR: out of memory");
    (*env)->GetByteArrayRegion(env, jBytes, 0, (jsize)size, (jbyte *)code);

    // 解析字符串表
    const char *str_table = jStringTable ? (*env)->GetStringUTFChars(env, jStringTable, NULL) : NULL;
    parse_string_table(str_table);
    if (str_table) (*env)->ReleaseStringUTFChars(env, jStringTable, str_table);

    // 解析PLT表
    const char *plt_table = jPltTable ? (*env)->GetStringUTFChars(env, jPltTable, NULL) : NULL;
    parse_plt_table(plt_table);
    if (plt_table) (*env)->ReleaseStringUTFChars(env, jPltTable, plt_table);

    // 解析函数表
    const char *func_table = jFuncTable ? (*env)->GetStringUTFChars(env, jFuncTable, NULL) : NULL;
    parse_func_table(func_table);
    if (func_table) (*env)->ReleaseStringUTFChars(env, jFuncTable, func_table);

    // Capstone反汇编 (使用偏移地址)
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        free(code);
        return (*env)->NewStringUTF(env, "ERR: Capstone初始化失败");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn *insns = NULL;
    // 使用偏移地址作为基址，这样Capstone计算的跳转目标也是偏移
    size_t count = cs_disasm(handle, code, size, (uint64_t)funcOffset, 0, &insns);

    if (count <= 0) {
        // 反汇编完全失败，直接显示原始字节
        size_t raw_buf_size = size * 32 + 4096;
        char *raw_buffer = (char *)calloc(1, raw_buf_size);
        if (!raw_buffer) {
            free(code);
            cs_close(&handle);
            return (*env)->NewStringUTF(env, "ERR: out of memory");
        }
        int rpos = 0;
        rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                        "; ARM64 Disassembly - 解析失败，显示原始字节\n"
                        "; Function Offset: 0x%llx, Size: %zu bytes\n\n",
                        (unsigned long long)funcOffset, size);
        for (size_t off = 0; off + 3 < size; off += 4) {
            uint32_t word = *(uint32_t *)(code + off);
            rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                            "%08llx:  .inst   0x%08x  ; %02x %02x %02x %02x\n",
                            (unsigned long long)(funcOffset + off), word,
                            code[off], code[off+1], code[off+2], code[off+3]);
        }
        size_t tail = size % 4;
        if (tail > 0) {
            size_t tail_off = size - tail;
            rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                            "%08llx:  .byte  ",
                            (unsigned long long)(funcOffset + tail_off));
            for (size_t t = 0; t < tail; t++) {
                rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                                "%s0x%02x", t > 0 ? ", " : "", code[tail_off + t]);
            }
            rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos, "\n");
        }
        free(code);
        cs_close(&handle);
        jstring result_str = (*env)->NewStringUTF(env, raw_buffer);
        free(raw_buffer);
        return result_str;
    }
    free(code);

    size_t buf_size = count * 256 + 4096;
    char *buffer = (char *)calloc(1, buf_size);
    if (!buffer) {
        cs_free(insns, count);
        cs_close(&handle);
        return (*env)->NewStringUTF(env, "ERR: out of memory");
    }

    int pos = 0;
    pos += snprintf(buffer + pos, buf_size - pos,
                    "; ARM64 Disassembly (Capstone) - 静态分析模式\n"
                    "; Function Offset: 0x%llx, Size: %zu bytes\n"
                    "; Instructions: %zu\n\n",
                    (unsigned long long)funcOffset, size, count);

    uint64_t reg_page[32];
    for (int r = 0; r < 32; r++) reg_page[r] = UINT64_MAX;

    for (size_t i = 0; i < count && pos < (int)buf_size - 512; i++) {
        cs_insn *ins = &insns[i];
        cs_detail *d = ins->detail;
        cs_arm64 *arm64 = d ? &d->arm64 : NULL;

        // 偏移地址直接就是 ins->address
        uint64_t insOffset = ins->address;

        char ops_formatted[256];
        int is_branch = (ins->id == ARM64_INS_B || ins->id == ARM64_INS_BL ||
                         ins->id == ARM64_INS_ADR || ins->id == ARM64_INS_ADRP ||
                         ins->id == ARM64_INS_CBZ || ins->id == ARM64_INS_CBNZ ||
                         ins->id == ARM64_INS_TBZ || ins->id == ARM64_INS_TBNZ);

        if (is_branch && arm64) {
            uint64_t target = 0;
            int last_imm_idx = -1;
            for (int j = 0; j < arm64->op_count; j++) {
                if (arm64->operands[j].type == ARM64_OP_IMM) last_imm_idx = j;
            }
            if (last_imm_idx >= 0) target = arm64->operands[last_imm_idx].imm;

            if (target) {
                const char *func_name = find_func_at(target);

                if (ins->id == ARM64_INS_TBZ || ins->id == ARM64_INS_TBNZ) {
                    char *op_copy = strdup(ins->op_str);
                    char *last_comma = strrchr(op_copy, ',');
                    if (last_comma) {
                        *last_comma = '\0';
                        if (func_name)
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s, %s", op_copy, func_name);
                        else
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s, #0x%llx", op_copy, (unsigned long long)target);
                    } else {
                        if (func_name)
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s", func_name);
                        else
                            snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx", (unsigned long long)target);
                    }
                    free(op_copy);
                } else if (ins->id == ARM64_INS_CBZ || ins->id == ARM64_INS_CBNZ) {
                    char *op_copy = strdup(ins->op_str);
                    char *comma = strchr(op_copy, ',');
                    if (comma) {
                        *comma = '\0';
                        if (func_name)
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s, %s", op_copy, func_name);
                        else
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s, #0x%llx", op_copy, (unsigned long long)target);
                    } else {
                        if (func_name)
                            snprintf(ops_formatted, sizeof(ops_formatted), "%s", func_name);
                        else
                            snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx", (unsigned long long)target);
                    }
                    free(op_copy);
                } else {
                    if (func_name)
                        snprintf(ops_formatted, sizeof(ops_formatted), "%s", func_name);
                    else
                        snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx", (unsigned long long)target);
                }
            } else {
                strncpy(ops_formatted, ins->op_str, sizeof(ops_formatted) - 1);
                ops_formatted[sizeof(ops_formatted) - 1] = '\0';
            }
        } else {
            strncpy(ops_formatted, ins->op_str, sizeof(ops_formatted) - 1);
            ops_formatted[sizeof(ops_formatted) - 1] = '\0';
        }

        // 负数简化
        {
            char *p = ops_formatted;
            while ((p = strstr(p, "#0xffffffffffff")) != NULL) {
                char *val_start = p + 1;
                char *endptr = NULL;
                uint64_t uval = strtoull(val_start, &endptr, 16);
                int64_t sval = (int64_t)uval;
                if (sval < 0 && sval > -0x10000) {
                    char suffix[128] = {0};
                    if (endptr) strncpy(suffix, endptr, sizeof(suffix) - 1);
                    int off = (int)(p - ops_formatted);
                    snprintf(p, sizeof(ops_formatted) - off, "#-0x%llx%s", (unsigned long long)(-sval), suffix);
                }
                p++;
            }
        }

        char line[512];
        int line_len = snprintf(line, sizeof(line), "%08llx:  %-8s %s",
                        (unsigned long long)insOffset, ins->mnemonic, ops_formatted);

        // PLT 和字符串注释
        const char *str_comment = NULL;
        const char *plt_comment = NULL;

        if (arm64 && (strcmp(ins->mnemonic, "bl") == 0 || strcmp(ins->mnemonic, "b") == 0)) {
            uint64_t target = 0;
            for (int j = 0; j < arm64->op_count; j++) {
                if (arm64->operands[j].type == ARM64_OP_IMM) { target = arm64->operands[j].imm; break; }
            }
            if (target) plt_comment = find_plt_at(target);
        }

        if (arm64) {
            if (strcmp(ins->mnemonic, "adrp") == 0 && arm64->op_count >= 2) {
                uint64_t target = calc_ref_target(ins, arm64);
                if (target != UINT64_MAX) {
                    int reg = arm64->operands[0].reg - ARM64_REG_X0;
                    if (reg >= 0 && reg < 32) reg_page[reg] = target;
                }
            } else if (strcmp(ins->mnemonic, "add") == 0 && arm64->op_count >= 3) {
                cs_arm64_op *src1 = &arm64->operands[1];
                cs_arm64_op *src2 = &arm64->operands[2];
                int src1_reg = src1->reg - ARM64_REG_X0;
                if (src2->type == ARM64_OP_IMM && src1_reg >= 0 && src1_reg < 32
                        && reg_page[src1_reg] != UINT64_MAX) {
                    uint64_t target = reg_page[src1_reg] + (uint64_t)src2->imm;
                    str_comment = find_string_at(target);
                    int dst_reg = arm64->operands[0].reg - ARM64_REG_X0;
                    if (dst_reg >= 0 && dst_reg < 32) reg_page[dst_reg] = target;
                }
            } else if (strcmp(ins->mnemonic, "adr") == 0) {
                uint64_t target = calc_ref_target(ins, arm64);
                if (target != UINT64_MAX) str_comment = find_string_at(target);
            } else if (ins->id == ARM64_INS_BL || ins->id == ARM64_INS_BLR) {
                for (int r = 0; r <= 18; r++) reg_page[r] = UINT64_MAX;
            }
        }

        if (plt_comment) {
            int pad = 36 - line_len; if (pad < 2) pad = 2;
            pos += snprintf(buffer + pos, buf_size - pos, "%s%*s; %s@PLT\n", line, pad, "", plt_comment);
        } else if (str_comment) {
            char short_str[64];
            if (strlen(str_comment) > 50) snprintf(short_str, sizeof(short_str), "%.50s...", str_comment);
            else snprintf(short_str, sizeof(short_str), "%s", str_comment);
            int pad = 36 - line_len; if (pad < 2) pad = 2;
            pos += snprintf(buffer + pos, buf_size - pos, "%s%*s; \"%s\"\n", line, pad, "", short_str);
        } else {
            pos += snprintf(buffer + pos, buf_size - pos, "%s\n", line);
        }
    }

    jstring result_str = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    cs_free(insns, count);
    cs_close(&handle);
    return result_str;
}

// ============================================================================
// JNI入口: decompileBytes - 从byte[]伪C反编译 (静态分析模式)
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_decompileBytes(
        JNIEnv *env, jclass clazz, jbyteArray jBytes, jlong funcOffset, jlong funcSize,
        jstring jFuncName, jstring jSignature) {

    jsize dataLen = (*env)->GetArrayLength(env, jBytes);
    size_t size = (size_t)funcSize;
    if (size == 0 || size > (size_t)dataLen) size = (size_t)dataLen;
    if (size > 16384) size = 16384;

    uint8_t *code = (uint8_t *)malloc(size);
    if (!code) return (*env)->NewStringUTF(env, "ERR: out of memory");
    (*env)->GetByteArrayRegion(env, jBytes, 0, (jsize)size, (jbyte *)code);

    const char *func_name = jFuncName ? (*env)->GetStringUTFChars(env, jFuncName, NULL) : NULL;
    const char *signature = jSignature ? (*env)->GetStringUTFChars(env, jSignature, NULL) : NULL;

    size_t buf_size = size * 64 + 4096;
    char *buffer = (char *)calloc(1, buf_size);
    if (!buffer) {
        free(code);
        if (func_name) (*env)->ReleaseStringUTFChars(env, jFuncName, func_name);
        if (signature) (*env)->ReleaseStringUTFChars(env, jSignature, signature);
        return (*env)->NewStringUTF(env, "ERR: out of memory");
    }

    decompile_function_ex(code, size, (uint64_t)funcOffset, func_name, signature, buffer, buf_size);

    free(code);
    if (func_name) (*env)->ReleaseStringUTFChars(env, jFuncName, func_name);
    if (signature) (*env)->ReleaseStringUTFChars(env, jSignature, signature);

    jstring result = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    return result;
}

// ============================================================================
// JNI入口: analyzeXRefs - 分析函数交叉引用
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_analyzeXRefs(
        JNIEnv *env, jclass clazz, jlong funcAddr, jlong funcSize, jlongArray jKnownFuncs) {

    const uint8_t *code = (const uint8_t *)(uintptr_t)funcAddr;
    size_t size = (size_t)funcSize;

    if (size == 0) size = 256;
    if (size > 65536) size = 65536;

    // 读取已知函数地址列表
    int known_count = 0;
    uint64_t known_funcs[1024];
    if (jKnownFuncs) {
        jsize len = (*env)->GetArrayLength(env, jKnownFuncs);
        if (len > 1024) len = 1024;
        jlong *arr = (*env)->GetLongArrayElements(env, jKnownFuncs, NULL);
        for (int i = 0; i < len; i++) {
            known_funcs[i] = (uint64_t)arr[i];
        }
        (*env)->ReleaseLongArrayElements(env, jKnownFuncs, arr, JNI_ABORT);
        known_count = len;
    }

    char buffer[MAX_XREFS * 64] = {0};

    crash_protection_enter();
    int sig = sigsetjmp(*crash_protection_get_jmpbuf(), 1);
    if (sig != 0) {
        crash_protection_leave();
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "ERR: 交叉引用分析崩溃: %s (signal %d), 地址=0x%llX", signal_name(sig), sig, (unsigned long long)funcAddr);
        LOGE("XRef analysis crash: %s at addr 0x%llX", signal_name(sig), (unsigned long long)funcAddr);
        return (*env)->NewStringUTF(env, errbuf);
    }

    analyze_function_xrefs(code, size, (uint64_t)funcAddr, known_funcs, known_count,
                           buffer, sizeof(buffer));
    crash_protection_leave();

    return (*env)->NewStringUTF(env, buffer);
}

// ============================================================================
// JNI入口: decompileFunction - 伪C反编译
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_decompileFunction(
        JNIEnv *env, jclass clazz, jlong funcAddr, jlong funcSize) {

    const uint8_t *code = (const uint8_t *)(uintptr_t)funcAddr;
    size_t size = (size_t)funcSize;

    if (size == 0) size = 256;
    if (size > 16384) size = 16384;

    size_t buf_size = size * 64 + 4096;
    char *buffer = (char *)calloc(1, buf_size);
    if (!buffer) return (*env)->NewStringUTF(env, "ERR: out of memory");

    // 崩溃保护读取内存
    crash_protection_enter();
    int sig = sigsetjmp(*crash_protection_get_jmpbuf(), 1);
    if (sig != 0) {
        crash_protection_leave();
        free(buffer);
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "ERR: 读取内存崩溃: %s (signal %d)", signal_name(sig), sig);
        return (*env)->NewStringUTF(env, errbuf);
    }

    decompile_function(code, size, (uint64_t)funcAddr, buffer, buf_size);
    crash_protection_leave();

    jstring result = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    return result;
}

// ============================================================================
// JNI入口: decompileFunctionEx - 带签名的伪C反编译
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_decompileFunctionEx(
        JNIEnv *env, jclass clazz, jlong funcAddr, jlong funcSize,
        jstring jFuncName, jstring jSignature, jlong baseAddress) {

    const uint8_t *code = (const uint8_t *)(uintptr_t)funcAddr;
    size_t size = (size_t)funcSize;

    if (size == 0) size = 256;
    if (size > 16384) size = 16384;

    const char *func_name = jFuncName ? (*env)->GetStringUTFChars(env, jFuncName, NULL) : NULL;
    const char *signature = jSignature ? (*env)->GetStringUTFChars(env, jSignature, NULL) : NULL;

    size_t buf_size = size * 64 + 4096;
    char *buffer = (char *)calloc(1, buf_size);
    if (!buffer) {
        if (func_name) (*env)->ReleaseStringUTFChars(env, jFuncName, func_name);
        if (signature) (*env)->ReleaseStringUTFChars(env, jSignature, signature);
        return (*env)->NewStringUTF(env, "ERR: out of memory");
    }

    crash_protection_enter();
    int sig = sigsetjmp(*crash_protection_get_jmpbuf(), 1);
    if (sig != 0) {
        crash_protection_leave();
        free(buffer);
        if (func_name) (*env)->ReleaseStringUTFChars(env, jFuncName, func_name);
        if (signature) (*env)->ReleaseStringUTFChars(env, jSignature, signature);
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "ERR: 读取内存崩溃: %s (signal %d)", signal_name(sig), sig);
        return (*env)->NewStringUTF(env, errbuf);
    }

    // 使用偏移地址进行反编译显示 (与汇编一致)
    uint64_t funcOffset = (uint64_t)(funcAddr - baseAddress);
    decompile_function_ex(code, size, funcOffset, func_name, signature, buffer, buf_size);
    crash_protection_leave();

    if (func_name) (*env)->ReleaseStringUTFChars(env, jFuncName, func_name);
    if (signature) (*env)->ReleaseStringUTFChars(env, jSignature, signature);

    jstring result = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    return result;
}

// ============================================================================
// JNI入口: getJavaVM - 返回JavaVM*指针
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_example_anative_core_NativeInvoker_getJavaVM(
        JNIEnv *env, jclass clazz) {
    return (jlong)(uintptr_t)g_jvm;
}

// ============================================================================
// JNI入口: nativeDlopen - 用dlopen加载SO，不触发JNI_OnLoad
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_example_anative_core_NativeInvoker_nativeDlopen(
        JNIEnv *env, jclass clazz, jstring jpath) {

#if !PLATFORM_SUPPORTS_EXECUTION
    return 0; // 非ARM64平台不支持动态加载
#endif

    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    if (!path) return 0;

    LOGI("dlopen: %s", path);

    // RTLD_NOW: 立即解析所有符号
    // RTLD_LAZY: 延迟解析，可能解决静态链接SO的问题
    // 不用 RTLD_GLOBAL 防止符号污染
    void *handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        LOGW("RTLD_NOW failed, trying RTLD_LAZY...");
        handle = dlopen(path, RTLD_LAZY);
        if (!handle) {
            LOGE("dlopen failed: %s", dlerror());
            (*env)->ReleaseStringUTFChars(env, jpath, path);
            return 0;
        }
    }

    LOGI("dlopen success, handle=%p", handle);
    (*env)->ReleaseStringUTFChars(env, jpath, path);

    return (jlong)(uintptr_t)handle;
}

// ============================================================================
// JNI入口: nativeDlclose - 卸载SO
// ============================================================================

JNIEXPORT void JNICALL
Java_com_example_anative_core_NativeInvoker_nativeDlclose(
        JNIEnv *env, jclass clazz, jlong handle) {

#if PLATFORM_SUPPORTS_EXECUTION
    if (handle != 0) {
        dlclose((void *)(uintptr_t)handle);
        LOGI("dlclose: handle=%p", (void *)(uintptr_t)handle);
    }
#endif
}

// ============================================================================
// JNI入口: nativeDlsym - 查找符号地址
// ============================================================================

JNIEXPORT jlong JNICALL
Java_com_example_anative_core_NativeInvoker_nativeDlsym(
        JNIEnv *env, jclass clazz, jlong handle, jstring jsym) {

#if !PLATFORM_SUPPORTS_EXECUTION
    return 0; // 非ARM64平台不支持
#endif

    if (handle == 0) return 0;

    const char *sym = (*env)->GetStringUTFChars(env, jsym, NULL);
    if (!sym) return 0;

    void *addr = dlsym((void *)(uintptr_t)handle, sym);
    LOGI("dlsym(%s) = %p", sym, addr);
    (*env)->ReleaseStringUTFChars(env, jsym, sym);

    return (jlong)(uintptr_t)addr;
}

// ============================================================================
// JNI入口: disassembleTextSection - 全局TEXT段反汇编，带函数高亮
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_disassembleTextSection(
        JNIEnv *env, jclass clazz, jlong baseAddr, jlong textSize, jlong highlightFuncAddr, jlong highlightFuncSize, jstring jStringTable, jstring jPltTable) {

    const uint8_t *code = (const uint8_t *)(uintptr_t)baseAddr;
    size_t size = (size_t)textSize;
    uint64_t base = (uint64_t)baseAddr;
    uint64_t hlStart = (uint64_t)highlightFuncAddr;
    uint64_t hlEnd = hlStart + (uint64_t)highlightFuncSize;

    // 限制TEXT段反汇编大小，防止大文件卡死（最大512KB，约几万条指令）
    const size_t MAX_TEXT_DISASM_SIZE = 512 * 1024;
    if (size == 0 || size > 16 * 1024 * 1024) {
        return (*env)->NewStringUTF(env, "ERR: invalid text size");
    }
    if (size > MAX_TEXT_DISASM_SIZE) {
        size = MAX_TEXT_DISASM_SIZE;
    }

    // 解析字符串表和PLT表
    const char *str_table = jStringTable ? (*env)->GetStringUTFChars(env, jStringTable, NULL) : NULL;
    parse_string_table(str_table);
    if (str_table) (*env)->ReleaseStringUTFChars(env, jStringTable, str_table);

    const char *plt_table = jPltTable ? (*env)->GetStringUTFChars(env, jPltTable, NULL) : NULL;
    parse_plt_table(plt_table);
    if (plt_table) (*env)->ReleaseStringUTFChars(env, jPltTable, plt_table);

    // 崩溃保护读取内存
    uint8_t *code_copy = (uint8_t *)malloc(size);
    if (!code_copy) return (*env)->NewStringUTF(env, "ERR: out of memory");

    crash_protection_enter();
    int sig = sigsetjmp(*crash_protection_get_jmpbuf(), 1);
    if (sig != 0) {
        crash_protection_leave();
        free(code_copy);
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "ERR: 读取TEXT段内存崩溃: %s (signal %d), 地址=0x%llX", signal_name(sig), sig, (unsigned long long)baseAddr);
        LOGE("TEXT section memory crash: %s at addr 0x%llX", signal_name(sig), (unsigned long long)baseAddr);
        return (*env)->NewStringUTF(env, errbuf);
    }
    memcpy(code_copy, code, size);
    crash_protection_leave();

    // Capstone反汇编
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        free(code_copy);
        return (*env)->NewStringUTF(env, "ERR: Capstone初始化失败");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_insn *insns = NULL;
    size_t count = cs_disasm(handle, code_copy, size, base, 0, &insns);

    if (count <= 0) {
        // TEXT段反汇编完全失败，显示原始字节
        size_t raw_buf_size = (size / 4) * 48 + 4096;
        if (raw_buf_size > 4 * 1024 * 1024) raw_buf_size = 4 * 1024 * 1024;
        char *raw_buffer = (char *)calloc(1, raw_buf_size);
        if (!raw_buffer) {
            free(code_copy);
            cs_close(&handle);
            return (*env)->NewStringUTF(env, "ERR: out of memory");
        }
        int rpos = 0;
        rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                        "; TEXT Disassembly - 解析失败，显示原始字节\n\n");
        for (size_t off = 0; off + 3 < size && rpos < (int)raw_buf_size - 128; off += 4) {
            uint32_t word = *(uint32_t *)(code_copy + off);
            rpos += snprintf(raw_buffer + rpos, raw_buf_size - rpos,
                            "%08llx:  .inst   0x%08x  ; %02x %02x %02x %02x\n",
                            (unsigned long long)(base + off), word,
                            code_copy[off], code_copy[off+1], code_copy[off+2], code_copy[off+3]);
        }
        free(code_copy);
        cs_close(&handle);
        jstring result_str = (*env)->NewStringUTF(env, raw_buffer);
        free(raw_buffer);
        return result_str;
    }
    free(code_copy);

    // 分配足够大的缓冲区
    size_t buf_size = count * 256 + 8192;
    char *buffer = (char *)calloc(1, buf_size);
    if (!buffer) {
        cs_free(insns, count);
        cs_close(&handle);
        return (*env)->NewStringUTF(env, "ERR: out of memory");
    }

    int pos = 0;
    pos += snprintf(buffer + pos, buf_size - pos,
                    "; ARM64 Global Disassembly (Capstone)\n"
                    "; Base: 0x%llx, Size: %zu bytes, Instructions: %zu\n"
                    "; Highlight: 0x%llx - 0x%llx\n\n",
                    (unsigned long long)base, size, count,
                    (unsigned long long)hlStart, (unsigned long long)hlEnd);

    uint64_t reg_page[32];
    for (int r = 0; r < 32; r++) reg_page[r] = UINT64_MAX;

    for (size_t i = 0; i < count && pos < (int)buf_size - 512; i++) {
        cs_insn *ins = &insns[i];
        cs_detail *d = ins->detail;
        cs_arm64 *arm64 = d ? &d->arm64 : NULL;

        uint64_t insAddr = ins->address;
        uint64_t insOffset = insAddr - base;

        // 检查是否在要高亮的函数范围内
        int is_highlight = (insAddr >= hlStart && insAddr < hlEnd);

        // 格式化操作数 (复用 disassembleFunctionEx 的逻辑)
        char ops_formatted[256];
        int is_branch = (ins->id == ARM64_INS_B || ins->id == ARM64_INS_BL ||
                         ins->id == ARM64_INS_ADR || ins->id == ARM64_INS_ADRP ||
                         ins->id == ARM64_INS_CBZ || ins->id == ARM64_INS_CBNZ ||
                         ins->id == ARM64_INS_TBZ || ins->id == ARM64_INS_TBNZ);

        if (is_branch && arm64) {
            uint64_t target = 0;
            int last_imm_idx = -1;
            for (int j = 0; j < arm64->op_count; j++) {
                if (arm64->operands[j].type == ARM64_OP_IMM) {
                    last_imm_idx = j;
                }
            }
            if (last_imm_idx >= 0) {
                target = arm64->operands[last_imm_idx].imm;
            }

            if (target) {
                uint64_t targetOffset = target - base;
                if (ins->id == ARM64_INS_TBZ || ins->id == ARM64_INS_TBNZ) {
                    char *op_copy = strdup(ins->op_str);
                    char *last_comma = strrchr(op_copy, ',');
                    if (last_comma) {
                        *last_comma = '\0';
                        snprintf(ops_formatted, sizeof(ops_formatted), "%s, #0x%llx",
                                op_copy, (unsigned long long)targetOffset);
                    } else {
                        snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx",
                                (unsigned long long)targetOffset);
                    }
                    free(op_copy);
                } else if (ins->id == ARM64_INS_CBZ || ins->id == ARM64_INS_CBNZ) {
                    char *op_copy = strdup(ins->op_str);
                    char *comma = strchr(op_copy, ',');
                    if (comma) {
                        *comma = '\0';
                        snprintf(ops_formatted, sizeof(ops_formatted), "%s, #0x%llx",
                                op_copy, (unsigned long long)targetOffset);
                    } else {
                        snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx",
                                (unsigned long long)targetOffset);
                    }
                    free(op_copy);
                } else {
                    snprintf(ops_formatted, sizeof(ops_formatted), "#0x%llx",
                            (unsigned long long)targetOffset);
                }
            } else {
                strncpy(ops_formatted, ins->op_str, sizeof(ops_formatted) - 1);
                ops_formatted[sizeof(ops_formatted) - 1] = '\0';
            }
        } else {
            strncpy(ops_formatted, ins->op_str, sizeof(ops_formatted) - 1);
            ops_formatted[sizeof(ops_formatted) - 1] = '\0';
        }

        // 后处理: 将超长无符号hex转为带符号短形式
        {
            char *p = ops_formatted;
            while ((p = strstr(p, "#0xffffffffffff")) != NULL) {
                char *val_start = p + 1;
                char *endptr = NULL;
                uint64_t uval = strtoull(val_start, &endptr, 16);
                int64_t sval = (int64_t)uval;
                if (sval < 0 && sval > -0x10000) {
                    char suffix[128] = {0};
                    if (endptr) strncpy(suffix, endptr, sizeof(suffix) - 1);
                    int off = (int)(p - ops_formatted);
                    snprintf(p, sizeof(ops_formatted) - off, "#-0x%llx%s",
                            (unsigned long long)(-sval), suffix);
                }
                p++;
            }
        }

        // 构建行前缀 (高亮标记)
        char prefix[8] = "  ";
        if (is_highlight) {
            prefix[0] = '>';
            prefix[1] = '>';
        }

        char line[512];
        int line_len = snprintf(line, sizeof(line),
                        "%s%08llx:  %-8s %s",
                        prefix, (unsigned long long)insOffset,
                        ins->mnemonic, ops_formatted);

        // 检测字符串引用和PLT调用
        const char *str_comment = NULL;
        const char *plt_comment = NULL;

        if (arm64 && (strcmp(ins->mnemonic, "bl") == 0 || strcmp(ins->mnemonic, "b") == 0)) {
            uint64_t target = 0;
            for (int j = 0; j < arm64->op_count; j++) {
                cs_arm64_op *op = &arm64->operands[j];
                if (op->type == ARM64_OP_IMM) {
                    target = op->imm;
                    break;
                }
            }
            if (target) {
                uint64_t targetOffset = target - base;
                plt_comment = find_plt_at(targetOffset);
            }
        }

        if (arm64) {
            if (strcmp(ins->mnemonic, "adrp") == 0 && arm64->op_count >= 2) {
                uint64_t target = calc_ref_target(ins, arm64);
                if (target != UINT64_MAX) {
                    int reg = arm64->operands[0].reg - ARM64_REG_X0;
                    if (reg >= 0 && reg < 32) reg_page[reg] = target;
                }
            } else if (strcmp(ins->mnemonic, "add") == 0 && arm64->op_count >= 3) {
                cs_arm64_op *dst = &arm64->operands[0];
                cs_arm64_op *src1 = &arm64->operands[1];
                cs_arm64_op *src2 = &arm64->operands[2];
                int src1_reg = src1->reg - ARM64_REG_X0;
                if (src2->type == ARM64_OP_IMM && src1_reg >= 0 && src1_reg < 32
                        && reg_page[src1_reg] != UINT64_MAX) {
                    uint64_t target = reg_page[src1_reg] + (uint64_t)src2->imm;
                    str_comment = find_string_at(target - base);
                    int dst_reg = dst->reg - ARM64_REG_X0;
                    if (dst_reg >= 0 && dst_reg < 32) reg_page[dst_reg] = target;
                }
            } else if (strcmp(ins->mnemonic, "adr") == 0) {
                uint64_t target = calc_ref_target(ins, arm64);
                if (target != UINT64_MAX) str_comment = find_string_at(target - base);
            } else if (ins->id == ARM64_INS_BL || ins->id == ARM64_INS_BLR) {
                for (int r = 0; r <= 18; r++) reg_page[r] = UINT64_MAX;
            }
        }

        // 追加注释
        if (plt_comment) {
            int pad = 38 - line_len;
            if (pad < 2) pad = 2;
            pos += snprintf(buffer + pos, buf_size - pos, "%s%*s; %s@PLT\n",
                            line, pad, "", plt_comment);
        } else if (str_comment) {
            char short_str[64];
            if (strlen(str_comment) > 50) {
                snprintf(short_str, sizeof(short_str), "%.50s...", str_comment);
            } else {
                snprintf(short_str, sizeof(short_str), "%s", str_comment);
            }
            int pad = 38 - line_len;
            if (pad < 2) pad = 2;
            pos += snprintf(buffer + pos, buf_size - pos, "%s%*s; \"%s\"\n",
                            line, pad, "", short_str);
        } else {
            pos += snprintf(buffer + pos, buf_size - pos, "%s\n", line);
        }
    }

    jstring result_str = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    cs_free(insns, count);
    cs_close(&handle);
    return result_str;
}

// ============================================================================
// JNI入口: scanXRefsFromBytes - 批量扫描交叉引用 (静态分析)
// 使用cs_disasm_iter逐条解码, 避免大量内存分配
// 返回格式: "F|caller_vaddr|callee_vaddr\nS|instr_vaddr|string_vaddr\n..."
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_scanXRefsFromBytes(
        JNIEnv *env, jclass clazz, jbyteArray jBytes, jlong textVAddr, jlong textSize,
        jstring jFuncTable, jstring jStringTable) {

    jsize dataLen = (*env)->GetArrayLength(env, jBytes);
    size_t size = (size_t)textSize;
    if (size == 0 || size > (size_t)dataLen) size = (size_t)dataLen;

    uint8_t *code = (uint8_t *)malloc(size);
    if (!code) return (*env)->NewStringUTF(env, "ERR:OOM");
    (*env)->GetByteArrayRegion(env, jBytes, 0, (jsize)size, (jbyte *)code);

    // 解析函数表
    const char *func_str = jFuncTable ? (*env)->GetStringUTFChars(env, jFuncTable, NULL) : NULL;
    parse_func_table(func_str);
    if (func_str) {
        // Debug: print first function table entry
        if (g_func_count > 0) {
            LOGI("scanXRefs: first func 0x%llx=%s, last func 0x%llx=%s, total=%d",
                 (unsigned long long)g_func_table[0].addr, g_func_table[0].name,
                 (unsigned long long)g_func_table[g_func_count-1].addr,
                 g_func_table[g_func_count-1].name, g_func_count);
        }
        (*env)->ReleaseStringUTFChars(env, jFuncTable, func_str);
    }

    // 解析字符串表
    const char *str_str = jStringTable ? (*env)->GetStringUTFChars(env, jStringTable, NULL) : NULL;
    parse_string_table(str_str);
    if (str_str) {
        if (g_string_count > 0) {
            LOGI("scanXRefs: first string 0x%llx='%s', total=%d",
                 (unsigned long long)g_string_table[0].addr, g_string_table[0].str, g_string_count);
        }
        (*env)->ReleaseStringUTFChars(env, jStringTable, str_str);
    }

    LOGI("scanXRefs: textVAddr=0x%llx size=%zu funcs=%d strings=%d",
         (unsigned long long)textVAddr, size, g_func_count, g_string_count);

    // Capstone初始化
    csh handle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        free(code);
        return (*env)->NewStringUTF(env, "ERR:Capstone");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // 使用cs_disasm_iter逐条解码, 不会一次性分配所有指令内存
    cs_insn *insn = cs_malloc(handle);
    if (!insn) {
        free(code);
        cs_close(&handle);
        return (*env)->NewStringUTF(env, "ERR:cs_malloc");
    }

    // 结果缓冲区 (动态扩展)
    size_t buf_size = 1024 * 1024; // 初始1MB
    char *buffer = (char *)calloc(1, buf_size);
    if (!buffer) {
        cs_free(insn, 1);
        free(code);
        cs_close(&handle);
        return (*env)->NewStringUTF(env, "ERR:OOM");
    }

    int pos = 0;
    // 用UINT64_MAX表示"未设置", 因为ADRP #0是合法的(同一页)
    uint64_t reg_page[32];
    for (int r = 0; r < 32; r++) reg_page[r] = UINT64_MAX;
    int xref_count = 0;
    size_t insn_count = 0;

    const uint8_t *code_ptr = code;
    size_t code_remaining = size;
    uint64_t address = (uint64_t)textVAddr;

    while (cs_disasm_iter(handle, &code_ptr, &code_remaining, &address, insn)) {
        insn_count++;
        cs_detail *d = insn->detail;
        cs_arm64 *arm64 = d ? &d->arm64 : NULL;
        uint64_t iaddr = insn->address;

        // 扩展缓冲区
        if (pos > (int)buf_size - 256) {
            size_t new_size = buf_size * 2;
            if (new_size > 64 * 1024 * 1024) break; // 最大64MB
            char *new_buf = (char *)realloc(buffer, new_size);
            if (!new_buf) break;
            buffer = new_buf;
            buf_size = new_size;
        }

        // BL / B: 提取跳转目标
        // BL 永远是函数调用；B 只有当目标落在 .text 范围内但距离当前指令较远时
        // (可能是 tail call) 才算跨函数引用
        if (insn->id == ARM64_INS_BL || insn->id == ARM64_INS_B) {
            if (arm64) {
                int last_imm = -1;
                for (int j = 0; j < arm64->op_count; j++) {
                    if (arm64->operands[j].type == ARM64_OP_IMM) last_imm = j;
                }
                if (last_imm >= 0) {
                    uint64_t target = arm64->operands[last_imm].imm;
                    uint64_t text_end = (uint64_t)textVAddr + (uint64_t)size;
                    int in_text = (target >= (uint64_t)textVAddr && target < text_end);
                    int is_call = 0;
                    if (insn->id == ARM64_INS_BL) {
                        is_call = 1;  // BL 永远是调用
                    } else if (in_text) {
                        // 普通 B：远跳（跨越 4KB 以上）视为 tail call
                        int64_t dist = (int64_t)target - (int64_t)iaddr;
                        if (dist < 0) dist = -dist;
                        if (dist > 0x1000) is_call = 1;
                    }
                    if (is_call && in_text) {
                        pos += snprintf(buffer + pos, buf_size - pos,
                                        "F|%llx|%llx\n",
                                        (unsigned long long)iaddr,
                                        (unsigned long long)target);
                        xref_count++;
                    }
                }
            }
            if (insn->id == ARM64_INS_BL) {
                for (int r = 0; r <= 18; r++) reg_page[r] = UINT64_MAX;
            }
        }
        // BLR: 间接调用, 重置寄存器
        else if (insn->id == ARM64_INS_BLR) {
            for (int r = 0; r <= 18; r++) reg_page[r] = UINT64_MAX;
        }
        // ADRP: 记录页地址
        else if (insn->id == ARM64_INS_ADRP) {
            if (arm64 && arm64->op_count >= 2
                && arm64->operands[0].type == ARM64_OP_REG
                && arm64->operands[1].type == ARM64_OP_IMM) {
                int rd = arm64->operands[0].reg - ARM64_REG_X0;
                uint64_t page = arm64->operands[1].imm;
                if (rd >= 0 && rd < 32) {
                    reg_page[rd] = page;
                }
            }
        }
        // ADR: 直接加载PC相对地址, 常用于加载字符串地址
        else if (insn->id == ARM64_INS_ADR) {
            if (arm64 && arm64->op_count >= 2
                && arm64->operands[0].type == ARM64_OP_REG
                && arm64->operands[1].type == ARM64_OP_IMM) {
                int rd = arm64->operands[0].reg - ARM64_REG_X0;
                uint64_t target = arm64->operands[1].imm;  // Capstone已计算为绝对地址
                if (rd >= 0 && rd < 32) reg_page[rd] = target;
                // 检查目标地址是否为已知字符串
                const char *str = find_string_at(target);
                if (str != NULL) {
                    pos += snprintf(buffer + pos, buf_size - pos,
                                    "S|%llx|%llx\n",
                                    (unsigned long long)iaddr,
                                    (unsigned long long)target);
                    xref_count++;
                }
            }
        }
        // ADD: 计算最终地址, 检查字符串引用
        else if (insn->id == ARM64_INS_ADD) {
            if (arm64 && arm64->op_count >= 3
                && arm64->operands[0].type == ARM64_OP_REG
                && arm64->operands[1].type == ARM64_OP_REG
                && arm64->operands[2].type == ARM64_OP_IMM) {
                int rd = arm64->operands[0].reg - ARM64_REG_X0;
                int rn = arm64->operands[1].reg - ARM64_REG_X0;
                uint64_t imm = arm64->operands[2].imm;
                if (rn >= 0 && rn < 32 && reg_page[rn] != UINT64_MAX) {
                    uint64_t target = reg_page[rn] + imm;
                    if (rd >= 0 && rd < 32) reg_page[rd] = target;
                    const char *str = find_string_at(target);
                    if (str != NULL) {
                        pos += snprintf(buffer + pos, buf_size - pos,
                                        "S|%llx|%llx\n",
                                        (unsigned long long)iaddr,
                                        (unsigned long long)target);
                        xref_count++;
                    }
                }
            }
        }
        // LDR (64-bit immediate offset): ADRP + LDR 模式用于加载字符串地址
        else if (insn->id == ARM64_INS_LDR) {
            if (arm64 && arm64->op_count >= 2
                && arm64->operands[0].type == ARM64_OP_REG  // 目标寄存器
                && arm64->operands[1].type == ARM64_OP_MEM) {  // 内存操作数
                cs_arm64_op *mem = &arm64->operands[1];
                int rn = mem->mem.base - ARM64_REG_X0;
                // 检查基址寄存器是否记录了ADRP页地址
                if (rn >= 0 && rn < 32 && reg_page[rn] != UINT64_MAX) {
                    // 计算内存地址: base + disp
                    uint64_t addr = reg_page[rn] + (uint64_t)mem->mem.disp;
                    // 检查这个地址是否指向一个已知字符串地址（LDR加载的是指针,指针指向字符串）
                    // 这里我们检查加载地址本身是否在字符串表, 但更准确的是应该检查内容
                    // 由于无法解引用, 我们假设地址本身如果匹配字符串地址就是引用
                    const char *str = find_string_at(addr);
                    if (str != NULL) {
                        pos += snprintf(buffer + pos, buf_size - pos,
                                        "S|%llx|%llx\n",
                                        (unsigned long long)iaddr,
                                        (unsigned long long)addr);
                        xref_count++;
                    }
                }
            }
        }
    }

    free(code);

    LOGI("scanXRefs done: %zu instructions scanned, %d xrefs found, result_len=%d", insn_count, xref_count, pos);

    cs_free(insn, 1);
    cs_close(&handle);

    jstring xref_result = (*env)->NewStringUTF(env, buffer);
    free(buffer);
    return xref_result;
}

// ============================================================================
// 内存读写 (用于 Hex 编辑器)
// ============================================================================

JNIEXPORT jbyteArray JNICALL
Java_com_example_anative_core_NativeInvoker_readMemory(JNIEnv *env, jclass clazz,
                                                        jlong addr, jint size) {
    if (size <= 0 || size > 65536) {
        size = 256;
    }

    LOGI("readMemory: addr=0x%llx size=%d", (unsigned long long)addr, size);

    jbyte *buffer = malloc(size);
    if (buffer == NULL) return NULL;

    int read_ok = 0;

    // 使用 sigsetjmp 崩溃保护读取
    crash_protection_enter();
    if (sigsetjmp(*crash_protection_get_jmpbuf(), 1) == 0) {
        memcpy(buffer, (void*)(uintptr_t)addr, size);
        read_ok = 1;
    } else {
        LOGE("readMemory: crashed reading addr 0x%llx", (unsigned long long)addr);
    }
    crash_protection_leave();

    if (!read_ok) {
        free(buffer);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, size);
    if (result == NULL) {
        free(buffer);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, result, 0, size, buffer);
    LOGI("readMemory: success, first bytes: %02X %02X %02X %02X",
         buffer[0]&0xFF, buffer[1]&0xFF, buffer[2]&0xFF, buffer[3]&0xFF);

    free(buffer);
    return result;
}

JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeInvoker_writeMemory(JNIEnv *env, jclass clazz,
                                                         jlong addr, jbyte value) {
    LOGI("writeMemory: addr=0x%llx value=0x%02X", (unsigned long long)addr, value & 0xFF);

    // 先尝试 mprotect 使页面可写
    uintptr_t page_start = (uintptr_t)addr & ~0xFFF;
    mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

    int write_ok = 0;
    crash_protection_enter();
    if (sigsetjmp(*crash_protection_get_jmpbuf(), 1) == 0) {
        *(volatile uint8_t*)(uintptr_t)addr = (uint8_t)value;
        write_ok = 1;
    } else {
        LOGE("writeMemory: crashed writing addr 0x%llx", (unsigned long long)addr);
    }
    crash_protection_leave();

    return write_ok ? JNI_TRUE : JNI_FALSE;
}

// ============================================================================
// JNI入口: analyzeFunctionCalls - 分析函数内部的所有调用
// 简化版：只返回 bl 指令的偏移和目标地址
// ============================================================================
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_analyzeFunctionCalls(JNIEnv *env, jclass clazz,
                                                                  jlong baseAddr,
                                                                  jlong funcOffset,
                                                                  jlong funcSize) {
    if (funcSize <= 0 || funcSize > 0x10000) return (*env)->NewStringUTF(env, "ERR:无效函数大小");

    uint8_t* base = (uint8_t*)(uintptr_t)baseAddr;
    uint8_t* funcAddr = base + funcOffset;

    // 分配结果缓冲区
    char* result = (char*)malloc(65536);
    if (!result) return (*env)->NewStringUTF(env, "ERR:内存不足");
    int pos = 0;
    int callCount = 0;

    pos += snprintf(result + pos, 65536 - pos, "# 函数调用分析\n# 基址: 0x%llX, 偏移: 0x%llX, 大小: %ld\n\n",
                    (unsigned long long)baseAddr, (unsigned long long)funcOffset, (long)funcSize);

    // 复制函数代码到缓冲区
    uint8_t* code = (uint8_t*)malloc(funcSize);
    if (!code) {
        free(result);
        return (*env)->NewStringUTF(env, "ERR:内存不足");
    }

    crash_protection_enter();
    if (sigsetjmp(*crash_protection_get_jmpbuf(), 1) == 0) {
        memcpy(code, funcAddr, funcSize);
        crash_protection_leave();
    } else {
        crash_protection_leave();
        free(code);
        free(result);
        return (*env)->NewStringUTF(env, "ERR:读取函数代码失败");
    }

    // Capstone反汇编
    csh csHandle;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &csHandle) != CS_ERR_OK) {
        free(code);
        free(result);
        return (*env)->NewStringUTF(env, "ERR:Capstone初始化失败");
    }
    cs_option(csHandle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insns = NULL;
    size_t count = cs_disasm(csHandle, code, funcSize, baseAddr + funcOffset, 0, &insns);
    free(code);

    if (count <= 0) {
        cs_close(&csHandle);
        free(result);
        return (*env)->NewStringUTF(env, "ERR:反汇编失败");
    }

    // 分析每条指令
    for (size_t i = 0; i < count; i++) {
        cs_insn* ins = &insns[i];
        cs_detail* detail = ins->detail;
        cs_arm64* arm64 = detail ? &detail->arm64 : NULL;

        // 只关注 bl 指令
        if (ins->id != ARM64_INS_BL) continue;

        uint64_t insOffset = ins->address - baseAddr;
        uint64_t targetAddr = 0;

        // 获取跳转目标地址
        if (arm64 && arm64->op_count > 0 && arm64->operands[0].type == ARM64_OP_IMM) {
            targetAddr = arm64->operands[0].imm;
        }

        if (targetAddr == 0) continue;

        uint64_t targetOffset = targetAddr - baseAddr;

        // 判断目标类型
        const char* typeStr = "内部";
        if (targetAddr < baseAddr || targetAddr > baseAddr + 0x1000000) {
            typeStr = "外部";
        }

        // 格式化输出
        pos += snprintf(result + pos, 65536 - pos, "[0x%04llX] bl 0x%llX (%s, 偏移: 0x%04llX)\n",
                        (unsigned long long)insOffset,
                        (unsigned long long)targetAddr,
                        typeStr,
                        (unsigned long long)targetOffset);
        callCount++;
    }

    cs_free(insns, count);
    cs_close(&csHandle);

    if (callCount == 0) {
        pos += snprintf(result + pos, 65536 - pos, "; 未找到函数调用 (bl 指令)\n");
    }

    jstring ret = (*env)->NewStringUTF(env, result);
    free(result);
    return ret;
}

// ============================================================================
// 写入多字节到内存
// ============================================================================

JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeInvoker_writeMemoryBytes(JNIEnv *env, jclass clazz,
                                                             jlong addr, jbyteArray jBytes) {
    jsize len = (*env)->GetArrayLength(env, jBytes);
    if (len <= 0 || len > 64) {
        LOGE("writeMemoryBytes: invalid length %d", len);
        return JNI_FALSE;
    }

    jbyte *bytes = (*env)->GetByteArrayElements(env, jBytes, NULL);
    if (!bytes) return JNI_FALSE;

    LOGI("writeMemoryBytes: addr=0x%llx len=%d", (unsigned long long)addr, len);

    // 使页面可写
    uintptr_t page_start = (uintptr_t)addr & ~0xFFF;
    mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

    int write_ok = 0;
    crash_protection_enter();
    if (sigsetjmp(*crash_protection_get_jmpbuf(), 1) == 0) {
        memcpy((void*)(uintptr_t)addr, bytes, len);
        write_ok = 1;
    } else {
        LOGE("writeMemoryBytes: crashed at addr 0x%llx", (unsigned long long)addr);
    }
    crash_protection_leave();

    (*env)->ReleaseByteArrayElements(env, jBytes, bytes, JNI_ABORT);
    return write_ok ? JNI_TRUE : JNI_FALSE;
}

// ============================================================================
// 汇编: 将ARM64汇编码转换为机器码
// ============================================================================

// Keystone 错误信息（最近一次）
static char g_last_asm_error[512] = {0};

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_getLastAssembleError(JNIEnv *env, jclass clazz) {
    return (*env)->NewStringUTF(env, g_last_asm_error);
}

JNIEXPORT jbyteArray JNICALL
Java_com_example_anative_core_NativeInvoker_assembleInstruction(JNIEnv *env, jclass clazz,
                                                               jstring jAssembly, jlong virtualOffset) {
    const char *assembly = (*env)->GetStringUTFChars(env, jAssembly, NULL);
    if (!assembly) return NULL;

    LOGI("assembleInstruction: '%s' @ offset=0x%llx", assembly, (unsigned long long)virtualOffset);
    g_last_asm_error[0] = '\0';

    // 动态加载 Keystone
    static void *ks_handle = NULL;
    typedef int (*ks_open_fn)(int architecture, int mode, void **engine);
    typedef int (*ks_close_fn)(void *engine);
    // 真实签名: int ks_asm(ks_engine*, const char*, uint64_t address,
    //                     unsigned char **insn, size_t *insn_size, size_t *stat_count);
    // 返回 0 成功 / -1 失败；insn 由 keystone 分配，需要 ks_free 释放
    typedef int (*ks_asm_fn)(void *engine, const char *string, uint64_t address,
                             unsigned char **insn, size_t *insn_size,
                             size_t *stat_count);
    typedef void (*ks_free_fn)(unsigned char *p);
    typedef const char *(*ks_strerror_fn)(int code);
    typedef int (*ks_errno_fn)(void *engine);

    static ks_open_fn ks_open_fn_ptr = NULL;
    static ks_close_fn ks_close_fn_ptr = NULL;
    static ks_asm_fn ks_asm_fn_ptr = NULL;
    static ks_free_fn ks_free_fn_ptr = NULL;
    static ks_strerror_fn ks_strerror_fn_ptr = NULL;
    static ks_errno_fn ks_errno_fn_ptr = NULL;
    static int ks_loaded = 0;

    if (!ks_loaded) {
        ks_loaded = 1;
        const char *ks_paths[] = {
            "libkeystone.so",
            "/system/lib64/libkeystone.so",
            NULL
        };
        for (int i = 0; ks_paths[i]; i++) {
            ks_handle = dlopen(ks_paths[i], RTLD_NOW);
            if (ks_handle) {
                LOGI("Loaded keystone from: %s", ks_paths[i]);
                break;
            }
        }
        if (ks_handle) {
            ks_open_fn_ptr     = (ks_open_fn)     dlsym(ks_handle, "ks_open");
            ks_close_fn_ptr    = (ks_close_fn)    dlsym(ks_handle, "ks_close");
            ks_asm_fn_ptr      = (ks_asm_fn)      dlsym(ks_handle, "ks_asm");
            ks_free_fn_ptr     = (ks_free_fn)     dlsym(ks_handle, "ks_free");
            ks_strerror_fn_ptr = (ks_strerror_fn) dlsym(ks_handle, "ks_strerror");
            ks_errno_fn_ptr    = (ks_errno_fn)    dlsym(ks_handle, "ks_errno");
            if (!ks_open_fn_ptr || !ks_asm_fn_ptr) {
                LOGE("keystone missing symbols");
                dlclose(ks_handle);
                ks_handle = NULL;
            }
        } else {
            LOGE("keystone not available: %s", dlerror());
        }
    }

    jbyteArray result = NULL;

    if (!ks_handle || !ks_open_fn_ptr || !ks_asm_fn_ptr) {
        snprintf(g_last_asm_error, sizeof(g_last_asm_error),
                 "libkeystone.so 未加载，无法汇编");
        (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);
        return NULL;
    }

    // Keystone 的 arch/mode 常量（与 Capstone 不同！）
    // KS_ARCH_ARM64 = 2, KS_MODE_LITTLE_ENDIAN = 0
    #define KS_ARCH_ARM64_VAL 2
    #define KS_MODE_LITTLE_ENDIAN_VAL 0

    void *ks = NULL;
    int open_rc = ks_open_fn_ptr(KS_ARCH_ARM64_VAL, KS_MODE_LITTLE_ENDIAN_VAL, &ks);
    if (open_rc != 0 || !ks) {
        const char *errstr = (ks_strerror_fn_ptr) ? ks_strerror_fn_ptr(open_rc) : "?";
        snprintf(g_last_asm_error, sizeof(g_last_asm_error),
                 "ks_open 失败: %s (rc=%d)", errstr ? errstr : "?", open_rc);
        LOGE("ks_open failed: rc=%d err=%s", open_rc, errstr ? errstr : "?");
        (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);
        return NULL;
    }

    unsigned char *insn = NULL;
    size_t insn_size = 0;
    size_t stat_count = 0;
    int asm_rc = ks_asm_fn_ptr(ks, assembly, (uint64_t)virtualOffset,
                               &insn, &insn_size, &stat_count);

    if (asm_rc == 0 && insn && insn_size > 0) {
        result = (*env)->NewByteArray(env, (jsize)insn_size);
        if (result) {
            (*env)->SetByteArrayRegion(env, result, 0, (jsize)insn_size, (jbyte*)insn);
        }
        LOGI("assembleInstruction: ok, %zu bytes", insn_size);
    } else {
        int err = ks_errno_fn_ptr ? ks_errno_fn_ptr(ks) : 0;
        const char *errstr = (ks_strerror_fn_ptr && err) ? ks_strerror_fn_ptr(err) : "unknown";
        snprintf(g_last_asm_error, sizeof(g_last_asm_error),
                 "汇编失败: %s (err=%d)", errstr ? errstr : "?", err);
        LOGE("assembleInstruction: %s for '%s'", g_last_asm_error, assembly);
    }

    if (insn && ks_free_fn_ptr) ks_free_fn_ptr(insn);
    if (ks_close_fn_ptr && ks) ks_close_fn_ptr(ks);

    (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);
    return result;
}

// ============================================================================
// 旧代码（已由 Keystone 替代），以下保留但不再被调用
// ============================================================================
#if 0
JNIEXPORT jbyteArray JNICALL
Java_com_example_anative_core_NativeInvoker_assembleInstruction_OLD(JNIEnv *env, jclass clazz,
                                                               jstring jAssembly, jlong virtualOffset) {
    const char *assembly = (*env)->GetStringUTFChars(env, jAssembly, NULL);
    if (!assembly) return NULL;

    jbyteArray result = NULL;

    if (ks_handle && ks_open_fn_ptr && ks_asm_fn_ptr) {
        void *ks = NULL;
        if (ks_open_fn_ptr(CS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks) == 0) {
            unsigned char encoding[64];
            unsigned long long addr = (unsigned long long)virtualOffset;
            size_t stat_count = 0;
            size_t count = ks_asm_fn_ptr(ks, assembly, strlen(assembly), &addr, encoding, sizeof(encoding), &stat_count);

            if (count > 0) {
                result = (*env)->NewByteArray(env, (jsize)count);
                if (result) {
                    (*env)->SetByteArrayRegion(env, result, 0, (jsize)count, (jbyte*)encoding);
                }
                LOGI("assembleInstruction: success, %zu bytes", count);
            } else {
                int err = ks_asm_fn_ptr ? 0 : -1;
                if (ks_strerror_fn_ptr) {
                    // 获取最后错误
                    LOGE("assembleInstruction: failed for '%s'", assembly);
                }
            }

            if (ks_close_fn_ptr && ks) {
                ks_close_fn_ptr(ks);
            }
        }
    } else {
        // Keystone 不可用：尝试手动解析简单指令
        LOGI("assembleInstruction: keystone not available, using fallback parser");

        // 简化版：支持最常见的几条指令的手动汇编
        // MOV Xd, Xn   -> 0xda010000 | (Xd << 0) | (Xn << 5)
        // MOVZ Xd, #imm -> 0x52800000 | (Xd << 0) | ((imm >> 0) << 5) & ~(0xFFFF << 5)  -> actually MOVZ encoding is different
        // NOP           -> 0xd503201f
        // RET           -> 0xd65f03c0

        // 简单指令表 (助记符 -> 编码规则)
        // 我们在这里做简化处理：先把指令转为小写，去掉空格

        uint32_t code = 0;
        int code_len = 4; // ARM64 默认4字节

        // 解析 mov xd, xn 格式
        {
            unsigned int xd = 0, xn = 0;
            if (sscanf(assembly, "mov x%u, x%u", &xd, &xn) == 2) {
                // D(21)=0 Rm(16-20)=Xn O(11-10)=01 Rd(4-0)=Xd  =>  0b01_000_XXXXX_XXXXX_00_XXXXX
                code = 0xaa010000 | ((xn & 0x1F) << 16) | ((xd & 0x1F) << 0);
            }
        }
        // 解析 mov wn, wn 格式
        if (code == 0) {
            unsigned int wd = 0, wn = 0;
            if (sscanf(assembly, "mov w%u, w%u", &wd, &wn) == 2) {
                code = 0x2a000000 | ((wn & 0x1F) << 16) | ((wd & 0x1F) << 0);
            }
        }
        // 解析 mov xd, xn, LSL #n 格式 (简化处理)
        if (code == 0) {
            unsigned int xd = 0, xn = 0;
            if (sscanf(assembly, "mov x%u, x%u, lsl #%u", &xd, &xn, &(unsigned int){0}) == 3) {
                code = 0xaa010000 | ((xn & 0x1F) << 16) | ((xd & 0x1F) << 0);
            }
        }
        // NOP
        if (code == 0 && strcasecmp(assembly, "nop") == 0) {
            code = 0xd503201f;
        }
        // RET
        if (code == 0 && strcasecmp(assembly, "ret") == 0) {
            code = 0xd65f03c0;
        }
        // RET Xn
        if (code == 0) {
            unsigned int xn = 31;
            if (sscanf(assembly, "ret x%u", &xn) == 1) {
                // RET等价于 RET X30 (无条件分支到LR)
                // 可以用正式编码: 0xd65f03c0 (RET) 固定返回地址
                // 但如果要指定寄存器，需要用更复杂的指令
                // ARM64的RET指令编码固定是 x30
                code = 0xd65f03c0;
            }
        }
        // B #imm (用户输入十六进制地址，自动转换为相对偏移)
        if (code == 0) {
            // 用户输入的数值直接当作十六进制处理
            unsigned long long target = 0;
            if (sscanf(assembly, "b #%llx", &target) == 1) {
                // 跳转偏移 = (目标 - 当前指令地址 - 4) / 4
                int64_t offset = ((int64_t)target - (int64_t)virtualOffset) / 4;
                int32_t offset_imm = (int32_t)offset;
                LOGI("B: target=0x%llx virtualOffset=0x%llx imm=%lld",
                     target, (unsigned long long)virtualOffset, (long long)offset);
                code = 0x14000000 | ((uint32_t)offset_imm & 0x03FFFFFF);
            } else {
                // 尝试解析负数: b #-100
                long long target_neg = 0;
                if (sscanf(assembly, "b #-%llx", &target_neg) == 1) {
                    int64_t offset = (-((int64_t)target_neg) - (int64_t)virtualOffset) / 4;
                    int32_t offset_imm = (int32_t)offset;
                    code = 0x14000000 | ((uint32_t)offset_imm & 0x03FFFFFF);
                }
            }
        }
        // BL #imm (用户输入十六进制地址，自动转换为相对偏移)
        if (code == 0) {
            unsigned long long target = 0;
            if (sscanf(assembly, "bl #%llx", &target) == 1) {
                int64_t offset = ((int64_t)target - (int64_t)virtualOffset) / 4;
                int32_t offset_imm = (int32_t)offset;
                code = 0x94000000 | ((uint32_t)offset_imm & 0x03FFFFFF);
            }
        }
        // LDR Xd, [SP, #imm] (支持十进制和0x十六进制)
        if (code == 0) {
            unsigned int xd = 0;
            int imm = 0;
            if (sscanf(assembly, "ldr x%u, [sp, #%d]", &xd, &imm) == 2) {
                int imm9 = imm / 8;
                if (imm9 >= -256 && imm9 < 256) {
                    if (imm9 >= 0) {
                        code = 0xf940000 | ((xd & 0x1F) << 9) | ((imm9 & 0x1FF) << 12);
                    }
                }
            } else {
                // 尝试解析 0x 十六进制格式
                unsigned int xd_hex = 0;
                unsigned int imm_hex = 0;
                if (sscanf(assembly, "ldr x%u, [sp, #0x%x]", &xd_hex, &imm_hex) == 2) {
                    int imm9 = imm_hex / 8;
                    if (imm9 >= 0 && imm9 < 512) {
                        code = 0xf940000 | ((xd_hex & 0x1F) << 9) | ((imm9 & 0x1FF) << 12);
                    }
                }
            }
        }
        // STR Xd, [SP, #imm] (支持十进制和0x十六进制)
        if (code == 0) {
            unsigned int xd = 0;
            int imm = 0;
            if (sscanf(assembly, "str x%u, [sp, #%d]", &xd, &imm) == 2) {
                int imm9 = imm / 8;
                if (imm9 >= 0 && imm9 < 512) {
                    code = 0xf900000 | ((xd & 0x1F) << 9) | ((imm9 & 0x1FF) << 12);
                }
            } else {
                // 尝试解析 0x 十六进制格式
                unsigned int xd_hex = 0;
                unsigned int imm_hex = 0;
                if (sscanf(assembly, "str x%u, [sp, #0x%x]", &xd_hex, &imm_hex) == 2) {
                    int imm9 = imm_hex / 8;
                    if (imm9 >= 0 && imm9 < 512) {
                        code = 0xf900000 | ((xd_hex & 0x1F) << 9) | ((imm9 & 0x1FF) << 12);
                    }
                }
            }
        }
        // ADD Xd, Xn, Xm
        if (code == 0) {
            unsigned int xd = 0, xn = 0, xm = 0;
            if (sscanf(assembly, "add x%u, x%u, x%u", &xd, &xn, &xm) == 3) {
                // Rd(4-0) Rn(9-5) Rm(16-20) 0b000_110_00000_XXXXX_000_XXXXX_XXXXX
                code = 0x8b000000 | ((xm & 0x1F) << 16) | ((xn & 0x1F) << 5) | (xd & 0x1F);
            }
        }
        // SUB Xd, Xn, Xm
        if (code == 0) {
            unsigned int xd = 0, xn = 0, xm = 0;
            if (sscanf(assembly, "sub x%u, x%u, x%u", &xd, &xn, &xm) == 3) {
                // Rd(4-0) Rn(9-5) Rm(16-20)
                code = 0xcb000000 | ((xm & 0x1F) << 16) | ((xn & 0x1F) << 5) | (xd & 0x1F);
            }
        }
        // CMP Xn, Xm
        if (code == 0) {
            unsigned int xn = 0, xm = 0;
            if (sscanf(assembly, "cmp x%u, x%u", &xn, &xm) == 2) {
                // CMP Xn, Xm = SUBS XZR, Xn, Xm
                code = 0xeb00001f | ((xm & 0x1F) << 16) | ((xn & 0x1F) << 5);
            }
        }
        // CBZ Xn, #target (用户输入十六进制地址，自动转换为相对偏移)
        if (code == 0) {
            unsigned int xn = 0;
            unsigned long long target = 0;
            if (sscanf(assembly, "cbz x%u, #%llx", &xn, &target) == 2) {
                int64_t offset = ((int64_t)target - (int64_t)virtualOffset) / 4;
                int32_t offset_imm = (int32_t)offset;
                uint32_t rt = xn & 0x1F;
                code = 0x34000000 | (rt << 0) | ((uint32_t)offset_imm & 0x7FFF);
            }
        }
        // CBNZ Xn, #target (用户输入十六进制地址，自动转换为相对偏移)
        if (code == 0) {
            unsigned int xn = 0;
            unsigned long long target = 0;
            if (sscanf(assembly, "cbnz x%u, #%llx", &xn, &target) == 2) {
                int64_t offset = ((int64_t)target - (int64_t)virtualOffset) / 4;
                int32_t offset_imm = (int32_t)offset;
                uint32_t rt = xn & 0x1F;
                code = 0x35000000 | (rt << 0) | ((uint32_t)offset_imm & 0x7FFF);
            }
        }
        if (code != 0) {
            result = (*env)->NewByteArray(env, 4);
            if (result) {
                uint8_t bytes[4] = {
                    (uint8_t)(code & 0xFF),
                    (uint8_t)((code >> 8) & 0xFF),
                    (uint8_t)((code >> 16) & 0xFF),
                    (uint8_t)((code >> 24) & 0xFF)
                };
                (*env)->SetByteArrayRegion(env, result, 0, 4, (jbyte*)bytes);
            }
            LOGI("assembleInstruction: fallback assembled '%s' -> 0x%08x", assembly, code);
        } else {
            LOGE("assembleInstruction: fallback failed for '%s'", assembly);
        }
    }

    (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);
    return result;
}
#endif // 旧 fallback 结束

// ============================================================================
// 直接写入SO文件 (patch)
// ============================================================================

JNIEXPORT jint JNICALL
Java_com_example_anative_core_NativeInvoker_patchInstruction(JNIEnv *env, jclass clazz,
                                                            jstring jSoPath, jlong virtualOffset,
                                                            jstring jAssembly) {
    const char *soPath = (*env)->GetStringUTFChars(env, jSoPath, NULL);
    const char *assembly = (*env)->GetStringUTFChars(env, jAssembly, NULL);
    if (!soPath || !assembly) {
        if (soPath) (*env)->ReleaseStringUTFChars(env, jSoPath, soPath);
        if (assembly) (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);
        return -1;
    }

    LOGI("patchInstruction: file=%s offset=0x%llx asm='%s'",
         soPath, (unsigned long long)virtualOffset, assembly);

    // 调用 assembleInstruction 获取机器码
    jclass cls = clazz;
    jmethodID mid = (*env)->GetStaticMethodID(env, cls,
            "assembleInstruction", "(Ljava/lang/String;J)[B");
    jstring jAsm = (*env)->NewStringUTF(env, assembly);
    jbyteArray jBytes = NULL;
    if (mid && jAsm) {
        jBytes = (jbyteArray)(*env)->CallStaticObjectMethod(env, cls, mid, jAsm, (jlong)virtualOffset);
    }
    if (!jBytes) {
        LOGE("patchInstruction: failed to assemble '%s'", assembly);
        (*env)->ReleaseStringUTFChars(env, jSoPath, soPath);
        (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);
        if (jAsm) (*env)->DeleteLocalRef(env, jAsm);
        return -1;
    }

    jsize codeLen = (*env)->GetArrayLength(env, jBytes);
    jbyte *code = (*env)->GetByteArrayElements(env, jBytes, NULL);

    // 打开文件并写入
    FILE *fp = fopen(soPath, "r+b");
    if (!fp) {
        LOGE("patchInstruction: cannot open file %s: %s", soPath, strerror(errno));
        (*env)->ReleaseByteArrayElements(env, jBytes, code, JNI_ABORT);
        (*env)->DeleteLocalRef(env, jAsm);
        (*env)->ReleaseStringUTFChars(env, jSoPath, soPath);
        (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);
        return -1;
    }

    // 将虚拟偏移转为文件偏移
    off_t fileOffset = (off_t)virtualOffset;  // 简化处理，假设虚拟偏移等于文件偏移
    if (fseek(fp, fileOffset, SEEK_SET) != 0) {
        LOGE("patchInstruction: fseek failed: %s", strerror(errno));
        fclose(fp);
        (*env)->ReleaseByteArrayElements(env, jBytes, code, JNI_ABORT);
        (*env)->DeleteLocalRef(env, jAsm);
        (*env)->ReleaseStringUTFChars(env, jSoPath, soPath);
        (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);
        return -1;
    }

    size_t written = fwrite(code, 1, codeLen, fp);
    fclose(fp);

    (*env)->ReleaseByteArrayElements(env, jBytes, code, JNI_ABORT);
    (*env)->DeleteLocalRef(env, jAsm);
    (*env)->ReleaseStringUTFChars(env, jSoPath, soPath);
    (*env)->ReleaseStringUTFChars(env, jAssembly, assembly);

    if (written < 0) {
        LOGE("patchInstruction: fwrite failed: %s", strerror(errno));
        return -1;
    }

    LOGI("patchInstruction: successfully wrote %zu bytes at offset 0x%llx", written, (unsigned long long)fileOffset);
    return (jint)written;
}
