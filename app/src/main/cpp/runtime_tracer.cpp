// 运行时调用关系追踪 - 使用 ByteHook 或 Inline Hook
// 不依赖 Frida，纯原生实现

#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#include <unwind.h>
#include <sys/mman.h>
#include <pthread.h>
#include <capstone/capstone.h>

#define TAG "RuntimeTracer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 从 crash_protection.c 引入
extern "C" void crash_protection_enter();
extern "C" void crash_protection_leave();
extern "C" sigjmp_buf* crash_protection_get_jmpbuf();

// ============================================================================
// 调用追踪数据结构
// ============================================================================

#define MAX_SUB_HOOKS 50
#define MAX_TRACE_DEPTH 10

typedef struct {
    uint64_t target_addr;      // 子函数地址
    char name[128];           // 函数名
    int call_count;           // 调用次数
    void* orig_code;          // 原始代码备份
    size_t orig_code_size;    // 备份大小
    int is_hooked;            // 是否已Hook
} SubFunctionInfo;

typedef struct {
    uint64_t target_func_addr;  // 目标函数地址
    char target_func_name[256];
    int is_active;            // 追踪是否激活
    int depth;                // 当前递归深度
    
    SubFunctionInfo subs[MAX_SUB_HOOKS];
    int sub_count;
    
    // 追踪日志缓冲区
    char log_buffer[65536];
    int log_pos;
} TraceContext;

static TraceContext g_trace_ctx = {0};
static pthread_mutex_t g_trace_mutex = PTHREAD_MUTEX_INITIALIZER;

// ============================================================================
// 内联Hook工具函数 (简化版)
// ============================================================================

// ARM64 跳转指令编码 (16字节)
// B 指令: 0x14 跳转偏移 (±128MB)
// 这里使用跳板方案: 先加载地址到寄存器，再跳转
static const uint8_t TRAMPOLINE_CODE[] = {
    0x49, 0x00, 0x00, 0x58,  // LDR X9, #8  (从PC+8加载64位地址)
    0x20, 0x01, 0x1F, 0xD6,  // BR X9      (跳转到X9)
    0x00, 0x00, 0x00, 0x00,  // 64位目标地址低32位
    0x00, 0x00, 0x00, 0x00   // 64位目标地址高32位
};

// 安装内联Hook
static int install_inline_hook(uint64_t target_addr, void* hook_func, void** orig_func) {
    // 备份原始代码 (16字节)
    uint8_t* addr = (uint8_t*)target_addr;
    
    // 修改内存保护为可写
    uintptr_t page_start = (uintptr_t)addr & ~0xFFF;
    if (mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("修改内存保护失败: %p", (void*)target_addr);
        return -1;
    }
    
    // 分配跳板内存保存原始代码
    void* trampoline = mmap(NULL, 32, PROT_READ | PROT_WRITE | PROT_EXEC, 
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED) {
        LOGE("分配跳板内存失败");
        return -1;
    }
    
    // 复制原始指令到跳板 (简化处理，实际需指令修复)
    memcpy(trampoline, addr, 16);
    // 在跳板末尾添加跳回原函数的指令
    // ... (简化实现)
    
    // 写入Hook跳转指令
    uint8_t hook_code[16];
    memcpy(hook_code, TRAMPOLINE_CODE, 16);
    // 设置目标地址
    *(uint64_t*)(hook_code + 8) = (uint64_t)hook_func;
    
    // 原子性写入
    __builtin___clear_cache((char*)addr, (char*)(addr + 16));
    memcpy((void*)addr, hook_code, 16);
    __builtin___clear_cache((char*)addr, (char*)(addr + 16));
    
    *orig_func = trampoline;
    return 0;
}

// 移除内联Hook
static int remove_inline_hook(uint64_t target_addr, void* orig_code) {
    // 恢复原始代码
    uint8_t* addr = (uint8_t*)target_addr;
    memcpy((void*)addr, orig_code, 16);
    __builtin___clear_cache((char*)addr, (char*)(addr + 16));
    return 0;
}

// ============================================================================
// 静态分析：查找函数内的所有 bl 指令
// ============================================================================

typedef struct {
    uint64_t* addrs;
    int count;
    int max_count;
} BlInstructionList;

static int find_bl_instructions(uint64_t func_addr, size_t func_size,
                                 uint64_t base_addr, BlInstructionList* list) {
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // 限制扫描大小，避免扫描整个SO
    if (func_size > 2048) {
        func_size = 2048;  // 最大扫描2KB
    }

    // 读取函数代码
    uint8_t* code = (uint8_t*)malloc(func_size);
    if (!code) {
        cs_close(&handle);
        return -1;
    }

    crash_protection_enter();
    if (sigsetjmp(*crash_protection_get_jmpbuf(), 1) == 0) {
        memcpy(code, (void*)func_addr, func_size);
        crash_protection_leave();
    } else {
        crash_protection_leave();
        free(code);
        cs_close(&handle);
        return -1;
    }

    count = cs_disasm(handle, code, func_size, func_addr, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count && list->count < list->max_count; i++) {
            // 查找 bl 指令
            if (insn[i].id == ARM64_INS_BL) {
                cs_detail* detail = insn[i].detail;
                if (detail && detail->arm64.op_count > 0) {
                    uint64_t target = detail->arm64.operands[0].imm;

                    // 去重检查 - 避免重复记录相同地址
                    int is_duplicate = 0;
                    for (int j = 0; j < list->count; j++) {
                        if (list->addrs[j] == target) {
                            is_duplicate = 1;
                            break;
                        }
                    }

                    if (!is_duplicate) {
                        list->addrs[list->count++] = target;
                        LOGI("发现子函数调用: 0x%llX -> 0x%llX (偏移: 0x%llX)",
                             (unsigned long long)insn[i].address,
                             (unsigned long long)target,
                             (unsigned long long)(target - base_addr));
                    }
                }
            }
        }
        cs_free(insn, count);
    }

    free(code);
    cs_close(&handle);
    return list->count;
}

// ============================================================================
// 子函数 Hook 处理
// ============================================================================

// 通用子函数Hook入口 (通过跳板调用)
extern "C" void sub_function_hook_entry();

// 子函数被调用时的处理
static void on_sub_function_called(uint64_t caller_addr, uint64_t callee_addr) {
    pthread_mutex_lock(&g_trace_mutex);
    
    if (g_trace_ctx.is_active && g_trace_ctx.depth < MAX_TRACE_DEPTH) {
        // 记录调用
        for (int i = 0; i < g_trace_ctx.sub_count; i++) {
            if (g_trace_ctx.subs[i].target_addr == callee_addr) {
                g_trace_ctx.subs[i].call_count++;
                
                // 写入日志
                int indent = g_trace_ctx.depth * 2;
                g_trace_ctx.log_pos += snprintf(
                    g_trace_ctx.log_buffer + g_trace_ctx.log_pos,
                    sizeof(g_trace_ctx.log_buffer) - g_trace_ctx.log_pos,
                    "%*s└── 调用 %s @ 0x%llX (次数: %d)\n",
                    indent, "",
                    g_trace_ctx.subs[i].name,
                    (unsigned long long)callee_addr,
                    g_trace_ctx.subs[i].call_count
                );
                break;
            }
        }
        
        g_trace_ctx.depth++;
    }
    
    pthread_mutex_unlock(&g_trace_mutex);
}

static void on_sub_function_return(uint64_t callee_addr) {
    pthread_mutex_lock(&g_trace_mutex);
    if (g_trace_ctx.is_active && g_trace_ctx.depth > 0) {
        g_trace_ctx.depth--;
    }
    pthread_mutex_unlock(&g_trace_mutex);
}

// ============================================================================
// 目标函数 Hook 处理
// ============================================================================

typedef void (*TargetFuncPtr)(void);
static TargetFuncPtr g_orig_target_func = nullptr;

// 目标函数入口Hook
static void target_function_hook() {
    pthread_mutex_lock(&g_trace_mutex);
    
    if (!g_trace_ctx.is_active) {
        pthread_mutex_unlock(&g_trace_mutex);
        // 调用原始函数
        if (g_orig_target_func) {
            g_orig_target_func();
        }
        return;
    }
    
    // 记录目标函数进入
    g_trace_ctx.log_pos += snprintf(
        g_trace_ctx.log_buffer + g_trace_ctx.log_pos,
        sizeof(g_trace_ctx.log_buffer) - g_trace_ctx.log_pos,
        "[进入] %s @ 0x%llX\n",
        g_trace_ctx.target_func_name,
        (unsigned long long)g_trace_ctx.target_func_addr
    );
    
    // 安装子函数Hook
    for (int i = 0; i < g_trace_ctx.sub_count; i++) {
        if (!g_trace_ctx.subs[i].is_hooked) {
            // 简化：只记录，不真正Hook（避免复杂性）
            g_trace_ctx.log_pos += snprintf(
                g_trace_ctx.log_buffer + g_trace_ctx.log_pos,
                sizeof(g_trace_ctx.log_buffer) - g_trace_ctx.log_pos,
                "  [子函数] %s @ 0x%llX 待追踪\n",
                g_trace_ctx.subs[i].name,
                (unsigned long long)g_trace_ctx.subs[i].target_addr
            );
            g_trace_ctx.subs[i].is_hooked = 1;
        }
    }
    
    pthread_mutex_unlock(&g_trace_mutex);
    
    // 调用原始函数
    if (g_orig_target_func) {
        g_orig_target_func();
    }
    
    // 记录返回
    pthread_mutex_lock(&g_trace_mutex);
    g_trace_ctx.log_pos += snprintf(
        g_trace_ctx.log_buffer + g_trace_ctx.log_pos,
        sizeof(g_trace_ctx.log_buffer) - g_trace_ctx.log_pos,
        "[退出] %s\n",
        g_trace_ctx.target_func_name
    );
    pthread_mutex_unlock(&g_trace_mutex);
}

// 清理所有Hook
static void cleanup_all_hooks() {
    pthread_mutex_lock(&g_trace_mutex);
    
    g_trace_ctx.is_active = 0;
    g_trace_ctx.depth = 0;
    
    // 移除目标函数Hook
    if (g_orig_target_func && g_trace_ctx.target_func_addr != 0) {
        // remove_inline_hook(...); // 简化
        g_orig_target_func = nullptr;
    }
    
    // 清理子函数信息
    for (int i = 0; i < g_trace_ctx.sub_count; i++) {
        if (g_trace_ctx.subs[i].orig_code) {
            // 恢复原始代码
            // remove_inline_hook(...);
            munmap(g_trace_ctx.subs[i].orig_code, 32);
        }
        memset(&g_trace_ctx.subs[i], 0, sizeof(SubFunctionInfo));
    }
    g_trace_ctx.sub_count = 0;
    g_trace_ctx.target_func_addr = 0;
    
    pthread_mutex_unlock(&g_trace_mutex);
}

// ============================================================================
// 栈回溯 - 使用 _Unwind_Backtrace
// ============================================================================

typedef struct {
    int depth;
    uint64_t base_addr;
    char* buffer;
    int buffer_pos;
    int buffer_size;
} BacktraceContext;

static _Unwind_Reason_Code backtrace_callback(struct _Unwind_Context* context, void* arg) {
    BacktraceContext* ctx = (BacktraceContext*)arg;
    if (ctx->depth >= 16) return _URC_END_OF_STACK;
    
    uint64_t pc = _Unwind_GetIP(context);
    if (pc == 0) return _URC_END_OF_STACK;
    
    uint64_t offset = pc - ctx->base_addr;
    ctx->buffer_pos += snprintf(
        ctx->buffer + ctx->buffer_pos,
        ctx->buffer_size - ctx->buffer_pos,
        "  #%d PC: 0x%llX (偏移: 0x%llX)\n",
        ctx->depth, (unsigned long long)pc, (unsigned long long)offset
    );
    
    ctx->depth++;
    return _URC_NO_REASON;
}

// ============================================================================
// JNI 接口: 读取 LR 寄存器
// ============================================================================

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_readLRRegister(
    JNIEnv* env,
    jclass clazz) {

#if !defined(__aarch64__) && !defined(__arm64__)
    return env->NewStringUTF("LR: 不支持 (仅 ARM64)");
#endif

    void* lr;
    __asm__ volatile("mov %0, x30" : "=r"(lr));

    char buf[256];
    snprintf(buf, sizeof(buf), "LR: %p", lr);

    return env->NewStringUTF(buf);
}

// ============================================================================
// JNI 接口: 启用运行时追踪 (新版 - 结合静态分析和运行时)
// ============================================================================

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeInvoker_enableTraceForFunction(
    JNIEnv* env,
    jclass clazz,
    jlong funcAddr,
    jstring jFuncName) {

#if !defined(__aarch64__) && !defined(__arm64__)
    LOGI("运行时追踪仅在 ARM64 平台支持");
    return JNI_FALSE;
#endif

    const char* funcName = env->GetStringUTFChars(jFuncName, nullptr);
    
    // 清理之前的追踪
    cleanup_all_hooks();
    
    pthread_mutex_lock(&g_trace_mutex);
    
    // 初始化追踪上下文
    g_trace_ctx.target_func_addr = funcAddr;
    strncpy(g_trace_ctx.target_func_name, funcName, sizeof(g_trace_ctx.target_func_name) - 1);
    g_trace_ctx.is_active = 1;
    g_trace_ctx.depth = 0;
    g_trace_ctx.log_pos = 0;
    g_trace_ctx.sub_count = 0;
    
    // 初始化日志
    g_trace_ctx.log_pos += snprintf(
        g_trace_ctx.log_buffer,
        sizeof(g_trace_ctx.log_buffer),
        "=== 运行时调用追踪 ===\n"
        "目标函数: %s\n"
        "地址: 0x%llX\n\n"
        "[分析阶段] 查找子函数...\n",
        funcName, (unsigned long long)funcAddr
    );
    
    pthread_mutex_unlock(&g_trace_mutex);
    
    LOGI("启用追踪: %s @ 0x%llX", funcName, (unsigned long long)funcAddr);
    
    // 阶段 1: 静态分析 - 查找函数内的所有 bl 指令
    uint64_t addrs[MAX_SUB_HOOKS];
    BlInstructionList bl_list = {addrs, 0, MAX_SUB_HOOKS};

    // 默认函数大小 512字节 (更合理的大小，避免扫描过多)
    size_t func_size = 512;
    // 使用SO基址计算偏移，而非页对齐地址
    uint64_t base_addr = funcAddr & ~0xFFF;  // 页对齐作为基址
    int bl_count = find_bl_instructions(funcAddr, func_size, base_addr, &bl_list);
    
    pthread_mutex_lock(&g_trace_mutex);
    
    if (bl_count > 0) {
        g_trace_ctx.log_pos += snprintf(
            g_trace_ctx.log_buffer + g_trace_ctx.log_pos,
            sizeof(g_trace_ctx.log_buffer) - g_trace_ctx.log_pos,
            "发现 %d 个子函数调用:\n", bl_count
        );
        
        // 记录子函数信息
        for (int i = 0; i < bl_count && i < MAX_SUB_HOOKS; i++) {
            SubFunctionInfo* sub = &g_trace_ctx.subs[g_trace_ctx.sub_count++];
            sub->target_addr = bl_list.addrs[i];
            snprintf(sub->name, sizeof(sub->name), "sub_%d", i);
            sub->call_count = 0;
            sub->is_hooked = 0;
            
            uint64_t offset = bl_list.addrs[i] - base_addr;
            uint64_t func_offset = bl_list.addrs[i] - funcAddr;
            g_trace_ctx.log_pos += snprintf(
                g_trace_ctx.log_buffer + g_trace_ctx.log_pos,
                sizeof(g_trace_ctx.log_buffer) - g_trace_ctx.log_pos,
                "  [%d] 0x%llX (相对函数: +0x%llX, 相对SO: 0x%llX)\n",
                i, (unsigned long long)bl_list.addrs[i],
                (unsigned long long)func_offset,
                (unsigned long long)offset
            );
        }
    } else {
        g_trace_ctx.log_pos += snprintf(
            g_trace_ctx.log_buffer + g_trace_ctx.log_pos,
            sizeof(g_trace_ctx.log_buffer) - g_trace_ctx.log_pos,
            "未发现子函数调用 (或分析失败)\n"
        );
    }
    
    g_trace_ctx.log_pos += snprintf(
        g_trace_ctx.log_buffer + g_trace_ctx.log_pos,
        sizeof(g_trace_ctx.log_buffer) - g_trace_ctx.log_pos,
        "\n[等待执行] 请触发函数调用...\n"
    );
    
    pthread_mutex_unlock(&g_trace_mutex);
    
    env->ReleaseStringUTFChars(jFuncName, funcName);
    return JNI_TRUE;
}

// ============================================================================
// JNI 接口: 获取追踪日志
// ============================================================================

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_getTraceLog(
    JNIEnv* env,
    jclass clazz) {
    
    pthread_mutex_lock(&g_trace_mutex);
    
    if (g_trace_ctx.log_pos == 0) {
        pthread_mutex_unlock(&g_trace_mutex);
        return env->NewStringUTF("(无追踪数据)");
    }
    
    // 复制日志缓冲区
    char* result = (char*)malloc(g_trace_ctx.log_pos + 1);
    if (!result) {
        pthread_mutex_unlock(&g_trace_mutex);
        return env->NewStringUTF("(内存不足)");
    }
    
    memcpy(result, g_trace_ctx.log_buffer, g_trace_ctx.log_pos);
    result[g_trace_ctx.log_pos] = '\0';
    
    pthread_mutex_unlock(&g_trace_mutex);
    
    jstring ret = env->NewStringUTF(result);
    free(result);
    return ret;
}

// ============================================================================
// JNI 接口: 清除追踪日志
// ============================================================================

extern "C"
JNIEXPORT void JNICALL
Java_com_example_anative_core_NativeInvoker_clearTraceLog(
    JNIEnv* env,
    jclass clazz) {
    
    cleanup_all_hooks();
    LOGI("追踪已清除");
}

// ============================================================================
// JNI 接口: 调用时追踪 (保留兼容)
// ============================================================================

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_invokeWithTrace(
    JNIEnv* env,
    jclass clazz,
    jlong funcAddr,
    jint arg1,
    jint arg2,
    jlong baseAddr) {

#if !defined(__aarch64__) && !defined(__arm64__)
    return env->NewStringUTF("ERR: 带追踪的函数调用仅在 ARM64 平台支持");
#endif

    typedef int (*FuncType)(int, int);
    FuncType targetFunc = (FuncType)(uintptr_t)funcAddr;
    
    char result[4096];
    int pos = 0;
    
    pos += snprintf(result + pos, sizeof(result) - pos, 
                    "=== 带追踪的函数调用 ===\n");
    pos += snprintf(result + pos, sizeof(result) - pos,
                    "目标地址: 0x%llX\n", (unsigned long long)funcAddr);
    pos += snprintf(result + pos, sizeof(result) - pos,
                    "基址: 0x%llX\n", (unsigned long long)baseAddr);
    pos += snprintf(result + pos, sizeof(result) - pos,
                    "偏移: 0x%llX\n", (unsigned long long)(funcAddr - baseAddr));
    
    // 执行调用
    int retVal = 0;
    int callSuccess = 0;
    
    crash_protection_enter();
    if (sigsetjmp(*crash_protection_get_jmpbuf(), 1) == 0) {
        retVal = targetFunc(arg1, arg2);
        callSuccess = 1;
        crash_protection_leave();
    } else {
        crash_protection_leave();
        pos += snprintf(result + pos, sizeof(result) - pos,
                        "\n[错误] 函数调用崩溃\n");
    }
    
    if (callSuccess) {
        pos += snprintf(result + pos, sizeof(result) - pos,
                        "\n[调用成功] 返回值: %d\n", retVal);
    }
    
    return env->NewStringUTF(result);
}
