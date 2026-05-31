#include <jni.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#define TAG "CrashProtection"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 平台检测：动态执行仅在 ARM64 真机支持
#if defined(__aarch64__) || defined(__arm64__)
    #define PLATFORM_SUPPORTS_EXECUTION 1
    #define PLATFORM_NAME "ARM64"
#else
    #define PLATFORM_SUPPORTS_EXECUTION 0
    #define PLATFORM_NAME "X86/Other"
#endif

// ============================================================================
// 崩溃保护：sigsetjmp / siglongjmp
// ============================================================================

static __thread sigjmp_buf g_jmp_buf;
static __thread volatile int g_crash_signal = 0;
static __thread volatile int g_protection_active = 0;

static struct sigaction g_old_sigsegv;
static struct sigaction g_old_sigbus;
static struct sigaction g_old_sigill;
static struct sigaction g_old_sigabrt;
static struct sigaction g_old_sigfpe;

static void crash_signal_handler(int sig, siginfo_t *info, void *ucontext) {
    if (g_protection_active) {
        g_crash_signal = sig;
        LOGE("Caught signal %d during protected call, jumping to safety", sig);
        siglongjmp(g_jmp_buf, sig);
    } else {
        // 非保护区域，转发给原始处理器
        LOGE("Signal %d outside protected call, forwarding to original handler", sig);
        struct sigaction *old = NULL;
        switch (sig) {
            case SIGSEGV: old = &g_old_sigsegv; break;
            case SIGBUS:  old = &g_old_sigbus;  break;
            case SIGILL:  old = &g_old_sigill;  break;
            case SIGABRT: old = &g_old_sigabrt; break;
            case SIGFPE:  old = &g_old_sigfpe;  break;
        }
        if (old && old->sa_sigaction) {
            old->sa_sigaction(sig, info, ucontext);
        }
    }
}

static int install_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);

    int ret = 0;
    ret |= sigaction(SIGSEGV, &sa, &g_old_sigsegv);
    ret |= sigaction(SIGBUS,  &sa, &g_old_sigbus);
    ret |= sigaction(SIGILL,  &sa, &g_old_sigill);
    ret |= sigaction(SIGABRT, &sa, &g_old_sigabrt);
    ret |= sigaction(SIGFPE,  &sa, &g_old_sigfpe);

    if (ret == 0) {
        LOGI("Signal handlers installed successfully");
    } else {
        LOGE("Failed to install some signal handlers");
    }
    return ret == 0;
}

// 在保护模式下调用函数前设置
void crash_protection_enter() {
    g_crash_signal = 0;
    g_protection_active = 1;
}

void crash_protection_leave() {
    g_protection_active = 0;
}

int crash_protection_was_crash() {
    return g_crash_signal != 0;
}

int crash_protection_get_signal() {
    return g_crash_signal;
}

sigjmp_buf* crash_protection_get_jmpbuf() {
    return &g_jmp_buf;
}

const char* signal_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGBUS:  return "SIGBUS";
        case SIGILL:  return "SIGILL";
        case SIGABRT: return "SIGABRT";
        case SIGFPE:  return "SIGFPE";
        default:      return "UNKNOWN";
    }
}

// ============================================================================
// Hook exit/abort 函数 (使用ByteHook)
// ============================================================================

// ByteHook 接口
typedef void* bytehook_stub_t;
typedef int (*bytehook_hook_func_t)(const char *caller_path_name,
                                     const char *callee_path_name,
                                     const char *sym_name,
                                     void *new_func,
                                     bytehook_stub_t *stub,
                                     void *arg);

static bytehook_hook_func_t g_bytehook_hook = NULL;
static void *g_bytehook_handle = NULL;

// 外部声明（crash保护相关的jump）
extern sigjmp_buf *crash_protection_get_jmpbuf(void);

// Hook替代函数 - 用longjmp跳转而不是返回
static void fake_exit(int status) {
    LOGI("[ByteHook] Intercepted exit(%d) - jumping to safety", status);
    sigjmp_buf *jb = crash_protection_get_jmpbuf();
    if (jb) {
        siglongjmp(*jb, 42);  // 跳回安全点
    }
    // 如果不在保护上下文中，死循环等待调试
    while(1) { sleep(1); }
}

static void fake__exit(int status) {
    LOGI("[ByteHook] Intercepted _exit(%d) - jumping to safety", status);
    sigjmp_buf *jb = crash_protection_get_jmpbuf();
    if (jb) {
        siglongjmp(*jb, 43);
    }
    while(1) { sleep(1); }
}

static void fake_abort(void) {
    LOGI("[ByteHook] Intercepted abort() - jumping to safety");
    sigjmp_buf *jb = crash_protection_get_jmpbuf();
    if (jb) {
        siglongjmp(*jb, 44);
    }
    while(1) { sleep(1); }
}

static int init_bytehook() {
    // 尝试初始化ByteHook
    g_bytehook_handle = dlopen("libbytehook.so", RTLD_NOW);
    if (!g_bytehook_handle) {
        LOGI("ByteHook not available: %s", dlerror());
        return 0;
    }

    // ByteHook初始化
    typedef int (*bytehook_init_func_t)(int mode, int debug);
    bytehook_init_func_t init = (bytehook_init_func_t) dlsym(g_bytehook_handle, "bytehook_init");
    if (init) {
        init(0, 0); // BYTEHOOK_MODE_AUTOMATIC = 0
    }

    g_bytehook_hook = (bytehook_hook_func_t) dlsym(g_bytehook_handle, "bytehook_hook_single");
    if (!g_bytehook_hook) {
        LOGI("ByteHook hook function not found");
        return 0;
    }

    LOGI("ByteHook initialized successfully");
    return 1;
}

static void hook_exit_functions() {
    if (!g_bytehook_hook) return;

    // Hook所有调用者对exit/abort的PLT调用
    // 注意: 这里我们hook的是目标SO可能调用的系统函数
    bytehook_stub_t stub = NULL;

    g_bytehook_hook(NULL, "libc.so", "exit", (void*)fake_exit, &stub, NULL);
    LOGI("Hooked exit()");

    g_bytehook_hook(NULL, "libc.so", "_exit", (void*)fake__exit, &stub, NULL);
    LOGI("Hooked _exit()");

    g_bytehook_hook(NULL, "libc.so", "abort", (void*)fake_abort, &stub, NULL);
    LOGI("Hooked abort()");
}

// ============================================================================
// RegisterNatives Hook (高级功能)
// ============================================================================

typedef struct {
    char className[256];
    char name[256];
    char signature[512];
    unsigned long address;
} CapturedRegistration;

#define MAX_CAPTURED 512
static CapturedRegistration g_captured[MAX_CAPTURED];
static int g_captured_count = 0;

// 原始RegisterNatives指针与hook偏移（供unhook恢复用）
typedef jint (*RegisterNatives_t)(JNIEnv*, jclass, const JNINativeMethod*, jint);
static RegisterNatives_t g_orig_RegisterNatives = NULL;
static size_t g_reg_hook_offset = 0;

// 前向声明（hook_FindClass用到的原始指针）
typedef jclass (*FindClass_t)(JNIEnv*, const char*);
static FindClass_t g_orig_FindClass = NULL;
typedef jmethodID (*GetMethodID_t)(JNIEnv*, jclass, const char*, const char*);
static GetMethodID_t g_orig_GetMethodID = NULL;
static jclass g_dummy_class = NULL;

// 记录最近一次 FindClass 请求的类名（用于 dummy class 的 RegisterNatives 捕获）
static __thread char g_last_findclass_name[256] = {0};

// 获取jclass的类名（使用原始JNI函数，避免递归进hook）
static void get_class_name(JNIEnv *env, jclass clazz, char *buf, size_t bufSize) {
    buf[0] = '\0';
    // 如果是dummy class，使用最近FindClass记录的名字
    if (clazz == g_dummy_class) {
        strncpy(buf, g_last_findclass_name, bufSize - 1);
        buf[bufSize - 1] = '\0';
        return;
    }
    // 使用原始函数避免递归
    FindClass_t origFind = g_orig_FindClass ? g_orig_FindClass : (*env)->FindClass;
    GetMethodID_t origGetMethod = g_orig_GetMethodID ? g_orig_GetMethodID : (*env)->GetMethodID;
    jclass classClass = origFind(env, "java/lang/Class");
    if (!classClass) { (*env)->ExceptionClear(env); return; }
    jmethodID getNameId = origGetMethod(env, classClass, "getName", "()Ljava/lang/String;");
    if (!getNameId) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, classClass); return; }
    jstring jname = (jstring)(*env)->CallObjectMethod(env, clazz, getNameId);
    if (!jname) { (*env)->ExceptionClear(env); (*env)->DeleteLocalRef(env, classClass); return; }
    const char *cname = (*env)->GetStringUTFChars(env, jname, NULL);
    if (cname) {
        strncpy(buf, cname, bufSize - 1);
        buf[bufSize - 1] = '\0';
        (*env)->ReleaseStringUTFChars(env, jname, cname);
    }
    (*env)->DeleteLocalRef(env, jname);
    (*env)->DeleteLocalRef(env, classClass);
}

static jint hook_RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods) {
    LOGI("RegisterNatives called with %d methods", nMethods);

    // 获取类名
    char className[256] = {0};
    get_class_name(env, clazz, className, sizeof(className));
    LOGI("  Class: %s", className);

    for (int i = 0; i < nMethods && g_captured_count < MAX_CAPTURED; i++) {
        CapturedRegistration *cap = &g_captured[g_captured_count];
        strncpy(cap->className, className, sizeof(cap->className) - 1);
        strncpy(cap->name, methods[i].name, sizeof(cap->name) - 1);
        strncpy(cap->signature, methods[i].signature, sizeof(cap->signature) - 1);
        cap->address = (unsigned long) methods[i].fnPtr;
        g_captured_count++;

        LOGI("  Captured: %s.%s %s @ %p", className, methods[i].name, methods[i].signature, methods[i].fnPtr);
    }

    // 不转发：仅捕获，调用结束后 Java 层立即调用 unhookRegisterNatives
    return 0;
}

// ============================================================================
// FindClass Hook (解决第三方SO的ClassNotFoundException崩溃)
// ============================================================================

// g_orig_FindClass, g_orig_GetMethodID, g_dummy_class 已在前面声明
static jobject g_app_classloader = NULL;  // 应用的ClassLoader

// 设置应用的ClassLoader（从Java层传入）
void set_app_classloader(JNIEnv *env, jobject loader) {
    if (g_app_classloader) {
        (*env)->DeleteGlobalRef(env, g_app_classloader);
    }
    g_app_classloader = (*env)->NewGlobalRef(env, loader);
    LOGI("App ClassLoader set: %p", g_app_classloader);
}

// 已失败类名缓存：避免重复查找导致无限循环
#define MAX_FAILED_CLASSES 128
static char g_failed_classes[MAX_FAILED_CLASSES][256];
static int g_failed_class_count = 0;

static int is_class_failed(const char *name) {
    for (int i = 0; i < g_failed_class_count; i++) {
        if (strcmp(g_failed_classes[i], name) == 0) return 1;
    }
    return 0;
}

static void add_failed_class(const char *name) {
    if (g_failed_class_count < MAX_FAILED_CLASSES) {
        strncpy(g_failed_classes[g_failed_class_count], name, 255);
        g_failed_classes[g_failed_class_count][255] = '\0';
        g_failed_class_count++;
    }
}

// 重入保护
static __thread int g_in_hook_findclass = 0;

static jclass hook_FindClass(JNIEnv *env, const char *name) {
    // 已知失败的类：直接返回dummy，不做任何JNI调用
    if (is_class_failed(name)) {
        // 更新 last_findclass_name 以便 RegisterNatives 获取类名
        strncpy(g_last_findclass_name, name, sizeof(g_last_findclass_name) - 1);
        g_last_findclass_name[sizeof(g_last_findclass_name) - 1] = '\0';
        for (int i = 0; g_last_findclass_name[i]; i++) {
            if (g_last_findclass_name[i] == '/') g_last_findclass_name[i] = '.';
        }
        (*env)->ExceptionClear(env);
        return g_dummy_class;
    }

    // 重入时：只走原始FindClass
    if (g_in_hook_findclass) {
        if (g_orig_FindClass) {
            jclass real = g_orig_FindClass(env, name);
            if (real) return real;
            (*env)->ExceptionClear(env);
        }
        return g_dummy_class;
    }

    LOGD("FindClass called for: %s", name);

    // 1. 先尝试真正的FindClass（系统类）
    if (g_orig_FindClass) {
        jclass real = g_orig_FindClass(env, name);
        if (real) {
            return real;
        }
        (*env)->ExceptionClear(env);
    }

    // 2. 尝试用应用的ClassLoader加载（APK中的类）
    if (g_app_classloader && g_orig_FindClass) {
        char dot_name[256];
        strncpy(dot_name, name, sizeof(dot_name) - 1);
        dot_name[sizeof(dot_name) - 1] = '\0';
        for (int i = 0; dot_name[i]; i++) {
            if (dot_name[i] == '/') dot_name[i] = '.';
        }

        g_in_hook_findclass = 1;

        jstring jname = (*env)->NewStringUTF(env, dot_name);
        // 直接使用原始 JNI 函数，避免递归 hook
        jclass classLoaderClass = (*env)->FindClass(env, "java/lang/ClassLoader");
        if (classLoaderClass) {
            jmethodID loadClass = (*env)->GetMethodID(env, classLoaderClass, "loadClass",
                                                       "(Ljava/lang/String;)Ljava/lang/Class;");
            if (loadClass) {
                jobject cls = (*env)->CallObjectMethod(env, g_app_classloader, loadClass, jname);
                if (cls && !(*env)->ExceptionCheck(env)) {
                    LOGI("  -> found via ClassLoader: %s", name);
                    (*env)->DeleteLocalRef(env, jname);
                    (*env)->DeleteLocalRef(env, classLoaderClass);
                    g_in_hook_findclass = 0;
                    return (jclass)cls;
                }
                (*env)->ExceptionClear(env);
            }
        }
        (*env)->DeleteLocalRef(env, jname);
        if (classLoaderClass) (*env)->DeleteLocalRef(env, classLoaderClass);

        g_in_hook_findclass = 0;
    }

    // 3. 全部失败 → 加入失败缓存 + 返回dummy
    add_failed_class(name);

    strncpy(g_last_findclass_name, name, sizeof(g_last_findclass_name) - 1);
    g_last_findclass_name[sizeof(g_last_findclass_name) - 1] = '\0';
    for (int i = 0; g_last_findclass_name[i]; i++) {
        if (g_last_findclass_name[i] == '/') g_last_findclass_name[i] = '.';
    }
    LOGI("  -> returning dummy class for: %s (cached)", g_last_findclass_name);
    (*env)->ExceptionClear(env);
    return g_dummy_class;
}

// g_orig_GetMethodID 已在前面声明
static jmethodID g_dummy_method = (jmethodID)0xDEAD0001;

static jmethodID hook_GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    LOGD("GetMethodID called: %s %s", name, sig);

    // 如果是dummy class，返回dummy method
    if (clazz == g_dummy_class) {
        LOGI("  -> returning dummy method");
        return g_dummy_method;
    }

    if (g_orig_GetMethodID) {
        return g_orig_GetMethodID(env, clazz, name, sig);
    }
    return NULL;
}

typedef jfieldID (*GetFieldID_t)(JNIEnv*, jclass, const char*, const char*);
static GetFieldID_t g_orig_GetFieldID = NULL;
static jfieldID g_dummy_field = (jfieldID)0xDEAD0002;

static jfieldID hook_GetFieldID(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    LOGD("GetFieldID called: %s %s", name, sig);

    if (clazz == g_dummy_class) {
        LOGI("  -> returning dummy field");
        return g_dummy_field;
    }

    if (g_orig_GetFieldID) {
        return g_orig_GetFieldID(env, clazz, name, sig);
    }
    return NULL;
}

// --- GetStaticMethodID / GetStaticFieldID hooks ---

typedef jmethodID (*GetStaticMethodID_t)(JNIEnv*, jclass, const char*, const char*);
static GetStaticMethodID_t g_orig_GetStaticMethodID = NULL;

static jmethodID hook_GetStaticMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    LOGD("GetStaticMethodID called: %s %s", name, sig);
    if (clazz == g_dummy_class) {
        return g_dummy_method;
    }
    if (g_orig_GetStaticMethodID) {
        jmethodID real = g_orig_GetStaticMethodID(env, clazz, name, sig);
        if (real) return real;
        (*env)->ExceptionClear(env);
    }
    return g_dummy_method;
}

typedef jfieldID (*GetStaticFieldID_t)(JNIEnv*, jclass, const char*, const char*);
static GetStaticFieldID_t g_orig_GetStaticFieldID = NULL;

static jfieldID hook_GetStaticFieldID(JNIEnv *env, jclass clazz, const char *name, const char *sig) {
    LOGD("GetStaticFieldID called: %s %s", name, sig);
    if (clazz == g_dummy_class) {
        return g_dummy_field;
    }
    if (g_orig_GetStaticFieldID) {
        jfieldID real = g_orig_GetStaticFieldID(env, clazz, name, sig);
        if (real) return real;
        (*env)->ExceptionClear(env);
    }
    return g_dummy_field;
}

// --- Call*Method hooks: 检测 dummy method ID, 安全返回 ---
// 如果 methodID 是 dummy, 直接返回默认值, 不调用 ART (避免解引用 0xDEAD0001 崩溃)

#define IS_DUMMY_METHOD(mid) ((mid) == g_dummy_method)

// CallVoidMethod (variadic → 通过 CallVoidMethodV hook)
typedef void (*CallVoidMethodV_t)(JNIEnv*, jobject, jmethodID, va_list);
static CallVoidMethodV_t g_orig_CallVoidMethodV = NULL;
static void hook_CallVoidMethodV(JNIEnv *env, jobject obj, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallVoidMethodV: dummy method, skip"); return; }
    if (g_orig_CallVoidMethodV) g_orig_CallVoidMethodV(env, obj, mid, args);
}

typedef jobject (*CallObjectMethodV_t)(JNIEnv*, jobject, jmethodID, va_list);
static CallObjectMethodV_t g_orig_CallObjectMethodV = NULL;
static jobject hook_CallObjectMethodV(JNIEnv *env, jobject obj, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallObjectMethodV: dummy method, return NULL"); return NULL; }
    if (g_orig_CallObjectMethodV) return g_orig_CallObjectMethodV(env, obj, mid, args);
    return NULL;
}

typedef jint (*CallIntMethodV_t)(JNIEnv*, jobject, jmethodID, va_list);
static CallIntMethodV_t g_orig_CallIntMethodV = NULL;
static jint hook_CallIntMethodV(JNIEnv *env, jobject obj, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallIntMethodV: dummy method, return 0"); return 0; }
    if (g_orig_CallIntMethodV) return g_orig_CallIntMethodV(env, obj, mid, args);
    return 0;
}

typedef jboolean (*CallBooleanMethodV_t)(JNIEnv*, jobject, jmethodID, va_list);
static CallBooleanMethodV_t g_orig_CallBooleanMethodV = NULL;
static jboolean hook_CallBooleanMethodV(JNIEnv *env, jobject obj, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallBooleanMethodV: dummy method, return false"); return JNI_FALSE; }
    if (g_orig_CallBooleanMethodV) return g_orig_CallBooleanMethodV(env, obj, mid, args);
    return JNI_FALSE;
}

typedef jlong (*CallLongMethodV_t)(JNIEnv*, jobject, jmethodID, va_list);
static CallLongMethodV_t g_orig_CallLongMethodV = NULL;
static jlong hook_CallLongMethodV(JNIEnv *env, jobject obj, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallLongMethodV: dummy method, return 0"); return 0; }
    if (g_orig_CallLongMethodV) return g_orig_CallLongMethodV(env, obj, mid, args);
    return 0;
}

// CallStatic* 系列
typedef void (*CallStaticVoidMethodV_t)(JNIEnv*, jclass, jmethodID, va_list);
static CallStaticVoidMethodV_t g_orig_CallStaticVoidMethodV = NULL;
static void hook_CallStaticVoidMethodV(JNIEnv *env, jclass cls, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallStaticVoidMethodV: dummy method, skip"); return; }
    if (g_orig_CallStaticVoidMethodV) g_orig_CallStaticVoidMethodV(env, cls, mid, args);
}

typedef jobject (*CallStaticObjectMethodV_t)(JNIEnv*, jclass, jmethodID, va_list);
static CallStaticObjectMethodV_t g_orig_CallStaticObjectMethodV = NULL;
static jobject hook_CallStaticObjectMethodV(JNIEnv *env, jclass cls, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallStaticObjectMethodV: dummy method, return NULL"); return NULL; }
    if (g_orig_CallStaticObjectMethodV) return g_orig_CallStaticObjectMethodV(env, cls, mid, args);
    return NULL;
}

typedef jint (*CallStaticIntMethodV_t)(JNIEnv*, jclass, jmethodID, va_list);
static CallStaticIntMethodV_t g_orig_CallStaticIntMethodV = NULL;
static jint hook_CallStaticIntMethodV(JNIEnv *env, jclass cls, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallStaticIntMethodV: dummy method, return 0"); return 0; }
    if (g_orig_CallStaticIntMethodV) return g_orig_CallStaticIntMethodV(env, cls, mid, args);
    return 0;
}

typedef jboolean (*CallStaticBooleanMethodV_t)(JNIEnv*, jclass, jmethodID, va_list);
static CallStaticBooleanMethodV_t g_orig_CallStaticBooleanMethodV = NULL;
static jboolean hook_CallStaticBooleanMethodV(JNIEnv *env, jclass cls, jmethodID mid, va_list args) {
    if (IS_DUMMY_METHOD(mid)) { LOGI("CallStaticBooleanMethodV: dummy, return false"); return JNI_FALSE; }
    if (g_orig_CallStaticBooleanMethodV) return g_orig_CallStaticBooleanMethodV(env, cls, mid, args);
    return JNI_FALSE;
}

// --- GetObjectClass hook: 对 dummy 对象返回 dummy class ---
typedef jclass (*GetObjectClass_t)(JNIEnv*, jobject);
static GetObjectClass_t g_orig_GetObjectClass = NULL;
static jclass hook_GetObjectClass(JNIEnv *env, jobject obj) {
    if (g_orig_GetObjectClass) {
        jclass cls = g_orig_GetObjectClass(env, obj);
        if (cls) return cls;
        (*env)->ExceptionClear(env);
    }
    return g_dummy_class;
}

// Hook JNIEnv 函数表中的指定函数
static void hook_jni_func(JNIEnv *env, void **func_ptr, void *new_func, void **orig_ptr, const char *name) {
    if (!func_ptr || !new_func) return;

    // mprotect 修改权限
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)func_ptr & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) != 0) {
        LOGE("mprotect failed for %s", name);
        return;
    }

    // 保存原函数
    if (orig_ptr) *orig_ptr = *func_ptr;

    // 写入新函数
    *func_ptr = new_func;

    // 恢复只读（可选，这里保持可写以简化）
    LOGI("Hooked JNIEnv->%s", name);
}

JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeInvoker_hookFindClass(JNIEnv *env, jclass clazz) {
    // 防止重复hook：第二次调用时 g_orig_FindClass 会被设为 hook_FindClass 导致死循环
    if (g_orig_FindClass) {
        LOGI("FindClass hook already installed, skipping");
        return JNI_TRUE;
    }

    // 创建 dummy class: 使用当前类作为替身
    g_dummy_class = (*env)->NewGlobalRef(env, clazz);
    if (!g_dummy_class) {
        LOGE("Failed to create dummy class");
        return JNI_FALSE;
    }

    // 获取 JNIEnv 函数表基址
    void **vtable = *(void ***)env;

    // 计算各函数偏移并hook
    // FindClass 偏移 = (char*)&((*env)->FindClass) - (char*)(*env)
    size_t offset_FindClass = (char*)&((*env)->FindClass) - (char*)(*env);
    hook_jni_func(env, vtable + offset_FindClass/sizeof(void*),
                  (void*)hook_FindClass, (void**)&g_orig_FindClass, "FindClass");

    // GetMethodID 偏移
    size_t offset_GetMethodID = (char*)&((*env)->GetMethodID) - (char*)(*env);
    hook_jni_func(env, vtable + offset_GetMethodID/sizeof(void*),
                  (void*)hook_GetMethodID, (void**)&g_orig_GetMethodID, "GetMethodID");

    // GetFieldID 偏移
    size_t offset_GetFieldID = (char*)&((*env)->GetFieldID) - (char*)(*env);
    hook_jni_func(env, vtable + offset_GetFieldID/sizeof(void*),
                  (void*)hook_GetFieldID, (void**)&g_orig_GetFieldID, "GetFieldID");

    // GetStaticMethodID
    size_t offset_GetStaticMethodID = (char*)&((*env)->GetStaticMethodID) - (char*)(*env);
    hook_jni_func(env, vtable + offset_GetStaticMethodID/sizeof(void*),
                  (void*)hook_GetStaticMethodID, (void**)&g_orig_GetStaticMethodID, "GetStaticMethodID");

    // GetStaticFieldID
    size_t offset_GetStaticFieldID = (char*)&((*env)->GetStaticFieldID) - (char*)(*env);
    hook_jni_func(env, vtable + offset_GetStaticFieldID/sizeof(void*),
                  (void*)hook_GetStaticFieldID, (void**)&g_orig_GetStaticFieldID, "GetStaticFieldID");

    // GetObjectClass
    size_t offset_GetObjectClass = (char*)&((*env)->GetObjectClass) - (char*)(*env);
    hook_jni_func(env, vtable + offset_GetObjectClass/sizeof(void*),
                  (void*)hook_GetObjectClass, (void**)&g_orig_GetObjectClass, "GetObjectClass");

    // Call*MethodV 系列 (variadic 版本通过 V 版本实现)
    size_t offset;
    offset = (char*)&((*env)->CallVoidMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallVoidMethodV, (void**)&g_orig_CallVoidMethodV, "CallVoidMethodV");

    offset = (char*)&((*env)->CallObjectMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallObjectMethodV, (void**)&g_orig_CallObjectMethodV, "CallObjectMethodV");

    offset = (char*)&((*env)->CallIntMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallIntMethodV, (void**)&g_orig_CallIntMethodV, "CallIntMethodV");

    offset = (char*)&((*env)->CallBooleanMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallBooleanMethodV, (void**)&g_orig_CallBooleanMethodV, "CallBooleanMethodV");

    offset = (char*)&((*env)->CallLongMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallLongMethodV, (void**)&g_orig_CallLongMethodV, "CallLongMethodV");

    offset = (char*)&((*env)->CallStaticVoidMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallStaticVoidMethodV, (void**)&g_orig_CallStaticVoidMethodV, "CallStaticVoidMethodV");

    offset = (char*)&((*env)->CallStaticObjectMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallStaticObjectMethodV, (void**)&g_orig_CallStaticObjectMethodV, "CallStaticObjectMethodV");

    offset = (char*)&((*env)->CallStaticIntMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallStaticIntMethodV, (void**)&g_orig_CallStaticIntMethodV, "CallStaticIntMethodV");

    offset = (char*)&((*env)->CallStaticBooleanMethodV) - (char*)(*env);
    hook_jni_func(env, vtable + offset/sizeof(void*), (void*)hook_CallStaticBooleanMethodV, (void**)&g_orig_CallStaticBooleanMethodV, "CallStaticBooleanMethodV");

    LOGI("JNI hooks installed - FindClass/Get*ID/Call*Method/GetObjectClass all hooked");
    return JNI_TRUE;
}

// ============================================================================
// JNI 接口
// ============================================================================

JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeInvoker_initCrashProtection(JNIEnv *env, jclass clazz) {
    LOGI("Initializing crash protection...");

    int ok = install_signal_handlers();

    // 尝试初始化ByteHook并hook exit函数
    if (init_bytehook()) {
        hook_exit_functions();
    }

    // 安装 FindClass hook (让第三方SO的FindClass不崩溃)
    Java_com_example_anative_core_NativeInvoker_hookFindClass(env, clazz);

    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeInvoker_hookRegisterNatives(JNIEnv *env, jclass clazz) {
    // 防止重复hook
    if (g_orig_RegisterNatives) {
        LOGI("RegisterNatives hook already installed, skipping");
        return JNI_TRUE;
    }

    // 保存原始RegisterNatives
    g_orig_RegisterNatives = (*env)->RegisterNatives;

    // 计算RegisterNatives在函数表中的偏移（同时保存供unhook使用）
    const void *table_base = (const void *)(*env);
    size_t offset = (const char *)&((*env)->RegisterNatives) - (const char *)table_base;
    g_reg_hook_offset = offset;
    void *target = (char *)(*(void **)env) + offset;

    // 函数表可能在只读内存页，需要先用mprotect修改权限
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)target & ~(page_size - 1));
    if (mprotect(page_start, page_size * 2, PROT_READ | PROT_WRITE) != 0) {
        LOGE("mprotect failed for JNIEnv table, cannot hook RegisterNatives");
        return JNI_FALSE;
    }

    RegisterNatives_t new_fn = hook_RegisterNatives;
    memcpy(target, &new_fn, sizeof(new_fn));

    // 恢复只读保护
    mprotect(page_start, page_size * 2, PROT_READ);

    LOGI("RegisterNatives hooked via JNIEnv table (offset=%zu)", offset);
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_com_example_anative_core_NativeInvoker_unhookRegisterNatives(JNIEnv *env, jclass clazz) {
    if (!g_orig_RegisterNatives || g_reg_hook_offset == 0) {
        LOGI("unhookRegisterNatives: not hooked, skip");
        return;
    }
    void *target = (char *)(*(void **)env) + g_reg_hook_offset;
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)target & ~(page_size - 1));
    if (mprotect(page_start, page_size * 2, PROT_READ | PROT_WRITE) != 0) {
        LOGE("unhook mprotect failed");
        return;
    }
    memcpy(target, &g_orig_RegisterNatives, sizeof(g_orig_RegisterNatives));
    mprotect(page_start, page_size * 2, PROT_READ);
    g_orig_RegisterNatives = NULL;
    g_reg_hook_offset = 0;
    LOGI("RegisterNatives unhooked, WebView safe");
}

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_getCapturedRegistrations(JNIEnv *env, jclass clazz) {
    // 格式: className|name|signature|address\n...
    char buffer[MAX_CAPTURED * 1024];
    buffer[0] = '\0';
    int offset = 0;

    for (int i = 0; i < g_captured_count; i++) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                          "%s|%s|%s|0x%lx\n",
                          g_captured[i].className,
                          g_captured[i].name,
                          g_captured[i].signature,
                          g_captured[i].address);
    }

    return (*env)->NewStringUTF(env, buffer);
}

JNIEXPORT void JNICALL
Java_com_example_anative_core_NativeInvoker_clearCapturedRegistrations(JNIEnv *env, jclass clazz) {
    g_captured_count = 0;
    memset(g_captured, 0, sizeof(g_captured));
    LOGI("Cleared captured registrations");
}

// ============================================================================
// callJniOnLoad - 调用目标SO的JNI_OnLoad
// ============================================================================

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_callJniOnLoad(JNIEnv *env, jclass clazz,
                                                           jlong handle, jstring jSymbol,
                                                           jstring jMaxCapture, jstring jPageSize) {
#if !PLATFORM_SUPPORTS_EXECUTION
    return (*env)->NewStringUTF(env, "ERR: JNI_OnLoad 执行仅在 ARM64 真机支持，当前平台 (" PLATFORM_NAME ") 仅支持静态分析");
#endif

    if (handle == 0) {
        return (*env)->NewStringUTF(env, "ERR:handle is null");
    }

    // 直接使用云端解密后的字符串
    char symbol[32] = {0};
    if (jSymbol) {
        const char *sym = (*env)->GetStringUTFChars(env, jSymbol, NULL);
        strncpy(symbol, sym, 31);
        (*env)->ReleaseStringUTFChars(env, jSymbol, sym);
    } else {
        // 没有云端数据，自然失败
        return (*env)->NewStringUTF(env, "ERR:missing cloud data");
    }

    // 查找 JNI_OnLoad
    typedef jint (*JNI_OnLoad_t)(JavaVM*, void*);
    JNI_OnLoad_t onload = (JNI_OnLoad_t)dlsym((void*)(uintptr_t)handle, symbol);

    if (!onload) {
        LOGI("No JNI_OnLoad found in target SO");
        return (*env)->NewStringUTF(env, "ERR:JNI_OnLoad not found in this SO");
    }

    // 使用云端配置的MAX_CAPTURED大小
    int max_capture = 256;  // 默认值
    if (jMaxCapture) {
        const char *cap = (*env)->GetStringUTFChars(env, jMaxCapture, NULL);
        max_capture = atoi(cap);
        (*env)->ReleaseStringUTFChars(env, jMaxCapture, cap);
    }

    // 使用云端配置的page_size
    long page_size = 4096;  // 默认值
    if (jPageSize) {
        const char *ps = (*env)->GetStringUTFChars(env, jPageSize, NULL);
        page_size = atol(ps);
        (*env)->ReleaseStringUTFChars(env, jPageSize, ps);
    }

    LOGI("Found JNI_OnLoad at %p, calling...", onload);

    // 获取JavaVM
    JavaVM *vm = NULL;
    (*env)->GetJavaVM(env, &vm);
    if (!vm) {
        return (*env)->NewStringUTF(env, "ERR:cannot get JavaVM");
    }

    // 清除旧的捕获数据
    g_captured_count = 0;

    // 调用 JNI_OnLoad (崩溃保护)
    crash_protection_enter();
    if (sigsetjmp(*crash_protection_get_jmpbuf(), 1) == 0) {
        jint version = onload(vm, NULL);
        crash_protection_leave();
        LOGI("JNI_OnLoad returned version: %d, captured %d registrations", version, g_captured_count);

        char result[128];
        snprintf(result, sizeof(result), "OK:%d|%d", version, g_captured_count);
        return (*env)->NewStringUTF(env, result);
    } else {
        crash_protection_leave();
        int sig = crash_protection_get_signal();
        LOGE("JNI_OnLoad crashed with signal %d (%s)", sig, signal_name(sig));

        char result[128];
        snprintf(result, sizeof(result), "CRASH:%s|%d", signal_name(sig), g_captured_count);
        return (*env)->NewStringUTF(env, result);
    }
}

// ============================================================================
// JNI: 设置应用的ClassLoader，用于hook_FindClass加载APK中的类
// ============================================================================
JNIEXPORT void JNICALL
Java_com_example_anative_core_NativeInvoker_setClassLoader(JNIEnv *env, jclass clazz, jobject loader) {
    set_app_classloader(env, loader);
}

// ============================================================================
// callCapturedNative - 调用捕获到的动态注册函数
// 自动注入 JNIEnv* + jclass, 根据签名解析剩余参数
// ============================================================================

// 解析JNI签名中的参数类型，返回参数个数（不含 env 和 jclass）
// types[] 填入: 'Z','B','S','I','J','F','D','L','[' 等
static int parse_jni_params(const char *sig, char *types, int max_types) {
    int count = 0;
    const char *p = sig;
    if (*p != '(') return 0;
    p++; // skip '('
    while (*p && *p != ')' && count < max_types) {
        if (*p == 'Z' || *p == 'B' || *p == 'S' || *p == 'I' ||
            *p == 'J' || *p == 'F' || *p == 'D') {
            types[count++] = *p++;
        } else if (*p == 'L') {
            types[count++] = 'L';
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
        } else if (*p == '[') {
            types[count++] = '[';
            // 跳过数组元素类型
            p++;
            if (*p == 'L') {
                while (*p && *p != ';') p++;
                if (*p == ';') p++;
            } else if (*p) {
                p++;
            }
        } else {
            p++;
        }
    }
    return count;
}

// 解析JNI签名的返回类型
static char parse_jni_return(const char *sig) {
    const char *p = strchr(sig, ')');
    if (p && *(p+1)) return *(p+1);
    return 'V';
}

JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_callCapturedNative(
        JNIEnv *env, jclass clazz,
        jint index, jobjectArray jParamValues) {

#if !PLATFORM_SUPPORTS_EXECUTION
    return (*env)->NewStringUTF(env, "ERR: 调用 native 函数仅在 ARM64 真机支持，当前平台 (" PLATFORM_NAME ") 仅支持静态分析");
#endif

    char result[2048];

    if (index < 0 || index >= g_captured_count) {
        snprintf(result, sizeof(result), "ERR:无效索引 %d (共 %d 个)", index, g_captured_count);
        return (*env)->NewStringUTF(env, result);
    }

    CapturedRegistration *cap = &g_captured[index];
    void *func_ptr = (void*)(uintptr_t)cap->address;

    LOGI("callCapturedNative: %s.%s %s @ %p", cap->className, cap->name, cap->signature, func_ptr);

    // 解析签名
    char param_types[16];
    int param_count = parse_jni_params(cap->signature, param_types, 16);
    char ret_type = parse_jni_return(cap->signature);

    // 检查用户提供的参数数量
    int user_count = jParamValues ? (*env)->GetArrayLength(env, jParamValues) : 0;
    if (user_count != param_count) {
        snprintf(result, sizeof(result), "ERR:签名需要 %d 个参数，提供了 %d 个", param_count, user_count);
        return (*env)->NewStringUTF(env, result);
    }

    // 构建参数: args[0]=env, args[1]=clazz, args[2..]=用户参数
    // arm64 ABI: 前8个参数通过 x0-x7 传递
    long args[16] = {0};
    int total_args = 2 + param_count;
    args[0] = (long)env;
    args[1] = (long)clazz;  // 作为 jclass/jobject

    // 解析用户参数
    for (int i = 0; i < param_count && i < 14; i++) {
        jstring jval = (jstring)(*env)->GetObjectArrayElement(env, jParamValues, i);
        const char *val = jval ? (*env)->GetStringUTFChars(env, jval, NULL) : "0";

        switch (param_types[i]) {
            case 'Z': // boolean
                args[2+i] = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0) ? 1 : 0;
                break;
            case 'B': // byte
            case 'S': // short
            case 'I': // int
                args[2+i] = (long)strtol(val, NULL, 0);
                break;
            case 'J': // long
                args[2+i] = strtol(val, NULL, 0);
                break;
            case 'F': { // float - 需要通过整型寄存器传（arm64 ABI会自动处理）
                float f = strtof(val, NULL);
                memcpy(&args[2+i], &f, sizeof(float));
                break;
            }
            case 'D': { // double
                double d = strtod(val, NULL);
                memcpy(&args[2+i], &d, sizeof(double));
                break;
            }
            case 'L': // object → 传 NULL 或创建 jstring
                if (val && strlen(val) > 0 && strcmp(val, "null") != 0) {
                    args[2+i] = (long)(*env)->NewStringUTF(env, val);
                } else {
                    args[2+i] = 0; // NULL
                }
                break;
            case '[': // array → 暂不支持，传 NULL
                args[2+i] = 0;
                break;
            default:
                args[2+i] = (long)strtol(val, NULL, 0);
                break;
        }

        if (jval) (*env)->ReleaseStringUTFChars(env, jval, val);
    }

    // 调用函数 (带崩溃保护)
    typedef long (*func_t)(long, long, long, long, long, long, long, long);
    long ret_long = 0;

    crash_protection_enter();
    if (sigsetjmp(*crash_protection_get_jmpbuf(), 1) == 0) {
        // arm64: 通过寄存器传递前8个参数
        ret_long = ((func_t)func_ptr)(
            args[0], args[1], args[2], args[3],
            args[4], args[5], args[6], args[7]);
        crash_protection_leave();
    } else {
        crash_protection_leave();
        int sig = crash_protection_get_signal();
        snprintf(result, sizeof(result), "ERR:崩溃 %s (signal %d)", signal_name(sig), sig);
        LOGE("callCapturedNative crashed: %s", result);
        return (*env)->NewStringUTF(env, result);
    }

    // 格式化返回值
    switch (ret_type) {
        case 'V':
            snprintf(result, sizeof(result), "OK:void (执行完成)");
            break;
        case 'Z':
            snprintf(result, sizeof(result), "OK:%s", ret_long ? "true" : "false");
            break;
        case 'I': case 'B': case 'S':
            snprintf(result, sizeof(result), "OK:%d (0x%x)", (int)ret_long, (unsigned int)ret_long);
            break;
        case 'J':
            snprintf(result, sizeof(result), "OK:%ld (0x%lx)", ret_long, (unsigned long)ret_long);
            break;
        case 'F': {
            float f;
            memcpy(&f, &ret_long, sizeof(float));
            snprintf(result, sizeof(result), "OK:%f", f);
            break;
        }
        case 'D': {
            double d;
            memcpy(&d, &ret_long, sizeof(double));
            snprintf(result, sizeof(result), "OK:%f", d);
            break;
        }
        case 'L': case '[': {
            if (ret_long == 0) {
                snprintf(result, sizeof(result), "OK:null");
            } else {
                // 尝试当作 jstring 读取
                jstring jret = (jstring)(uintptr_t)ret_long;
                jclass strClass = g_orig_FindClass ? g_orig_FindClass(env, "java/lang/String") : (*env)->FindClass(env, "java/lang/String");
                if (strClass && (*env)->IsInstanceOf(env, jret, strClass)) {
                    const char *str = (*env)->GetStringUTFChars(env, jret, NULL);
                    if (str) {
                        snprintf(result, sizeof(result), "OK:\"%s\"", str);
                        (*env)->ReleaseStringUTFChars(env, jret, str);
                    } else {
                        snprintf(result, sizeof(result), "OK:object@0x%lx", (unsigned long)ret_long);
                    }
                } else {
                    (*env)->ExceptionClear(env);
                    snprintf(result, sizeof(result), "OK:object@0x%lx", (unsigned long)ret_long);
                }
            }
            break;
        }
        default:
            snprintf(result, sizeof(result), "OK:0x%lx", (unsigned long)ret_long);
            break;
    }

    LOGI("callCapturedNative result: %s", result);
    return (*env)->NewStringUTF(env, result);
}
