#include <jni.h>
#include <android/log.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <linux/elf.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <signal.h>
#include <pthread.h>

#define TAG "NativeDebugger"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

#define BRK_0_OPCODE 0xD4200000
#define MAX_BREAKPOINTS 32

typedef struct {
    uint64_t addr;
    uint32_t original;
    int active;
} Breakpoint;

typedef struct {
    pid_t pid;
    uint64_t base_addr;  // child dlopen base
    Breakpoint bps[MAX_BREAKPOINTS];
    int bp_count;
    int attached;
} DebugSession;

static DebugSession g_session = {0};
static pthread_mutex_t g_debug_mutex = PTHREAD_MUTEX_INITIALIZER;

static long safe_ptrace(int request, pid_t pid, void *addr, void *data) {
    errno = 0;
    long ret = ptrace(request, pid, addr, data);
    if (errno != 0 && ret == -1) {
        LOGE("ptrace(%d, %d) failed: %s", request, pid, strerror(errno));
    }
    return ret;
}

static int read_memory_raw(pid_t pid, uint64_t addr, uint8_t *buf, size_t size) {
    struct iovec local = { buf, size };
    struct iovec remote = { (void *)addr, size };
    ssize_t ret = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (ret < 0) {
        size_t i = 0;
        for (; i < size; i += sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
            if (errno != 0) return -1;
            size_t copy = (size - i) < sizeof(long) ? (size - i) : sizeof(long);
            memcpy(buf + i, &word, copy);
        }
        return 0;
    }
    return (ret == (ssize_t)size) ? 0 : -1;
}

static int write_memory_raw(pid_t pid, uint64_t addr, const uint8_t *buf, size_t size) {
    struct iovec local = { (void *)buf, size };
    struct iovec remote = { (void *)addr, size };
    ssize_t ret = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (ret < 0) {
        size_t i = 0;
        for (; i < size; i += sizeof(long)) {
            long word = 0;
            size_t copy = (size - i) < sizeof(long) ? (size - i) : sizeof(long);
            if (copy < sizeof(long)) {
                errno = 0;
                word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + i), NULL);
                if (errno != 0) return -1;
            }
            memcpy(&word, buf + i, copy);
            if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i), (void *)word) < 0) return -1;
        }
        return 0;
    }
    return (ret == (ssize_t)size) ? 0 : -1;
}

static int get_registers(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

static int set_registers(pid_t pid, const struct user_pt_regs *regs) {
    struct iovec iov = { (void *)regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static int find_breakpoint_index(uint64_t addr) {
    for (int i = 0; i < g_session.bp_count; i++) {
        if (g_session.bps[i].addr == addr && g_session.bps[i].active) return i;
    }
    return -1;
}

static int install_breakpoint(pid_t pid, uint64_t addr) {
    if (find_breakpoint_index(addr) >= 0) return 0;
    if (g_session.bp_count >= MAX_BREAKPOINTS) return -1;
    uint32_t original = 0;
    if (read_memory_raw(pid, addr, (uint8_t *)&original, 4) != 0) return -1;
    uint32_t brk = BRK_0_OPCODE;
    if (write_memory_raw(pid, addr, (uint8_t *)&brk, 4) != 0) return -1;
    int idx = g_session.bp_count++;
    g_session.bps[idx].addr = addr;
    g_session.bps[idx].original = original;
    g_session.bps[idx].active = 1;
    LOGI("Breakpoint installed at 0x%llX", (unsigned long long)addr);
    return 0;
}

static int remove_breakpoint(pid_t pid, uint64_t addr) {
    int idx = find_breakpoint_index(addr);
    if (idx < 0) return -1;
    if (write_memory_raw(pid, addr, (uint8_t *)&g_session.bps[idx].original, 4) != 0) return -1;
    g_session.bps[idx].active = 0;
    for (int i = idx; i < g_session.bp_count - 1; i++) g_session.bps[i] = g_session.bps[i + 1];
    g_session.bp_count--;
    LOGI("Breakpoint removed at 0x%llX", (unsigned long long)addr);
    return 0;
}

static void remove_all_breakpoints(pid_t pid) {
    for (int i = 0; i < g_session.bp_count; i++) {
        if (g_session.bps[i].active) {
            write_memory_raw(pid, g_session.bps[i].addr, (uint8_t *)&g_session.bps[i].original, 4);
        }
    }
    g_session.bp_count = 0;
}

static uint64_t get_pc(pid_t pid) {
    struct user_pt_regs regs;
    if (get_registers(pid, &regs) == 0) return regs.pc;
    return 0;
}

static int set_pc(pid_t pid, uint64_t pc) {
    struct user_pt_regs regs;
    if (get_registers(pid, &regs) != 0) return -1;
    regs.pc = pc;
    return set_registers(pid, &regs);
}

static int do_single_step(pid_t pid) {
    uint64_t pc = get_pc(pid);
    if (pc == 0) return -1;

    // ARM64: PC 指向 BRK 本身
    int bp_idx = find_breakpoint_index(pc);
    if (bp_idx >= 0) {
        // 当前停在断点上，先恢复原指令
        if (write_memory_raw(pid, pc, (uint8_t *)&g_session.bps[bp_idx].original, 4) != 0) return -1;
        LOGI("do_single_step: restored original at 0x%llX", (unsigned long long)pc);
    }

    // 使用 PTRACE_SINGLESTEP 执行一条指令
    if (safe_ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
        // 恢复 BRK
        if (bp_idx >= 0) {
            uint32_t brk = BRK_0_OPCODE;
            write_memory_raw(pid, pc, (uint8_t *)&brk, 4);
        }
        LOGE("do_single_step: PTRACE_SINGLESTEP failed: %s", strerror(errno));
        return -1;
    }

    int status = 0;
    int wait_ret = waitpid(pid, &status, 0);
    if (wait_ret < 0) {
        LOGE("do_single_step: waitpid failed: %s", strerror(errno));
        if (bp_idx >= 0) {
            uint32_t brk = BRK_0_OPCODE;
            write_memory_raw(pid, pc, (uint8_t *)&brk, 4);
        }
        return -1;
    }

    // 重新安装断点 BRK
    if (bp_idx >= 0) {
        uint32_t brk = BRK_0_OPCODE;
        write_memory_raw(pid, pc, (uint8_t *)&brk, 4);
        LOGI("do_single_step: re-installed BRK at 0x%llX", (unsigned long long)pc);
    }

    uint64_t new_pc = get_pc(pid);
    LOGI("do_single_step: 0x%llX -> 0x%llX", (unsigned long long)pc, (unsigned long long)new_pc);
    return 0;
}

static const char* signal_name(int sig) {
    switch (sig) {
        case SIGTRAP: return "SIGTRAP";
        case SIGSEGV: return "SIGSEGV";
        case SIGILL:  return "SIGILL";
        case SIGBUS:  return "SIGBUS";
        case SIGABRT: return "SIGABRT";
        case SIGFPE:  return "SIGFPE";
        case SIGINT:  return "SIGINT";
        default:      return "UNKNOWN";
    }
}

static int handle_breakpoint_hit(pid_t pid, uint64_t pc) {
    // ARM64: PC 指向 BRK 指令本身
    int idx = find_breakpoint_index(pc);
    if (idx < 0) {
        // 兼容：某些内核可能 PC 已越过 BRK
        idx = find_breakpoint_index(pc - 4);
        if (idx < 0) return 0;
        pc = pc - 4;
    }
    LOGI("Breakpoint hit at 0x%llX", (unsigned long long)pc);
    // 恢复原指令
    if (write_memory_raw(pid, pc, (uint8_t *)&g_session.bps[idx].original, 4) != 0) return -1;
    // PC 已经指向 BRK 地址，不需要调整
    return 0;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeAttachProcess(JNIEnv *env, jclass clazz, jint jpid) {
    pid_t pid = (pid_t)jpid;
    pthread_mutex_lock(&g_debug_mutex);
    if (g_session.attached && g_session.pid != 0) {
        safe_ptrace(PTRACE_DETACH, g_session.pid, NULL, NULL);
        remove_all_breakpoints(g_session.pid);
    }
    memset(&g_session, 0, sizeof(g_session));
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        LOGE("PTRACE_ATTACH failed: %s", strerror(errno));
        pthread_mutex_unlock(&g_debug_mutex);
        return JNI_FALSE;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        LOGE("waitpid after attach failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        pthread_mutex_unlock(&g_debug_mutex);
        return JNI_FALSE;
    }
    g_session.pid = pid;
    g_session.attached = 1;
    pthread_mutex_unlock(&g_debug_mutex);
    LOGI("Attached to pid %d", pid);
    return JNI_TRUE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeDetachProcess(JNIEnv *env, jclass clazz, jint jpid) {
    pid_t pid = (pid_t)jpid;
    pthread_mutex_lock(&g_debug_mutex);
    if (!g_session.attached || g_session.pid != pid) {
        pthread_mutex_unlock(&g_debug_mutex);
        return JNI_FALSE;
    }
    remove_all_breakpoints(pid);
    if (safe_ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        pthread_mutex_unlock(&g_debug_mutex);
        return JNI_FALSE;
    }
    g_session.attached = 0;
    g_session.pid = 0;
    pthread_mutex_unlock(&g_debug_mutex);
    LOGI("Detached from pid %d", pid);
    return JNI_TRUE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeContinue(JNIEnv *env, jclass clazz, jint jpid) {
    pid_t pid = (pid_t)jpid;
    pthread_mutex_lock(&g_debug_mutex);
    if (!g_session.attached || g_session.pid != pid) {
        pthread_mutex_unlock(&g_debug_mutex);
        return JNI_FALSE;
    }
    for (int i = 0; i < g_session.bp_count; i++) {
        if (g_session.bps[i].active) {
            uint32_t current = 0;
            if (read_memory_raw(pid, g_session.bps[i].addr, (uint8_t *)&current, 4) == 0) {
                if (current != BRK_0_OPCODE) {
                    uint32_t brk = BRK_0_OPCODE;
                    write_memory_raw(pid, g_session.bps[i].addr, (uint8_t *)&brk, 4);
                }
            }
        }
    }
    long ret = safe_ptrace(PTRACE_CONT, pid, NULL, NULL);
    pthread_mutex_unlock(&g_debug_mutex);
    return (ret >= 0) ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeDebugger_nativeWaitEvent(JNIEnv *env, jclass clazz, jint jpid, jint timeoutMs) {
    pid_t pid = (pid_t)jpid;
    int status = 0;
    int ret;

    if (timeoutMs < 0) {
        // 非阻塞：立即检查
        ret = waitpid(pid, &status, WNOHANG);
        if (ret == 0) return env->NewStringUTF("RUNNING");
    } else if (timeoutMs == 0) {
        // 阻塞：一直等到事件
        ret = waitpid(pid, &status, 0);
    } else {
        // 超时等待：轮询
        int elapsed = 0;
        int interval = 10; // 10ms 间隔
        while (elapsed < timeoutMs) {
            ret = waitpid(pid, &status, WNOHANG);
            if (ret != 0) goto got_event;
            usleep(interval * 1000);
            elapsed += interval;
        }
        return env->NewStringUTF("TIMEOUT");
    }

got_event:
    if (ret < 0) {
        char err[256];
        snprintf(err, sizeof(err), "ERR:waitpid failed:%s", strerror(errno));
        return env->NewStringUTF(err);
    }
    if (ret == 0) return env->NewStringUTF("TIMEOUT");
    if (WIFEXITED(status)) {
        char msg[128];
        snprintf(msg, sizeof(msg), "EXIT|%d", WEXITSTATUS(status));
        return env->NewStringUTF(msg);
    }
    if (WIFSIGNALED(status)) {
        char msg[128];
        snprintf(msg, sizeof(msg), "SIGNALED|%d|%s", WTERMSIG(status), signal_name(WTERMSIG(status)));
        return env->NewStringUTF(msg);
    }
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        uint64_t pc = 0;
        if (g_session.attached && g_session.pid == pid) pc = get_pc(pid);
        if (sig == SIGTRAP && g_session.attached && g_session.pid == pid) {
            handle_breakpoint_hit(pid, pc);
        }
        char msg[256];
        snprintf(msg, sizeof(msg), "STOP|%d|%s|PC=0x%llX", sig, signal_name(sig), (unsigned long long)pc);
        return env->NewStringUTF(msg);
    }
    return env->NewStringUTF("UNKNOWN");
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_example_anative_core_NativeDebugger_nativeReadMemory(JNIEnv *env, jclass clazz, jint jpid, jlong jaddr, jint jsize) {
    pid_t pid = (pid_t)jpid;
    uint64_t addr = (uint64_t)jaddr;
    int size = jsize;
    if (size <= 0 || size > 1024 * 1024) return NULL;
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return NULL;
    if (read_memory_raw(pid, addr, buf, size) != 0) {
        free(buf);
        return NULL;
    }
    jbyteArray result = env->NewByteArray(size);
    env->SetByteArrayRegion(result, 0, size, (jbyte *)buf);
    free(buf);
    return result;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeWriteMemory(JNIEnv *env, jclass clazz, jint jpid, jlong jaddr, jbyteArray jdata) {
    pid_t pid = (pid_t)jpid;
    uint64_t addr = (uint64_t)jaddr;
    if (jdata == NULL) return JNI_FALSE;
    jsize size = env->GetArrayLength(jdata);
    if (size <= 0) return JNI_FALSE;
    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) return JNI_FALSE;
    env->GetByteArrayRegion(jdata, 0, size, (jbyte *)buf);
    int ret = write_memory_raw(pid, addr, buf, size);
    free(buf);
    return (ret == 0) ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeDebugger_nativeReadRegisters(JNIEnv *env, jclass clazz, jint jpid) {
    pid_t pid = (pid_t)jpid;
    struct user_pt_regs regs;
    if (get_registers(pid, &regs) != 0) return env->NewStringUTF("ERR:Failed to read registers");
    char buf[4096];
    int pos = 0;
    pos += snprintf(buf + pos, sizeof(buf) - pos, "PC=0x%llX|SP=0x%llX|LR=0x%llX",
        (unsigned long long)regs.pc, (unsigned long long)regs.sp, (unsigned long long)regs.regs[30]);
    for (int i = 0; i < 31; i++) {
        pos += snprintf(buf + pos, sizeof(buf) - pos, "|X%d=0x%llX", i, (unsigned long long)regs.regs[i]);
    }
    return env->NewStringUTF(buf);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeWriteRegister(JNIEnv *env, jclass clazz, jint jpid, jstring jname, jlong jvalue) {
    pid_t pid = (pid_t)jpid;
    const char *name = env->GetStringUTFChars(jname, NULL);
    if (!name) return JNI_FALSE;
    struct user_pt_regs regs;
    if (get_registers(pid, &regs) != 0) {
        env->ReleaseStringUTFChars(jname, name);
        return JNI_FALSE;
    }
    int ok = 0;
    if (strcmp(name, "PC") == 0 || strcmp(name, "pc") == 0) {
        regs.pc = (uint64_t)jvalue; ok = 1;
    } else if (strcmp(name, "SP") == 0 || strcmp(name, "sp") == 0) {
        regs.sp = (uint64_t)jvalue; ok = 1;
    } else if (strcmp(name, "LR") == 0 || strcmp(name, "lr") == 0) {
        regs.regs[30] = (uint64_t)jvalue; ok = 1;
    } else if (name[0] == 'X' || name[0] == 'x') {
        int idx = atoi(name + 1);
        if (idx >= 0 && idx <= 30) { regs.regs[idx] = (uint64_t)jvalue; ok = 1; }
    }
    env->ReleaseStringUTFChars(jname, name);
    if (ok) return (set_registers(pid, &regs) == 0) ? JNI_TRUE : JNI_FALSE;
    return JNI_FALSE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeSetBreakpoint(JNIEnv *env, jclass clazz, jint jpid, jlong jaddr) {
    pid_t pid = (pid_t)jpid;
    uint64_t addr = (uint64_t)jaddr;
    pthread_mutex_lock(&g_debug_mutex);
    int ret = install_breakpoint(pid, addr);
    pthread_mutex_unlock(&g_debug_mutex);
    return (ret == 0) ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeRemoveBreakpoint(JNIEnv *env, jclass clazz, jint jpid, jlong jaddr) {
    pid_t pid = (pid_t)jpid;
    uint64_t addr = (uint64_t)jaddr;
    pthread_mutex_lock(&g_debug_mutex);
    int ret = remove_breakpoint(pid, addr);
    pthread_mutex_unlock(&g_debug_mutex);
    return (ret == 0) ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeSingleStep(JNIEnv *env, jclass clazz, jint jpid) {
    pid_t pid = (pid_t)jpid;
    pthread_mutex_lock(&g_debug_mutex);
    int ret = do_single_step(pid);
    pthread_mutex_unlock(&g_debug_mutex);
    return (ret == 0) ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeDebugger_nativeGetBreakpoints(JNIEnv *env, jclass clazz, jint jpid) {
    pthread_mutex_lock(&g_debug_mutex);
    char buf[4096];
    int pos = 0;
    for (int i = 0; i < g_session.bp_count; i++) {
        if (g_session.bps[i].active) {
            pos += snprintf(buf + pos, sizeof(buf) - pos, "%s0x%llX", (i > 0) ? "|" : "", (unsigned long long)g_session.bps[i].addr);
        }
    }
    pthread_mutex_unlock(&g_debug_mutex);
    if (pos == 0) return env->NewStringUTF("");
    return env->NewStringUTF(buf);
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_anative_core_NativeDebugger_nativeSpawnAndTrace(JNIEnv *env, jclass clazz, jstring jsoPath, jlong jfuncOffset) {
    (void)jfuncOffset;
    const char *soPath = env->GetStringUTFChars(jsoPath, NULL);
    if (!soPath) return -1;

    int pipe_fd[2];
    if (pipe(pipe_fd) != 0) {
        env->ReleaseStringUTFChars(jsoPath, soPath);
        return -1;
    }

    pid_t child = fork();
    if (child < 0) {
        close(pipe_fd[0]); close(pipe_fd[1]);
        env->ReleaseStringUTFChars(jsoPath, soPath);
        return -1;
    }

    if (child == 0) {
        // Child process
        close(pipe_fd[0]);

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            LOGE("child PTRACE_TRACEME failed: %s", strerror(errno));
            close(pipe_fd[1]);
            _exit(1);
        }

        // First stop: wait for parent to attach
        raise(SIGSTOP);

        // Parent will PTRACE_CONT us here
        // Then we dlopen the target SO
        void *handle = dlopen(soPath, RTLD_NOW);
        uint64_t base = 0;
        if (handle) {
            base = (uint64_t)handle;
            void *sym = dlsym(handle, "JNI_OnLoad");
            if (sym) {
                Dl_info info;
                if (dladdr(sym, &info) && info.dli_fbase) {
                    base = (uint64_t)info.dli_fbase;
                }
            }
        }

        // Send base back to parent via pipe
        ssize_t written = write(pipe_fd[1], &base, sizeof(base));
        if (written != sizeof(base)) {
            LOGE("child failed to write base to pipe");
        }
        close(pipe_fd[1]);

        // Second stop: after dlopen, parent can set breakpoints
        raise(SIGSTOP);

        // Parent CONT: enter infinite loop waiting for breakpoints/signals
        while (1) {
            pause();
        }
        _exit(0);
    }

    // Parent
    close(pipe_fd[1]);
    env->ReleaseStringUTFChars(jsoPath, soPath);

    // 1. Wait child first stop (after TRACEME + SIGSTOP)
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        LOGE("parent waitpid first failed: %s", strerror(errno));
        close(pipe_fd[0]);
        return -1;
    }
    LOGI("child first stop, status=0x%x", status);

    // 2. Init debug session
    pthread_mutex_lock(&g_debug_mutex);
    if (g_session.attached && g_session.pid != 0) {
        safe_ptrace(PTRACE_DETACH, g_session.pid, NULL, NULL);
        remove_all_breakpoints(g_session.pid);
    }
    memset(&g_session, 0, sizeof(g_session));
    g_session.pid = child;
    g_session.attached = 1;
    pthread_mutex_unlock(&g_debug_mutex);

    // 3. Let child continue to dlopen
    if (safe_ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
        LOGE("parent PTRACE_CONT failed: %s", strerror(errno));
        close(pipe_fd[0]);
        return (jint)child;
    }

    // 4. Wait child second stop (after dlopen + SIGSTOP)
    if (waitpid(child, &status, 0) < 0) {
        LOGE("parent waitpid second failed: %s", strerror(errno));
        close(pipe_fd[0]);
        return (jint)child;
    }
    LOGI("child second stop after dlopen, status=0x%x", status);

    // 5. Read SO base from pipe
    uint64_t base = 0;
    ssize_t rd = read(pipe_fd[0], &base, sizeof(base));
    close(pipe_fd[0]);

    if (rd == sizeof(base)) {
        LOGI("child SO base = 0x%llX", (unsigned long long)base);
        pthread_mutex_lock(&g_debug_mutex);
        g_session.base_addr = base;
        pthread_mutex_unlock(&g_debug_mutex);
    } else {
        LOGW("failed to read base from pipe, rd=%zd", rd);
    }

    LOGI("spawn trace ready, child=%d, base=0x%llX", child, (unsigned long long)base);
    return (jint)child;
}

extern "C"
JNIEXPORT jlong JNICALL
Java_com_example_anative_core_NativeDebugger_nativeGetChildBase(JNIEnv *env, jclass clazz, jint jpid) {
    (void)jpid;
    pthread_mutex_lock(&g_debug_mutex);
    jlong base = (jlong)g_session.base_addr;
    pthread_mutex_unlock(&g_debug_mutex);
    return base;
}

// 在子进程中调用指定函数（绝对地址）
// 只修改 PC 指向目标函数，保持 SP/LR 等不变
// 如果函数入口有断点 (BRK)，子进程会立即 SIGTRAP 停下
// 函数正常 RET 后回到原 LR（子进程 pause 循环），不会崩溃
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeCallFunction(JNIEnv *env, jclass clazz, jint jpid, jlong jfuncAddr) {
    pid_t pid = (pid_t)jpid;
    uint64_t funcAddr = (uint64_t)jfuncAddr;

    pthread_mutex_lock(&g_debug_mutex);
    if (!g_session.attached || g_session.pid != pid) {
        pthread_mutex_unlock(&g_debug_mutex);
        LOGE("nativeCallFunction: not attached to pid %d", pid);
        return JNI_FALSE;
    }

    struct user_pt_regs regs;
    if (get_registers(pid, &regs) != 0) {
        pthread_mutex_unlock(&g_debug_mutex);
        LOGE("nativeCallFunction: failed to get regs");
        return JNI_FALSE;
    }

    uint64_t oldPc = regs.pc;
    regs.pc = funcAddr;

    if (set_registers(pid, &regs) != 0) {
        pthread_mutex_unlock(&g_debug_mutex);
        LOGE("nativeCallFunction: failed to set regs");
        return JNI_FALSE;
    }

    // 确保所有活跃断点已写入内存（BRK 指令在目标地址）
    for (int i = 0; i < g_session.bp_count; i++) {
        if (g_session.bps[i].active) {
            uint32_t current = 0;
            if (read_memory_raw(pid, g_session.bps[i].addr, (uint8_t *)&current, 4) == 0) {
                if (current != BRK_0_OPCODE) {
                    uint32_t brk = BRK_0_OPCODE;
                    write_memory_raw(pid, g_session.bps[i].addr, (uint8_t *)&brk, 4);
                    LOGI("nativeCallFunction: re-installed bp at 0x%llX",
                         (unsigned long long)g_session.bps[i].addr);
                }
            }
        }
    }

    LOGI("nativeCallFunction: PC 0x%llX -> 0x%llX, bp_count=%d",
         (unsigned long long)oldPc, (unsigned long long)funcAddr, g_session.bp_count);

    long ret = safe_ptrace(PTRACE_CONT, pid, NULL, NULL);
    pthread_mutex_unlock(&g_debug_mutex);
    return (ret == 0) ? JNI_TRUE : JNI_FALSE;
}

// 带参数调用：设置 x0-x7 + PC，然后 PTRACE_CONT
extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeDebugger_nativeCallFunctionWithArgs(JNIEnv *env, jclass clazz,
        jint jpid, jlong jfuncAddr, jlongArray jargs) {
    pid_t pid = (pid_t)jpid;
    uint64_t funcAddr = (uint64_t)jfuncAddr;

    pthread_mutex_lock(&g_debug_mutex);
    if (!g_session.attached || g_session.pid != pid) {
        pthread_mutex_unlock(&g_debug_mutex);
        LOGE("nativeCallFunctionWithArgs: not attached to pid %d", pid);
        return JNI_FALSE;
    }

    struct user_pt_regs regs;
    if (get_registers(pid, &regs) != 0) {
        pthread_mutex_unlock(&g_debug_mutex);
        LOGE("nativeCallFunctionWithArgs: failed to get regs");
        return JNI_FALSE;
    }

    // 设置参数到 x0-x7
    jsize argc = 0;
    jlong *args = NULL;
    if (jargs != NULL) {
        argc = env->GetArrayLength(jargs);
        args = env->GetLongArrayElements(jargs, NULL);
        if (args) {
            for (int i = 0; i < argc && i < 8; i++) {
                regs.regs[i] = (uint64_t)args[i];
            }
            env->ReleaseLongArrayElements(jargs, args, JNI_ABORT);
        }
    }

    uint64_t oldPc = regs.pc;
    regs.pc = funcAddr;

    if (set_registers(pid, &regs) != 0) {
        pthread_mutex_unlock(&g_debug_mutex);
        LOGE("nativeCallFunctionWithArgs: failed to set regs");
        return JNI_FALSE;
    }

    // 确保所有活跃断点 BRK 已写入
    for (int i = 0; i < g_session.bp_count; i++) {
        if (g_session.bps[i].active) {
            uint32_t current = 0;
            if (read_memory_raw(pid, g_session.bps[i].addr, (uint8_t *)&current, 4) == 0) {
                if (current != BRK_0_OPCODE) {
                    uint32_t brk = BRK_0_OPCODE;
                    write_memory_raw(pid, g_session.bps[i].addr, (uint8_t *)&brk, 4);
                }
            }
        }
    }

    LOGI("nativeCallFunctionWithArgs: PC 0x%llX -> 0x%llX, argc=%d, x0=0x%llX x1=0x%llX x2=0x%llX",
         (unsigned long long)oldPc, (unsigned long long)funcAddr, argc,
         (unsigned long long)regs.regs[0], (unsigned long long)regs.regs[1],
         (unsigned long long)regs.regs[2]);

    long ret = safe_ptrace(PTRACE_CONT, pid, NULL, NULL);
    pthread_mutex_unlock(&g_debug_mutex);
    return (ret == 0) ? JNI_TRUE : JNI_FALSE;
}
