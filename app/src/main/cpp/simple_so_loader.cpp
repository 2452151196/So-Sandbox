#include <jni.h>
#include <dlfcn.h>
#include <android/log.h>
#include <string>

#define TAG "SOLoader"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// SO 加载器类
class SOLoader {
private:
    void* handle;
    std::string soPath;

public:
    SOLoader(const char* path) : soPath(path), handle(nullptr) {
        handle = dlopen(path, RTLD_LAZY);
        if (handle) {
            LOGI("Successfully loaded SO: %s", path);
        } else {
            LOGE("Failed to load SO: %s, error: %s", path, dlerror());
        }
    }

    ~SOLoader() {
        if (handle) {
            dlclose(handle);
            LOGI("Closed SO: %s", soPath.c_str());
        }
    }

    bool isLoaded() const {
        return handle != nullptr;
    }

    // 获取函数地址
    void* getSymbol(const char* symbolName) {
        if (!handle) {
            LOGE("SO not loaded");
            return nullptr;
        }

        void* symbol = dlsym(handle, symbolName);
        if (symbol) {
            LOGI("Found symbol: %s at %p", symbolName, symbol);
        } else {
            LOGE("Symbol not found: %s, error: %s", symbolName, dlerror());
        }

        return symbol;
    }

    // 调用 int native_add(JNIEnv*, jobject, int, int)
    int callNativeAdd(JNIEnv* env, jobject obj, int a, int b) {
        // C++ mangled name: _Z10native_addP7_JNIEnvP8_jobjectii
        typedef int (*NativeAddFunc)(JNIEnv*, jobject, int, int);
        
        NativeAddFunc func = (NativeAddFunc)getSymbol("_Z10native_addP7_JNIEnvP8_jobjectii");
        if (!func) {
            return -1;
        }

        return func(env, obj, a, b);
    }
};

// 全局 SO 加载器实例
static SOLoader* g_soLoader = nullptr;

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_SOLoader_loadSO(JNIEnv *env, jobject thiz, jstring soPath) {
    const char* path = env->GetStringUTFChars(soPath, 0);
    
    if (g_soLoader) {
        delete g_soLoader;
    }
    
    g_soLoader = new SOLoader(path);
    bool result = g_soLoader->isLoaded();
    
    env->ReleaseStringUTFChars(soPath, path);
    return result ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jint JNICALL
Java_com_example_anative_core_SOLoader_callNativeAdd(JNIEnv *env, jobject thiz, jint a, jint b) {
    if (!g_soLoader) {
        LOGE("SO not loaded");
        return -1;
    }
    
    return g_soLoader->callNativeAdd(env, thiz, a, b);
}

extern "C"
JNIEXPORT void JNICALL
Java_com_example_anative_core_SOLoader_unloadSO(JNIEnv *env, jobject thiz) {
    if (g_soLoader) {
        delete g_soLoader;
        g_soLoader = nullptr;
    }
}
