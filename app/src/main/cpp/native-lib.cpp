#include <jni.h>
#include <string>
#include <vector>
#include <cstdint>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <cstring>
#include <array>
#include <android/log.h>

// --- 字符串混淆模块 ---
namespace O {
    template<size_t N>
    class S {
    private:
        std::array<char, N> d;
        static constexpr char k = 0x55;
        constexpr char t(char c) const { return c ^ k; }
    public:
        constexpr S(const char* s) : d{} {
            for (size_t i = 0; i < N; ++i) { d[i] = t(s[i]); }
        }
        std::string D() const {
            std::string r; r.reserve(N);
            for (size_t i = 0; i < N; ++i) {
                char c = t(d[i]);
                if (c == '\0') break;
                r += c;
            }
            return r;
        }
    };
}

#define _S(s) (O::S<sizeof(s)>(s).D())

// --- 配置模块 ---
namespace C {
    std::string a() {
        // 保留原有逻辑：XOR 解密预设哈希
        const char* h = "2359285182393755D3DF118CD0DA9BED11AAF6C608ED3381E020D8634C6CE022";
        constexpr char k = 'G';
        // 使用 uint8_t 避免 narrowing 编译错误
        std::array<uint8_t, 65> e = {};
        for(size_t i = 0; i < 64; ++i) { e[i] = h[i] ^ k; }
        e[64] = 0 ^ k;

        std::string d; d.reserve(64);
        for(size_t i = 0; i < 64; ++i) { d += (char)(e[i] ^ k); }
        return d;
    }
}

// --- 核心逻辑 ---
namespace I {
    // 系统调用封装
    static intptr_t o(intptr_t f, const char *p, intptr_t l, intptr_t m) {
#if defined(__aarch64__)
        register intptr_t x0 asm("x0") = f; register const char* x1 asm("x1") = p; register intptr_t x2 asm("x2") = l; register intptr_t x3 asm("x3") = m; register intptr_t x8 asm("x8") = __NR_openat; asm volatile("svc #0" : "=r"(x0) : "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory"); return x0;
#else
        return syscall(__NR_openat, f, p, l, m);
#endif
    }
    static ssize_t r(intptr_t f, void *b, size_t c) {
#if defined(__aarch64__)
        register intptr_t x0 asm("x0") = f; register void* x1 asm("x1") = b; register size_t x2 asm("x2") = c; register intptr_t x8 asm("x8") = __NR_read; asm volatile("svc #0" : "=r"(x0) : "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory"); return x0;
#else
        return syscall(__NR_read, f, b, c);
#endif
    }
    static off_t l(intptr_t f, off_t o, int w) {
#if defined(__aarch64__)
        register intptr_t x0 asm("x0") = f; register off_t x1 asm("x1") = o; register int x2 asm("x2") = w; register intptr_t x8 asm("x8") = __NR_lseek; asm volatile("svc #0" : "=r"(x0) : "r"(x0), "r"(x1), "r"(x2), "r"(x8) : "memory"); return x0;
#else
        return syscall(__NR_lseek, f, o, w);
#endif
    }
    static int c(intptr_t f) {
#if defined(__aarch64__)
        register intptr_t x0 asm("x0") = f; register intptr_t x8 asm("x8") = __NR_close; asm volatile("svc #0" : "=r"(x0) : "r"(x0), "r"(x8) : "memory"); return x0;
#else
        return syscall(__NR_close, f);
#endif
    }

    // SHA256 算法体 (保持原有逻辑)
    struct T { uint32_t s[8]; uint64_t b; uint8_t d[64]; size_t l; };
    static inline uint32_t R(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static void ts(T* ctx, const uint8_t d[]) {
        static const uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t a,b,c,d1,e,f,g,h,t1,t2,m[64];
        for(int i=0;i<16;++i) m[i]=(d[i*4]<<24)|(d[i*4+1]<<16)|(d[i*4+2]<<8)|(d[i*4+3]);
        for(int i=16;i<64;++i) m[i]=(R(m[i-2],17)^R(m[i-2],19)^(m[i-2]>>10))+m[i-7]+(R(m[i-15],7)^R(m[i-15],18)^(m[i-15]>>3))+m[i-16];
        a=ctx->s[0]; b=ctx->s[1]; c=ctx->s[2]; d1=ctx->s[3]; e=ctx->s[4]; f=ctx->s[5]; g=ctx->s[6]; h=ctx->s[7];
        for(int i=0;i<64;++i){
            t1=h+(R(e,6)^R(e,11)^R(e,25))+((e&f)^(~e&g))+k[i]+m[i];
            t2=(R(a,2)^R(a,13)^R(a,22))+((a&b)^(a&c)^(b&c));
            h=g; g=f; f=e; e=d1+t1; d1=c; c=b; b=a; a=t1+t2;
        }
        ctx->s[0]+=a; ctx->s[1]+=b; ctx->s[2]+=c; ctx->s[3]+=d1; ctx->s[4]+=e; ctx->s[5]+=f; ctx->s[6]+=g; ctx->s[7]+=h;
    }
    static void i(T* ctx) { ctx->l=0; ctx->b=0; ctx->s[0]=0x6a09e667; ctx->s[1]=0xbb67ae85; ctx->s[2]=0x3c6ef372; ctx->s[3]=0xa54ff53a; ctx->s[4]=0x510e527f; ctx->s[5]=0x9b05688c; ctx->s[6]=0x1f83d9ab; ctx->s[7]=0x5be0cd19; }
    static void u(T* ctx, const uint8_t d[], size_t len) { for(size_t i=0;i<len;++i){ctx->d[ctx->l]=d[i]; ctx->l++; if(ctx->l==64){ts(ctx,ctx->d); ctx->b+=512; ctx->l=0;}} }
    static void f(T* ctx, uint8_t hash[]) {
        uint32_t j=ctx->l; if(ctx->l<56){ctx->d[j++]=0x80; while(j<56)ctx->d[j++]=0;} else {ctx->d[j++]=0x80; while(j<64)ctx->d[j++]=0; ts(ctx,ctx->d); memset(ctx->d,0,56);}
        ctx->b+=ctx->l*8; for(int n=0;n<8;n++) ctx->d[63-n]=(uint8_t)(ctx->b>>(n*8)); ts(ctx,ctx->d);
        for(int n=0;n<8;n++) for(int k=0;k<4;k++) hash[n*4+k]=(ctx->s[n]>>(24-k*8))&0xFF;
    }

    static std::string hx(const uint8_t* b, size_t len) {
        const char* d = "0123456789ABCDEF";
        std::string s; s.reserve(len*2);
        for(size_t i=0;i<len;++i){ s+=d[(b[i]>>4)&0xF]; s+=d[b[i]&0xF]; }
        return s;
    }

    static std::string p() {
        intptr_t fd = o(AT_FDCWD, _S("/proc/self/maps").c_str(), O_RDONLY, 0); if (fd < 0) return "";
        char buf[2048]; std::string s; ssize_t nr;
        while((nr = r(fd, buf, sizeof(buf))) > 0) s.append(buf, nr);
        c(fd);
        size_t b_pos = s.find(_S("base.apk"));
        size_t d_pos = s.find(_S("/data/app/"));
        if(b_pos != std::string::npos && d_pos != std::string::npos) {
            size_t st = s.rfind('/', b_pos);
            if(st != std::string::npos) return s.substr(st, s.find('\n', b_pos) - st);
        }
        return "";
    }

    // 校验核心
    static void v() {
        std::string ex = C::a();
        std::string ap = p(); if(ap.empty()) _exit(137);
        intptr_t fd = o(AT_FDCWD, ap.c_str(), O_RDONLY, 0); if(fd < 0) _exit(137);
        off_t fs = l(fd, 0, SEEK_END); if(fs < 22) { c(fd); _exit(137); }

        uint32_t sig; bool fnd = false; off_t e_st = (fs > 65557) ? (fs - 65557) : 0;
        for(off_t i = fs - 22; i >= e_st; --i) {
            l(fd, i, SEEK_SET); if(r(fd, &sig, 4) == 4 && sig == 0x06054b50) {
                l(fd, i + 16, SEEK_SET); r(fd, &sig, 4); fnd = true; break;
            }
        }
        if(!fnd) { c(fd); _exit(137); }

        l(fd, sig - 24, SEEK_SET); uint64_t b_sz; uint64_t mg[2]; r(fd, &b_sz, 8); r(fd, mg, 16);
        if(mg[0] != 0x20676953204b5041LL || mg[1] != 0x3234206b636f6c42LL) { c(fd); _exit(137); }

        off_t s_off = sig - b_sz - 8; l(fd, s_off, SEEK_SET); uint64_t b_sz_c; r(fd, &b_sz_c, 8);
        off_t cur = s_off + 8; off_t end = s_off + b_sz_c;
        std::vector<uint8_t> vt;
        while(cur < end) {
            l(fd, cur, SEEK_SET); uint64_t p_sz; uint32_t p_id; r(fd, &p_sz, 8); r(fd, &p_id, 4);
            if(p_id == 0x7109871a) {
                uint32_t v2_l; r(fd, &v2_l, 4); vt.resize(v2_l); r(fd, vt.data(), v2_l); break;
            }
            cur += p_sz + 8;
        }
        c(fd);
        if(vt.empty()) _exit(137);

        const uint8_t* d = vt.data();
        uint32_t s_l, si_l, sd_l, dg_l, ct_l, f_c_l;
        memcpy(&s_l, d, 4); memcpy(&si_l, d+4, 4);
        memcpy(&sd_l, d+8, 4); const uint8_t* sd = d + 12;
        memcpy(&dg_l, sd, 4); memcpy(&ct_l, sd + 4 + dg_l, 4);
        memcpy(&f_c_l, sd + 8 + dg_l, 4);
        const uint8_t* f_c = sd + 12 + dg_l;

        T ctx; i(&ctx); u(&ctx, f_c, f_c_l); uint8_t h[32]; f(&ctx, h);
        if(hx(h, 32) != ex) _exit(137);
    }
}

// --- 入口 ---


// =============================================================================
// C层AES解密 - 使用 mbedTLS 实现
// =============================================================================
#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/base64.h>

// Capstone 反汇编（用于流程图生成）
#include <capstone/capstone.h>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>

namespace Crypto {
    // Base64解码
    static std::string base64Decode(const std::string& input) {
        size_t outLen = 0;
        mbedtls_base64_decode(nullptr, 0, &outLen, (const unsigned char*)input.c_str(), input.length());
        
        std::string output(outLen, '\0');
        int ret = mbedtls_base64_decode((unsigned char*)output.data(), output.length(), &outLen, 
                                        (const unsigned char*)input.c_str(), input.length());
        if (ret != 0) return "";
        
        output.resize(outLen);
        return output;
    }

    // bytes转hex
    static std::string bytesToHex(const uint8_t* data, size_t len) {
        static const char hex[] = "0123456789abcdef";
        std::string result;
        for (size_t i = 0; i < len; i++) {
            result.push_back(hex[(data[i] >> 4) & 0xF]);
            result.push_back(hex[data[i] & 0xF]);
        }
        return result;
    }

    // PBKDF2-HMAC-SHA256派生密钥 (mbedTLS 2.28.8 API)
    static std::vector<uint8_t> pbkdf2HmacSha256(const std::string& password, 
                                                  const uint8_t* salt, size_t saltLen,
                                                  int iterations, size_t keyLen) {
        std::vector<uint8_t> key(keyLen);
        
        // 初始化 MD 上下文
        mbedtls_md_context_t md_ctx;
        mbedtls_md_init(&md_ctx);
        
        const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        int ret = mbedtls_md_setup(&md_ctx, md_info, 1); // 1 = HMAC
        if (ret != 0) {
            mbedtls_md_free(&md_ctx);
            return {};
        }
        
        ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
                                        (const unsigned char*)password.c_str(), password.length(),
                                        salt, saltLen, iterations, keyLen, key.data());
        mbedtls_md_free(&md_ctx);
        
        if (ret != 0) {
            return {};
        }
        return key;
    }

    // AES-256-CBC解密
    static std::string aesDecrypt(const std::string& encryptedB64, const std::string& key) {
        // Base64解码
        std::string combined = base64Decode(encryptedB64);
        if (combined.length() < 24) return "";

        // 提取：salt(8) + iv(16) + ciphertext
        uint8_t salt[8];
        uint8_t iv[16];
        memcpy(salt, combined.data(), 8);
        memcpy(iv, combined.data() + 8, 16);
        std::string ciphertext = combined.substr(24);

        // 派生密钥：PBKDF2(key + saltHex, salt, 10000, 256bit)
        std::string keySalt = key + bytesToHex(salt, 8);
        std::vector<uint8_t> derivedKey = pbkdf2HmacSha256(keySalt, salt, 8, 10000, 32);
        if (derivedKey.empty()) return "";

        // AES-256-CBC解密
        mbedtls_aes_context aes_ctx;
        mbedtls_aes_setkey_dec(&aes_ctx, derivedKey.data(), 256);

        std::vector<uint8_t> plaintext(ciphertext.length());
        size_t nc_off = 0;
        uint8_t stream_block[16];
        
        int ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, 
                                        ciphertext.length(), iv,
                                        (const unsigned char*)ciphertext.data(),
                                        plaintext.data());
        if (ret != 0) return "";

        // 去除PKCS7填充
        size_t padLen = plaintext.empty() ? 0 : plaintext.back();
        if (padLen > 0 && padLen <= 16) {
            bool validPadding = true;
            for (size_t i = 0; i < padLen; i++) {
                if (plaintext[plaintext.size() - 1 - i] != padLen) {
                    validPadding = false;
                    break;
                }
            }
            if (validPadding) {
                plaintext.resize(plaintext.size() - padLen);
            }
        }

        return std::string((char*)plaintext.data(), plaintext.size());
    }
}

// 声明外部函数（来自 crash_protection.c 和 invoker.c）
extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_anative_core_NativeInvoker_hookRegisterNatives(JNIEnv* env, jclass clazz);

extern "C" JNIEXPORT void JNICALL
Java_com_example_anative_core_NativeInvoker_unhookRegisterNatives(JNIEnv* env, jclass clazz);

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_getCapturedRegistrations(JNIEnv* env, jclass clazz);

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_anative_core_NativeInvoker_callJniOnLoad(JNIEnv* env, jclass clazz,
                                                           jlong handle, jstring jSymbol,
                                                           jstring jMaxCapture, jstring jPageSize);

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_anative_ui_RegisterNativesActivity_executeCloudHookNative(
    JNIEnv* env, jclass clazz, jlong handle, 
    jstring encryptedSymbol, jstring encryptedMaxCapture, jstring encryptedPageSize,
    jstring deviceFingerprint) {
    
    if (!encryptedSymbol || !encryptedMaxCapture || !encryptedPageSize || !deviceFingerprint) {
        return nullptr;
    }

    // 获取加密数据和密钥
    const char* symEnc = env->GetStringUTFChars(encryptedSymbol, nullptr);
    const char* maxEnc = env->GetStringUTFChars(encryptedMaxCapture, nullptr);
    const char* pageEnc = env->GetStringUTFChars(encryptedPageSize, nullptr);
    const char* fp = env->GetStringUTFChars(deviceFingerprint, nullptr);

    // C层解密
    std::string symbol = Crypto::aesDecrypt(symEnc, fp);
    std::string maxCapture = Crypto::aesDecrypt(maxEnc, fp);
    std::string pageSize = Crypto::aesDecrypt(pageEnc, fp);

    env->ReleaseStringUTFChars(encryptedSymbol, symEnc);
    env->ReleaseStringUTFChars(encryptedMaxCapture, maxEnc);
    env->ReleaseStringUTFChars(encryptedPageSize, pageEnc);
    env->ReleaseStringUTFChars(deviceFingerprint, fp);

    // 检查解密结果
    if (symbol.empty() || maxCapture.empty() || pageSize.empty()) {
        __android_log_print(ANDROID_LOG_ERROR, "DTZC-Native", "Decryption failed");
        return nullptr;
    }

    __android_log_print(ANDROID_LOG_DEBUG, "DTZC-Native", 
                       "Decrypted symbol=%s, maxCapture=%s, pageSize=%s",
                       symbol.c_str(), maxCapture.c_str(), pageSize.c_str());

    // C层执行完整Hook流程（密钥和数据都在so中，最安全）
    __android_log_print(ANDROID_LOG_INFO, "DTZC-Native", "C层执行Hook流程...");
    
    // 1. 安装Hook
    Java_com_example_anative_core_NativeInvoker_hookRegisterNatives(env, clazz);
    
    // 2. 调用目标SO的JNI_OnLoad（传入解密后的明文）
    jstring jSymbol = env->NewStringUTF(symbol.c_str());
    jstring jMaxCapture = env->NewStringUTF(maxCapture.c_str());
    jstring jPageSize = env->NewStringUTF(pageSize.c_str());
    
    jstring onloadResult = Java_com_example_anative_core_NativeInvoker_callJniOnLoad(
        env, clazz, handle, jSymbol, jMaxCapture, jPageSize);
    
    env->DeleteLocalRef(jSymbol);
    env->DeleteLocalRef(jMaxCapture);
    env->DeleteLocalRef(jPageSize);
    
    // 3. 卸载Hook
    Java_com_example_anative_core_NativeInvoker_unhookRegisterNatives(env, clazz);
    
    // 4. 获取捕获的注册数据
    jstring captured = Java_com_example_anative_core_NativeInvoker_getCapturedRegistrations(env, clazz);
    
    __android_log_print(ANDROID_LOG_INFO, "DTZC-Native", "Hook流程完成");
    
    // 返回捕获的注册数据（字符串格式）
    return captured;
}

// ============================================================================
// C层流程图生成（安全：加密配置解密+Capstone分析都在so中完成）
// ============================================================================

struct FlowchartNode {
    uint64_t addr;
    std::vector<uint8_t> bytes;
    std::string disasm;
    std::vector<uint64_t> successors;
    bool isBranch;
    bool isCondBranch;
};

static bool hasMnemonic(const std::vector<std::string>& insns, const std::string& mnemonic) {
    for (const auto& insn : insns) {
        if (mnemonic == insn) {
            return true;
        }
    }
    return false;
}

static uint64_t extractBranchTargetFromDisasm(const std::string& disasm) {
    size_t addrPos = disasm.find("0x");
    if (addrPos == std::string::npos) {
        return 0;
    }
    return strtoull(disasm.c_str() + addrPos, nullptr, 16);
}

static std::vector<std::string> parseBranchInsns(const std::string& config) {
    std::vector<std::string> insns;
    // 解析 branch_insns 数组
    size_t start = config.find("\"branch_insns\"");
    if (start != std::string::npos) {
        start = config.find("[", start);
        size_t end = config.find("]", start);
        if (start != std::string::npos && end != std::string::npos) {
            std::string arr = config.substr(start + 1, end - start - 1);
            size_t pos = 0;
            while ((pos = arr.find("\"", pos)) != std::string::npos) {
                size_t endQuote = arr.find("\"", pos + 1);
                if (endQuote != std::string::npos) {
                    insns.push_back(arr.substr(pos + 1, endQuote - pos - 1));
                    pos = endQuote + 1;
                } else break;
            }
        }
    }
    return insns;
}

static std::vector<std::string> parseCondBranchInsns(const std::string& config) {
    std::vector<std::string> insns;
    // 解析 cond_branch_insns 数组
    size_t start = config.find("\"cond_branch_insns\"");
    if (start != std::string::npos) {
        start = config.find("[", start);
        size_t end = config.find("]", start);
        if (start != std::string::npos && end != std::string::npos) {
            std::string arr = config.substr(start + 1, end - start - 1);
            size_t pos = 0;
            while ((pos = arr.find("\"", pos)) != std::string::npos) {
                size_t endQuote = arr.find("\"", pos + 1);
                if (endQuote != std::string::npos) {
                    insns.push_back(arr.substr(pos + 1, endQuote - pos - 1));
                    pos = endQuote + 1;
                } else break;
            }
        }
    }
    return insns;
}

static std::string generateFlowchartJson(const std::vector<FlowchartNode>& nodes, uint64_t baseAddress) {
    std::ostringstream json;
    json << "{";
    json << "\"nodes\":";
    json << "[";
    for (size_t i = 0; i < nodes.size(); i++) {
        const auto& node = nodes[i];
        if (i > 0) json << ",";
        json << "{";
        uint64_t offset = node.addr - baseAddress;
        json << "\"id\":" << std::dec << offset << ",";
        // 地址格式化为十六进制字符串
        std::ostringstream addrStream;
        addrStream << "0x" << std::hex << offset;
        json << "\"address\":\"" << addrStream.str() << "\",";
        json << "\"disasm\":\"";
        // 转义特殊字符
        for (char c : node.disasm) {
            switch (c) {
                case '"': json << "\\\""; break;
                case '\\': json << "\\\\"; break;
                case '\b': json << "\\b"; break;
                case '\f': json << "\\f"; break;
                case '\n': json << "\\n"; break;
                case '\r': json << "\\r"; break;
                case '\t': json << "\\t"; break;
                default:
                    if (c >= 0x20 && c <= 0x7E) {
                        json << c;
                    } else {
                        // 其他控制字符转义为 \u00XX
                        char buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                        json << buf;
                    }
            }
        }
        json << "\",";
        json << "\"isBranch\":" << (node.isBranch ? "true" : "false") << ",";
        json << "\"isCondBranch\":" << (node.isCondBranch ? "true" : "false") << ",";
        json << "\"bytes\":\"";
        for (auto b : node.bytes) {
            json << std::hex << std::setfill('0') << std::setw(2) << (int)b;
        }
        json << std::dec; // 重置为十进制
        json << "\"";
        json << "}";
    }
    json << "],";
    
    // edges
    json << "\"edges\":";
    json << "[";
    bool firstEdge = true;
    for (const auto& node : nodes) {
        uint64_t fromOffset = node.addr - baseAddress;
        for (uint64_t succ : node.successors) {
            uint64_t toOffset = succ - baseAddress;
            if (!firstEdge) json << ",";
            firstEdge = false;
            json << "{";
            json << "\"from\":" << std::dec << fromOffset << ",";
            json << "\"to\":" << std::dec << toOffset;
            json << "}";
        }
    }
    json << "]";
    json << "}";
    return json.str();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_anative_ui_FlowChartFragment_generateFlowchartNative(
    JNIEnv* env, jclass clazz,
    jstring encryptedConfig,
    jstring deviceFingerprint,
    jbyteArray funcBytes,
    jlong funcAddr,
    jlong baseAddress,
    jlong funcSize) {
    
    if (!encryptedConfig || !deviceFingerprint || !funcBytes) {
        return nullptr;
    }

    // 获取加密配置和密钥
    const char* encConfig = env->GetStringUTFChars(encryptedConfig, nullptr);
    const char* fp = env->GetStringUTFChars(deviceFingerprint, nullptr);

    std::string encConfigStr = encConfig ? encConfig : "";
    std::string fingerprintStr = fp ? fp : "";

    // 获取函数字节码
    jsize bytesLen = env->GetArrayLength(funcBytes);
    jbyte* bytesPtr = env->GetByteArrayElements(funcBytes, nullptr);
    std::vector<uint8_t> code(bytesPtr, bytesPtr + bytesLen);
    env->ReleaseByteArrayElements(funcBytes, bytesPtr, JNI_ABORT);

    // C层解密配置
    std::string config = Crypto::aesDecrypt(encConfigStr, fingerprintStr);
    
    env->ReleaseStringUTFChars(encryptedConfig, encConfig);
    env->ReleaseStringUTFChars(deviceFingerprint, fp);

    if (config.empty()) {
        __android_log_print(ANDROID_LOG_ERROR, "FlowChart-Native", "Config decryption failed");
        return nullptr;
    }

    __android_log_print(ANDROID_LOG_DEBUG, "FlowChart-Native", "Config decrypted (first 200 chars): %.200s", config.c_str());

    // 解析分支指令配置
    std::vector<std::string> branchInsns = parseBranchInsns(config);
    std::vector<std::string> condBranchInsns = parseCondBranchInsns(config);
    
    // 配置解析失败，直接报错（网络获取失败或未授权）
    if (branchInsns.empty() || condBranchInsns.empty()) {
        __android_log_print(ANDROID_LOG_ERROR, "FlowChart-Native", "Config parsing failed: branchInsns=%zu, condBranchInsns=%zu", branchInsns.size(), condBranchInsns.size());
        return nullptr;
    }
    
    __android_log_print(ANDROID_LOG_INFO, "FlowChart-Native", 
                       "Branch insns: %zu, Cond branch: %zu, Code size: %zu", 
                       branchInsns.size(), condBranchInsns.size(), code.size());

    // Capstone 反汇编
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK) {
        __android_log_print(ANDROID_LOG_ERROR, "FlowChart-Native", "Capstone init failed");
        return nullptr;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, code.data(), code.size(), funcAddr, 0, &insn);
    
    __android_log_print(ANDROID_LOG_DEBUG, "FlowChart-Native", "Disassembled %zu instructions, baseAddr=0x%lx", count, baseAddress);

    if (count == 0) {
        __android_log_print(ANDROID_LOG_ERROR, "FlowChart-Native", "Disassembly failed");
        cs_close(&handle);
        return nullptr;
    }

    std::set<uint64_t> blockStarts;
    std::vector<std::string> instrDisasm(count);
    blockStarts.insert((uint64_t)funcAddr);

    for (size_t i = 0; i < count; i++) {
        std::string mnemonic = insn[i].mnemonic;
        std::string fullDisasm = mnemonic;
        if (insn[i].op_str[0]) {
            fullDisasm += " ";
            fullDisasm += insn[i].op_str;
        }
        instrDisasm[i] = fullDisasm;

        if (hasMnemonic(branchInsns, mnemonic) && mnemonic != "bl" && mnemonic != "blr") {
            uint64_t target = extractBranchTargetFromDisasm(fullDisasm);
            if (target >= (uint64_t)funcAddr && target < (uint64_t)(funcAddr + funcSize)) {
                blockStarts.insert(target);
            }
            if (hasMnemonic(condBranchInsns, mnemonic) && i + 1 < count) {
                blockStarts.insert(insn[i + 1].address);
            }
        }
    }

    std::vector<FlowchartNode> nodes;
    std::map<uint64_t, size_t> addrToNode;
    FlowchartNode currentNode{};
    bool hasCurrentNode = false;

    for (size_t i = 0; i < count; i++) {
        uint64_t address = insn[i].address;
        bool startNewBlock = !hasCurrentNode || blockStarts.count(address) > 0;
        if (startNewBlock) {
            if (hasCurrentNode) {
                addrToNode[currentNode.addr] = nodes.size();
                nodes.push_back(currentNode);
            }
            currentNode = FlowchartNode{};
            currentNode.addr = address;
            currentNode.isBranch = false;
            currentNode.isCondBranch = false;
            hasCurrentNode = true;
        }

        if (!currentNode.disasm.empty()) {
            currentNode.disasm += "\n";
        }
        std::ostringstream line;
        uint64_t offset = address - baseAddress;
        line << std::hex << offset << ": " << instrDisasm[i];
        currentNode.disasm += line.str();
        currentNode.bytes.insert(currentNode.bytes.end(), insn[i].bytes, insn[i].bytes + insn[i].size);

        std::string mnemonic = insn[i].mnemonic;
        if (hasMnemonic(branchInsns, mnemonic)) {
            currentNode.isBranch = true;
            if (hasMnemonic(condBranchInsns, mnemonic)) {
                currentNode.isCondBranch = true;
            }
        }

        bool endsBlock = false;
        if (i + 1 == count) {
            endsBlock = true;
        } else if (hasMnemonic(branchInsns, mnemonic) && mnemonic != "bl" && mnemonic != "blr") {
            endsBlock = true;
        } else if (blockStarts.count(insn[i + 1].address) > 0) {
            endsBlock = true;
        }

        if (endsBlock) {
            addrToNode[currentNode.addr] = nodes.size();
            nodes.push_back(currentNode);
            currentNode = FlowchartNode{};
            hasCurrentNode = false;
        }
    }

    cs_free(insn, count);
    cs_close(&handle);

    for (size_t i = 0; i < nodes.size(); i++) {
        if (nodes[i].disasm.empty()) {
            continue;
        }

        std::string lastLine = nodes[i].disasm;
        size_t lastBreak = lastLine.rfind('\n');
        if (lastBreak != std::string::npos) {
            lastLine = lastLine.substr(lastBreak + 1);
        }

        size_t colonPos = lastLine.find(':');
        std::string tail = colonPos == std::string::npos ? lastLine : lastLine.substr(colonPos + 1);
        while (!tail.empty() && tail[0] == ' ') {
            tail.erase(0, 1);
        }
        size_t sp = tail.find(' ');
        std::string mnemonic = sp == std::string::npos ? tail : tail.substr(0, sp);

        if (hasMnemonic(branchInsns, mnemonic)) {
            uint64_t target = extractBranchTargetFromDisasm(tail);
            if (mnemonic == "ret" || mnemonic == "br") {
                continue;
            }
            if (mnemonic == "blr" || mnemonic == "bl") {
                if (i + 1 < nodes.size()) {
                    nodes[i].successors.push_back(nodes[i + 1].addr);
                }
                continue;
            }
            if (hasMnemonic(condBranchInsns, mnemonic)) {
                if (target && addrToNode.count(target) > 0) {
                    nodes[i].successors.push_back(target);
                }
                if (i + 1 < nodes.size()) {
                    nodes[i].successors.push_back(nodes[i + 1].addr);
                }
                continue;
            }
            if (target && addrToNode.count(target) > 0) {
                nodes[i].successors.push_back(target);
            }
            continue;
        }

        if (i + 1 < nodes.size()) {
            nodes[i].successors.push_back(nodes[i + 1].addr);
        }
    }

    // 替换所有disasm中的虚拟地址为偏移地址（仅用于显示）
    for (auto& node : nodes) {
        std::string& disasm = node.disasm;
        size_t pos = 0;
        while ((pos = disasm.find("0x", pos)) != std::string::npos) {
            size_t endPos = pos + 2;
            while (endPos < disasm.length() && isxdigit(disasm[endPos])) {
                endPos++;
            }
            if (endPos > pos + 2) {
                std::string addrStr = disasm.substr(pos, endPos - pos);
                uint64_t va = strtoull(addrStr.c_str(), nullptr, 16);
                if (va >= baseAddress && va < baseAddress + 0x10000000) {
                    uint64_t off = va - baseAddress;
                    std::ostringstream offStr;
                    offStr << "0x" << std::hex << off;
                    disasm.replace(pos, endPos - pos, offStr.str());
                }
            }
            pos++;
        }
    }

    // 生成JSON
    std::string json = generateFlowchartJson(nodes, baseAddress);
    
    __android_log_print(ANDROID_LOG_INFO, "FlowChart-Native", 
                       "Generated flowchart: %zu nodes", nodes.size());

    return env->NewStringUTF(json.c_str());
}