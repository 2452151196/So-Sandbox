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
        const char* h = "8C3BE50AB290D439DA436D255E02271D9ED73930C80F5EBEA98741AC81CDCA52";
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
__attribute__((constructor, visibility("hidden")))
static void _e() {
    I::v();
}