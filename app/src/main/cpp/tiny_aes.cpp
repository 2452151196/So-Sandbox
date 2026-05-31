#include "tiny_aes.h"
#include <algorithm>

namespace TinyAES {

// S-box 和逆 S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

AES256::AES256(const uint8_t* key) {
    keyExpansion(key);
}

void AES256::setIV(const uint8_t* ivData) {
    memcpy(iv, ivData, 16);
}

std::vector<uint8_t> AES256::decrypt(const uint8_t* data, size_t len) {
    std::vector<uint8_t> result(len);
    uint8_t state[16];
    uint8_t prevCipher[16];
    memcpy(prevCipher, iv, 16);
    
    for (size_t i = 0; i < len; i += 16) {
        memcpy(state, data + i, 16);
        uint8_t currCipher[16];
        memcpy(currCipher, state, 16);
        
        invCipher(state);
        
        for (int j = 0; j < 16; j++) {
            result[i + j] = state[j] ^ prevCipher[j];
        }
        memcpy(prevCipher, currCipher, 16);
    }
    
    return result;
}

void AES256::keyExpansion(const uint8_t* key) {
    uint8_t temp[4];
    int i = 0;
    
    for (i = 0; i < 32; i++) {
        roundKey[i] = key[i];
    }
    
    for (; i < 240; i += 4) {
        for (int j = 0; j < 4; j++) {
            temp[j] = roundKey[i - 4 + j];
        }
        
        if (i % 32 == 0) {
            uint8_t k = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[i / 32];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[k];
        } else if (i % 32 == 16) {
            for (int j = 0; j < 4; j++) {
                temp[j] = sbox[temp[j]];
            }
        }
        
        for (int j = 0; j < 4; j++) {
            roundKey[i + j] = roundKey[i - 32 + j] ^ temp[j];
        }
    }
}

void AES256::invCipher(uint8_t* state) {
    addRoundKey(14, state);
    
    for (uint8_t round = 13; round > 0; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(round, state);
        invMixColumns(state);
    }
    
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(0, state);
}

void AES256::invSubBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = getSBoxInvert(state[i]);
    }
}

void AES256::invShiftRows(uint8_t* state) {
    uint8_t temp[16];
    
    temp[0] = state[0];
    temp[1] = state[13];
    temp[2] = state[10];
    temp[3] = state[7];
    temp[4] = state[4];
    temp[5] = state[1];
    temp[6] = state[14];
    temp[7] = state[11];
    temp[8] = state[8];
    temp[9] = state[5];
    temp[10] = state[2];
    temp[11] = state[15];
    temp[12] = state[12];
    temp[13] = state[9];
    temp[14] = state[6];
    temp[15] = state[3];
    
    memcpy(state, temp, 16);
}

void AES256::invMixColumns(uint8_t* state) {
    uint8_t a, b, c, d;
    
    for (int i = 0; i < 4; i++) {
        a = state[i * 4 + 0];
        b = state[i * 4 + 1];
        c = state[i * 4 + 2];
        d = state[i * 4 + 3];
        
        state[i * 4 + 0] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        state[i * 4 + 1] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        state[i * 4 + 2] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        state[i * 4 + 3] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
}

void AES256::addRoundKey(uint8_t round, uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[round * 16 + i];
    }
}

uint8_t AES256::getSBoxInvert(uint8_t num) {
    return rsbox[num];
}

uint8_t AES256::multiply(uint8_t x, uint8_t y) {
    return ((y & 0x01) * x) ^
           ((y >> 1 & 0x01) * ((x << 1) ^ ((x & 0x80) ? 0x1b : 0))) ^
           ((y >> 2 & 0x01) * ((x << 2) ^ ((x & 0x40) ? 0x1b : 0) ^ ((x & 0x80) ? 0x1b : 0))) ^
           ((y >> 3 & 0x01) * ((x << 3) ^ ((x & 0x20) ? 0x1b : 0) ^ ((x & 0x40) ? 0x1b : 0) ^ ((x & 0x80) ? 0x1b : 0)));
}

// SHA-256 简化实现
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    
    for (int i = 0; i < 16; i++) {
        w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }
    
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256(const uint8_t* data, size_t len, uint8_t hash[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    size_t bitLen = len * 8;
    size_t paddedLen = ((len + 8) / 64 + 1) * 64;
    uint8_t* padded = new uint8_t[paddedLen];
    memcpy(padded, data, len);
    padded[len] = 0x80;
    for (size_t i = len + 1; i < paddedLen - 8; i++) {
        padded[i] = 0;
    }
    for (int i = 0; i < 8; i++) {
        padded[paddedLen - 1 - i] = (bitLen >> (i * 8)) & 0xff;
    }
    
    for (size_t i = 0; i < paddedLen; i += 64) {
        sha256_transform(state, padded + i);
    }
    delete[] padded;
    
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xff;
        hash[i * 4 + 3] = state[i] & 0xff;
    }
}

// HMAC-SHA256
static void hmac_sha256(const uint8_t* key, size_t keyLen,
                        const uint8_t* msg, size_t msgLen,
                        uint8_t result[32]) {
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    
    for (size_t i = 0; i < keyLen && i < 64; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
    
    uint8_t* inner = new uint8_t[64 + msgLen];
    memcpy(inner, k_ipad, 64);
    memcpy(inner + 64, msg, msgLen);
    
    uint8_t innerHash[32];
    sha256(inner, 64 + msgLen, innerHash);
    delete[] inner;
    
    uint8_t outer[64 + 32];
    memcpy(outer, k_opad, 64);
    memcpy(outer + 64, innerHash, 32);
    sha256(outer, 64 + 32, result);
}

// PBKDF2-HMAC-SHA256
std::vector<uint8_t> pbkdf2_sha256(const std::string& password, 
                                    const uint8_t* salt, size_t saltLen,
                                    int iterations, size_t keyLen) {
    std::vector<uint8_t> result(keyLen);
    size_t blockCount = (keyLen + 31) / 32;
    
    for (size_t i = 1; i <= blockCount; i++) {
        uint8_t u[32];
        uint8_t t[32];
        
        uint8_t block[4];
        block[0] = (i >> 24) & 0xff;
        block[1] = (i >> 16) & 0xff;
        block[2] = (i >> 8) & 0xff;
        block[3] = i & 0xff;
        
        uint8_t* firstMsg = new uint8_t[saltLen + 4];
        memcpy(firstMsg, salt, saltLen);
        memcpy(firstMsg + saltLen, block, 4);
        hmac_sha256((const uint8_t*)password.c_str(), password.length(), 
                    firstMsg, saltLen + 4, u);
        delete[] firstMsg;
        memcpy(t, u, 32);
        
        for (int j = 1; j < iterations; j++) {
            hmac_sha256((const uint8_t*)password.c_str(), password.length(),
                        u, 32, u);
            for (int k = 0; k < 32; k++) {
                t[k] ^= u[k];
            }
        }
        
        size_t copyLen = (i - 1) * 32 + 32 > keyLen ? keyLen - (i - 1) * 32 : 32;
        memcpy(result.data() + (i - 1) * 32, t, copyLen);
    }
    
    return result;
}

// Base64 解码
std::string base64Decode(const std::string& input) {
    static const std::string b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    int val = 0, valb = -8;
    for (char c : input) {
        if (c == '=') break;
        size_t pos = b64.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            output.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

// bytes 转 hex
std::string bytesToHex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    for (size_t i = 0; i < len; i++) {
        result.push_back(hex[(data[i] >> 4) & 0xF]);
        result.push_back(hex[data[i] & 0xF]);
    }
    return result;
}

// AES-256-CBC 完整解密
std::string aes256cbc_decrypt(const std::string& encryptedB64, const std::string& keyStr) {
    // Base64 解码
    std::string combined = base64Decode(encryptedB64);
    if (combined.length() < 24) return "";
    
    // 提取 salt, iv, ciphertext
    uint8_t salt[8];
    uint8_t iv[16];
    memcpy(salt, combined.data(), 8);
    memcpy(iv, combined.data() + 8, 16);
    std::string ciphertext = combined.substr(24);
    
    // PBKDF2 派生密钥
    std::string keySalt = keyStr + bytesToHex(salt, 8);
    std::vector<uint8_t> derivedKey = pbkdf2_sha256(keySalt, salt, 8, 10000, 32);
    
    // AES-256-CBC 解密
    AES256 aes(derivedKey.data());
    aes.setIV(iv);
    std::vector<uint8_t> plaintext = aes.decrypt((const uint8_t*)ciphertext.data(), ciphertext.length());
    
    // 去除 PKCS7 填充
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

} // namespace TinyAES
