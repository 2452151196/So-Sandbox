#ifndef TINY_AES_H
#define TINY_AES_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// 简单的 AES-256-CBC 实现 (基于 tiny-AES-c)
namespace TinyAES {

class AES256 {
public:
    AES256(const uint8_t* key);
    void setIV(const uint8_t* iv);
    std::vector<uint8_t> decrypt(const uint8_t* data, size_t len);

private:
    uint8_t roundKey[240]; // 60 * 4 = 240
    uint8_t iv[16];
    
    void keyExpansion(const uint8_t* key);
    void invCipher(uint8_t* state);
    void invSubBytes(uint8_t* state);
    void invShiftRows(uint8_t* state);
    void invMixColumns(uint8_t* state);
    void addRoundKey(uint8_t round, uint8_t* state);
    uint8_t getSBoxInvert(uint8_t num);
    uint8_t multiply(uint8_t x, uint8_t y);
};

// PBKDF2-HMAC-SHA256 简化实现
std::vector<uint8_t> pbkdf2_sha256(const std::string& password, 
                                    const uint8_t* salt, size_t saltLen,
                                    int iterations, size_t keyLen);

// Base64 编解码
std::string base64Decode(const std::string& input);
std::string bytesToHex(const uint8_t* data, size_t len);

// 完整的 AES-256-CBC 解密
std::string aes256cbc_decrypt(const std::string& encryptedB64, const std::string& keyStr);

} // namespace TinyAES

#endif // TINY_AES_H
