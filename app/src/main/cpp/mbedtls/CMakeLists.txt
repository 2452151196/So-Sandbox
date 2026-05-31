# mbedTLS 库 (轻量级SSL/TLS)
# 用于C层AES解密
# 注意：需要手动下载 mbedtls-2.28.8 源码并解压到本目录
# 下载地址：https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.8.tar.gz

cmake_minimum_required(VERSION 3.10.2)
project(mbedtls LANGUAGES C)

# 设置mbedTLS源码路径
set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls-2.28.8)

# 检查源码是否存在
if(NOT EXISTS ${MBEDTLS_DIR})
    message(WARNING "mbedTLS source not found at ${MBEDTLS_DIR}")
    message(WARNING "Please download: https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.8.tar.gz")
    message(WARNING "And extract to: ${CMAKE_CURRENT_SOURCE_DIR}")
    message(FATAL_ERROR "mbedTLS is required for AES decryption")
endif()

# 设置mbedTLS选项
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)

# 添加mbedTLS库
add_library(mbedcrypto STATIC
    ${MBEDTLS_DIR}/library/aes.c
    ${MBEDTLS_DIR}/library/aesni.c
    ${MBEDTLS_DIR}/library/arc4.c
    ${MBEDTLS_DIR}/library/aria.c
    ${MBEDTLS_DIR}/library/asn1parse.c
    ${MBEDTLS_DIR}/library/asn1write.c
    ${MBEDTLS_DIR}/library/base64.c
    ${MBEDTLS_DIR}/library/bignum.c
    ${MBEDTLS_DIR}/library/blowfish.c
    ${MBEDTLS_DIR}/library/camellia.c
    ${MBEDTLS_DIR}/library/ccm.c
    ${MBEDTLS_DIR}/library/chacha20.c
    ${MBEDTLS_DIR}/library/chachapoly.c
    ${MBEDTLS_DIR}/library/cipher.c
    ${MBEDTLS_DIR}/library/cipher_wrap.c
    ${MBEDTLS_DIR}/library/cmac.c
    ${MBEDTLS_DIR}/library/constant_time.c
    ${MBEDTLS_DIR}/library/ctr_drbg.c
    ${MBEDTLS_DIR}/library/des.c
    ${MBEDTLS_DIR}/library/dhm.c
    ${MBEDTLS_DIR}/library/ecdh.c
    ${MBEDTLS_DIR}/library/ecdsa.c
    ${MBEDTLS_DIR}/library/ecjpake.c
    ${MBEDTLS_DIR}/library/ecp.c
    ${MBEDTLS_DIR}/library/ecp_curves.c
    ${MBEDTLS_DIR}/library/entropy.c
    ${MBEDTLS_DIR}/library/entropy_poll.c
    ${MBEDTLS_DIR}/library/gcm.c
    ${MBEDTLS_DIR}/library/hkdf.c
    ${MBEDTLS_DIR}/library/hmac_drbg.c
    ${MBEDTLS_DIR}/library/md.c
    ${MBEDTLS_DIR}/library/md2.c
    ${MBEDTLS_DIR}/library/md4.c
    ${MBEDTLS_DIR}/library/md5.c
    ${MBEDTLS_DIR}/library/memory_buffer_alloc.c
    ${MBEDTLS_DIR}/library/nist_kw.c
    ${MBEDTLS_DIR}/library/oid.c
    ${MBEDTLS_DIR}/library/padlock.c
    ${MBEDTLS_DIR}/library/pem.c
    ${MBEDTLS_DIR}/library/pk.c
    ${MBEDTLS_DIR}/library/pk_wrap.c
    ${MBEDTLS_DIR}/library/pkcs12.c
    ${MBEDTLS_DIR}/library/pkcs5.c
    ${MBEDTLS_DIR}/library/pkparse.c
    ${MBEDTLS_DIR}/library/pkwrite.c
    ${MBEDTLS_DIR}/library/platform.c
    ${MBEDTLS_DIR}/library/platform_util.c
    ${MBEDTLS_DIR}/library/poly1305.c
    ${MBEDTLS_DIR}/library/ripemd160.c
    ${MBEDTLS_DIR}/library/rsa.c
    ${MBEDTLS_DIR}/library/sha1.c
    ${MBEDTLS_DIR}/library/sha256.c
    ${MBEDTLS_DIR}/library/sha512.c
    ${MBEDTLS_DIR}/library/threading.c
    ${MBEDTLS_DIR}/library/timing.c
    ${MBEDTLS_DIR}/library/version.c
    ${MBEDTLS_DIR}/library/version_features.c
    ${MBEDTLS_DIR}/library/xtea.c
)

target_include_directories(mbedcrypto PUBLIC 
    ${MBEDTLS_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# 创建自定义配置文件
file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/include/mbedtls_config.h "
/* mbedTLS 配置文件 - Android */
#define MBEDTLS_PKCS5_C
#define MBEDTLS_PKCS12_C
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_WITH_PADDING
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_VERSION_C
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD

#include \"mbedtls/check_config.h\"
")

# 添加宏定义
target_compile_definitions(mbedcrypto PUBLIC 
    -DMBEDTLS_CONFIG_FILE=<mbedtls_config.h>
)

# 设置编译选项
target_compile_options(mbedcrypto PRIVATE 
    -Os
    -fomit-frame-pointer
)

# 链接库
find_library(log-lib log)
target_link_libraries(mbedcrypto ${log-lib})
