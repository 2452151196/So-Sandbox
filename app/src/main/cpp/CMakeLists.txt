# CMakeLists.txt - SO Sandbox 动态加载与分析工具

cmake_minimum_required(VERSION 3.18.1)

project("so_sandbox")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# =============================================================================
# Capstone 反汇编引擎 (仅ARM64)
# =============================================================================
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SYSZ_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_M68K_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_EVM_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_RISCV_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_MOS65XX_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BPF_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_SH_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_TRICORE_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ALPHA_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_HPPA_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_LOONGARCH_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_XTENSA_SUPPORT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARC_SUPPORT OFF CACHE BOOL "" FORCE)

add_subdirectory(capstone)

# =============================================================================
# SO Sandbox 核心库 (Capstone 反汇编 + 运行时追踪)
# =============================================================================
add_library(
        so_sandbox
        SHARED
        invoker.c
        crash_protection.c
        decompiler.c
        runtime_tracer.cpp
        native-lib.cpp
        tiny_aes.cpp
        debugger.cpp)

target_include_directories(so_sandbox PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/capstone/include)

# 添加 mbedTLS 子目录
add_subdirectory(mbedtls)

# 查找Android系统库
find_library(log-lib log)
find_library(dl-lib dl)

target_link_libraries(
        so_sandbox
        capstone
        mbedcrypto
        ${log-lib}
        ${dl-lib}
        -latomic
        -lm)