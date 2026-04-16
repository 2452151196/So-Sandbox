# ===================================================================
#           nativehook/src/main/cpp/CMakeLists.txt (最终修正版)
# ===================================================================

cmake_minimum_required(VERSION 3.4.1)

# [保留] 作者原有的架构判断逻辑，这非常重要
if(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "arm64-v8a")
    set(OS_DEPENDENDED_SRC
            archs/arm/arm64/assembler/assembler_arm64.cpp
            archs/arm/arm64/inst/inst_arm64.cpp
            archs/arm/arm64/register/register_arm64.cpp
            archs/arm/arm64/register/register_list_arm64.cpp
            archs/arm/arm64/decoder/decoder_arm64.cpp
            archs/arm/arm64/relocate/code_relocate_arm64.cpp
            archs/arm/arm64/hook/hook_arm64.cpp)

elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "armeabi-v7a")
    set(OS_DEPENDENDED_SRC
            archs/arm/arm32/inst/inst_arm32.cpp
            archs/arm/arm32/inst/inst_t32.cpp
            archs/arm/arm32/inst/inst_t16.cpp
            archs/arm/arm32/register/register_arm32.cpp
            archs/arm/arm32/register/register_list_arm32.cpp
            archs/arm/arm32/assembler/assembler_arm32.cpp
            archs/arm/arm32/decoder/decoder_arm32.cpp
            archs/arm/arm32/hook/hook_arm32.cpp
            archs/arm/arm32/hook/breakpoint_shellcode.S
            archs/arm/arm32/relocate/code_relocate_arm32.cpp)
endif()

# [保留] 作者原有的库定义和源文件列表
add_library(
        sandhook-native
        SHARED
        sandhook_native.cpp
        decoder/decoder.cpp
        relocate/code_relocate.cpp
        elf/elf.cpp
        assembler/assembler.cpp
        buffer/code_buffer.cpp
        utils/platform.cpp
        hook/hook.cpp
        ${OS_DEPENDENDED_SRC})

# 【关键修正】
# 我们不再使用旧的、全局的 include_directories() 命令。
# 而是使用新的、与目标绑定的 target_include_directories() 命令，
# 并将关键字设为 PUBLIC，这样其他链接到 sandhook-native 的目标就能自动获得这些路径。
target_include_directories(sandhook-native PUBLIC
        # 这里把原来 include_directories() 里的所有目录都复制过来
        # 并使用 ${CMAKE_CURRENT_SOURCE_DIR} 来确保路径是绝对的
        ${CMAKE_CURRENT_SOURCE_DIR}/asm
        ${CMAKE_CURRENT_SOURCE_DIR}/decoder
        ${CMAKE_CURRENT_SOURCE_DIR}/elf
        ${CMAKE_CURRENT_SOURCE_DIR}/utils
        ${CMAKE_CURRENT_SOURCE_DIR}/includes
        ${CMAKE_CURRENT_SOURCE_DIR}/buffer
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm64/inst
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm64/register
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm64/decoder
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm64/assembler
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm64/relocate
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm64/hook
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm32/inst
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm32/register
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm32/assembler
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm32/decoder
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm32/hook
        ${CMAKE_CURRENT_SOURCE_DIR}/archs/arm/arm32/relocate
        # ${CMAKE_CURRENT_SOURCE_DIR}/src/main/cpp/antihook # 这行路径看起来很奇怪，可能是个笔误，先注释掉
)

# [保留] 作者原有的系统库查找和链接
find_library(log-lib log)
target_link_libraries(sandhook-native ${log-lib})

# [保留] 作者原有的C++标准和语言设置
add_definitions(-std=c++11)
ENABLE_LANGUAGE(ASM)