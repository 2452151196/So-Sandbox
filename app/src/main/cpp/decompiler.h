#ifndef DECOMPILER_H
#define DECOMPILER_H

#include <stdint.h>
#include <stddef.h>

// 将函数的机器码翻译为伪C代码
// code: 函数起始地址
// code_size: 函数大小(字节)
// base_addr: 函数在内存中的绝对地址
// output: 输出缓冲区
// output_size: 缓冲区大小
// 返回值: 写入output的字节数
int decompile_function(const uint8_t *code, size_t code_size, uint64_t base_addr,
                       char *output, size_t output_size);

// 带函数签名的版本
// func_name: 函数名 (可NULL)
// signature: 函数签名描述, 格式 "retType|name0:type0|name1:type1|..." (可NULL)
int decompile_function_ex(const uint8_t *code, size_t code_size, uint64_t base_addr,
                          const char *func_name, const char *signature,
                          char *output, size_t output_size);

#endif // DECOMPILER_H
