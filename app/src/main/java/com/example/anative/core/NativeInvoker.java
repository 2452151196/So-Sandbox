package com.example.anative.core;

public class NativeInvoker {
    static {
        System.loadLibrary("so_sandbox");
    }

    /**
     * 初始化崩溃保护 (信号处理 + ByteHook)
     */
    public static native boolean initCrashProtection();

    /**
     * 使用libffi调用指定地址的函数
     * @param funcAddr 函数的绝对内存地址
     * @param retType 返回值类型: "void","int","long","float","double","string"
     * @param paramTypes 参数类型数组
     * @param paramValues 参数值数组 (字符串形式)
     * @return 结果字符串, 以"OK:"开头表示成功, 以"ERR:"开头表示错误
     */
    public static native String invokeFunction(
            long funcAddr,
            String retType,
            String[] paramTypes,
            String[] paramValues
    );

    /**
     * Hook RegisterNatives 以捕获动态注册的JNI函数
     * @return 是否成功
     */
    public static native boolean hookRegisterNatives();

    /**
     * Hook FindClass/GetMethodID/GetFieldID (让第三方SO的JNI调用不崩溃)
     */
    public static native boolean hookFindClass();

    /**
     * 设置应用的ClassLoader，用于hook_FindClass加载APK中的类
     * @param loader 当前应用的ClassLoader
     */
    public static native void setClassLoader(ClassLoader loader);

    /**
     * 分析函数交叉引用 (BL/B指令目标)
     * @param funcAddr 函数地址
     * @param funcSize 函数大小
     * @param knownFuncAddrs 已知函数地址列表 (用于匹配调用目标)
     * @return 格式: "caller|callee|type|..." 或 "none"
     */
    public static native String analyzeXRefs(long funcAddr, long funcSize, long[] knownFuncAddrs);

    /**
     * 获取捕获到的动态注册函数列表
     * @return 格式: "className|name|signature|address\n..."
     */
    public static native String getCapturedRegistrations();

    /**
     * 清除已捕获的注册数据
     */
    public static native void clearCapturedRegistrations();

    /**
     * 调用目标SO的JNI_OnLoad，触发RegisterNatives捕获
     * @param handle dlopen句柄
     * @return "OK:version|count" 或 "ERR:msg" 或 "CRASH:signal|count"
     */
    public static native String callJniOnLoad(long handle);

    /**
     * 调用捕获到的动态注册函数
     * 自动注入 JNIEnv* + jclass，根据签名解析参数类型
     * @param index 捕获列表中的索引
     * @param paramValues 用户参数值（不含 env 和 jclass），字符串形式
     * @return "OK:结果" 或 "ERR:错误信息"
     */
    public static native String callCapturedNative(int index, String[] paramValues);

    /**
     * 反汇编函数
     * @param funcAddr 函数的绝对内存地址
     * @param funcSize 函数大小(字节), 0表示使用默认值
     * @return ARM64汇编文本
     */
    public static native String disassembleFunction(long funcAddr, long funcSize);

    /**
     * 带字符串表注释的反汇编 (显示偏移地址)
     * @param funcAddr 函数的绝对内存地址
     * @param funcSize 函数大小
     * @param stringTable 字符串表格式 "offset|str|offset|str|..." (偏移地址)
     * @param pltTable PLT表格式 "offset|name|offset|name|..." (偏移地址和函数名)
     * @param baseAddress SO基址
     * @return 带注释的反汇编文本 (显示偏移而非绝对地址)
     */
    public static native String disassembleFunctionEx(long funcAddr, long funcSize, String stringTable, String pltTable, long baseAddress, String funcTable);

    /**
     * 全局TEXT段反汇编，高亮显示指定函数
     * @param baseAddr SO基址（代码段起始）
     * @param textSize 代码段大小
     * @param highlightFuncAddr 要高亮的函数地址
     * @param highlightFuncSize 要高亮的函数大小
     * @param stringTable 字符串表
     * @param pltTable PLT表
     * @return 全局反汇编文本，当前函数行前会有 ">>" 标记
     */
    public static native String disassembleTextSection(long baseAddr, long textSize, long highlightFuncAddr, long highlightFuncSize, String stringTable, String pltTable);

    /**
     * 伪C反编译
     * @param funcAddr 函数的绝对内存地址
     * @param funcSize 函数大小(字节), 0表示使用默认值
     * @return 伪C代码文本
     */
    public static native String decompileFunction(long funcAddr, long funcSize);

    /**
     * 带签名的伪C反编译 (显示偏移地址)
     * @param funcAddr 函数的绝对内存地址
     * @param funcSize 函数大小(字节)
     * @param funcName 函数名 (可null)
     * @param signature 签名描述 "retType|name0:type0|..." (可null)
     * @param baseAddress SO基址，用于计算偏移地址显示
     * @return 伪C代码文本 (地址显示为偏移)
     */
    public static native String decompileFunctionEx(long funcAddr, long funcSize, String funcName, String signature, long baseAddress);

    /**
     * 从byte[]反汇编 (静态分析模式，SO未加载到内存时使用)
     * @param bytes 函数机器码字节
     * @param funcOffset 函数在文件中的偏移
     * @param funcSize 函数大小
     * @param stringTable 字符串表
     * @param pltTable PLT表
     * @return 汇编文本
     */
    public static native String disassembleBytes(byte[] bytes, long funcOffset, long funcSize, String stringTable, String pltTable, String funcTable);

    /**
     * 从byte[]伪C反编译 (静态分析模式)
     * @param bytes 函数机器码字节
     * @param funcOffset 函数在文件中的偏移
     * @param funcSize 函数大小
     * @param funcName 函数名
     * @param signature 签名
     * @return 伪C文本
     */
    public static native String decompileBytes(byte[] bytes, long funcOffset, long funcSize, String funcName, String signature);

    /**
     * 批量扫描.text段的交叉引用 (静态分析)
     * @param textBytes .text段字节数据
     * @param textVAddr .text段虚拟地址
     * @param textSize .text段大小
     * @param funcTable 函数表 "addr|name|addr|name|..."
     * @param stringTable 字符串表 "addr|str|addr|str|..."
     * @return 格式: "F|caller_vaddr|callee_vaddr\nS|instr_vaddr|string_vaddr\n..."
     */
    public static native String scanXRefsFromBytes(byte[] textBytes, long textVAddr, long textSize,
                                                    String funcTable, String stringTable);

    /**
     * 获取JavaVM指针 (用于手动调用JNI_OnLoad)
     * @return JavaVM*的long值
     */
    public static native long getJavaVM();

    /**
     * 用dlopen加载SO文件 (不触发JNI_OnLoad, 避免ClassNotFoundException崩溃)
     * @param path SO文件的绝对路径
     * @return dlopen句柄, 0表示失败
     */
    public static native long nativeDlopen(String path);

    /**
     * 卸载SO文件
     * @param handle dlopen返回的句柄
     */
    public static native void nativeDlclose(long handle);

    /**
     * 查找SO中的符号地址
     * @param handle dlopen返回的句柄
     * @param symbol 符号名
     * @return 符号的绝对地址, 0表示未找到
     */
    public static native long nativeDlsym(long handle, String symbol);

    /**
     * 计算函数的绝对地址 = 基址 + 偏移
     */
    public static long calcAbsoluteAddress(long baseAddress, long offset) {
        return baseAddress + offset;
    }

    /**
     * 读取内存字节
     * @param addr 绝对内存地址
     * @param size 读取字节数
     * @return 读取的字节数组
     */
    public static native byte[] readMemory(long addr, int size);

    /**
     * 写入内存字节
     * @param addr 内存地址
     * @param value 写入的字节值
     * @return 是否成功
     */
    public static native boolean writeMemory(long addr, byte value);

    /**
     * 写入多字节到内存 (用于写入完整指令)
     * @param addr 内存地址
     * @param bytes 要写入的字节数组
     * @return 是否成功
     */
    public static native boolean writeMemoryBytes(long addr, byte[] bytes);

    /**
     * 汇编写入: 将ARM64汇编码转换为机器码
     * @param assembly 汇编指令，如 "MOV X0, X1"
     * @param virtualOffset 指令的虚拟偏移地址
     * @return 机器码字节数组，或null表示失败
     */
    public static native byte[] assembleInstruction(String assembly, long virtualOffset);

    /**
     * 获取上一次 assembleInstruction 失败的错误信息
     * @return 错误描述字符串，没有错误时返回空字符串
     */
    public static native String getLastAssembleError();

    /**
     * 解析单条指令为机器码并写入SO文件
     * @param soPath SO文件路径
     * @param virtualOffset 虚拟偏移地址
     * @param assembly 汇编指令
     * @return 写入的字节数，-1表示失败
     */
    public static native int patchInstruction(String soPath, long virtualOffset, String assembly);

    /**
     * 启用运行时追踪 - 在函数执行时记录其内部调用
     * @param funcAddr 函数绝对地址
     * @param funcName 函数名称（用于日志显示）
     * @return 是否成功
     */
    public static native boolean enableTraceForFunction(long funcAddr, String funcName);

    /**
     * 获取追踪日志
     * @return 追踪记录的调用树文本
     */
    public static native String getTraceLog();

    /**
     * 清除追踪日志
     */
    public static native void clearTraceLog();
}
