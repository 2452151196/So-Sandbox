package com.example.anative.core;

public class NativeDebugger {
    static {
        System.loadLibrary("so_sandbox");
    }

    public static native boolean nativeAttachProcess(int pid);
    public static native boolean nativeDetachProcess(int pid);
    public static native boolean nativeContinue(int pid);
    public static native String nativeWaitEvent(int pid, int timeoutMs);
    public static native byte[] nativeReadMemory(int pid, long addr, int size);
    public static native boolean nativeWriteMemory(int pid, long addr, byte[] data);
    public static native String nativeReadRegisters(int pid);
    public static native boolean nativeWriteRegister(int pid, String name, long value);
    public static native boolean nativeSetBreakpoint(int pid, long addr);
    public static native boolean nativeRemoveBreakpoint(int pid, long addr);
    public static native boolean nativeSingleStep(int pid);
    public static native String nativeGetBreakpoints(int pid);
    public static native long nativeGetChildBase(int pid);
    public static native int nativeSpawnAndTrace(String soPath, long funcOffset);
    public static native boolean nativeCallFunction(int pid, long funcAddr);
    public static native boolean nativeCallFunctionWithArgs(int pid, long funcAddr, long[] args);
}
