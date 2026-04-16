package com.example.anative.core;

/**
 * PLT (Procedure Linkage Table) 条目
 * 用于动态链接的外部函数跳转
 */
public class PltEntry {
    public final long offset;        // 在SO文件中的偏移
    public final long size;          // PLT条目大小 (通常16字节)
    public final String symbolName;  // 目标函数名 (如 "printf", "malloc")
    public final long gotOffset;     // 对应的GOT表项偏移

    public PltEntry(long offset, long size, String symbolName, long gotOffset) {
        this.offset = offset;
        this.size = size;
        this.symbolName = symbolName;
        this.gotOffset = gotOffset;
    }

    @Override
    public String toString() {
        return String.format("PLT[0x%X]: %s", offset, symbolName);
    }
}
