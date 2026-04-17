package com.example.anative.core;

import android.util.Log;

import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 交叉引用扫描器 - 使用Capstone原生引擎扫描.text段
 * 通过NativeInvoker.scanXRefsFromBytes一次性扫描所有BL/B和ADRP+ADD
 * 构建:
 * - 函数调用图 (谁调用了谁)
 * - 字符串引用图 (哪个函数引用了哪个字符串)
 */
public class XRefScanner {

    private static final String TAG = "XRefScanner";

    /** 函数调用引用 */
    public static class CallRef {
        public final long instrOffset;       // BL/B指令地址 (虚拟地址)
        public final long callerFuncOffset;  // 调用方函数起始地址
        public final String callerFuncName;  // 调用方函数名

        public CallRef(long instrOffset, long callerFuncOffset, String callerFuncName) {
            this.instrOffset = instrOffset;
            this.callerFuncOffset = callerFuncOffset;
            this.callerFuncName = callerFuncName;
        }
    }

    /** 字符串引用 */
    public static class StringRef {
        public final long instrOffset;   // ADD指令地址
        public final long funcOffset;    // 所在函数起始地址
        public final String funcName;    // 所在函数名

        public StringRef(long instrOffset, long funcOffset, String funcName) {
            this.instrOffset = instrOffset;
            this.funcOffset = funcOffset;
            this.funcName = funcName;
        }
    }

    // 目标函数offset → 调用它的地方列表
    private final Map<Long, List<CallRef>> callersMap = new HashMap<>();
    // 函数offset → 它调用的目标列表
    private final Map<Long, List<CallRef>> calleesMap = new HashMap<>();
    // 字符串virtualAddress → 引用它的地方列表
    private final Map<Long, List<StringRef>> stringRefMap = new HashMap<>();

    private boolean scanned = false;
    private boolean hasStringData = false;
    private int totalFuncCount = 0;  // 实际传入的函数总数

    public synchronized boolean isScanned() {
        return scanned;
    }

    public boolean hasStringData() {
        return hasStringData;
    }

    public int getScannedFuncCount() {
        return totalFuncCount;  // 返回实际扫描的函数总数
    }

    /**
     * 扫描SO文件的.text段, 构建交叉引用 (使用Capstone原生引擎)
     */
    public synchronized void scan(String soPath, List<NativeFunction> functions,
                                  List<ElfParser.StringEntry> strings) {
        if (scanned) return;

        try {
            long startTime = System.currentTimeMillis();
            this.totalFuncCount = (functions != null) ? functions.size() : 0;

            // 找到.text段
            List<ElfParser.SectionInfo> sections = ElfParser.parseSections(soPath);
            ElfParser.SectionInfo textSec = null;
            for (ElfParser.SectionInfo s : sections) {
                if (".text".equals(s.name)) {
                    textSec = s;
                    break;
                }
            }
            if (textSec == null) {
                Log.w(TAG, "No .text section found");
                scanned = true;
                return;
            }

            // 读取.text段字节
            long readSize = Math.min(textSec.size, 16 * 1024 * 1024); // max 16MB
            byte[] textBytes;
            try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
                textBytes = new byte[(int) readSize];
                raf.seek(textSec.offset);
                raf.readFully(textBytes);
            }
            long textVAddr = textSec.virtualAddress;

            Log.i(TAG, String.format("Text section: vaddr=0x%X offset=0x%X size=%d",
                    textVAddr, textSec.offset, readSize));

            // 构建函数表字符串: "addr|name|addr|name|..."
            StringBuilder funcTableSb = new StringBuilder();
            List<NativeFunction> sortedFuncs = new ArrayList<>(functions);
            sortedFuncs.sort(Comparator.comparingLong(NativeFunction::getOffset));
            for (NativeFunction f : sortedFuncs) {
                if (funcTableSb.length() > 0) funcTableSb.append('|');
                funcTableSb.append(String.format("%X", f.getOffset()));
                funcTableSb.append('|');
                // 函数名中的|和换行符会破坏解析, 替换掉
                String safeName = f.getDemangledName()
                        .replace('|', '/')
                        .replace('\n', ' ')
                        .replace('\r', ' ');
                funcTableSb.append(safeName);
            }

            // 构建字符串表: "addr|str|addr|str|..."
            StringBuilder strTableSb = new StringBuilder();
            if (strings != null && !strings.isEmpty()) {
                for (ElfParser.StringEntry s : strings) {
                    if (strTableSb.length() > 0) strTableSb.append('|');
                    strTableSb.append(String.format("%X", s.virtualAddress));
                    strTableSb.append('|');
                    // 截断过长字符串, 避免JNI传输过大
                    String val = s.value.length() > 64 ? s.value.substring(0, 64) : s.value;
                    strTableSb.append(val.replace('|', ' ').replace('\n', ' '));
                }
                hasStringData = true;
            }

            Log.i(TAG, String.format("Scanning: %d funcs, %d strings, %d bytes of .text",
                    sortedFuncs.size(), strings != null ? strings.size() : 0, textBytes.length));
            Log.d(TAG, "Total functions in table: " + sortedFuncs.size());
            if (sortedFuncs.size() > 0) {
                Log.d(TAG, "First func: 0x" + Long.toHexString(sortedFuncs.get(0).getOffset()) + "=" + sortedFuncs.get(0).getDemangledName());
                Log.d(TAG, "Last func: 0x" + Long.toHexString(sortedFuncs.get(sortedFuncs.size()-1).getOffset()) + "=" + sortedFuncs.get(sortedFuncs.size()-1).getDemangledName());
            }

            // 调用原生Capstone扫描
            Log.d(TAG, "Calling native scanXRefsFromBytes...");
            long nativeStart = System.currentTimeMillis();
            String funcTableStr = funcTableSb.toString();
            String strTableStr = strTableSb.toString();
            Log.d(TAG, "Func table length=" + funcTableStr.length() + ", String table length=" + strTableStr.length());
            Log.d(TAG, "First 100 chars of funcTable: " + funcTableStr.substring(0, Math.min(100, funcTableStr.length())));

            String result = NativeInvoker.scanXRefsFromBytes(
                    textBytes, textVAddr, readSize,
                    funcTableStr, strTableStr);
            long nativeElapsed = System.currentTimeMillis() - nativeStart;

            if (result == null || result.isEmpty() || result.startsWith("ERR")) {
                Log.w(TAG, "Native scan returned: " + (result != null ? result : "null") + " in " + nativeElapsed + "ms");
                scanned = true;
                return;
            }
            Log.i(TAG, "Native scan completed in " + nativeElapsed + "ms, result length=" + result.length());
            if (result.length() > 0) {
                Log.d(TAG, "First 200 chars of result: " + result.substring(0, Math.min(200, result.length())).replace("\n", "|"));
            }

            // 解析结果, 构建映射
            // 函数地址 → NativeFunction 映射
            Map<Long, NativeFunction> funcByOffset = new HashMap<>();
            for (NativeFunction f : sortedFuncs) {
                funcByOffset.put(f.getOffset(), f);
            }

            String[] lines = result.split("\n");
            int funcRefs = 0, strRefs = 0;

            for (String line : lines) {
                if (line.length() < 5) continue;
                String[] parts = line.split("\\|");
                if (parts.length < 3) continue;

                try {
                    long instrAddr = Long.parseLong(parts[1], 16);
                    long targetAddr = Long.parseLong(parts[2], 16);

                    if ("F".equals(parts[0])) {
                        // 函数调用: instrAddr处的BL/B跳转到targetAddr
                        NativeFunction caller = findContainingFunction(instrAddr, sortedFuncs);
                        long callerOffset;
                        String callerName;
                        if (caller != null) {
                            callerOffset = caller.getOffset();
                            callerName = caller.getDemangledName();
                        } else {
                            // Stripped 区域：用合成名
                            callerOffset = instrAddr;
                            callerName = String.format("sub_%X", instrAddr);
                        }

                        NativeFunction callee = funcByOffset.get(targetAddr);
                        String calleeName = callee != null ? callee.getDemangledName()
                                : String.format("sub_%X", targetAddr);

                        // callers: targetAddr 被 caller 调用
                        CallRef callerRef = new CallRef(instrAddr, callerOffset, callerName);
                        callersMap.computeIfAbsent(targetAddr, k -> new ArrayList<>()).add(callerRef);

                        // callees: caller 调用了 targetAddr
                        CallRef calleeRef = new CallRef(instrAddr, targetAddr, calleeName);
                        calleesMap.computeIfAbsent(callerOffset, k -> new ArrayList<>()).add(calleeRef);
                        funcRefs++;
                    } else if ("S".equals(parts[0])) {
                        // 字符串引用: instrAddr处引用了targetAddr
                        NativeFunction func = findContainingFunction(instrAddr, sortedFuncs);
                        if (func != null) {
                            StringRef ref = new StringRef(instrAddr, func.getOffset(), func.getDemangledName());
                            stringRefMap.computeIfAbsent(targetAddr, k -> new ArrayList<>()).add(ref);
                            strRefs++;
                        }
                    }
                } catch (NumberFormatException ignored) {
                }
            }

            scanned = true;
            long elapsed = System.currentTimeMillis() - startTime;
            Log.i(TAG, String.format("XRef scan done in %dms: %d func xrefs, %d string xrefs (from %d lines), callers=%d, callees=%d, strRefs=%d",
                    elapsed, funcRefs, strRefs, lines.length, callersMap.size(), calleesMap.size(), stringRefMap.size()));

        } catch (Exception e) {
            Log.e(TAG, "XRef scan failed: " + e.getMessage(), e);
            scanned = true;
        }
    }

    /** 获取某函数被谁调用 */
    public List<CallRef> getCallersOf(long funcOffset) {
        return callersMap.getOrDefault(funcOffset, Collections.emptyList());
    }

    /** 获取某函数调用了谁 */
    public List<CallRef> getCalleesOf(long funcOffset) {
        return calleesMap.getOrDefault(funcOffset, Collections.emptyList());
    }

    /**
     * 获取某地址范围 [start, end) 内所有 BL/B 调用目标
     * 用于合成/stripped 函数：我们不知道它的精确起止，按估计范围查
     */
    public List<CallRef> getCalleesInRange(long startOffset, long endOffset) {
        List<CallRef> result = new ArrayList<>();
        for (Map.Entry<Long, List<CallRef>> e : calleesMap.entrySet()) {
            long callerOff = e.getKey();
            if (callerOff >= startOffset && callerOff < endOffset) {
                result.addAll(e.getValue());
            }
        }
        // 同时遍历所有 callers 记录，按 instrOffset 过滤（更精确）
        java.util.Set<Long> seen = new java.util.HashSet<>();
        List<CallRef> byInstr = new ArrayList<>();
        for (List<CallRef> list : callersMap.values()) {
            for (CallRef ref : list) {
                if (ref.instrOffset >= startOffset && ref.instrOffset < endOffset) {
                    if (seen.add(ref.instrOffset)) {
                        byInstr.add(ref);
                    }
                }
            }
        }
        return byInstr.isEmpty() ? result : byInstr;
    }

    /** 获取引用某字符串的函数列表 */
    public List<StringRef> getStringRefsAt(long stringVAddr) {
        return stringRefMap.getOrDefault(stringVAddr, Collections.emptyList());
    }

    /** 调试用: 获取所有有字符串引用的地址 */
    public java.util.Set<Long> getStringRefKeys() {
        return stringRefMap.keySet();
    }

    // ---- 内部工具方法 ----

    private NativeFunction findContainingFunction(long addr, List<NativeFunction> sortedFuncs) {
        int lo = 0, hi = sortedFuncs.size() - 1;
        NativeFunction result = null;
        while (lo <= hi) {
            int mid = (lo + hi) / 2;
            NativeFunction f = sortedFuncs.get(mid);
            if (f.getOffset() <= addr) {
                result = f;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if (result != null) {
            if (result.getSize() > 0 && addr >= result.getOffset() + result.getSize()) {
                return null;
            }
            return result;
        }
        return null;
    }
}
