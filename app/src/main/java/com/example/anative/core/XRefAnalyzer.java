package com.example.anative.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 交叉引用分析器
 * 构建函数调用图 (BL/B指令分析)
 */
public class XRefAnalyzer {

    public static class XRef {
        public final long callerAddr;  // 调用指令地址
        public final long calleeAddr;  // 被调用函数地址
        public final boolean isCall;   // true=BL调用, false=B跳转

        public XRef(long caller, long callee, boolean isCall) {
            this.callerAddr = caller;
            this.calleeAddr = callee;
            this.isCall = isCall;
        }
    }

    // 调用图: 函数地址 -> 它调用的函数列表
    private final Map<Long, List<XRef>> outgoing = new HashMap<>();
    // 反向引用: 函数地址 -> 调用它的函数列表
    private final Map<Long, List<XRef>> incoming = new HashMap<>();

    /**
     * 解析native返回的交叉引用字符串
     * format: "caller|callee|type|caller|callee|type|..."
     */
    public void parseXRefString(String result, long baseAddress, long sourceFuncOffset) {
        outgoing.clear();
        incoming.clear();

        if (result == null || result.equals("none") || result.startsWith("ERR:")) {
            return;
        }

        String[] parts = result.split("\\|");
        for (int i = 0; i + 2 < parts.length; i += 3) {
            try {
                long caller = Long.parseLong(parts[i], 16);
                long callee = Long.parseLong(parts[i+1], 16);
                boolean isCall = parts[i+2].equals("call");

                XRef ref = new XRef(caller, callee, isCall);

                // 绝对地址 -> 相对地址转换 (用于匹配函数列表)
                long calleeRel = callee - baseAddress;

                outgoing.computeIfAbsent(sourceFuncOffset, k -> new ArrayList<>()).add(ref);
                incoming.computeIfAbsent(calleeRel, k -> new ArrayList<>()).add(ref);

            } catch (NumberFormatException e) {
                // skip
            }
        }
    }

    /**
     * 获取某函数调用了哪些函数
     */
    public List<XRef> getCallsFrom(long funcOffset) {
        return outgoing.getOrDefault(funcOffset, new ArrayList<>());
    }

    /**
     * 获取哪些函数调用了某函数
     */
    public List<XRef> getCallsTo(long funcOffset) {
        return incoming.getOrDefault(funcOffset, new ArrayList<>());
    }

    /**
     * 判断某函数是否有交叉引用信息
     */
    public boolean hasXRefs(long funcOffset) {
        return outgoing.containsKey(funcOffset) || incoming.containsKey(funcOffset);
    }

    /**
     * 获取调用统计信息
     */
    public String getStats() {
        int outCount = outgoing.values().stream().mapToInt(List::size).sum();
        int inCount = incoming.values().stream().mapToInt(List::size).sum();
        return String.format("调用: %d, 被调用: %d", outCount, inCount);
    }
}
