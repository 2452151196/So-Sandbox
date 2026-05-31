package com.example.anative.core;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class DebugSessionManager {

    public interface OnBreakpointChangeListener {
        void onBreakpointsChanged(Set<Long> breakpointOffsets);
    }

    public interface OnStateChangeListener {
        void onDebugStateChanged(boolean active, String status);
    }

    private static final DebugSessionManager INSTANCE = new DebugSessionManager();

    private int childPid = 0;
    private long childBase = 0;
    private boolean active = false;
    private String soPath = null;
    private String statusText = "未连接";

    // 断点偏移集合（相对 SO 文件偏移，不是绝对地址）
    private final Set<Long> breakpointOffsets = new HashSet<>();
    private OnBreakpointChangeListener bpListener;
    private OnStateChangeListener stateListener;

    private DebugSessionManager() {}

    public static DebugSessionManager getInstance() {
        return INSTANCE;
    }

    public synchronized void setBreakpointChangeListener(OnBreakpointChangeListener l) {
        this.bpListener = l;
    }

    public synchronized void setStateChangeListener(OnStateChangeListener l) {
        this.stateListener = l;
    }

    public synchronized boolean isActive() {
        return active;
    }

    public synchronized int getChildPid() {
        return childPid;
    }

    public synchronized long getChildBase() {
        return childBase;
    }

    public synchronized String getSoPath() {
        return soPath;
    }

    public synchronized String getStatusText() {
        return statusText;
    }

    public synchronized Set<Long> getBreakpointOffsets() {
        return Collections.unmodifiableSet(new HashSet<>(breakpointOffsets));
    }

    /**
     * Spawn 子进程并加载 SO
     * @param soPath SO 文件路径
     * @param funcOffset 函数偏移量（可选，>0 时自动在入口设断点）
     * @return true if spawn succeeded
     */
    public synchronized boolean spawnChild(String soPath, long funcOffset) {
        // 先关旧的
        if (active && childPid > 0) {
            NativeDebugger.nativeDetachProcess(childPid);
        }
        breakpointOffsets.clear();
        this.soPath = soPath;

        int pid = NativeDebugger.nativeSpawnAndTrace(soPath, funcOffset);
        if (pid <= 0) {
            active = false;
            childPid = 0;
            childBase = 0;
            statusText = "Spawn 失败";
            notifyState();
            return false;
        }

        childPid = pid;
        childBase = NativeDebugger.nativeGetChildBase(pid);
        active = true;
        statusText = "已连接 PID=" + pid + " Base=0x" + Long.toHexString(childBase);
        notifyState();

        // 自动在函数入口设断点
        if (funcOffset > 0 && childBase > 0) {
            toggleBreakpoint(funcOffset);
        }

        return true;
    }

    /**
     * 切换断点（以 SO 文件偏移为单位）
     * @return true if breakpoint is now set, false if removed
     */
    public synchronized boolean toggleBreakpoint(long fileOffset) {
        if (!active || childPid <= 0 || childBase <= 0) return false;

        long absAddr = childBase + fileOffset;

        if (breakpointOffsets.contains(fileOffset)) {
            // 移除
            boolean ok = NativeDebugger.nativeRemoveBreakpoint(childPid, absAddr);
            if (ok) breakpointOffsets.remove(fileOffset);
            notifyBreakpoints();
            return false;
        } else {
            // 添加
            boolean ok = NativeDebugger.nativeSetBreakpoint(childPid, absAddr);
            if (ok) breakpointOffsets.add(fileOffset);
            notifyBreakpoints();
            return true;
        }
    }

    public synchronized boolean hasBreakpoint(long fileOffset) {
        return breakpointOffsets.contains(fileOffset);
    }

    public synchronized boolean continueExec() {
        if (!active || childPid <= 0) return false;
        return NativeDebugger.nativeContinue(childPid);
    }

    public synchronized boolean singleStep() {
        if (!active || childPid <= 0) return false;
        return NativeDebugger.nativeSingleStep(childPid);
    }

    public synchronized String waitEvent(int timeoutMs) {
        if (!active || childPid <= 0) return null;
        return NativeDebugger.nativeWaitEvent(childPid, timeoutMs);
    }

    public synchronized String readRegisters() {
        if (!active || childPid <= 0) return null;
        return NativeDebugger.nativeReadRegisters(childPid);
    }

    /**
     * 调用子进程中指定偏移处的函数
     * @param fileOffset 函数在SO中的文件偏移
     * @return true if call was initiated
     */
    public synchronized boolean callFunction(long fileOffset) {
        if (!active || childPid <= 0 || childBase <= 0) return false;
        long absAddr = childBase + fileOffset;
        return NativeDebugger.nativeCallFunction(childPid, absAddr);
    }

    public synchronized boolean callFunctionWithArgs(long fileOffset, long[] args) {
        if (!active || childPid <= 0 || childBase <= 0) return false;
        long absAddr = childBase + fileOffset;
        return NativeDebugger.nativeCallFunctionWithArgs(childPid, absAddr, args);
    }

    public synchronized byte[] readMemory(long addr, int size) {
        if (!active || childPid <= 0) return null;
        return NativeDebugger.nativeReadMemory(childPid, addr, size);
    }

    /**
     * 获取当前 PC 对应的文件偏移（用于高亮当前执行行）
     */
    public synchronized long getCurrentPcOffset() {
        if (!active || childPid <= 0 || childBase <= 0) return -1;
        String regs = NativeDebugger.nativeReadRegisters(childPid);
        if (regs == null || regs.startsWith("ERR")) return -1;
        // 格式: PC=0xXXX|SP=...
        try {
            String pcStr = regs.split("\\|")[0]; // PC=0xXXX
            long pc = Long.parseLong(pcStr.substring(5), 16); // skip "PC=0x"
            return pc - childBase;
        } catch (Exception e) {
            return -1;
        }
    }

    public synchronized void detach() {
        if (active && childPid > 0) {
            NativeDebugger.nativeDetachProcess(childPid);
        }
        active = false;
        childPid = 0;
        childBase = 0;
        breakpointOffsets.clear();
        statusText = "已分离";
        notifyState();
        notifyBreakpoints();
    }

    private void notifyBreakpoints() {
        if (bpListener != null) {
            bpListener.onBreakpointsChanged(new HashSet<>(breakpointOffsets));
        }
    }

    private void notifyState() {
        if (stateListener != null) {
            stateListener.onDebugStateChanged(active, statusText);
        }
    }
}
