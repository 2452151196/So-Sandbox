package com.example.anative.core;

import java.util.List;

/**
 * 用于跨Activity传递大数据，避免TransactionTooLargeException。
 * Intent Binder限制约500KB，函数列表可能超过此限制。
 */
public class DataHolder {
    private static DataHolder instance;

    private List<NativeFunction> functions;
    private long baseAddress;
    private List<ElfParser.StringEntry> strings;
    private List<PltEntry> pltEntries;
    private List<ElfParser.SectionInfo> sections;
    private String soPath;
    private String originalUri;  // 用户选择的原始文件URI
    private XRefAnalyzer xrefs;
    private XRefScanner xrefScanner;
    private long dlopenHandle;

    // 存储修改的指令: key=offset, value=新的汇编指令字符串
    private java.util.Map<Long, String> modifiedInstructions = new java.util.HashMap<>();

    // 标记是否有未保存的修改
    private volatile boolean hasUnsavedChanges = false;

    public static DataHolder getInstance() {
        if (instance == null) {
            instance = new DataHolder();
        }
        return instance;
    }

    public void setFunctions(List<NativeFunction> functions) {
        this.functions = functions;
    }

    public List<NativeFunction> getFunctions() {
        return functions;
    }

    public void setBaseAddress(long baseAddress) {
        this.baseAddress = baseAddress;
    }

    public long getBaseAddress() {
        return baseAddress;
    }

    public void setStrings(List<ElfParser.StringEntry> strings) {
        this.strings = strings;
    }

    public List<ElfParser.StringEntry> getStrings() {
        return strings;
    }

    public void setXRefs(XRefAnalyzer xrefs) {
        this.xrefs = xrefs;
    }

    public XRefAnalyzer getXRefs() {
        return xrefs;
    }

    public void setPltEntries(List<PltEntry> pltEntries) {
        this.pltEntries = pltEntries;
    }

    public List<PltEntry> getPltEntries() {
        return pltEntries;
    }

    public void setSections(List<ElfParser.SectionInfo> sections) {
        this.sections = sections;
    }

    public List<ElfParser.SectionInfo> getSections() {
        return sections;
    }

    public void setSoPath(String soPath) {
        if (soPath == null || soPath.trim().isEmpty()) {
            return;
        }
        // 先卸载旧SO
        if (this.dlopenHandle != 0) {
            try {
                com.example.anative.core.NativeInvoker.nativeDlclose(this.dlopenHandle);
            } catch (Exception e) {
                // 忽略dlclose错误
            }
        }
        
        this.soPath = soPath;
        // 切换SO文件时清除所有旧缓存
        this.xrefScanner = null;
        this.xrefs = null;
        this.functions = null;
        this.strings = null;
        this.pltEntries = null;
        this.sections = null;
        // 清除dlopen句柄和基址，避免JNI_OnLoad重复调用
        this.dlopenHandle = 0;
        this.baseAddress = 0;
    }

    public String getSoPath() {
        return soPath;
    }

    public void setOriginalUri(String uri) {
        this.originalUri = uri;
    }

    public String getOriginalUri() {
        return originalUri;
    }

    public void setXRefScanner(XRefScanner scanner) {
        this.xrefScanner = scanner;
    }

    public XRefScanner getXRefScanner() {
        return xrefScanner;
    }

    public void setDlopenHandle(long handle) {
        this.dlopenHandle = handle;
    }

    public long getDlopenHandle() {
        return dlopenHandle;
    }

    // ========== 指令修改管理 ==========

    public void putModifiedInstruction(long offset, String newAssembly) {
        modifiedInstructions.put(offset, newAssembly);
        hasUnsavedChanges = true;
    }

    public String getModifiedInstruction(long offset) {
        return modifiedInstructions.get(offset);
    }

    public boolean hasModifiedInstruction(long offset) {
        return modifiedInstructions.containsKey(offset);
    }

    public java.util.Map<Long, String> getAllModifiedInstructions() {
        return new java.util.HashMap<>(modifiedInstructions);
    }

    public boolean hasUnsavedChanges() {
        return hasUnsavedChanges;
    }

    public void clearUnsavedChanges() {
        hasUnsavedChanges = false;
    }

    public void markFileModified() {
        hasUnsavedChanges = true;
    }

    public int getModifiedCount() {
        return modifiedInstructions.size();
    }

    public void removeModifiedInstruction(long offset) {
        modifiedInstructions.remove(offset);
        if (modifiedInstructions.isEmpty()) {
            hasUnsavedChanges = false;
        }
    }

    public void clearAllModifiedInstructions() {
        modifiedInstructions.clear();
        hasUnsavedChanges = false;
    }
}
