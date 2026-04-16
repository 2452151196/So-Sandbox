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
    private XRefAnalyzer xrefs;
    private XRefScanner xrefScanner;
    private long dlopenHandle;

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
        this.soPath = soPath;
        // 切换SO文件时清除所有旧缓存
        this.xrefScanner = null;
        this.xrefs = null;
        this.functions = null;
        this.strings = null;
        this.pltEntries = null;
        this.sections = null;
    }

    public String getSoPath() {
        return soPath;
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
}
