package com.example.anative.core;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class NativeFunction implements Serializable {
    private String name;
    private long offset;
    private long size;
    private String source; // "dynsym" or "symtab"

    // 函数签名 (用户可编辑)
    private String returnType = "long";    // void, int, long, float, double, string
    private List<ParamInfo> params;        // 参数列表
    private String demangledName;          // demangle后的名字
    private boolean isJni;                 // 是否JNI函数

    public static class ParamInfo implements Serializable {
        public String type;  // int, long, float, double, string
        public String name;  // 参数名

        public ParamInfo(String type, String name) {
            this.type = type;
            this.name = name;
        }

        @Override
        public String toString() {
            return type + " " + name;
        }
    }

    public NativeFunction(String name, long offset, long size, String source) {
        this.name = name;
        this.offset = offset;
        this.size = size;
        this.source = source;
        this.params = new ArrayList<>();
        inferSignature();
    }

    // 从函数名自动推断参数
    private void inferSignature() {
        if (name == null) return;

        // JNI函数: Java_包名_类名_方法名
        if (name.startsWith("Java_")) {
            isJni = true;
            returnType = "long"; // jobject/jint 等都是指针大小
            params.add(new ParamInfo("jnienv", "env"));    // JNIEnv* (自动注入)
            params.add(new ParamInfo("jobject", "thiz"));  // jobject/jclass (自动注入)

            // 解析JNI函数名提取可读名
            String[] parts = name.split("_");
            if (parts.length >= 4) {
                demangledName = parts[parts.length - 1]; // 方法名
            }

            // JNI函数后面可能有更多参数，但从名字无法确定
            // 用户可以手动添加
            return;
        }

        // JNI_OnLoad
        if (name.equals("JNI_OnLoad")) {
            isJni = true;
            returnType = "int";
            // JavaVM* 自动注入
            params.add(new ParamInfo("javavm", "vm"));
            params.add(new ParamInfo("long", "reserved"));
            demangledName = "JNI_OnLoad";
            return;
        }

        // C++ mangled name: _Z开头
        if (name.startsWith("_Z")) {
            demangledName = demangleCpp(name);
            // C++ 函数无法从名字推断参数类型，保持空让用户填
            return;
        }

        // 常见C库函数签名
        inferCommonCFunction();
    }

    // 简单C++ demangle (提取函数名部分)
    private String demangleCpp(String mangled) {
        try {
            // _Z[N]<len><name>... 格式
            int idx = 2;
            boolean nested = false;
            if (mangled.charAt(idx) == 'N') {
                nested = true;
                idx++;
            }
            StringBuilder result = new StringBuilder();
            while (idx < mangled.length()) {
                char c = mangled.charAt(idx);
                if (c >= '0' && c <= '9') {
                    int len = 0;
                    while (idx < mangled.length() && mangled.charAt(idx) >= '0' && mangled.charAt(idx) <= '9') {
                        len = len * 10 + (mangled.charAt(idx) - '0');
                        idx++;
                    }
                    if (idx + len <= mangled.length()) {
                        if (result.length() > 0) result.append("::");
                        result.append(mangled, idx, idx + len);
                        idx += len;
                    } else break;
                } else {
                    break; // 参数编码开始
                }
            }
            return result.length() > 0 ? result.toString() : mangled;
        } catch (Exception e) {
            return mangled;
        }
    }

    // 常见C函数签名推断
    private void inferCommonCFunction() {
        switch (name) {
            case "malloc":
                returnType = "long";
                params.add(new ParamInfo("long", "size"));
                break;
            case "free":
                returnType = "void";
                params.add(new ParamInfo("long", "ptr"));
                break;
            case "memcpy":
            case "memmove":
                returnType = "long";
                params.add(new ParamInfo("long", "dst"));
                params.add(new ParamInfo("long", "src"));
                params.add(new ParamInfo("long", "len"));
                break;
            case "memset":
                returnType = "long";
                params.add(new ParamInfo("long", "ptr"));
                params.add(new ParamInfo("int", "val"));
                params.add(new ParamInfo("long", "len"));
                break;
            case "strlen":
                returnType = "long";
                params.add(new ParamInfo("string", "str"));
                break;
            case "strcmp":
            case "strncmp":
                returnType = "int";
                params.add(new ParamInfo("string", "s1"));
                params.add(new ParamInfo("string", "s2"));
                if (name.equals("strncmp"))
                    params.add(new ParamInfo("long", "n"));
                break;
            case "puts":
            case "printf":
                returnType = "int";
                params.add(new ParamInfo("string", "fmt"));
                break;
            case "open":
                returnType = "int";
                params.add(new ParamInfo("string", "path"));
                params.add(new ParamInfo("int", "flags"));
                break;
            case "close":
                returnType = "int";
                params.add(new ParamInfo("int", "fd"));
                break;
            case "read":
                returnType = "long";
                params.add(new ParamInfo("int", "fd"));
                params.add(new ParamInfo("long", "buf"));
                params.add(new ParamInfo("long", "count"));
                break;
            case "write":
                returnType = "long";
                params.add(new ParamInfo("int", "fd"));
                params.add(new ParamInfo("long", "buf"));
                params.add(new ParamInfo("long", "count"));
                break;
            case "dlopen":
                returnType = "long";
                params.add(new ParamInfo("string", "filename"));
                params.add(new ParamInfo("int", "flags"));
                break;
            case "dlsym":
                returnType = "long";
                params.add(new ParamInfo("long", "handle"));
                params.add(new ParamInfo("string", "symbol"));
                break;
            case "dlclose":
                returnType = "int";
                params.add(new ParamInfo("long", "handle"));
                break;
            // 默认: 不推断，用户自己配
        }
    }

    // Getters
    public String getName() { return name; }
    public long getOffset() { return offset; }
    public long getSize() { return size; }
    public void setSize(long size) { this.size = size; }
    public String getSource() { return source; }
    public String getReturnType() { return returnType; }
    public List<ParamInfo> getParams() { return params; }
    public boolean isJni() { return isJni; }

    public String getDemangledName() {
        return demangledName != null ? demangledName : name;
    }

    // Setters (用户编辑后更新)
    public void setReturnType(String returnType) { this.returnType = returnType; }
    public void setParams(List<ParamInfo> params) { this.params = params; }

    public String getSignatureString() {
        StringBuilder sb = new StringBuilder();
        sb.append(returnType).append(" ").append(getDemangledName()).append("(");
        for (int i = 0; i < params.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(params.get(i));
        }
        if (params.isEmpty()) sb.append("void");
        sb.append(")");
        return sb.toString();
    }

    // 生成给native decompiler用的签名格式: "retType|name0:type0|name1:type1|..."
    public String getNativeSignature() {
        StringBuilder sb = new StringBuilder();
        sb.append(returnType != null ? returnType : "long");
        for (ParamInfo p : params) {
            sb.append("|").append(p.name).append(":").append(p.type);
        }
        return sb.toString();
    }

    public String getOffsetHex() {
        return String.format("%X", offset);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NativeFunction that = (NativeFunction) o;
        return offset == that.offset && name.equals(that.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode() * 31 + Long.hashCode(offset);
    }
}
