package com.example.anative.core;

public class InvokeResult {
    private final boolean success;
    private final String value;
    private final String error;

    private InvokeResult(boolean success, String value, String error) {
        this.success = success;
        this.value = value;
        this.error = error;
    }

    public static InvokeResult success(String value) {
        return new InvokeResult(true, value, null);
    }

    public static InvokeResult error(String error) {
        return new InvokeResult(false, null, error);
    }

    public boolean isSuccess() { return success; }
    public String getValue() { return value; }
    public String getError() { return error; }

    @Override
    public String toString() {
        if (success) {
            return "成功: " + value;
        } else {
            return "错误: " + error;
        }
    }
}
