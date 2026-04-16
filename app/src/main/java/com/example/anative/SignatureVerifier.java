package com.example.anative;

import android.util.Log;

public class SignatureVerifier {
    private static final String TAG = "SignatureVerifier";
    static {
        // 旧库已移除，SO Sandbox使用 so_sandbox 库
    }
    /**
     * 终极版 Native 校验方法。
     * 它使用直接系统调用来打开并解析 APK 文件，
     * 提取 v2/v3 签名证书，并校验其哈希值。
     * @return 如果校验通过则返回 true。如果失败，进程会被终止。
     */

    /**
     * 公开的签名校验入口。
     * 应该在应用生命周期的早期调用，例如 Application.onCreate()。
     */

    private static void _exit(int code) {
        Log.e(TAG, "校验检查失败。正在退出进程，代码: " + code);
        // 一种更强硬的退出方式
        android.os.Process.killProcess(android.os.Process.myPid());
        System.exit(code);
    }
}