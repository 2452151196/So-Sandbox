package com.example.anative.core;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

public class SoLoader {
    private static final String TAG = "SoLoader";
    private static final String SO_DIR = "loaded_so";

    private final Context context;
    private String loadedSoPath;
    private long baseAddress;
    private long dlopenHandle;  // dlopen句柄

    public SoLoader(Context context) {
        this.context = context.getApplicationContext();
    }

    /**
     * 将SO文件从Uri复制到私有目录并用dlopen加载 (不触发JNI_OnLoad)
     */
    public boolean loadSo(Uri uri) throws IOException {
        return loadSo(uri, false);
    }

    public boolean loadSo(Uri uri, boolean staticOnly) throws IOException {
        // 如果有旧句柄先关闭
        if (dlopenHandle != 0) {
            NativeInvoker.nativeDlclose(dlopenHandle);
            dlopenHandle = 0;
        }

        // 复制到私有目录
        File soDir = new File(context.getFilesDir(), SO_DIR);
        if (!soDir.exists()) {
            soDir.mkdirs();
        }

        // 清理旧文件
        File[] oldFiles = soDir.listFiles();
        if (oldFiles != null) {
            for (File f : oldFiles) {
                f.delete();
            }
        }

        // 获取原始文件名
        String originalFileName = getFileNameFromUri(uri);
        if (originalFileName == null || originalFileName.isEmpty()) {
            originalFileName = "target.so";
        }
        File targetFile = new File(soDir, originalFileName);

        try (InputStream is = context.getContentResolver().openInputStream(uri);
             FileOutputStream fos = new FileOutputStream(targetFile)) {
            if (is == null) {
                throw new IOException("无法打开文件");
            }
            byte[] buffer = new byte[8192];
            int len;
            while ((len = is.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
            }
        }

        // 设置可执行权限
        targetFile.setReadable(true);
        targetFile.setExecutable(true);

        loadedSoPath = targetFile.getAbsolutePath();
        Log.i(TAG, "SO copied to: " + loadedSoPath);

        if (staticOnly) {
            Log.i(TAG, "Static analysis only mode (user choice)");
            baseAddress = 0;
            return true;
        }

        // 用dlopen加载 (不触发JNI_OnLoad, 避免第三方SO的FindClass崩溃)
        // 注意：dlopen可能因缺少依赖而失败，但ELF静态分析仍可进行
        dlopenHandle = NativeInvoker.nativeDlopen(loadedSoPath);
        if (dlopenHandle == 0) {
            Log.w(TAG, "dlopen failed (missing deps?), using static analysis mode");
            // 静态分析模式：不返回错误，只是无法动态调用函数
            baseAddress = 0;
            return true; // 仍然成功，用于ELF解析
        }
        Log.i(TAG, "SO loaded via dlopen, handle=0x" + Long.toHexString(dlopenHandle));

        // 获取基址
        baseAddress = getBaseAddressFromMaps(loadedSoPath);
        Log.i(TAG, "Base address: 0x" + Long.toHexString(baseAddress));

        return true;
    }

    /**
     * 解析 /proc/self/maps 获取SO的基址
     */
    private long getBaseAddressFromMaps(String soPath) {
        String soName = new File(soPath).getName();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        new java.io.FileInputStream("/proc/self/maps")))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(soName) && line.contains("r-xp")) {
                    // 格式: 地址范围 权限 偏移 设备 inode 路径
                    // 如: 7a8c000000-7a8c001000 r-xp 00000000 ...
                    String addrRange = line.split("\\s+")[0];
                    String startAddr = addrRange.split("-")[0];
                    return Long.parseUnsignedLong(startAddr, 16);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse /proc/self/maps", e);
        }
        return 0;
    }

    public String getLoadedSoPath() {
        return loadedSoPath;
    }

    public long getBaseAddress() {
        return baseAddress;
    }

    public long getDlopenHandle() {
        return dlopenHandle;
    }

    /**
     * 从Uri获取原始文件名
     */
    private String getFileNameFromUri(Uri uri) {
        if (uri == null) return null;
        String fileName = null;
        String scheme = uri.getScheme();
        if ("file".equals(scheme)) {
            fileName = uri.getLastPathSegment();
        } else if ("content".equals(scheme)) {
            // 使用 DocumentsContract 解析 content URI
            String path = uri.getPath();
            if (path != null) {
                int slash = path.lastIndexOf('/');
                if (slash >= 0 && slash < path.length() - 1) {
                    fileName = path.substring(slash + 1);
                }
            }
            // 如果还没有获取到文件名，尝试查询
            if (fileName == null || fileName.isEmpty() || fileName.startsWith("msf:")) {
                try {
                    String displayName = uri.getLastPathSegment();
                    if (displayName != null) {
                        int colon = displayName.lastIndexOf(':');
                        if (colon >= 0) {
                            fileName = displayName.substring(colon + 1);
                        } else {
                            fileName = displayName;
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Failed to get display name from URI");
                }
            }
        }
        return fileName;
    }
}
