package com.example.anative;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.provider.OpenableColumns;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 文件工具类，处理从其他应用传入的文件 URI
 */
public class FileUtils {

    /**
     * 尝试从 URI 获取真实文件路径
     */
    public static String getPathFromUri(Context context, Uri uri) {
        if (uri == null) return null;

        String scheme = uri.getScheme();

        // 文件 scheme 直接返回路径
        if ("file".equals(scheme)) {
            return uri.getPath();
        }

        // content scheme 尝试查询
        if ("content".equals(scheme)) {
            // 尝试获取文件名并在缓存目录查找
            String fileName = getFileName(context, uri);
            if (fileName != null) {
                // 检查是否是已缓存的文件
                File cacheFile = new File(context.getCacheDir(), fileName);
                if (cacheFile.exists()) {
                    return cacheFile.getAbsolutePath();
                }
            }
        }

        return null;
    }

    /**
     * 将文件复制到缓存目录并返回路径
     */
    public static String copyToCache(Context context, Uri uri) {
        if (uri == null) return null;

        InputStream inputStream = null;
        FileOutputStream outputStream = null;

        try {
            String fileName = getFileName(context, uri);
            if (fileName == null || fileName.isEmpty()) {
                fileName = "shared_file.so";
            }

            // 生成唯一文件名
            String uniqueName = System.currentTimeMillis() + "_" + fileName;
            File cacheFile = new File(context.getCacheDir(), uniqueName);

            ContentResolver resolver = context.getContentResolver();
            inputStream = resolver.openInputStream(uri);
            if (inputStream == null) return null;

            outputStream = new FileOutputStream(cacheFile);

            byte[] buffer = new byte[8192];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, read);
            }

            outputStream.flush();
            return cacheFile.getAbsolutePath();

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            try {
                if (inputStream != null) inputStream.close();
                if (outputStream != null) outputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 从 URI 获取文件名
     */
    public static String getFileName(Context context, Uri uri) {
        String result = null;

        // 先尝试从 URI 路径获取
        String path = uri.getPath();
        if (path != null) {
            int cut = path.lastIndexOf('/');
            if (cut != -1) {
                result = path.substring(cut + 1);
            }
        }

        // 如果路径没有文件名，查询 ContentResolver
        if (result == null || result.isEmpty()) {
            Cursor cursor = null;
            try {
                ContentResolver resolver = context.getContentResolver();
                cursor = resolver.query(uri, null, null, null, null);
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex >= 0) {
                        result = cursor.getString(nameIndex);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                if (cursor != null) cursor.close();
            }
        }

        return result;
    }
}
