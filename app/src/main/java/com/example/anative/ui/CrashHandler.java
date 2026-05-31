package com.example.anative.ui;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class CrashHandler implements Thread.UncaughtExceptionHandler {

    private static final String TAG = "CrashHandler";
    private static final String CRASH_FILE = "crash_last.log";
    private static final String CRASH_PREFS = "crash_prefs";
    private static final String KEY_CRASH_TIME = "crash_time";
    private static final String KEY_CRASH_EXISTS = "crash_exists";

    private final Thread.UncaughtExceptionHandler defaultHandler;
    private final Context appContext;

    private CrashHandler(Context context) {
        this.appContext = context.getApplicationContext();
        this.defaultHandler = Thread.getDefaultUncaughtExceptionHandler();
    }

    public static void init(Application app) {
        Thread.setDefaultUncaughtExceptionHandler(new CrashHandler(app));
    }

    @Override
    public void uncaughtException(Thread thread, Throwable ex) {
        String crashInfo = collectCrashInfo(thread, ex);
        saveCrashInfo(crashInfo);

        // 交给系统默认处理器，让应用正常崩溃退出
        if (defaultHandler != null) {
            defaultHandler.uncaughtException(thread, ex);
        }
    }

    private String collectCrashInfo(Thread thread, Throwable ex) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);

        pw.println("===== So Sandbox 崩溃报告 =====");
        pw.println("崩溃时间: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date()));
        pw.println("线程: " + thread.getName() + " (id=" + thread.getId() + ")");
        pw.println();

        // 设备信息
        pw.println("--- 设备信息 ---");
        pw.println("Android 版本: " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")");
        pw.println("设备: " + Build.MANUFACTURER + " " + Build.MODEL);
        pw.println("品牌: " + Build.BRAND);
        pw.println("硬件: " + Build.HARDWARE);
        pw.println("ABIs: " + String.join(", ", Build.SUPPORTED_ABIS));
        pw.println("App 版本: " + getAppVersion());
        pw.println();

        // 存储信息
        try {
            StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
            long blockSize = stat.getBlockSizeLong();
            long availableBlocks = stat.getAvailableBlocksLong();
            pw.println("内部存储可用: " + formatSize(availableBlocks * blockSize));
            pw.println();
        } catch (Exception ignored) {
        }

        // 异常堆栈
        pw.println("--- 异常堆栈 ---");
        ex.printStackTrace(pw);
        pw.println();

        pw.println("===== 报告结束 =====");
        pw.flush();

        return sw.toString();
    }

    private void saveCrashInfo(String crashInfo) {
        try {
            File dir = appContext.getFilesDir();
            File file = new File(dir, CRASH_FILE);
            BufferedWriter writer = new BufferedWriter(new FileWriter(file));
            writer.write(crashInfo);
            writer.flush();
            writer.close();

            SharedPreferences prefs = appContext.getSharedPreferences(CRASH_PREFS, Context.MODE_PRIVATE);
            prefs.edit()
                    .putString(KEY_CRASH_TIME, new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date()))
                    .putBoolean(KEY_CRASH_EXISTS, true)
                    .commit();

            Log.e(TAG, "崩溃日志已保存到: " + file.getAbsolutePath());
        } catch (Exception e) {
            Log.e(TAG, "保存崩溃日志失败", e);
        }
    }

    public static boolean hasCrashLog(Context context) {
        File file = new File(context.getFilesDir(), CRASH_FILE);
        return file.exists() && file.length() > 0;
    }

    public static String getCrashLog(Context context) {
        try {
            File file = new File(context.getFilesDir(), CRASH_FILE);
            if (!file.exists()) return null;

            StringBuilder sb = new StringBuilder();
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            reader.close();
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "读取崩溃日志失败", e);
            return null;
        }
    }

    public static String getCrashTime(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(CRASH_PREFS, Context.MODE_PRIVATE);
        return prefs.getString(KEY_CRASH_TIME, "");
    }

    public static void clearCrashLog(Context context) {
        try {
            File file = new File(context.getFilesDir(), CRASH_FILE);
            if (file.exists()) file.delete();
        } catch (Exception ignored) {
        }
        SharedPreferences prefs = context.getSharedPreferences(CRASH_PREFS, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(KEY_CRASH_EXISTS, false).apply();
    }

    public static void writeTestCrashLog(Context context) {
        try {
            String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date());
            StringBuilder sb = new StringBuilder();
            sb.append("===== So Sandbox 崩溃报告 =====\n");
            sb.append("崩溃时间: ").append(time).append("\n");
            sb.append("线程: main (id=1)\n\n");
            sb.append("--- 设备信息 ---\n");
            sb.append("Android 版本: ").append(Build.VERSION.RELEASE).append(" (API ").append(Build.VERSION.SDK_INT).append(")\n");
            sb.append("设备: ").append(Build.MANUFACTURER).append(" ").append(Build.MODEL).append("\n");
            sb.append("品牌: ").append(Build.BRAND).append("\n");
            sb.append("硬件: ").append(Build.HARDWARE).append("\n");
            sb.append("ABIs: ").append(String.join(", ", Build.SUPPORTED_ABIS)).append("\n\n");
            sb.append("--- 异常堆栈 ---\n");
            sb.append("java.lang.RuntimeException: 这是一条手动生成的测试崩溃日志\n");
            sb.append("    at com.example.anative.ui.MainActivity.onOptionsItemSelected(MainActivity.java:607)\n");
            sb.append("    at android.app.Activity.onMenuItemSelected(Activity.java:0000)\n\n");
            sb.append("===== 报告结束 =====\n");

            File file = new File(context.getFilesDir(), CRASH_FILE);
            BufferedWriter writer = new BufferedWriter(new FileWriter(file));
            writer.write(sb.toString());
            writer.flush();
            writer.close();

            SharedPreferences prefs = context.getSharedPreferences(CRASH_PREFS, Context.MODE_PRIVATE);
            prefs.edit()
                    .putString(KEY_CRASH_TIME, time)
                    .putBoolean(KEY_CRASH_EXISTS, true)
                    .commit();
        } catch (Exception e) {
            Log.e(TAG, "写入测试崩溃日志失败", e);
        }
    }

    private String getAppVersion() {
        try {
            return appContext.getPackageManager().getPackageInfo(appContext.getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static String formatSize(long size) {
        if (size < 1024) return size + " B";
        if (size < 1024 * 1024) return String.format(Locale.getDefault(), "%.2f KB", size / 1024.0);
        if (size < 1024 * 1024 * 1024) return String.format(Locale.getDefault(), "%.2f MB", size / (1024.0 * 1024));
        return String.format(Locale.getDefault(), "%.2f GB", size / (1024.0 * 1024 * 1024));
    }
}
