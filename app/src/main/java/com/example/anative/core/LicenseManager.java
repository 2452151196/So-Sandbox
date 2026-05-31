package com.example.anative.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.provider.Settings;
import android.util.Log;

import com.example.anative.ui.SettingsActivity;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 授权管理器 - 处理卡密验证和设备白名单
 */
public class LicenseManager {
    private static final String TAG = "LicenseManager";
    private static final String DEFAULT_SERVER_URL = "http://192.168.10.5:8902";
    
    private final Context context;
    private final SharedPreferences prefs;
    private final ExecutorService executor;
    
    public interface AuthCallback {
        void onResult(boolean authorized, String message);
    }
    
    public interface VerifyCallback {
        void onResult(boolean success, int days, String message);
    }
    
    public LicenseManager(Context context) {
        this.context = context.getApplicationContext();
        this.prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE);
        this.executor = Executors.newSingleThreadExecutor();
    }
    
    /**
     * 获取服务器地址（支持本地调试）
     * 默认：http://chahaoma.xyz:8902
     * 本地测试：http://192.168.x.x:8902 或 http://10.0.2.2:8902（模拟器）
     */
    public static String getServerUrl(Context context) {
        return "http://chahaoma.xyz:8902";
    }
    
    /**
     * 获取设备ID (Android ID)
     */
    public static String getDeviceId(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
    }
    
    /**
     * 检查本地授权状态（是否已激活且未过期）
     */
    public boolean isAuthorized() {
        boolean authorized = prefs.getBoolean(SettingsActivity.PREF_DEVICE_AUTHORIZED, false);
        if (!authorized) return false;
        
        // 检查是否过期
        long expireAt = prefs.getLong(SettingsActivity.PREF_EXPIRE_AT, 0);
        if (expireAt > 0) {
            long now = System.currentTimeMillis();
            if (now >= expireAt) {
                // 已过期，清除授权状态
                prefs.edit()
                    .putBoolean(SettingsActivity.PREF_DEVICE_AUTHORIZED, false)
                    .apply();
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 验证卡密并绑定设备到白名单
     */
    public void verifyCardKey(String cardKey, VerifyCallback callback) {
        executor.execute(() -> {
            try {
                String deviceId = getDeviceId(context);
                URL url = new URL(getServerUrl(context) + "/api/verifyCard");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                conn.setDoOutput(true);
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(10000);
                
                String params = "cardKey=" + URLEncoder.encode(cardKey, "UTF-8") +
                        "&deviceId=" + URLEncoder.encode(deviceId, "UTF-8");
                
                OutputStream os = conn.getOutputStream();
                os.write(params.getBytes("UTF-8"));
                os.flush();
                os.close();
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                
                JSONObject json = new JSONObject(response.toString());
                
                if (json.getBoolean("ok")) {
                    int days = json.optInt("days", 30);
                    long expireAt = json.optLong("expireAt", 0);
                    if (expireAt == 0) {
                        expireAt = System.currentTimeMillis() + days * 24L * 60 * 60 * 1000;
                    }
                    prefs.edit()
                            .putString(SettingsActivity.PREF_CARD_KEY, cardKey)
                            .putBoolean(SettingsActivity.PREF_DEVICE_AUTHORIZED, true)
                            .putLong(SettingsActivity.PREF_EXPIRE_AT, expireAt)
                            .apply();
                    callback.onResult(true, days, "激活成功，有效期" + days + "天");
                } else {
                    String msg = json.optString("msg", "验证失败");
                    callback.onResult(false, 0, msg);
                }
            } catch (Exception e) {
                Log.e(TAG, "verifyCardKey error", e);
                callback.onResult(false, 0, "网络错误: " + e.getMessage());
            }
        });
    }
    
    /**
     * 检查设备是否在服务端白名单中（实时验证）
     * 用于关键功能（动态注册、流程图、交叉引用）的权限检查
     */
    public void checkDeviceWhitelist(AuthCallback callback) {
        executor.execute(() -> {
            try {
                String deviceId = getDeviceId(context);
                URL url = new URL(getServerUrl(context) + "/api/checkDevice?deviceId=" + URLEncoder.encode(deviceId, "UTF-8"));
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);
                
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                
                JSONObject json = new JSONObject(response.toString());
                boolean authorized = json.optBoolean("ok", false);
                String msg = json.optString("msg", authorized ? "已授权" : "未授权");
                
                // 同步本地状态
                if (authorized != isAuthorized()) {
                    prefs.edit().putBoolean(SettingsActivity.PREF_DEVICE_AUTHORIZED, authorized).apply();
                }
                
                callback.onResult(authorized, msg);
            } catch (Exception e) {
                Log.e(TAG, "checkDeviceWhitelist error", e);
                // 网络错误时，使用本地缓存的授权状态
                callback.onResult(isAuthorized(), "离线模式: " + (isAuthorized() ? "已授权" : "未授权"));
            }
        });
    }
    
    /**
     * 清除授权（用于退出登录或测试）
     */
    public void clearAuthorization() {
        prefs.edit()
                .remove(SettingsActivity.PREF_DEVICE_AUTHORIZED)
                .remove(SettingsActivity.PREF_CARD_KEY)
                .apply();
    }
    
    public void shutdown() {
        executor.shutdown();
    }
    
    /**
     * 获取设备指纹（静态方法）
     */
    public static String getDeviceFingerprint(Context context) {
        String androidId = getDeviceId(context);
        String fingerprint = androidId + "_" + android.os.Build.MANUFACTURER + "_" + android.os.Build.MODEL;
        return hashString(fingerprint);
    }
    
    private static String hashString(String input) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().substring(0, 32);
        } catch (Exception e) {
            return input.substring(0, Math.min(input.length(), 32));
        }
    }
}
