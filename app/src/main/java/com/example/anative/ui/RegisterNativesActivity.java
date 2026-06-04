package com.example.anative.ui;

import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class RegisterNativesActivity extends AppCompatActivity {

    public static final String EXTRA_STATIC_MODE = "static_mode";

    private TextView tvStatus;
    private ProgressBar progressBar;
    private RecyclerView recyclerView;
    private RegNativeAdapter adapter;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean staticMode = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_register_natives);

        staticMode = getIntent().getBooleanExtra(EXTRA_STATIC_MODE, false);

        androidx.appcompat.widget.Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(staticMode ? "JNI 注册表 (静态)" : "RegisterNatives 代理");
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        toolbar.setNavigationOnClickListener(v -> finish());

        tvStatus = findViewById(R.id.tvStatus);
        progressBar = findViewById(R.id.progressBar);
        recyclerView = findViewById(R.id.recyclerView);

        adapter = new RegNativeAdapter();
        adapter.setOnItemClickListener(this::jumpToFunction);
        adapter.setOnItemCallListener(this::showCallDialog);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));
        recyclerView.setAdapter(adapter);

        staticMode = getIntent().getBooleanExtra(EXTRA_STATIC_MODE, false);
        if (staticMode) {
            runStaticOnly();
        } else {
            runProxy();
        }
    }

    private void runStaticOnly() {
        progressBar.setVisibility(View.GONE);
        ParseSummary summary = parseAndDisplay(null);
        tvStatus.setText("静态分析模式：静态注册 " + summary.staticCount + " 个函数");
        tvStatus.setTextColor(getResColor(R.color.text_secondary));
    }

    private void runProxy() {
        long handle = DataHolder.getInstance().getDlopenHandle();
        if (handle == 0) {
            tvStatus.setText("⚠ SO未动态加载（可能缺少依赖），无法调用JNI_OnLoad");
            tvStatus.setTextColor(getResColor(R.color.red_error));
            return;
        }

        progressBar.setVisibility(View.VISIBLE);
        tvStatus.setText("正在Hook RegisterNatives并调用JNI_OnLoad...");
        tvStatus.setTextColor(getResColor(R.color.text_secondary));

        // 直接 Hook RegisterNatives → 调用 JNI_OnLoad → 捕获动态注册函数
        executeHook(handle, "JNI_OnLoad", "256", "4096");
    }

    private void callCloudForData(long handle) {
        String deviceId = android.provider.Settings.Secure.getString(
            getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);

        // 打印设备ID（用于添加到授权列表）
        android.util.Log.d("DTZC", "Device ID: " + deviceId);
        android.util.Log.d("DTZC", "Device Fingerprint: " + generateDeviceFingerprint());

        // 生成设备指纹（包含更多信息）
        String deviceFingerprint = generateDeviceFingerprint();

        long timestamp = System.currentTimeMillis();

        // 简单签名（实际应该用更安全的方式）
        String sign = md5(deviceFingerprint + timestamp + "dtzc-key-2024").substring(0, 16);

        // 读取服务器地址（支持本地调试）
        android.content.SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
        String serverUrl = "http://chahaoma.xyz:8902";
        android.util.Log.d("DTZC", "Server URL: " + serverUrl);

        // 使用HTTP调用云函数
        new Thread(() -> {
            try {
                java.net.URL url = new java.net.URL(serverUrl + "/api/DTZC");
                java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                conn.setDoOutput(true);
                
                // 构建参数
                String params = "deviceId=" + java.net.URLEncoder.encode(deviceId, "UTF-8") +
                              "&fingerprint=" + java.net.URLEncoder.encode(deviceFingerprint, "UTF-8") +
                              "&timestamp=" + timestamp +
                              "&sign=" + java.net.URLEncoder.encode(sign, "UTF-8");
                
                java.io.OutputStream os = conn.getOutputStream();
                os.write(params.getBytes("UTF-8"));
                os.flush();
                os.close();
                
                // 读取响应
                int responseCode = conn.getResponseCode();
                java.io.InputStream is = conn.getInputStream();
                java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(is));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                
                // 解析响应
                org.json.JSONObject json = new org.json.JSONObject(response.toString());
                
                if (json.getBoolean("ok")) {
                    org.json.JSONObject data = json.getJSONObject("data");
                    String cloudSymbol = data.getString("symbol");
                    String cloudMaxCapture = data.getString("maxCapture");
                    String cloudPageSize = data.getString("pageSize");
                    
                    // C层解密并执行Hook（安全：密钥和数据都在so中）
                    String capturedData = executeCloudHookNative(handle, cloudSymbol, cloudMaxCapture, cloudPageSize, deviceFingerprint);
                    
                    handler.post(() -> {
                        progressBar.setVisibility(View.GONE);
                        if (capturedData != null && !capturedData.isEmpty()) {
                            tvStatus.setText("✅ 云端授权成功");
                            tvStatus.setTextColor(getResColor(R.color.green_success));
                            // 解析并显示捕获的函数到列表（静态注册全部显示）
                            ParseSummary summary = parseAndDisplay(capturedData, Integer.MAX_VALUE);
                            tvStatus.setText("✅ 云端授权成功\n动态注册: " + summary.dynamicCount + " 个，静态注册: " + summary.staticCount + " 个");
                        } else if (capturedData != null) {
                            // 未捕获到动态注册，显示全部静态注册
                            ParseSummary summary = parseAndDisplay(null, Integer.MAX_VALUE);
                            tvStatus.setText("✅ 云端授权成功（未捕获到动态注册函数）\n静态注册: " + summary.staticCount + " 个");
                            tvStatus.setTextColor(getResColor(R.color.green_success));
                        } else {
                            tvStatus.setText("❌ C层处理失败");
                            tvStatus.setTextColor(getResColor(R.color.red_error));
                        }
                    });
                } else {
                    handler.post(() -> {
                        progressBar.setVisibility(View.GONE);
                        // Fallback到静态模式（仅显示前5个）
                        ParseSummary summary = parseAndDisplay(null, 5);
                        tvStatus.setText("⚠ 未获得赞助，仅显示前 5 个静态注册（共有 " + summary.staticCount + " 个）\n激活赞助可获得动态注册功能");
                        tvStatus.setTextColor(getResColor(R.color.text_secondary));
                    });
                }
                
            } catch (Exception e) {
                e.printStackTrace();
                handler.post(() -> {
                    progressBar.setVisibility(View.GONE);
                    // Fallback到静态模式（仅显示前5个）
                    ParseSummary summary = parseAndDisplay(null, 5);
                    tvStatus.setText("⚠ 未获得赞助，仅显示前 5 个静态注册（共有 " + summary.staticCount + " 个）\n激活赞助可获得动态注册功能");
                    tvStatus.setTextColor(getResColor(R.color.text_secondary));
                });
            }
        }).start();
    }
    
    /**
     * C层解密并执行云端Hook（安全：解密在so中完成）
     * @return 成功返回 "symbol=xxx,maxCapture=yyy,pageSize=zzz"，失败返回null
     */
    private native String executeCloudHookNative(long handle, String encryptedSymbol, 
                                                    String encryptedMaxCapture, String encryptedPageSize,
                                                    String deviceFingerprint);
    
    private void executeHook(long handle, String cloudSymbol, String cloudMaxCapture, String cloudPageSize) {
        executor.execute(() -> {
            // 设置应用的ClassLoader
            try {
                NativeInvoker.setClassLoader(getClassLoader());
            } catch (Exception e) { /* ignore */ }

            // Hook FindClass
            try {
                NativeInvoker.hookFindClass();
            } catch (Exception e) { /* ignore */ }

            // 仅在 callJniOnLoad 前后安装/卸载 hook，不影响 WebView 等其他库
            try { NativeInvoker.hookRegisterNatives(); } catch (Exception e) { /* ignore */ }

            // 调用目标 SO 的 JNI_OnLoad（传递云端加密数据）
            String result = NativeInvoker.callJniOnLoad(handle, cloudSymbol, cloudMaxCapture, cloudPageSize);

            // 立即卸载 hook，恢复原始 RegisterNatives
            try { NativeInvoker.unhookRegisterNatives(); } catch (Exception e) { /* ignore */ }

            // 获取捕获到的注册数据
            String captured = NativeInvoker.getCapturedRegistrations();

            handler.post(() -> {
                progressBar.setVisibility(View.GONE);
                handleResult(result, captured);
            });
        });
    }
    
    private String md5(String s) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(s.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
    
    private String generateDeviceFingerprint() {
        try {
            // 收集设备信息
            String androidId = android.provider.Settings.Secure.getString(
                getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
            
            String fingerprint = androidId + "|" +
                android.os.Build.BRAND + "|" +
                android.os.Build.MODEL + "|" +
                android.os.Build.MANUFACTURER + "|" +
                android.os.Build.VERSION.SDK_INT + "|" +
                android.os.Build.VERSION.RELEASE;
            
            // 获取应用签名哈希
            try {
                android.content.pm.PackageManager pm = getPackageManager();
                android.content.pm.PackageInfo packageInfo = pm.getPackageInfo(
                    getPackageName(), android.content.pm.PackageManager.GET_SIGNATURES);
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    android.content.pm.Signature[] signatures = packageInfo.signatures;
                    if (signatures != null && signatures.length > 0) {
                        fingerprint += "|" + md5(signatures[0].toCharsString());
                    }
                }
            } catch (Exception e) {
                // 忽略签名获取失败
            }
            
            // 最终哈希
            return md5(fingerprint);
        } catch (Exception e) {
            return android.provider.Settings.Secure.getString(
                getContentResolver(), android.provider.Settings.Secure.ANDROID_ID);
        }
    }
    
    private String aesDecrypt(String encrypted, String key) {
        try {
            // Base64解码
            byte[] combined = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP);
            
            if (combined.length < 24) {  // salt(8) + iv(16) + 至少1字节密文
                return "";
            }
            
            // 提取：salt(8) + iv(16) + ciphertext
            byte[] salt = new byte[8];
            byte[] iv = new byte[16];
            byte[] ciphertext = new byte[combined.length - 24];
            
            System.arraycopy(combined, 0, salt, 0, 8);
            System.arraycopy(combined, 8, iv, 0, 16);
            System.arraycopy(combined, 24, ciphertext, 0, ciphertext.length);
            
            // PBKDF2派生密钥
            javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                (key + bytesToHex(salt)).toCharArray(), salt, 10000, 256);
            javax.crypto.SecretKey tmp = factory.generateSecret(spec);
            byte[] derivedKey = tmp.getEncoded();
            
            // AES-256-CBC解密
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(derivedKey, "AES");
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = cipher.doFinal(ciphertext);
            
            return new String(decrypted, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
    
    private String aesEncrypt(String data, String key) {
        try {
            // 生成随机IV（16字节）
            byte[] iv = new byte[16];
            new java.security.SecureRandom().nextBytes(iv);
            
            // 生成随机盐（8字节）
            byte[] salt = new byte[8];
            new java.security.SecureRandom().nextBytes(salt);
            
            // 派生密钥：PBKDF2
            javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                (key + bytesToHex(salt)).toCharArray(), salt, 10000, 256);
            javax.crypto.SecretKey tmp = factory.generateSecret(spec);
            byte[] derivedKey = tmp.getEncoded();
            
            // AES-256-CBC加密
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(derivedKey, "AES");
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(iv);
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
            
            // 组合：salt(8) + iv(16) + ciphertext
            byte[] combined = new byte[8 + 16 + encrypted.length];
            System.arraycopy(salt, 0, combined, 0, 8);
            System.arraycopy(iv, 0, combined, 8, 16);
            System.arraycopy(encrypted, 0, combined, 24, encrypted.length);
            
            return android.util.Base64.encodeToString(combined, android.util.Base64.NO_WRAP);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void handleResult(String result, String captured) {
        if (result == null) {
            tvStatus.setText("❌ 调用失败: 返回null");
            tvStatus.setTextColor(getResColor(R.color.red_error));
            return;
        }

        if (result.startsWith("ERR:")) {
            String msg = result.substring(4);
            ParseSummary summary = parseAndDisplay(null); // 仍显示静态注册函数
            tvStatus.setText("❌ " + msg + "（动态注册 " + summary.dynamicCount + " 个，静态注册 " + summary.staticCount + " 个）");
            tvStatus.setTextColor(getResColor(R.color.red_error));
            return;
        }

        if (result.startsWith("CRASH:")) {
            String[] parts = result.substring(6).split("\\|");
            String signal = parts.length > 0 ? parts[0] : "unknown";
            int count = parts.length > 1 ? Integer.parseInt(parts[1]) : 0;
            ParseSummary summary = parseAndDisplay(captured);
            tvStatus.setText("⚠ JNI_OnLoad 崩溃 (信号: " + signal + ")，动态注册 " + summary.dynamicCount + " 个，静态注册 " + summary.staticCount + " 个");
            tvStatus.setTextColor(getResColor(R.color.orange_accent));
            return;
        }

        if (result.startsWith("OK:")) {
            String[] parts = result.substring(3).split("\\|");
            int version = parts.length > 0 ? Integer.parseInt(parts[0]) : 0;
            int count = parts.length > 1 ? Integer.parseInt(parts[1]) : 0;

            String versionStr;
            switch (version) {
                case 0x00010001: versionStr = "JNI 1.1"; break;
                case 0x00010002: versionStr = "JNI 1.2"; break;
                case 0x00010004: versionStr = "JNI 1.4"; break;
                case 0x00010006: versionStr = "JNI 1.6"; break;
                default: versionStr = "0x" + Integer.toHexString(version); break;
            }

            ParseSummary summary = parseAndDisplay(captured);
            tvStatus.setText("✓ JNI_OnLoad 成功 (版本: " + versionStr + ")，动态注册 " + summary.dynamicCount + " 个，静态注册 " + summary.staticCount + " 个");
            tvStatus.setTextColor(getResColor(R.color.green_success));
        }
    }

    private ParseSummary parseAndDisplay(String captured) {
        return parseAndDisplay(captured, Integer.MAX_VALUE);
    }

    private ParseSummary parseAndDisplay(String captured, int staticLimit) {
        List<RegNativeItem> items = new ArrayList<>();
        long baseAddress = DataHolder.getInstance().getBaseAddress();
        int dynamicCount = 0;

        // 1. 解析动态注册的函数
        if (captured != null && !captured.isEmpty()) {
            String[] lines = captured.split("\n");
            int idx = 0;
            for (String line : lines) {
                if (line.isEmpty()) continue;
                String[] parts = line.split("\\|");
                if (parts.length >= 4) {
                    RegNativeItem item = new RegNativeItem();
                    item.index = idx++;
                    item.isStatic = false;
                    item.className = parts[0];
                    item.methodName = parts[1];
                    item.signature = parts[2];
                    try {
                        item.address = Long.parseUnsignedLong(parts[3].replace("0x", ""), 16);
                    } catch (NumberFormatException e) {
                        item.address = 0;
                    }
                    item.offset = baseAddress > 0 ? item.address - baseAddress : 0;
                    items.add(item);
                    dynamicCount++;
                }
            }
        }

        // 2. 追加静态注册的 JNI 函数 (Java_ 前缀)
        List<RegNativeItem> staticItems = loadStaticJniFunctions(baseAddress, staticLimit);
        items.addAll(staticItems);

        adapter.setItems(items);
        return new ParseSummary(dynamicCount, staticItems.size());
    }

    static class ParseSummary {
        final int dynamicCount;
        final int staticCount;

        ParseSummary(int dynamicCount, int staticCount) {
            this.dynamicCount = dynamicCount;
            this.staticCount = staticCount;
        }
    }

    private List<RegNativeItem> loadStaticJniFunctions(long baseAddress, int limit) {
        List<RegNativeItem> items = new ArrayList<>();
        List<NativeFunction> functions = DataHolder.getInstance().getFunctions();
        if (functions == null) return items;

        android.util.Log.d("LoadStatic", "Total functions: " + functions.size() + ", baseAddress=0x" + Long.toHexString(baseAddress) + ", limit=" + limit);

        int count = 0;
        for (NativeFunction f : functions) {
            if (count >= limit) break;
            if (f.getName() != null && f.getName().startsWith("Java_")) {
                RegNativeItem item = new RegNativeItem();
                item.isStatic = true;
                item.index = -1; // 静态注册不能用 callCapturedNative

                // 解析 Java_com_example_ClassName_methodName
                String fullName = f.getName();
                String[] segments = fullName.split("_", 2); // "Java" + rest
                if (segments.length >= 2) {
                    String rest = segments[1]; // com_example_ClassName_methodName
                    // 尝试把最后一个段当方法名，其余当类名
                    int lastUnderscore = rest.lastIndexOf('_');
                    if (lastUnderscore > 0) {
                        item.className = rest.substring(0, lastUnderscore).replace('_', '.');
                        item.methodName = rest.substring(lastUnderscore + 1);
                    } else {
                        item.className = "";
                        item.methodName = rest;
                    }
                } else {
                    item.className = "";
                    item.methodName = fullName;
                }

                item.signature = "(静态注册 - 签名未知)";
                item.offset = f.getOffset();
                item.address = baseAddress > 0 ? baseAddress + f.getOffset() : f.getOffset();
                item.funcSize = f.getSize();
                items.add(item);
                count++;  // 在添加后立即递增

                android.util.Log.d("LoadStatic", "Added: " + item.methodName + " @ 0x" + Long.toHexString(item.address) + " (offset=0x" + Long.toHexString(item.offset) + ")");
            }
        }

        android.util.Log.d("LoadStatic", "Total static JNI items: " + items.size());
        return items;
    }

    private void jumpToFunction(RegNativeItem item) {
        long baseAddress = DataHolder.getInstance().getBaseAddress();
        long absAddr;
        long funcSize;
        String funcName;

        if (item.isStatic) {
            absAddr = item.address;
            funcSize = item.funcSize > 0 ? item.funcSize : 256;
            funcName = "Java_" + item.className.replace('.', '_') + "_" + item.methodName;
        } else {
            absAddr = item.address;
            funcSize = 256; // 动态注册不知道大小，默认 256
            funcName = item.className + "." + item.methodName;
        }

        android.util.Log.d("JumpDebug", "Jumping to: " + funcName + " @ 0x" + Long.toHexString(absAddr) + " (base=0x" + Long.toHexString(baseAddress) + ", isStatic=" + item.isStatic + ", offset=0x" + Long.toHexString(item.offset) + ")");

        Intent intent = new Intent(this, FunctionDetailActivity.class);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_NAME, funcName);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_ADDR, absAddr);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_SIZE, funcSize);
        intent.putExtra(FunctionDetailActivity.EXTRA_DEMANGLED_NAME, item.methodName);
        intent.putExtra(FunctionDetailActivity.EXTRA_SIGNATURE, item.signature);
        // 动态注册函数：传递调用所需信息
        if (!item.isStatic) {
            intent.putExtra(FunctionDetailActivity.EXTRA_CAPTURED_INDEX, item.index);
            intent.putExtra(FunctionDetailActivity.EXTRA_JNI_CLASS, item.className);
            intent.putExtra(FunctionDetailActivity.EXTRA_JNI_METHOD, item.methodName);
            intent.putExtra(FunctionDetailActivity.EXTRA_JNI_SIG, item.signature);
        }
        startActivity(intent);
    }

    private int getResColor(int id) {
        return androidx.core.content.ContextCompat.getColor(this, id);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }

    // ============================================================
    // 数据模型
    // ============================================================

    static class RegNativeItem {
        int index;          // 在捕获列表中的索引（仅动态注册有效）
        boolean isStatic;   // true=静态注册, false=动态注册
        String className;
        String methodName;
        String signature;
        long address;       // 绝对地址（动态）或偏移量（静态）
        long offset;        // 相对基址偏移
        long funcSize;      // 函数大小（静态注册用）
    }

    // ============================================================
    // Adapter
    // ============================================================

    static class RegNativeAdapter extends RecyclerView.Adapter<RegNativeAdapter.VH> {
        private List<RegNativeItem> items = new ArrayList<>();
        private OnItemClickListener clickListener;
        private OnItemCallListener callListener;

        interface OnItemClickListener {
            void onItemClick(RegNativeItem item);
        }
        interface OnItemCallListener {
            void onItemCall(RegNativeItem item);
        }

        void setOnItemClickListener(OnItemClickListener l) { this.clickListener = l; }
        void setOnItemCallListener(OnItemCallListener l) { this.callListener = l; }

        void setItems(List<RegNativeItem> items) {
            this.items = items;
            notifyDataSetChanged();
        }

        @Override
        public int getItemCount() { return items.size(); }

        @androidx.annotation.NonNull
        @Override
        public VH onCreateViewHolder(@androidx.annotation.NonNull android.view.ViewGroup parent, int viewType) {
            android.view.View v = android.view.LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_reg_native, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(@androidx.annotation.NonNull VH h, int pos) {
            RegNativeItem item = items.get(pos);
            h.tvClass.setText(item.className);
            h.tvMethod.setText(item.methodName);
            h.tvSig.setText(item.signature);

            // 类型标签（带圆角背景）
            GradientDrawable typeBg = new GradientDrawable();
            typeBg.setShape(GradientDrawable.RECTANGLE);
            typeBg.setCornerRadius(8f);
            if (item.isStatic) {
                h.tvType.setText("静态注册");
                typeBg.setColor(0xFF607D8B); // 灰蓝
            } else {
                h.tvType.setText("动态注册");
                typeBg.setColor(0xFF4CAF50); // 绿
            }
            h.tvType.setBackground(typeBg);

            // 地址
            if (item.offset > 0) {
                h.tvAddr.setText(String.format("0x%X  (offset: 0x%X)", item.address, item.offset));
            } else {
                h.tvAddr.setText(String.format("0x%X", item.address));
            }

            // 调用按钮：只有动态注册才显示（带圆角背景）
            GradientDrawable btnBg = new GradientDrawable();
            btnBg.setShape(GradientDrawable.RECTANGLE);
            btnBg.setCornerRadius(12f);
            btnBg.setColor(0xFF4CAF50); // 绿色
            h.btnCall.setBackground(btnBg);
            if (!item.isStatic) {
                h.btnCall.setVisibility(android.view.View.VISIBLE);
                h.btnCall.setOnClickListener(v -> {
                    if (callListener != null) callListener.onItemCall(item);
                });
            } else {
                h.btnCall.setVisibility(android.view.View.GONE);
            }

            // 点击整行 → 跳转查看函数
            h.itemView.setOnClickListener(v -> {
                if (clickListener != null) clickListener.onItemClick(item);
            });
        }

        static class VH extends RecyclerView.ViewHolder {
            TextView tvClass, tvMethod, tvSig, tvAddr, tvType, btnCall;
            VH(android.view.View v) {
                super(v);
                tvClass = v.findViewById(R.id.tvClass);
                tvMethod = v.findViewById(R.id.tvMethod);
                tvSig = v.findViewById(R.id.tvSig);
                tvAddr = v.findViewById(R.id.tvAddr);
                tvType = v.findViewById(R.id.tvType);
                btnCall = v.findViewById(R.id.btnCall);
            }
        }
    }

    // ============================================================
    // 调用对话框
    // ============================================================

    private void showCallDialog(RegNativeItem item) {
        // 解析签名参数
        List<ParamInfo> params = parseSignatureParams(item.signature);
        char retType = parseReturnType(item.signature);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int)(16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);

        // 函数信息
        TextView tvInfo = new TextView(this);
        tvInfo.setText(String.format("%s.%s\n签名: %s\n地址: 0x%X\n返回: %s",
                item.className, item.methodName, item.signature, item.address,
                typeToName(retType)));
        tvInfo.setTextSize(13);
        layout.addView(tvInfo);

        // 自动注入提示
        TextView tvAuto = new TextView(this);
        tvAuto.setText("\n参数 0: JNIEnv* (自动注入)\n参数 1: jclass (自动注入)");
        tvAuto.setTextSize(12);
        tvAuto.setTextColor(0xFF888888);
        layout.addView(tvAuto);

        // 用户参数输入
        List<EditText> paramEdits = new ArrayList<>();
        for (int i = 0; i < params.size(); i++) {
            ParamInfo p = params.get(i);
            TextView label = new TextView(this);
            label.setText(String.format("\n参数 %d: %s", i + 2, p.typeName));
            label.setTextSize(12);
            layout.addView(label);

            EditText et = new EditText(this);
            et.setHint(p.hint);
            et.setTextSize(14);
            et.setSingleLine(true);
            if (p.isNumeric) {
                et.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_FLAG_SIGNED);
            }
            et.setText(p.defaultValue);
            layout.addView(et);
            paramEdits.add(et);
        }

        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);

        new AlertDialog.Builder(this)
                .setTitle("调用 " + item.methodName)
                .setView(scroll)
                .setPositiveButton("调用", (d, w) -> {
                    String[] values = new String[paramEdits.size()];
                    for (int i = 0; i < paramEdits.size(); i++) {
                        values[i] = paramEdits.get(i).getText().toString();
                    }
                    callCapturedFunction(item, values);
                })
                .setNeutralButton("追踪并调用", (d, w) -> {
                    String[] values = new String[paramEdits.size()];
                    for (int i = 0; i < paramEdits.size(); i++) {
                        values[i] = paramEdits.get(i).getText().toString();
                    }
                    callCapturedFunctionWithTrace(item, values);
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void callCapturedFunctionWithTrace(RegNativeItem item, String[] paramValues) {
        executor.execute(() -> {
            // 1. 启用追踪
            try {
                NativeInvoker.enableTraceForFunction(item.address, item.methodName);
            } catch (Exception e) {
                Log.e("Trace", "启用追踪失败: " + e.getMessage());
            }

            // 2. 调用函数
            String result;
            try {
                result = NativeInvoker.callCapturedNative(item.index, paramValues);
            } catch (Throwable t) {
                result = "ERR:Java异常: " + t.getMessage();
            }

            // 3. 获取追踪结果
            String traceLog = "";
            try {
                traceLog = NativeInvoker.getTraceLog();
                NativeInvoker.clearTraceLog();
            } catch (Exception e) {
                Log.e("Trace", "获取追踪日志失败: " + e.getMessage());
            }

            final String r = result;
            final String trace = traceLog;
            handler.post(() -> {
                String title, msg;
                if (r != null && r.startsWith("OK:")) {
                    title = "追踪调用成功";
                    msg = "返回值: " + r.substring(3) + "\n\n=== 调用追踪 ===\n" + trace;
                } else if (r != null && r.startsWith("ERR:")) {
                    title = "调用失败";
                    msg = r.substring(4) + "\n\n=== 调用追踪 ===\n" + trace;
                } else {
                    title = "结果";
                    msg = (r != null ? r : "null") + "\n\n=== 调用追踪 ===\n" + trace;
                }
                new AlertDialog.Builder(this)
                        .setTitle(title)
                        .setMessage(item.methodName + "\n\n" + msg)
                        .setPositiveButton("确定", null)
                        .show();
            });
        });
    }

    private void callCapturedFunction(RegNativeItem item, String[] paramValues) {
        executor.execute(() -> {
            String result;
            try {
                result = NativeInvoker.callCapturedNative(item.index, paramValues);
            } catch (Throwable t) {
                result = "ERR:Java异常: " + t.getMessage();
            }
            final String r = result;
            handler.post(() -> {
                String title, msg;
                if (r != null && r.startsWith("OK:")) {
                    title = "调用成功";
                    msg = r.substring(3);
                } else if (r != null && r.startsWith("ERR:")) {
                    title = "调用失败";
                    msg = r.substring(4);
                } else {
                    title = "结果";
                    msg = r != null ? r : "null";
                }
                new AlertDialog.Builder(this)
                        .setTitle(title)
                        .setMessage(item.methodName + "\n\n" + msg)
                        .setPositiveButton("确定", null)
                        .show();
            });
        });
    }

    // ============================================================
    // JNI 签名解析
    // ============================================================

    static class ParamInfo {
        String typeName;
        String hint;
        String defaultValue;
        boolean isNumeric;
    }

    private List<ParamInfo> parseSignatureParams(String sig) {
        List<ParamInfo> params = new ArrayList<>();
        int i = sig.indexOf('(');
        if (i < 0) return params;
        i++;

        while (i < sig.length() && sig.charAt(i) != ')') {
            ParamInfo p = new ParamInfo();
            char c = sig.charAt(i);
            switch (c) {
                case 'Z':
                    p.typeName = "boolean"; p.hint = "true/false"; p.defaultValue = "false"; p.isNumeric = false;
                    i++; break;
                case 'B':
                    p.typeName = "byte"; p.hint = "0-255"; p.defaultValue = "0"; p.isNumeric = true;
                    i++; break;
                case 'S':
                    p.typeName = "short"; p.hint = "整数"; p.defaultValue = "0"; p.isNumeric = true;
                    i++; break;
                case 'I':
                    p.typeName = "int"; p.hint = "整数"; p.defaultValue = "0"; p.isNumeric = true;
                    i++; break;
                case 'J':
                    p.typeName = "long"; p.hint = "长整数"; p.defaultValue = "0"; p.isNumeric = true;
                    i++; break;
                case 'F':
                    p.typeName = "float"; p.hint = "浮点数"; p.defaultValue = "0.0"; p.isNumeric = false;
                    i++; break;
                case 'D':
                    p.typeName = "double"; p.hint = "双精度浮点"; p.defaultValue = "0.0"; p.isNumeric = false;
                    i++; break;
                case 'L': {
                    int end = sig.indexOf(';', i);
                    String cls = end > 0 ? sig.substring(i + 1, end).replace('/', '.') : "Object";
                    p.typeName = cls;
                    if (cls.equals("java.lang.String")) {
                        p.hint = "字符串内容"; p.defaultValue = ""; p.isNumeric = false;
                    } else {
                        p.hint = "null 或值"; p.defaultValue = "null"; p.isNumeric = false;
                    }
                    i = end > 0 ? end + 1 : i + 1;
                    break;
                }
                case '[': {
                    p.typeName = "array"; p.hint = "暂不支持，传null"; p.defaultValue = "null"; p.isNumeric = false;
                    i++;
                    if (i < sig.length() && sig.charAt(i) == 'L') {
                        int end = sig.indexOf(';', i);
                        i = end > 0 ? end + 1 : i + 1;
                    } else if (i < sig.length()) {
                        i++;
                    }
                    break;
                }
                default:
                    p.typeName = String.valueOf(c); p.hint = ""; p.defaultValue = "0"; p.isNumeric = true;
                    i++; break;
            }
            params.add(p);
        }
        return params;
    }

    private char parseReturnType(String sig) {
        int i = sig.indexOf(')');
        if (i >= 0 && i + 1 < sig.length()) return sig.charAt(i + 1);
        return 'V';
    }

    private String typeToName(char c) {
        switch (c) {
            case 'V': return "void";
            case 'Z': return "boolean";
            case 'B': return "byte";
            case 'S': return "short";
            case 'I': return "int";
            case 'J': return "long";
            case 'F': return "float";
            case 'D': return "double";
            case 'L': return "Object";
            case '[': return "array";
            default: return String.valueOf(c);
        }
    }
}
