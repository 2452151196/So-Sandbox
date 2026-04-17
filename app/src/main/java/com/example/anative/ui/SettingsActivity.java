package com.example.anative.ui;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.appcompat.widget.SwitchCompat;
import androidx.cardview.widget.CardView;

import com.example.anative.R;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputLayout;
import com.google.android.material.textfield.TextInputEditText;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class SettingsActivity extends AppCompatActivity {

    public static final String PREF_AI_URL = "ai_url";
    public static final String PREF_AI_KEY = "ai_key";
    public static final String PREF_AI_TEMPLATE = "ai_template";
    public static final String PREF_AI_RESPONSE_PATH = "ai_response_path";
    public static final String PREF_AI_PROVIDER = "ai_provider";
    public static final String PREF_AI_MODEL = "ai_model";
    public static final String PREF_AI_ADVANCED = "ai_advanced";
    public static final String PREF_AI_PSEUDOC_ENABLED = "ai_pseudoc_enabled";
    public static final String PREF_PSEUDOC_PROMPT = "pseudoc_prompt";
    public static final String PREF_CODE_FONT_SIZE = "code_font_size";

    private static final String TAG = "SettingsActivity";
    private static final float DEFAULT_CODE_FONT_SIZE_SP = 13f;
    private static final String QQ_GROUP_NUMBER = "123456789";
    private static final String UPDATE_URL = "";
    private static final String DEFAULT_OPENAI_TEMPLATE = "{\n"
            + "  \"model\": \"gpt-3.5-turbo\",\n"
            + "  \"messages\": [\n"
            + "    {\"role\": \"user\", \"content\": \"{{prompt}}\"}\n"
            + "  ]\n"
            + "}";

    private SwitchCompat switchTheme;
    private SwitchCompat switchAiPseudoC;
    private TextView tvAiStatus;
    private TextView tvCodeFontSize;
    private TextView tvUpdateStatus;
    private TextView tvAboutSummary;
    private CardView cardAiSettings;
    private CardView cardPseudoCPrompt;
    private CardView cardCodeFontSize;
    private CardView cardQqGroup;
    private CardView cardCheckUpdate;
    private CardView cardAbout;
    private TextView tvPseudoCPromptPreview;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        // 夜间模式设置
        switchTheme = findViewById(R.id.switch_theme);
        switchAiPseudoC = findViewById(R.id.switch_ai_pseudoc);
        int currentMode = AppCompatDelegate.getDefaultNightMode();
        switchTheme.setChecked(currentMode == AppCompatDelegate.MODE_NIGHT_YES);
        switchAiPseudoC.setChecked(prefs.getBoolean(PREF_AI_PSEUDOC_ENABLED, false));

        switchTheme.setOnCheckedChangeListener((buttonView, isChecked) -> {
            int newMode = isChecked ? AppCompatDelegate.MODE_NIGHT_YES : AppCompatDelegate.MODE_NIGHT_NO;
            prefs.edit().putInt("night_mode", newMode).apply();
            AppCompatDelegate.setDefaultNightMode(newMode);
            Toast.makeText(this, isChecked ? "已切换到夜间模式" : "已切换到日间模式", Toast.LENGTH_SHORT).show();
            recreate();
        });

        switchAiPseudoC.setOnCheckedChangeListener((buttonView, isChecked) -> {
            prefs.edit().putBoolean(PREF_AI_PSEUDOC_ENABLED, isChecked).apply();
            Toast.makeText(this, isChecked ? "已开启 AI 伪C" : "已关闭 AI 伪C", Toast.LENGTH_SHORT).show();
        });

        // 伪C提示词设置
        cardPseudoCPrompt = findViewById(R.id.card_pseudoc_prompt);
        tvPseudoCPromptPreview = findViewById(R.id.tv_pseudoc_prompt_preview);
        updatePseudoCPromptPreview();

        cardPseudoCPrompt.setOnClickListener(v -> showPseudoCPromptDialog());

        // AI 设置
        tvAiStatus = findViewById(R.id.tv_ai_status);
        cardAiSettings = findViewById(R.id.card_ai_settings);
        tvCodeFontSize = findViewById(R.id.tv_code_font_size);
        tvUpdateStatus = findViewById(R.id.tv_update_status);
        tvAboutSummary = findViewById(R.id.tv_about_summary);
        cardCodeFontSize = findViewById(R.id.card_code_font_size);
        cardQqGroup = findViewById(R.id.card_qq_group);
        cardCheckUpdate = findViewById(R.id.card_check_update);
        cardAbout = findViewById(R.id.card_about);

        updateAiStatus();
        updateCodeFontSizeSummary();
        updateUpdateStatus();
        updateAboutSummary();

        cardAiSettings.setOnClickListener(v -> showAiSettingsDialog());
        cardCodeFontSize.setOnClickListener(v -> showCodeFontSizeDialog());
        cardQqGroup.setOnClickListener(v -> showQqGroupDialog());
        cardCheckUpdate.setOnClickListener(v -> showCheckUpdateDialog());
        cardAbout.setOnClickListener(v -> showAboutDialog());
    }

    private void updateAiStatus() {
        String url = prefs.getString(PREF_AI_URL, "");
        String key = prefs.getString(PREF_AI_KEY, "");
        String template = prefs.getString(PREF_AI_TEMPLATE, "");
        String responsePath = prefs.getString(PREF_AI_RESPONSE_PATH, "");
        boolean advanced = prefs.getBoolean(PREF_AI_ADVANCED, false);
        String provider = prefs.getString(PREF_AI_PROVIDER, "OpenAI");

        if (url.isEmpty() && key.isEmpty()) {
            tvAiStatus.setText("未配置");
        } else if (url.isEmpty()) {
            tvAiStatus.setText("已配置 Key，缺少网址");
        } else if (key.isEmpty()) {
            tvAiStatus.setText("已配置网址，缺少 Key");
        } else if (advanced || !template.isEmpty() || !responsePath.isEmpty()) {
            tvAiStatus.setText("已配置 (高级模式)");
        } else {
            tvAiStatus.setText("已配置 (" + provider + ")");
        }
    }

    private void updatePseudoCPromptPreview() {
        String savedPrompt = prefs.getString(PREF_PSEUDOC_PROMPT, "");
        if (savedPrompt.isEmpty()) {
            tvPseudoCPromptPreview.setText("默认：转换为Java代码");
        } else {
            tvPseudoCPromptPreview.setText("自定义：" + savedPrompt);
        }
    }

    private void updateCodeFontSizeSummary() {
        tvCodeFontSize.setText(formatFontSize(getCodeFontSizeSp(this)));
    }

    private void updateUpdateStatus() {
        tvUpdateStatus.setText("当前版本 v" + getAppVersionName());
    }

    private void updateAboutSummary() {
        tvAboutSummary.setText("当前版本 v" + getAppVersionName());
    }

    private String getAppVersionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "1.0";
        }
    }

    public static float getCodeFontSizeSp(Context context) {
        SharedPreferences prefs = context.getSharedPreferences("app_prefs", MODE_PRIVATE);
        return prefs.getFloat(PREF_CODE_FONT_SIZE, DEFAULT_CODE_FONT_SIZE_SP);
    }

    private String formatFontSize(float sizeSp) {
        if (Math.abs(sizeSp - Math.round(sizeSp)) < 0.01f) {
            return ((int) sizeSp) + "sp";
        }
        return String.format(java.util.Locale.getDefault(), "%.1fsp", sizeSp);
    }

    private void showCodeFontSizeDialog() {
        final String[] options = {"11sp", "12sp", "13sp", "14sp", "15sp", "16sp", "18sp"};
        final float[] values = {11f, 12f, 13f, 14f, 15f, 16f, 18f};
        float current = getCodeFontSizeSp(this);
        int checked = 0;
        for (int i = 0; i < values.length; i++) {
            if (Math.abs(values[i] - current) < 0.01f) {
                checked = i;
                break;
            }
        }

        final int[] selected = {checked};
        new AlertDialog.Builder(this)
                .setTitle("代码字体大小")
                .setSingleChoiceItems(options, checked, (dialog, which) -> selected[0] = which)
                .setPositiveButton("确定", (dialog, which) -> {
                    prefs.edit().putFloat(PREF_CODE_FONT_SIZE, values[selected[0]]).apply();
                    updateCodeFontSizeSummary();
                    Toast.makeText(this, "代码字体大小已保存", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void showQqGroupDialog() {
        String message = "QQ群号：" + QQ_GROUP_NUMBER + "\n\n可复制群号后在 QQ 中搜索加入。";
        new AlertDialog.Builder(this)
                .setTitle("加入QQ群")
                .setMessage(message)
                .setPositiveButton("复制群号", (dialog, which) -> {
                    android.content.ClipboardManager clipboardManager =
                            (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (clipboardManager != null) {
                        clipboardManager.setPrimaryClip(android.content.ClipData.newPlainText("qq_group", QQ_GROUP_NUMBER));
                        Toast.makeText(this, "群号已复制", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("关闭", null)
                .show();
    }

    private void showCheckUpdateDialog() {
        String message = "当前版本：v" + getAppVersionName();
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle("检测更新")
                .setMessage(message)
                .setNegativeButton("关闭", null);

        if (UPDATE_URL == null || UPDATE_URL.trim().isEmpty()) {
            builder.setPositiveButton("知道了", (dialog, which) ->
                    Toast.makeText(this, "暂未配置更新地址", Toast.LENGTH_SHORT).show());
        } else {
            builder.setPositiveButton("前往更新", (dialog, which) -> openUrl(UPDATE_URL));
        }
        builder.show();
    }

    private void showAboutDialog() {
        String message = "应用名称：" + getString(R.string.app_name)
                + "\n版本：v" + getAppVersionName()
                + "\n\n这是一个用于 SO 加载、函数分析、汇编查看、伪C转换与 JNI 注册分析的工具。";
        new AlertDialog.Builder(this)
                .setTitle("关于软件")
                .setMessage(message)
                .setPositiveButton("确定", null)
                .show();
    }

    private void openUrl(String url) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(this, "无法打开链接", Toast.LENGTH_SHORT).show();
        }
    }

    private void showPseudoCPromptDialog() {
        View dialogView = getLayoutInflater().inflate(R.layout.dialog_simple_input, null);
        TextInputEditText etPrompt = dialogView.findViewById(R.id.et_input);
        String currentPrompt = prefs.getString(PREF_PSEUDOC_PROMPT, "");
        if (currentPrompt.isEmpty()) {
            currentPrompt = "你是一位顶尖的ARM64逆向工程专家。请将以下汇编代码转换为清晰、易读的C语言伪代码。如果可能，请添加必要的注释。\n\n汇编代码：\n{{assembly_code}}";
        }
        etPrompt.setText(currentPrompt);

        new AlertDialog.Builder(this)
                .setTitle("伪C提示词")
                .setView(dialogView)
                .setPositiveButton("确定", (dialog, which) -> {
                    String newPrompt = etPrompt.getText() != null ? etPrompt.getText().toString() : "";
                    prefs.edit().putString(PREF_PSEUDOC_PROMPT, newPrompt).apply();
                    updatePseudoCPromptPreview();
                    Toast.makeText(this, "提示词已保存", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void showAiSettingsDialog() {
        View dialogView = getLayoutInflater().inflate(R.layout.dialog_ai_settings, null);
        TextInputEditText etUrl = dialogView.findViewById(R.id.et_dialog_ai_url);
        TextInputEditText etModel = dialogView.findViewById(R.id.et_dialog_ai_model);
        TextInputEditText etKey = dialogView.findViewById(R.id.et_dialog_ai_key);
        TextInputEditText etTemplate = dialogView.findViewById(R.id.et_dialog_ai_template);
        TextInputEditText etResponsePath = dialogView.findViewById(R.id.et_dialog_ai_response_path);
        TextInputLayout layoutProvider = dialogView.findViewById(R.id.layout_dialog_provider);
        TextInputLayout layoutModel = dialogView.findViewById(R.id.layout_dialog_model);
        TextInputLayout layoutUrl = dialogView.findViewById(R.id.layout_dialog_url);
        TextInputLayout layoutTemplate = dialogView.findViewById(R.id.layout_dialog_template);
        TextInputLayout layoutResponsePath = dialogView.findViewById(R.id.layout_dialog_response_path);
        TextView tvAdvHint = dialogView.findViewById(R.id.tv_ai_adv_hint);
        Spinner spProvider = dialogView.findViewById(R.id.sp_dialog_ai_provider);
        MaterialButton btnToggleAdvanced = dialogView.findViewById(R.id.btn_toggle_advanced);
        MaterialButton btnTestAi = dialogView.findViewById(R.id.btn_test_ai);

        String[] providers = new String[]{"OpenAI", "DeepSeek", "Gemini", "Claude", "OpenRouter", "Moonshot(Kimi)", "Qwen(通义千问)"};
        ArrayAdapter<String> providerAdapter = new ArrayAdapter<>(
                this,
                android.R.layout.simple_spinner_item,
                providers
        );
        providerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spProvider.setAdapter(providerAdapter);

        String savedProvider = prefs.getString(PREF_AI_PROVIDER, "OpenAI");
        int providerIndex = 0;
        for (int i = 0; i < providers.length; i++) {
            if (providers[i].equals(savedProvider)) {
                providerIndex = i;
                break;
            }
        }
        spProvider.setSelection(providerIndex);

        etUrl.setText(prefs.getString(PREF_AI_URL, ""));
        etKey.setText(prefs.getString(PREF_AI_KEY, ""));
        etModel.setText(prefs.getString(PREF_AI_MODEL, defaultModelForProvider(savedProvider)));
        String savedTemplate = prefs.getString(PREF_AI_TEMPLATE, "");
        etTemplate.setText(savedTemplate.isEmpty() ? DEFAULT_OPENAI_TEMPLATE : savedTemplate);
        etResponsePath.setText(prefs.getString(PREF_AI_RESPONSE_PATH, ""));
        final boolean[] isAdvanced = {prefs.getBoolean(PREF_AI_ADVANCED, false)};
        applyAiModeUi(isAdvanced[0], layoutProvider, layoutModel, layoutUrl, layoutTemplate, layoutResponsePath, tvAdvHint, btnToggleAdvanced);

        spProvider.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> parent, View view, int position, long id) {
                if (isAdvanced[0]) return;
                String provider = providers[position];
                if (etModel.getText() == null || etModel.getText().toString().trim().isEmpty()) {
                    etModel.setText(defaultModelForProvider(provider));
                }
                etUrl.setText(defaultUrlForProvider(provider));
            }

            @Override
            public void onNothingSelected(android.widget.AdapterView<?> parent) {
            }
        });

        btnToggleAdvanced.setOnClickListener(v -> {
            isAdvanced[0] = !isAdvanced[0];
            applyAiModeUi(isAdvanced[0], layoutProvider, layoutModel, layoutUrl, layoutTemplate, layoutResponsePath, tvAdvHint, btnToggleAdvanced);
            if (!isAdvanced[0]) {
                String provider = String.valueOf(spProvider.getSelectedItem());
                etUrl.setText(defaultUrlForProvider(provider));
            }
        });

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(dialogView)
                .setPositiveButton("保存", (dialogInterface, which) -> {
                    String url = etUrl.getText() != null ? etUrl.getText().toString().trim() : "";
                    String key = etKey.getText() != null ? etKey.getText().toString().trim() : "";
                    String model = etModel.getText() != null ? etModel.getText().toString().trim() : "";
                    String template = etTemplate.getText() != null ? etTemplate.getText().toString().trim() : "";
                    String responsePath = etResponsePath.getText() != null ? etResponsePath.getText().toString().trim() : "";
                    String provider = String.valueOf(spProvider.getSelectedItem());

                    if (!isAdvanced[0]) {
                        if (model.isEmpty()) {
                            model = defaultModelForProvider(provider);
                        }
                        url = defaultUrlForProvider(provider);
                        template = buildProviderTemplate(provider, model);
                        responsePath = "choices[0].message.content";
                    }

                    prefs.edit()
                            .putString(PREF_AI_URL, url)
                            .putString(PREF_AI_KEY, key)
                            .putString(PREF_AI_TEMPLATE, template)
                            .putString(PREF_AI_RESPONSE_PATH, responsePath)
                            .putString(PREF_AI_PROVIDER, provider)
                            .putString(PREF_AI_MODEL, model)
                            .putBoolean(PREF_AI_ADVANCED, isAdvanced[0])
                            .apply();

                    updateAiStatus();
                    Toast.makeText(this, "AI 设置已保存", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("取消", null)
                .create();

        btnTestAi.setOnClickListener(v -> {
            if (!isAdvanced[0]) {
                String provider = String.valueOf(spProvider.getSelectedItem());
                String model = etModel.getText() != null ? etModel.getText().toString().trim() : "";
                if (model.isEmpty()) {
                    model = defaultModelForProvider(provider);
                    etModel.setText(model);
                }
                etUrl.setText(defaultUrlForProvider(provider));
                etTemplate.setText(buildProviderTemplate(provider, model));
                etResponsePath.setText("choices[0].message.content");
            }
            testAiRequest(etUrl, etKey, etTemplate, etResponsePath, btnTestAi);
        });
        if (!isAdvanced[0]) {
            etUrl.setText(defaultUrlForProvider(String.valueOf(spProvider.getSelectedItem())));
        }
        dialog.show();
    }

    private void testAiRequest(TextInputEditText etUrl, TextInputEditText etKey,
                               TextInputEditText etTemplate, TextInputEditText etResponsePath, MaterialButton btnTestAi) {
        String url = etUrl.getText() != null ? etUrl.getText().toString().trim() : "";
        String key = etKey.getText() != null ? etKey.getText().toString().trim() : "";
        String template = etTemplate.getText() != null ? etTemplate.getText().toString().trim() : "";
        String responsePath = etResponsePath.getText() != null ? etResponsePath.getText().toString().trim() : "";

        if (url.isEmpty()) {
            Toast.makeText(this, "请先填写 AI API 网址", Toast.LENGTH_SHORT).show();
            return;
        }
        if (key.isEmpty()) {
            Toast.makeText(this, "请先填写 AI API Key", Toast.LENGTH_SHORT).show();
            return;
        }

        btnTestAi.setEnabled(false);
        btnTestAi.setText("测试中...");

        new Thread(() -> {
            HttpURLConnection connection = null;
            try {
                AiConfig config = new AiConfig(url, key, template, responsePath);
                AiRequestSpec spec = buildRequestSpec(config, "ping");

                Log.d(TAG, "AI test request starting");
                Log.d(TAG, "AI test URL: " + spec.url);
                Log.d(TAG, "AI test method: " + spec.method);
                Log.d(TAG, "AI test auth: Bearer " + maskKey(key));
                Log.d(TAG, "AI test body: " + spec.body);

                connection = (HttpURLConnection) URI.create(spec.url).toURL().openConnection();
                connection.setRequestMethod(spec.method);
                connection.setConnectTimeout(10000);
                connection.setReadTimeout(15000);
                boolean hasBody = spec.body != null && !spec.body.isEmpty();
                connection.setDoOutput(hasBody);
                applyRequestHeaders(connection, spec.headers);

                if (hasBody) {
                    try (OutputStream os = connection.getOutputStream()) {
                        os.write(spec.body.getBytes(StandardCharsets.UTF_8));
                    }
                }

                int code = connection.getResponseCode();
                InputStream stream = code >= 200 && code < 300
                        ? connection.getInputStream()
                        : connection.getErrorStream();
                String response = readStream(stream);
                Log.d(TAG, "AI test response code: " + code);
                Log.d(TAG, "AI test response headers: " + connection.getHeaderFields());
                Log.d(TAG, "AI test response body: " + response);
                String message = code >= 200 && code < 300
                        ? "测试成功: HTTP " + code
                        : "测试失败: HTTP " + code + "\n" + trimResponse(response);

                runOnUiThread(() -> {
                    btnTestAi.setEnabled(true);
                    btnTestAi.setText("测试连接");
                    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
                });
            } catch (Exception e) {
                Log.e(TAG, "AI test request failed", e);
                runOnUiThread(() -> {
                    btnTestAi.setEnabled(true);
                    btnTestAi.setText("测试连接");
                    Toast.makeText(this, "测试失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }).start();
    }

    private String readStream(InputStream stream) throws Exception {
        if (stream == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line).append('\n');
            }
        }
        return builder.toString().trim();
    }

    private String trimResponse(String response) {
        if (response == null) {
            return "";
        }
        return response.length() > 120 ? response.substring(0, 120) + "..." : response;
    }

    private String maskKey(String key) {
        if (key == null || key.isEmpty()) {
            return "";
        }
        if (key.length() <= 8) {
            return "****";
        }
        return key.substring(0, 4) + "****" + key.substring(key.length() - 4);
    }

    /**
     * 获取 AI 请求配置，包含替换占位符后的完整信息
     */
    public static class AiConfig {
        public final String url;
        public final String key;
        public final String template;
        public final String responsePath;

        public AiConfig(String url, String key, String template, String responsePath) {
            this.url = url;
            this.key = key;
            this.template = template;
            this.responsePath = responsePath;
        }

        /**
         * 应用模板，将 {{url}} 和 {{key}} 替换为实际值
         * 如果 template 为空，返回默认 OpenAI 格式
         */
        public String applyTemplate() {
            String requestBody;
            if (template == null || template.isEmpty()) {
                requestBody = DEFAULT_OPENAI_TEMPLATE;
            } else {
                requestBody = template;
            }

            return requestBody
                    .replace("{{url}}", url != null ? url : "")
                    .replace("{{key}}", key != null ? key : "");
        }
    }

    public static class AiRequestSpec {
        public final String method;
        public final String url;
        public final String body;
        public final Map<String, String> headers;
        public final String responsePath;

        public AiRequestSpec(String method, String url, String body, Map<String, String> headers, String responsePath) {
            this.method = method;
            this.url = url;
            this.body = body;
            this.headers = headers;
            this.responsePath = responsePath;
        }
    }

    /**
     * 从 SharedPreferences 读取 AI 配置
     */
    public static AiConfig getAiConfig(SharedPreferences prefs) {
        String url = prefs.getString(PREF_AI_URL, "");
        String key = prefs.getString(PREF_AI_KEY, "");
        String template = prefs.getString(PREF_AI_TEMPLATE, "");
        String responsePath = prefs.getString(PREF_AI_RESPONSE_PATH, "");
        return new AiConfig(url, key, template, responsePath);
    }

    /**
     * 构建最终请求（支持极致自定义）
     *
     * 1) 兼容旧模式：
     *    template 作为请求 body，method=POST，url=配置的 AI URL
     *
     * 2) 全自定义模式（template 为 JSON 且包含任一键：method/url/headers/body）：
     *    {
     *      "method": "POST",
     *      "url": "https://xxx",
     *      "headers": {"Authorization":"Bearer {{key}}"},
     *      "body": {...} // 也可写字符串
     *    }
     */
    public static AiRequestSpec buildRequestSpec(AiConfig config, String prompt) {
        String rawPrompt = prompt != null ? prompt : "";
        String escapedPrompt = escapeJson(rawPrompt);
        String baseUrl = config.url != null ? config.url : "";
        String key = config.key != null ? config.key : "";
        String template = (config.template == null || config.template.trim().isEmpty())
                ? DEFAULT_OPENAI_TEMPLATE
                : config.template;

        Map<String, String> headers = buildRequestHeaders(key);
        String method = "POST";
        String requestUrl = baseUrl;
        String requestBody = replaceTokens(template, baseUrl, key, escapedPrompt, rawPrompt);
        String responsePath = config.responsePath != null ? config.responsePath.trim() : "";

        try {
            String trimmed = template.trim();
            if (trimmed.startsWith("{")) {
                JSONObject obj = new JSONObject(replaceTokens(template, baseUrl, key, escapedPrompt, rawPrompt));
                boolean hasFullRequestShape = obj.has("method") || obj.has("url") || obj.has("headers") || obj.has("body");
                if (hasFullRequestShape) {
                    method = obj.optString("method", "POST").trim();
                    if (method.isEmpty()) method = "POST";
                    requestUrl = obj.optString("url", baseUrl).trim();
                    if (requestUrl.isEmpty()) requestUrl = baseUrl;

                    JSONObject customHeaders = obj.optJSONObject("headers");
                    if (customHeaders != null) {
                        Iterator<String> keys = customHeaders.keys();
                        while (keys.hasNext()) {
                            String k = keys.next();
                            String v = customHeaders.optString(k, "");
                            headers.put(k, v);
                        }
                    }

                    if (obj.has("body")) {
                        Object bodyObj = obj.get("body");
                        if (bodyObj instanceof JSONObject) {
                            requestBody = ((JSONObject) bodyObj).toString();
                        } else {
                            requestBody = String.valueOf(bodyObj);
                        }
                    } else {
                        requestBody = "";
                    }

                    if (responsePath.isEmpty()) {
                        responsePath = obj.optString("response_path", "").trim();
                    }
                }
            }
        } catch (JSONException ignored) {
            // 不是 JSON 或 JSON 非法时，按旧模式处理
        }

        return new AiRequestSpec(method, requestUrl, requestBody, headers, responsePath);
    }

    public static Map<String, String> buildRequestHeaders(String key) {
        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json; charset=utf-8");
        if (key != null && !key.trim().isEmpty()) {
            headers.put("Authorization", "Bearer " + key);
        }
        return headers;
    }

    public static void applyRequestHeaders(HttpURLConnection connection, Map<String, String> headers) {
        if (connection == null || headers == null) return;
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() == null || entry.getKey().trim().isEmpty()) continue;
            if (entry.getValue() == null) continue;
            connection.setRequestProperty(entry.getKey(), entry.getValue());
        }
    }

    public static String replaceTokens(String input, String url, String key, String escapedPrompt, String rawPrompt) {
        if (input == null) return "";
        return input
                .replace("{{url}}", url != null ? url : "")
                .replace("{{key}}", key != null ? key : "")
                .replace("{{prompt}}", escapedPrompt != null ? escapedPrompt : "")
                .replace("{{prompt_raw}}", rawPrompt != null ? rawPrompt : "");
    }

    public static String escapeJson(String value) {
        if (value == null) return "";
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    private String defaultUrlForProvider(String provider) {
        switch (provider) {
            case "DeepSeek":
                return "https://api.deepseek.com/chat/completions";
            case "Gemini":
                return "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent";
            case "Claude":
                return "https://api.anthropic.com/v1/messages";
            case "OpenRouter":
                return "https://openrouter.ai/api/v1/chat/completions";
            case "Moonshot(Kimi)":
                return "https://api.moonshot.cn/v1/chat/completions";
            case "Qwen(通义千问)":
                return "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions";
            default:
                return "https://api.openai.com/v1/chat/completions";
        }
    }

    private String defaultModelForProvider(String provider) {
        switch (provider) {
            case "DeepSeek":
                return "deepseek-chat";
            case "Gemini":
                return "gemini-2.5-flash";
            case "Claude":
                return "claude-3-5-sonnet-20241022";
            case "OpenRouter":
                return "openai/gpt-4o-mini";
            case "Moonshot(Kimi)":
                return "moonshot-v1-8k";
            case "Qwen(通义千问)":
                return "qwen-plus";
            default:
                return "gpt-4o-mini";
        }
    }

    private String buildProviderTemplate(String provider, String model) {
        String safeModel = (model == null || model.trim().isEmpty()) ? defaultModelForProvider(provider) : model.trim();
        if ("Gemini".equals(provider)) {
            return "{\n"
                    + "  \"method\": \"POST\",\n"
                    + "  \"url\": \"{{url}}\",\n"
                    + "  \"headers\": {\n"
                    + "    \"Authorization\": \"Bearer {{key}}\",\n"
                    + "    \"Content-Type\": \"application/json\"\n"
                    + "  },\n"
                    + "  \"body\": {\n"
                    + "    \"contents\": [\n"
                    + "      {\n"
                    + "        \"role\": \"user\",\n"
                    + "        \"parts\": [\n"
                    + "          {\"text\": \"{{prompt_raw}}\"}\n"
                    + "        ]\n"
                    + "      }\n"
                    + "    ]\n"
                    + "  },\n"
                    + "  \"response_path\": \"candidates[0].content.parts[0].text\"\n"
                    + "}";
        }
        if ("Claude".equals(provider)) {
            return "{\n"
                    + "  \"method\": \"POST\",\n"
                    + "  \"url\": \"{{url}}\",\n"
                    + "  \"headers\": {\n"
                    + "    \"x-api-key\": \"{{key}}\",\n"
                    + "    \"anthropic-version\": \"2023-06-01\",\n"
                    + "    \"Content-Type\": \"application/json\"\n"
                    + "  },\n"
                    + "  \"body\": {\n"
                    + "    \"model\": \"" + safeModel + "\",\n"
                    + "    \"max_tokens\": 2048,\n"
                    + "    \"messages\": [\n"
                    + "      {\"role\": \"user\", \"content\": \"{{prompt_raw}}\"}\n"
                    + "    ]\n"
                    + "  },\n"
                    + "  \"response_path\": \"content[0].text\"\n"
                    + "}";
        }
        return "{\n"
                + "  \"method\": \"POST\",\n"
                + "  \"url\": \"{{url}}\",\n"
                + "  \"headers\": {\n"
                + "    \"Authorization\": \"Bearer {{key}}\",\n"
                + "    \"Content-Type\": \"application/json\"\n"
                + "  },\n"
                + "  \"body\": {\n"
                + "    \"model\": \"" + safeModel + "\",\n"
                + "    \"messages\": [\n"
                + "      {\"role\": \"user\", \"content\": \"{{prompt_raw}}\"}\n"
                + "    ]\n"
                + "  },\n"
                + "  \"response_path\": \"choices[0].message.content\"\n"
                + "}";
    }

    private void applyAiModeUi(boolean advanced,
                               TextInputLayout layoutProvider,
                               TextInputLayout layoutModel,
                               TextInputLayout layoutUrl,
                               TextInputLayout layoutTemplate,
                               TextInputLayout layoutResponsePath,
                               TextView tvAdvHint,
                               MaterialButton btnToggleAdvanced) {
        layoutProvider.setVisibility(advanced ? View.GONE : View.VISIBLE);
        layoutModel.setVisibility(advanced ? View.GONE : View.VISIBLE);
        layoutUrl.setVisibility(advanced ? View.VISIBLE : View.GONE);
        layoutTemplate.setVisibility(advanced ? View.VISIBLE : View.GONE);
        layoutResponsePath.setVisibility(advanced ? View.VISIBLE : View.GONE);
        tvAdvHint.setVisibility(advanced ? View.VISIBLE : View.GONE);
        btnToggleAdvanced.setText(advanced ? "普通模式" : "高级模式");
    }
}
