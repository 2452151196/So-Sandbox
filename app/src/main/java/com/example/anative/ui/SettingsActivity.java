package com.example.anative.ui;

import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.appcompat.widget.SwitchCompat;
import androidx.cardview.widget.CardView;

import com.example.anative.R;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class SettingsActivity extends AppCompatActivity {

    public static final String PREF_AI_URL = "ai_url";
    public static final String PREF_AI_KEY = "ai_key";
    public static final String PREF_AI_TEMPLATE = "ai_template";
    public static final String PREF_AI_PSEUDOC_ENABLED = "ai_pseudoc_enabled";
    public static final String PREF_PSEUDOC_PROMPT = "pseudoc_prompt";

    private static final String TAG = "SettingsActivity";
    private static final String DEFAULT_OPENAI_TEMPLATE = "{\n"
            + "  \"model\": \"gpt-3.5-turbo\",\n"
            + "  \"messages\": [\n"
            + "    {\"role\": \"user\", \"content\": \"{{prompt}}\"}\n"
            + "  ]\n"
            + "}";

    private SwitchCompat switchTheme;
    private SwitchCompat switchAiPseudoC;
    private TextView tvAiStatus;
    private CardView cardAiSettings;
    private CardView cardPseudoCPrompt;
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

        updateAiStatus();

        cardAiSettings.setOnClickListener(v -> showAiSettingsDialog());
    }

    private void updateAiStatus() {
        String url = prefs.getString(PREF_AI_URL, "");
        String key = prefs.getString(PREF_AI_KEY, "");
        String template = prefs.getString(PREF_AI_TEMPLATE, "");

        if (url.isEmpty() && key.isEmpty()) {
            tvAiStatus.setText("未配置");
        } else if (url.isEmpty()) {
            tvAiStatus.setText("已配置 Key，缺少网址");
        } else if (key.isEmpty()) {
            tvAiStatus.setText("已配置网址，缺少 Key");
        } else if (!template.isEmpty()) {
            tvAiStatus.setText("已配置 (自定义模板)");
        } else {
            tvAiStatus.setText("已配置 (默认 OpenAI)");
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
        TextInputEditText etKey = dialogView.findViewById(R.id.et_dialog_ai_key);
        TextInputEditText etTemplate = dialogView.findViewById(R.id.et_dialog_ai_template);
        MaterialButton btnTestAi = dialogView.findViewById(R.id.btn_test_ai);

        etUrl.setText(prefs.getString(PREF_AI_URL, ""));
        etKey.setText(prefs.getString(PREF_AI_KEY, ""));
        String savedTemplate = prefs.getString(PREF_AI_TEMPLATE, "");
        etTemplate.setText(savedTemplate.isEmpty() ? DEFAULT_OPENAI_TEMPLATE : savedTemplate);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(dialogView)
                .setPositiveButton("保存", (dialogInterface, which) -> {
                    String url = etUrl.getText() != null ? etUrl.getText().toString().trim() : "";
                    String key = etKey.getText() != null ? etKey.getText().toString().trim() : "";
                    String template = etTemplate.getText() != null ? etTemplate.getText().toString().trim() : "";

                    prefs.edit()
                            .putString(PREF_AI_URL, url)
                            .putString(PREF_AI_KEY, key)
                            .putString(PREF_AI_TEMPLATE, template)
                            .apply();

                    updateAiStatus();
                    Toast.makeText(this, "AI 设置已保存", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("取消", null)
                .create();

        btnTestAi.setOnClickListener(v -> testAiRequest(etUrl, etKey, etTemplate, btnTestAi));
        dialog.show();
    }

    private void testAiRequest(TextInputEditText etUrl, TextInputEditText etKey,
                               TextInputEditText etTemplate, MaterialButton btnTestAi) {
        String url = etUrl.getText() != null ? etUrl.getText().toString().trim() : "";
        String key = etKey.getText() != null ? etKey.getText().toString().trim() : "";
        String template = etTemplate.getText() != null ? etTemplate.getText().toString().trim() : "";

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
                String bodyTemplate = template.isEmpty() ? DEFAULT_OPENAI_TEMPLATE : template;
                String requestBody = bodyTemplate
                        .replace("{{url}}", url)
                        .replace("{{key}}", key)
                        .replace("{{prompt}}", "ping");

                Log.d(TAG, "AI test request starting");
                Log.d(TAG, "AI test URL: " + url);
                Log.d(TAG, "AI test auth: Bearer " + maskKey(key));
                Log.d(TAG, "AI test body: " + requestBody);

                connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
                connection.setRequestMethod("POST");
                connection.setConnectTimeout(10000);
                connection.setReadTimeout(15000);
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                connection.setRequestProperty("Authorization", "Bearer " + key);

                try (OutputStream os = connection.getOutputStream()) {
                    os.write(requestBody.getBytes(StandardCharsets.UTF_8));
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

        public AiConfig(String url, String key, String template) {
            this.url = url;
            this.key = key;
            this.template = template;
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

    /**
     * 从 SharedPreferences 读取 AI 配置
     */
    public static AiConfig getAiConfig(SharedPreferences prefs) {
        String url = prefs.getString(PREF_AI_URL, "");
        String key = prefs.getString(PREF_AI_KEY, "");
        String template = prefs.getString(PREF_AI_TEMPLATE, "");
        return new AiConfig(url, key, template);
    }
}
