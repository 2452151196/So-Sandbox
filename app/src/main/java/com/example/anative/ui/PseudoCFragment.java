package com.example.anative.ui;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.json.JSONObject;
import org.json.JSONArray;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.example.anative.core.PltEntry;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PseudoCFragment extends Fragment {

    private static final String TAG = "PseudoCFragment";
    private static final String DEFAULT_AI_TEMPLATE = "{\n"
            + "  \"model\": \"gpt-3.5-turbo\",\n"
            + "  \"messages\": [\n"
            + "    {\"role\": \"system\", \"content\": \"You are a reverse engineering assistant. Convert assembly to readable pseudo C code. Return code only.\"},\n"
            + "    {\"role\": \"user\", \"content\": \"{{prompt}}\"}\n"
            + "  ]\n"
            + "}";

    private static final String ARG_FUNC_ADDR = "func_addr";
    private static final String ARG_FUNC_SIZE = "func_size";
    private static final String ARG_FUNC_NAME = "func_name";
    private static final String ARG_SIGNATURE = "signature";
    private static final String ARG_BASE_ADDR = "base_addr";

    private long funcAddr;
    private long funcSize;
    private String funcName;
    private String signature;
    private long baseAddr;

    private TextView tvCode;
    private ProgressBar progressBar;
    private LinearLayout llAiStatus;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    public static PseudoCFragment newInstance(long funcAddr, long funcSize, String funcName, String signature, long baseAddr) {
        PseudoCFragment fragment = new PseudoCFragment();
        Bundle args = new Bundle();
        args.putLong(ARG_FUNC_ADDR, funcAddr);
        args.putLong(ARG_FUNC_SIZE, funcSize);
        args.putString(ARG_FUNC_NAME, funcName);
        args.putString(ARG_SIGNATURE, signature);
        args.putLong(ARG_BASE_ADDR, baseAddr);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            funcAddr = getArguments().getLong(ARG_FUNC_ADDR);
            funcSize = getArguments().getLong(ARG_FUNC_SIZE);
            funcName = getArguments().getString(ARG_FUNC_NAME);
            signature = getArguments().getString(ARG_SIGNATURE);
            baseAddr = getArguments().getLong(ARG_BASE_ADDR);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_code_view, container, false);
        tvCode = view.findViewById(R.id.tvCode);
        progressBar = view.findViewById(R.id.progressBar);
        llAiStatus = view.findViewById(R.id.ll_ai_status);
        return view;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        loadPseudoC();
    }

    private void loadPseudoC() {
        progressBar.setVisibility(View.VISIBLE);
        tvCode.setText("");
        llAiStatus.setVisibility(View.GONE);

        executor.execute(() -> {
            String name = funcName != null ? funcName : "func";

            // 先加载本地伪C
            String localResult;
            if (baseAddr == 0) {
                localResult = decompileFromFile(funcAddr, funcSize, name, signature);
            } else {
                localResult = NativeInvoker.decompileFunctionEx(funcAddr, funcSize, name, signature, baseAddr);
            }

            // 显示本地伪C
            final String localCode = localResult;
            handler.post(() -> {
                progressBar.setVisibility(View.GONE);
                tvCode.setText(highlightPseudoC(localCode));
            });

            // 如果AI开关开启，异步请求AI
            if (isAiPseudoCEnabled()) {
                handler.post(() -> {
                    // 显示透明浮层
                    llAiStatus.setVisibility(View.VISIBLE);
                });

                executor.execute(() -> {
                    String aiResult = decompileWithAi(name);
                    final String aiCode = aiResult;
                    handler.post(() -> {
                        llAiStatus.setVisibility(View.GONE);
                        tvCode.setText(highlightPseudoC(aiCode));
                    });
                });
            }
        });
    }

    private boolean isAiPseudoCEnabled() {
        if (getContext() == null) {
            return false;
        }
        SharedPreferences prefs = requireContext().getSharedPreferences("app_prefs", android.content.Context.MODE_PRIVATE);
        return prefs.getBoolean(SettingsActivity.PREF_AI_PSEUDOC_ENABLED, false);
    }

    private String decompileWithAi(String name) {
        Log.d(TAG, "AI pseudo-C mode ACTIVATED");
        if (getContext() == null) {
            return "ERR: 上下文不可用";
        }
        SharedPreferences prefs = requireContext().getSharedPreferences("app_prefs", android.content.Context.MODE_PRIVATE);
        SettingsActivity.AiConfig config = SettingsActivity.getAiConfig(prefs);
        if (config.url == null || config.url.trim().isEmpty()) {
            return "ERR: 未配置 AI URL";
        }
        if (config.key == null || config.key.trim().isEmpty()) {
            return "ERR: 未配置 AI Key";
        }
        Log.d(TAG, "AI config OK, building assembly...");

        String asm = buildAssemblyForAi();
        if (asm == null || asm.trim().isEmpty() || asm.startsWith("ERR:")) {
            return asm == null || asm.isEmpty() ? "ERR: 汇编为空" : asm;
        }

        String prompt = buildAiPrompt(name, asm);
        String template = (config.template == null || config.template.trim().isEmpty())
                ? DEFAULT_AI_TEMPLATE
                : config.template;
        String requestBody = template
                .replace("{{url}}", config.url)
                .replace("{{key}}", config.key)
                .replace("{{prompt}}", escapeJson(prompt));

        HttpURLConnection connection = null;
        try {
            Log.d(TAG, "AI pseudo-C request URL: " + config.url);
            Log.d(TAG, "AI pseudo-C prompt length: " + prompt.length());
            connection = (HttpURLConnection) URI.create(config.url).toURL().openConnection();
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(30000);
            connection.setReadTimeout(60000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            connection.setRequestProperty("Authorization", "Bearer " + config.key);

            try (OutputStream os = connection.getOutputStream()) {
                os.write(requestBody.getBytes(StandardCharsets.UTF_8));
            }

            int code = connection.getResponseCode();
            InputStream stream = code >= 200 && code < 300 ? connection.getInputStream() : connection.getErrorStream();
            String response = readStream(stream);
            Log.d(TAG, "AI pseudo-C response code: " + code);
            Log.d(TAG, "AI pseudo-C response body: " + response);
            if (code < 200 || code >= 300) {
                return "ERR: AI 请求失败 HTTP " + code + "\n" + trimResponse(response);
            }
            String content = extractAiContent(response);
            return content == null || content.trim().isEmpty()
                    ? "ERR: AI 返回为空\n" + trimResponse(response)
                    : content.trim();
        } catch (Exception e) {
            Log.e(TAG, "AI pseudo-C request failed", e);
            String errorMsg = e.getMessage();
            if (errorMsg != null && (errorMsg.contains("timeout") || errorMsg.contains("timed out"))) {
                return "ERR: AI 请求超时，请稍后重试或检查网络连接";
            }
            return "ERR: AI 请求失败: " + e.getMessage();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String buildAssemblyForAi() {
        List<ElfParser.StringEntry> stringsList = DataHolder.getInstance().getStrings();
        List<PltEntry> pltList = DataHolder.getInstance().getPltEntries();
        String stringTable = buildStringTable(stringsList);
        String pltTable = buildPltTable(pltList);
        String funcTable = buildFuncTable();

        if (baseAddr == 0) {
            return disassembleFromFile(funcAddr, funcSize, stringTable, pltTable, funcTable);
        }
        return NativeInvoker.disassembleFunctionEx(funcAddr, funcSize, stringTable, pltTable, baseAddr, funcTable);
    }

    private String disassembleFromFile(long virtualAddr, long size, String stringTable, String pltTable, String funcTable) {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null) return "ERR: SO文件路径未知";
        try {
            long fileOffset = ElfParser.virtualAddrToFileOffset(soPath, virtualAddr);
            RandomAccessFile raf = new RandomAccessFile(soPath, "r");
            if (size == 0) size = 256;
            if (size > 65536) size = 65536;
            if (fileOffset + size > raf.length()) size = raf.length() - fileOffset;
            if (size <= 0) { raf.close(); return "ERR: 无效的函数偏移"; }
            byte[] bytes = new byte[(int) size];
            raf.seek(fileOffset);
            raf.readFully(bytes);
            raf.close();
            return NativeInvoker.disassembleBytes(bytes, virtualAddr, size, stringTable, pltTable, funcTable);
        } catch (Exception e) {
            return "ERR: 读取SO文件失败: " + e.getMessage();
        }
    }

    private String buildAiPrompt(String name, String asm) {
        if (getContext() == null) {
            return "请将下面的汇编转换为伪C代码\n" + asm;
        }
        SharedPreferences prefs = requireContext().getSharedPreferences("app_prefs", android.content.Context.MODE_PRIVATE);
        String customPrompt = prefs.getString(SettingsActivity.PREF_PSEUDOC_PROMPT, "");
        if (customPrompt != null && !customPrompt.trim().isEmpty()) {
            // 替换 {{assembly_code}} 占位符
            return customPrompt.replace("{{assembly_code}}", asm);
        }
        // 默认提示词
        return "请将下面的 ARM/Native 汇编转换为可读性较高的伪C代码，只返回伪C代码，不要解释。\n"
                + "函数名: " + name + "\n"
                + "签名: " + (signature == null ? "unknown" : signature) + "\n"
                + "汇编:\n" + asm;
    }

    private String escapeJson(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r");
    }

    private String extractAiContent(String response) {
        if (response == null || response.isEmpty()) {
            return "";
        }
        try {
            JSONObject json = new JSONObject(response);
            if (json.has("choices")) {
                JSONArray choices = json.getJSONArray("choices");
                if (choices.length() > 0) {
                    JSONObject firstChoice = choices.getJSONObject(0);
                    if (firstChoice.has("message")) {
                        JSONObject message = firstChoice.getJSONObject("message");
                        if (message.has("content")) {
                            return message.getString("content");
                        }
                    }
                }
            }
            // 如果标准结构不存在，尝试直接返回
            return response;
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse AI response as JSON", e);
            // JSON 解析失败，返回原始响应
            return response;
        }
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
        return response;
    }

    private String buildFuncTable() {
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        if (funcs == null || funcs.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (NativeFunction f : funcs) {
            if (sb.length() > 0) sb.append("|");
            sb.append(String.format("%X", f.getOffset())).append("|").append(f.getDemangledName());
        }
        return sb.toString();
    }

    private String buildStringTable(List<ElfParser.StringEntry> strings) {
        if (strings == null || strings.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (ElfParser.StringEntry e : strings) {
            if (sb.length() > 0) sb.append("|");
            sb.append(String.format("%X", e.virtualAddress)).append("|").append(e.value);
        }
        return sb.toString();
    }

    private String buildPltTable(List<PltEntry> pltEntries) {
        if (pltEntries == null || pltEntries.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (PltEntry e : pltEntries) {
            if (sb.length() > 0) sb.append("|");
            sb.append(String.format("%X", e.offset)).append("|").append(e.symbolName);
        }
        return sb.toString();
    }

    private String decompileFromFile(long virtualAddr, long size, String name, String sig) {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null) return "ERR: SO文件路径未知";
        try {
            long fileOffset = ElfParser.virtualAddrToFileOffset(soPath, virtualAddr);
            RandomAccessFile raf = new RandomAccessFile(soPath, "r");
            if (size == 0) size = 256;
            if (size > 16384) size = 16384;
            if (fileOffset + size > raf.length()) size = raf.length() - fileOffset;
            if (size <= 0) { raf.close(); return "ERR: 无效的函数偏移"; }
            byte[] bytes = new byte[(int) size];
            raf.seek(fileOffset);
            raf.readFully(bytes);
            raf.close();
            return NativeInvoker.decompileBytes(bytes, virtualAddr, size, name, sig);
        } catch (Exception e) {
            return "ERR: 读取SO文件失败: " + e.getMessage();
        }
    }

    private SpannableString highlightPseudoC(String code) {
        SpannableString ss = new SpannableString(code);
        int cKeyword = getResColor(R.color.code_keyword);
        int cType = getResColor(R.color.code_type);
        int cFunc = getResColor(R.color.code_func);
        int cNum = getResColor(R.color.code_num);
        int cStr = getResColor(R.color.code_string);
        int cComment = getResColor(R.color.code_comment);

        // 高亮注释 (最先，后面不覆盖)
        Pattern commentPattern = Pattern.compile("//.*$", Pattern.MULTILINE);
        Matcher m = commentPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(cComment), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        // 高亮字符串
        Pattern strPattern = Pattern.compile("\"[^\"]*\"");
        m = strPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(cStr), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        // 高亮控制流关键字
        String[] controlKw = {"if", "else", "goto", "return", "while", "for", "switch", "case", "break"};
        for (String kw : controlKw) {
            Pattern p = Pattern.compile("\\b" + kw + "\\b");
            m = p.matcher(code);
            while (m.find()) {
                ss.setSpan(new ForegroundColorSpan(cKeyword), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }

        // 高亮类型
        String[] types = {"void", "int", "long", "unsigned", "int64_t", "int32_t", "int8_t",
                "int16_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
                "byte", "short", "float", "double", "char", "bool",
                "JNIEnv", "jobject", "jclass", "jstring", "jint", "jlong", "JavaVM"};
        for (String t : types) {
            Pattern p = Pattern.compile("\\b" + t + "\\b");
            m = p.matcher(code);
            while (m.find()) {
                ss.setSpan(new ForegroundColorSpan(cType), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }

        // 高亮函数调用
        Pattern funcPattern = Pattern.compile("\\b([a-zA-Z_][a-zA-Z0-9_]*)\\s*\\(");
        m = funcPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(cFunc), m.start(1), m.end(1), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        // 高亮十六进制数
        Pattern hexPattern = Pattern.compile("-?0x[0-9a-fA-F]+");
        m = hexPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(cNum), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        // 高亮十进制数
        Pattern numPattern = Pattern.compile("(?<!0x)(?<![a-fA-F0-9])\\b\\d+\\b");
        m = numPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(cNum), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        return ss;
    }

    private int getResColor(int resId) {
        return requireContext().getResources().getColor(resId, requireContext().getTheme());
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
