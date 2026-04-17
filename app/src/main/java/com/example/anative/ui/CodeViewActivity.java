package com.example.anative.ui;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.util.TypedValue;
import android.view.View;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.example.anative.core.PltEntry;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CodeViewActivity extends AppCompatActivity {

    public static final String EXTRA_FUNC_NAME = "func_name";
    public static final String EXTRA_FUNC_ADDR = "func_addr";
    public static final String EXTRA_FUNC_SIZE = "func_size";
    public static final String EXTRA_MODE = "mode"; // "asm" or "pseudoc"
    public static final String EXTRA_DEMANGLED_NAME = "demangled_name";
    public static final String EXTRA_SIGNATURE = "signature";

    private TextView tvTitle, tvSubtitle, tvInfo, tvCode;
    private MaterialButton btnToggle, btnSave;
    private ProgressBar progressBar;

    private long funcAddr;      // 运行时绝对地址
    private long funcOffset;    // 相对于SO基址的偏移
    private long baseAddress;   // SO基址
    private long funcSize;
    private String funcName;
    private String demangledName;
    private String signature;
    private List<ElfParser.StringEntry> stringsList;
    private List<PltEntry> pltList;
    private boolean isAsmMode = true;

    private String cachedAsm = null;
    private String cachedPseudoC = null;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_code_view);

        tvTitle = findViewById(R.id.tv_title);
        tvSubtitle = findViewById(R.id.tv_subtitle);
        tvInfo = findViewById(R.id.tv_info);
        tvCode = findViewById(R.id.tv_code);
        tvCode.setTextSize(TypedValue.COMPLEX_UNIT_SP, SettingsActivity.getCodeFontSizeSp(this));
        btnToggle = findViewById(R.id.btn_toggle);
        btnSave = findViewById(R.id.btn_save);
        progressBar = findViewById(R.id.progress_bar);

        ImageButton btnBack = findViewById(R.id.btn_back);
        btnBack.setOnClickListener(v -> finish());

        funcName = getIntent().getStringExtra(EXTRA_FUNC_NAME);
        funcAddr = getIntent().getLongExtra(EXTRA_FUNC_ADDR, 0);
        funcSize = getIntent().getLongExtra(EXTRA_FUNC_SIZE, 0);
        demangledName = getIntent().getStringExtra(EXTRA_DEMANGLED_NAME);
        signature = getIntent().getStringExtra(EXTRA_SIGNATURE);
        baseAddress = DataHolder.getInstance().getBaseAddress();
        stringsList = DataHolder.getInstance().getStrings();
        pltList = DataHolder.getInstance().getPltEntries();
        funcOffset = funcAddr - baseAddress;
        isAsmMode = "asm".equals(getIntent().getStringExtra(EXTRA_MODE));

        tvSubtitle.setText(funcName);
        tvInfo.setText(String.format("偏移: 0x%X  |  运行时: 0x%X  |  大小: %d bytes",
                funcOffset, funcAddr, funcSize));

        btnToggle.setOnClickListener(v -> {
            isAsmMode = !isAsmMode;
            updateView();
        });

        btnSave.setOnClickListener(v -> saveModifiedSo());

        updateView();
    }

    private void updateView() {
        if (isAsmMode) {
            tvTitle.setText("ARM64 汇编");
            btnToggle.setText("切换伪C");
            if (cachedAsm != null) {
                displayCode(cachedAsm, true);
            } else {
                loadCode(true);
            }
        } else {
            tvTitle.setText("伪C代码");
            btnToggle.setText("切换汇编");
            if (cachedPseudoC != null) {
                displayCode(cachedPseudoC, false);
            } else {
                loadCode(false);
            }
        }
    }

    private void loadCode(boolean asm) {
        progressBar.setVisibility(View.VISIBLE);
        tvCode.setText("");

        executor.execute(() -> {
            String result;
            if (asm) {
                String stringTable = buildStringTable(stringsList);
                String pltTable = buildPltTable(pltList);
                String funcTable = buildFuncTable();
                if (baseAddress == 0) {
                    result = disassembleFromFile(funcAddr, funcSize, stringTable, pltTable, funcTable);
                } else {
                    result = NativeInvoker.disassembleFunctionEx(funcAddr, funcSize, stringTable, pltTable, baseAddress, funcTable);
                }
                cachedAsm = result;
            } else {
                String name = demangledName != null ? demangledName : funcName;
                if (baseAddress == 0) {
                    result = decompileFromFile(funcAddr, funcSize, name, signature);
                } else {
                    result = NativeInvoker.decompileFunctionEx(funcAddr, funcSize, name, signature, baseAddress);
                }
                cachedPseudoC = result;
            }
            final String code = result;
            handler.post(() -> {
                progressBar.setVisibility(View.GONE);
                displayCode(code, asm);
            });
        });
    }

    private void displayCode(String code, boolean isAsm) {
        if (code == null || code.isEmpty()) {
            tvCode.setText("无数据");
            return;
        }

        if (code.startsWith("ERR:")) {
            tvCode.setTextColor(getResources().getColor(R.color.red_error, null));
            tvCode.setText(code);
            return;
        }

        tvCode.setTextColor(getResources().getColor(R.color.text_primary, null));

        if (isAsm) {
            tvCode.setText(highlightAsm(code));
        } else {
            tvCode.setText(highlightPseudoC(code));
        }
    }

    private SpannableString highlightAsm(String code) {
        SpannableString ss = new SpannableString(code);
        int cyan = getResources().getColor(R.color.cyan_500, null);
        int green = 0xFF4CAF50;
        int yellow = 0xFFFFEB3B;
        int gray = 0xFF888888;
        int orange = 0xFFFF9800;

        Pattern addrPattern = Pattern.compile("^0x[0-9a-fA-F]+:", Pattern.MULTILINE);
        Matcher m = addrPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(gray), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        String[] branchMnemonics = {"bl", "blr", "br", "b", "ret", "b\\.\\w+"};
        for (String mne : branchMnemonics) {
            Pattern p = Pattern.compile("\\s(" + mne + ")\\s", Pattern.MULTILINE);
            Matcher mm = p.matcher(code);
            while (mm.find()) {
                ss.setSpan(new ForegroundColorSpan(orange), mm.start(1), mm.end(1), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }

        Pattern commentPattern = Pattern.compile(";.*$", Pattern.MULTILINE);
        m = commentPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(green), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        Pattern immPattern = Pattern.compile("#0x[0-9a-fA-F]+|#\\d+");
        m = immPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(yellow), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        return ss;
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

    private SpannableString highlightPseudoC(String code) {
        SpannableString ss = new SpannableString(code);
        int cyan = getResources().getColor(R.color.cyan_500, null);
        int green = 0xFF4CAF50;
        int orange = 0xFFFF9800;
        int purple = 0xFFCE93D8;
        int yellow = 0xFFFFEB3B;

        String[] keywords = {"if", "goto", "return", "long", "int", "void", "unsigned", "int64_t", "int32_t", "int8_t", "int16_t", "uint8_t", "uint16_t", "byte", "short", "float", "double", "char", "JNIEnv", "jobject", "jclass", "JavaVM"};
        for (String kw : keywords) {
            Pattern p = Pattern.compile("\\b" + kw + "\\b");
            Matcher m = p.matcher(code);
            while (m.find()) {
                ss.setSpan(new ForegroundColorSpan(orange), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }

        Pattern commentPattern = Pattern.compile("//.*$", Pattern.MULTILINE);
        Matcher m = commentPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(green), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        Pattern callPattern = Pattern.compile("call_0x[0-9a-fA-F]+");
        m = callPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(cyan), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        Pattern labelPattern = Pattern.compile("^loc_[0-9a-fA-F]+:", Pattern.MULTILINE);
        m = labelPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(purple), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        Pattern numPattern = Pattern.compile("\\b0x[0-9a-fA-F]+\\b");
        m = numPattern.matcher(code);
        while (m.find()) {
            ss.setSpan(new ForegroundColorSpan(yellow), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        return ss;
    }

    private void saveModifiedSo() {
        String originalUriStr = DataHolder.getInstance().getOriginalUri();
        String soPath = DataHolder.getInstance().getSoPath();

        if (originalUriStr == null && soPath == null) {
            Toast.makeText(this, "SO文件路径未知", Toast.LENGTH_SHORT).show();
            return;
        }

        String newFileName;
        if (soPath != null) {
            newFileName = new File(soPath).getName().replace(".so", "_patched.so");
        } else {
            newFileName = "export_patched.so";
        }

        Toast.makeText(this, "正在保存...", Toast.LENGTH_SHORT).show();
        executor.execute(() -> {
            try {
                Uri originalUri = Uri.parse(originalUriStr);
                String destDir = getExternalFilesDir(null).getAbsolutePath();
                File destFile = new File(destDir, newFileName);

                InputStream is = getContentResolver().openInputStream(originalUri);
                if (is == null) throw new Exception("无法打开原始文件");
                OutputStream os = new java.io.FileOutputStream(destFile);
                byte[] buffer = new byte[8192];
                int len;
                while ((len = is.read(buffer)) != -1) {
                    os.write(buffer, 0, len);
                }
                is.close();
                os.close();

                final File savedFile = destFile;
                handler.post(() -> showSaveSuccessDialog(savedFile));
            } catch (Exception e) {
                handler.post(() -> Toast.makeText(this,
                        "保存失败: " + e.getMessage(), Toast.LENGTH_LONG).show());
            }
        });
    }

    private void showSaveSuccessDialog(File savedFile) {
        String path = savedFile.getAbsolutePath();
        new AlertDialog.Builder(this)
                .setTitle("保存成功")
                .setMessage(path)
                .setPositiveButton("复制路径", (dialog, which) -> {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(ClipData.newPlainText("SO路径", path));
                    Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
                })
                .setNeutralButton("打开目录", (dialog, which) -> {
                    try {
                        Intent openDir = new Intent(Intent.ACTION_VIEW);
                        Uri dirUri = Uri.parse("file://" + savedFile.getParent());
                        openDir.setDataAndType(dirUri, "resource/folder");
                        startActivity(openDir);
                    } catch (Exception e) {
                        try {
                            Intent intent = Intent.createChooser(
                                    new Intent(Intent.ACTION_VIEW).setDataAndType(
                                            Uri.parse("file://" + savedFile.getParent()), "*/*"), "打开目录");
                            startActivity(intent);
                        } catch (Exception e2) {
                            Toast.makeText(this, "无法打开目录", Toast.LENGTH_SHORT).show();
                        }
                    }
                })
                .setNegativeButton("关闭", null)
                .show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
    }
}
