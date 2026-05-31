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
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.widget.ViewPager2;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.DebugSessionManager;
import androidx.fragment.app.FragmentManager;

import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FunctionDetailActivity extends AppCompatActivity {

    public static final String EXTRA_FUNC_NAME = "func_name";
    public static final String EXTRA_FUNC_ADDR = "func_addr";
    public static final String EXTRA_FUNC_SIZE = "func_size";
    public static final String EXTRA_DEMANGLED_NAME = "demangled_name";
    public static final String EXTRA_SIGNATURE = "signature";
    public static final String EXTRA_CAPTURED_INDEX = "captured_index";
    public static final String EXTRA_JNI_CLASS = "jni_class";
    public static final String EXTRA_JNI_METHOD = "jni_method";
    public static final String EXTRA_JNI_SIG = "jni_sig";

    private String funcName;
    private long funcAddr;
    private long funcSize;
    private String demangledName;
    private String signature;
    private long baseAddress;

    // 动态注册调用信息（从 RegisterNativesActivity 传入）
    private int capturedIndex = -1;
    private String jniClass;
    private String jniMethod;
    private String jniSig;

    private ViewPager2 viewPager;
    private TabLayout tabLayout;
    private FunctionPagerAdapter pagerAdapter;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    // 调试面板
    private LinearLayout debugPanel;
    private LinearLayout dbgExpandContent;
    private TextView tvDbgStatus;
    private TextView tvDbgPC;
    private TextView tvDbgBreakpoints;
    private TextView tvDbgRegisters;
    private TextView btnDbgToggle;
    private EditText etDbgOffset;
    private boolean dbgPanelExpanded = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_function_detail);

        funcName = getIntent().getStringExtra(EXTRA_FUNC_NAME);
        funcAddr = getIntent().getLongExtra(EXTRA_FUNC_ADDR, 0);
        funcSize = getIntent().getLongExtra(EXTRA_FUNC_SIZE, 0);
        demangledName = getIntent().getStringExtra(EXTRA_DEMANGLED_NAME);
        signature = getIntent().getStringExtra(EXTRA_SIGNATURE);
        baseAddress = DataHolder.getInstance().getBaseAddress();
        capturedIndex = getIntent().getIntExtra(EXTRA_CAPTURED_INDEX, -1);
        jniClass = getIntent().getStringExtra(EXTRA_JNI_CLASS);
        jniMethod = getIntent().getStringExtra(EXTRA_JNI_METHOD);
        jniSig = getIntent().getStringExtra(EXTRA_JNI_SIG);

        androidx.appcompat.widget.Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(demangledName != null ? demangledName : funcName);
            getSupportActionBar().setSubtitle(String.format("0x%X | %d bytes", funcAddr - baseAddress, funcSize));
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        toolbar.setNavigationOnClickListener(v -> finish());

        viewPager = findViewById(R.id.viewPager);
        tabLayout = findViewById(R.id.tabLayout);

        pagerAdapter = new FunctionPagerAdapter(this, funcAddr, funcSize, demangledName, signature);
        viewPager.setAdapter(pagerAdapter);
        viewPager.setOffscreenPageLimit(2);
        viewPager.setUserInputEnabled(false);
        viewPager.setPageTransformer(new DepthPageTransformer());

        String[] tabTitles = {"汇编", "伪C", "Hex", "Sections", "流程图"};
        new TabLayoutMediator(tabLayout, viewPager,
                (tab, position) -> tab.setText(tabTitles[position])
        ).attach();

        // 设置 HexFragment 的刷新监听器，当 hex 修改时刷新 AsmFragment
        viewPager.post(() -> {
            Fragment hexFragment = pagerAdapter.getFragment(2);
            if (hexFragment instanceof HexFragment) {
                ((HexFragment) hexFragment).setOnRefreshListener(() -> {
                    Fragment asmFragment = pagerAdapter.getFragment(0);
                    if (asmFragment instanceof AsmFragment) {
                        ((AsmFragment) asmFragment).refreshDisplay();
                    }
                });
            }
        });


        tabLayout.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override public void onTabSelected(TabLayout.Tab tab) {
                viewPager.setCurrentItem(tab.getPosition(), true);
            }
            @Override public void onTabUnselected(TabLayout.Tab tab) {}
            @Override public void onTabReselected(TabLayout.Tab tab) {}
        });

        initDebugPanel();
    }

    @Override
    protected void onResume() {
        super.onResume();
        // 当从其他页面返回时刷新显示
        if (pagerAdapter != null) {
            pagerAdapter.refreshAllFragments();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_function_detail, menu);
        return true;
    }

    @Override
    public void onBackPressed() {
        if (DataHolder.getInstance().hasUnsavedChanges()) {
            new AlertDialog.Builder(this)
                    .setTitle("文件已修改")
                    .setMessage("是否保存修改后的 SO 文件到 sdcard/SoSandbox？")
                    .setPositiveButton("保存", (dialog, which) -> {
                        saveModifiedSo(true);
                    })
                    .setNegativeButton("不保存", (dialog, which) -> {
                        DataHolder.getInstance().clearUnsavedChanges();
                        DataHolder.getInstance().clearAllModifiedInstructions();
                        finish();
                    })
                    .setNeutralButton("取消", null)
                    .show();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.action_run) {
            saveModifiedSo(false);
            return true;
        } else if (item.getItemId() == R.id.action_copy_all) {
            copyCurrentPageContent();
            return true;
        } else if (item.getItemId() == R.id.action_debug) {
            launchDebugger();
            return true;
        } else if (item.getItemId() == R.id.action_export) {
            exportCurrentPage();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void launchDebugger() {
        // 显示底部调试面板而不是跳转 Activity
        debugPanel.setVisibility(View.VISIBLE);
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        if (dbg.isActive()) {
            updateDbgStatus();
        }
    }

    // ================== 调试面板 ==================

    private void initDebugPanel() {
        debugPanel = findViewById(R.id.debugPanel);
        dbgExpandContent = findViewById(R.id.dbgExpandContent);
        tvDbgStatus = findViewById(R.id.tvDbgStatus);
        tvDbgPC = findViewById(R.id.tvDbgPC);
        tvDbgBreakpoints = findViewById(R.id.tvDbgBreakpoints);
        btnDbgToggle = findViewById(R.id.btnDbgToggle);
        etDbgOffset = findViewById(R.id.etDbgOffset);
        tvDbgRegisters = findViewById(R.id.tvDbgRegisters);

        // 预填当前函数偏移
        long currentFuncOffset = funcAddr - baseAddress;
        etDbgOffset.setText(String.format("0x%X", currentFuncOffset));

        // 折叠/展开
        btnDbgToggle.setOnClickListener(v -> {
            dbgPanelExpanded = !dbgPanelExpanded;
            dbgExpandContent.setVisibility(dbgPanelExpanded ? View.VISIBLE : View.GONE);
            btnDbgToggle.setText(dbgPanelExpanded ? "▼" : "▲");
        });

        // 启动调试
        findViewById(R.id.btnDbgSpawn).setOnClickListener(v -> dbgSpawn());
        // 调用函数（弹出 InvokeDialog）
        findViewById(R.id.btnDbgCall).setOnClickListener(v -> dbgCallFunction());
        // 继续
        findViewById(R.id.btnDbgContinue).setOnClickListener(v -> dbgContinue());
        // 单步
        findViewById(R.id.btnDbgStep).setOnClickListener(v -> dbgStep());
        // 分离
        findViewById(R.id.btnDbgDetach).setOnClickListener(v -> dbgDetach());
        // 偏移下断点
        findViewById(R.id.btnDbgSetBp).setOnClickListener(v -> dbgSetBpByOffset());
        // 刷新寄存器
        findViewById(R.id.btnRefreshRegs).setOnClickListener(v -> refreshRegisters());

        // 如果调试会话已激活，直接显示面板
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        if (dbg.isActive()) {
            debugPanel.setVisibility(View.VISIBLE);
            updateDbgStatus();
        }

        // 监听断点变化
        dbg.setBreakpointChangeListener(offsets -> handler.post(() -> {
            updateDbgBreakpointList();
            syncBreakpointsToAsm();
        }));
        dbg.setStateChangeListener((active, status) -> handler.post(() -> {
            tvDbgStatus.setText(status);
            if (active) {
                debugPanel.setVisibility(View.VISIBLE);
            }
        }));
    }

    private long parseOffset(String text) {
        if (text == null) return -1;
        text = text.trim();
        if (text.isEmpty()) return -1;
        try {
            if (text.startsWith("0x") || text.startsWith("0X")) {
                return Long.parseLong(text.substring(2), 16);
            }
            return Long.parseLong(text, 16);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private void dbgSpawn() {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null || soPath.isEmpty()) {
            Toast.makeText(this, "未加载 SO 文件", Toast.LENGTH_SHORT).show();
            return;
        }
        long currentFuncOffset = funcAddr - baseAddress;
        executor.execute(() -> {
            DebugSessionManager dbg = DebugSessionManager.getInstance();
            boolean ok = dbg.spawnChild(soPath, currentFuncOffset);
            handler.post(() -> {
                if (ok) {
                    Toast.makeText(this, "Spawn 成功 PID=" + dbg.getChildPid(), Toast.LENGTH_SHORT).show();
                    updateDbgStatus();
                    syncBreakpointsToAsm();
                } else {
                    Toast.makeText(this, "Spawn 失败（检查 Root 权限）", Toast.LENGTH_SHORT).show();
                }
            });
        });
    }

    private NativeFunction findCurrentFunction() {
        java.util.List<com.example.anative.core.NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        if (funcs == null) return null;
        long offset = funcAddr - baseAddress;
        for (NativeFunction f : funcs) {
            if (f.getOffset() == offset) return f;
        }
        // 没找到精确匹配，尝试按名字找
        for (NativeFunction f : funcs) {
            if (f.getName() != null && f.getName().equals(funcName)) return f;
        }
        return null;
    }

    private void dbgCallFunction() {
        // 动态注册函数：弹出参数输入窗口
        if (capturedIndex >= 0 && jniSig != null) {
            showCapturedCallDialog();
            return;
        }
        Toast.makeText(this, "仅支持动态注册的函数（请从动态注册页面进入）", Toast.LENGTH_SHORT).show();
    }

    private void showCapturedCallDialog() {
        String className = jniClass != null ? jniClass : "";
        String methodName = jniMethod != null ? jniMethod : funcName;

        java.util.List<String[]> params = parseJniSigParams(jniSig);
        char retType = parseJniRetType(jniSig);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);

        TextView tvInfo = new TextView(this);
        tvInfo.setText(String.format("%s.%s\n签名: %s\n地址: 0x%X  (偏移: 0x%X)\n返回: %s",
                className, methodName, jniSig, funcAddr, funcAddr - baseAddress,
                jniTypeToName(retType)));
        tvInfo.setTextSize(13);
        layout.addView(tvInfo);

        TextView tvAuto = new TextView(this);
        tvAuto.setText("\n参数 0: JNIEnv* (自动注入)\n参数 1: jclass (自动注入)");
        tvAuto.setTextSize(12);
        tvAuto.setTextColor(0xFF888888);
        layout.addView(tvAuto);

        java.util.List<EditText> paramEdits = new java.util.ArrayList<>();
        for (int i = 0; i < params.size(); i++) {
            String[] p = params.get(i);
            TextView label = new TextView(this);
            label.setText(String.format("\n参数 %d: %s", i + 2, p[0]));
            label.setTextSize(12);
            layout.addView(label);

            EditText et = new EditText(this);
            et.setHint(p[1]);
            et.setTextSize(14);
            et.setSingleLine(true);
            et.setText(p[2]);
            layout.addView(et);
            paramEdits.add(et);
        }

        android.widget.ScrollView scroll = new android.widget.ScrollView(this);
        scroll.addView(layout);

        new android.app.AlertDialog.Builder(this)
                .setTitle("调用 " + methodName)
                .setView(scroll)
                .setPositiveButton("调试调用", (d, w) -> {
                    // 子进程调用：断点生效
                    long[] args = parseArgsToLongs(paramEdits);
                    executeDebugCall(methodName, args);
                })
                .setNeutralButton("直接调用", (d, w) -> {
                    // 主进程调用：带完整 JNI 环境，无断点
                    String[] values = new String[paramEdits.size()];
                    for (int i = 0; i < paramEdits.size(); i++) {
                        values[i] = paramEdits.get(i).getText().toString();
                    }
                    executeMainProcessCall(capturedIndex, methodName, values);
                })
                .setNegativeButton("取消", null)
                .show();
    }

    /** 解析用户输入为 long 数组（用于 x2-x7），x0=0(JNIEnv*), x1=0(jclass) */
    private long[] parseArgsToLongs(java.util.List<EditText> paramEdits) {
        // x0 = JNIEnv* (0), x1 = jclass (0), x2..x7 = 用户参数
        int total = 2 + paramEdits.size();
        long[] args = new long[Math.min(total, 8)];
        args[0] = 0; // JNIEnv*
        args[1] = 0; // jclass
        for (int i = 0; i < paramEdits.size() && i + 2 < 8; i++) {
            String text = paramEdits.get(i).getText().toString().trim();
            try {
                if (text.startsWith("0x") || text.startsWith("0X")) {
                    args[i + 2] = Long.parseUnsignedLong(text.substring(2), 16);
                } else {
                    args[i + 2] = Long.parseLong(text);
                }
            } catch (NumberFormatException e) {
                args[i + 2] = 0;
            }
        }
        return args;
    }

    /** 子进程调用：spawn + 断点 + 设置参数寄存器 + PC → 等待断点命中 */
    private void executeDebugCall(String methodName, long[] args) {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null || soPath.isEmpty()) {
            Toast.makeText(this, "未加载 SO 文件", Toast.LENGTH_SHORT).show();
            return;
        }
        final long funcOffset = funcAddr - baseAddress;

        executor.execute(() -> {
            DebugSessionManager dbg = DebugSessionManager.getInstance();

            // 1) 自动 Spawn
            if (!dbg.isActive()) {
                boolean ok = dbg.spawnChild(soPath, funcOffset);
                if (!ok) {
                    handler.post(() -> Toast.makeText(this, "Spawn 失败", Toast.LENGTH_SHORT).show());
                    return;
                }
                handler.post(() -> syncBreakpointsToAsm());
            }

            // 2) 确保函数入口有断点
            if (!dbg.hasBreakpoint(funcOffset)) {
                dbg.toggleBreakpoint(funcOffset);
                handler.post(() -> {
                    updateDbgBreakpointList();
                    syncBreakpointsToAsm();
                });
            }

            // 3) 设置 x0-x7 + PC，继续执行
            boolean called = dbg.callFunctionWithArgs(funcOffset, args);
            if (!called) {
                handler.post(() -> Toast.makeText(this, "调用失败", Toast.LENGTH_SHORT).show());
                return;
            }

            // 4) 等待断点命中
            String event = dbg.waitEvent(10000);
            String regs = dbg.readRegisters();

            handler.post(() -> {
                updateDbgStatus();
                if (event != null && event.startsWith("STOP|")) {
                    Toast.makeText(this, "断点命中！可查看寄存器并单步", Toast.LENGTH_SHORT).show();
                } else if (event != null && event.equals("TIMEOUT")) {
                    Toast.makeText(this, "超时（函数可能已执行完毕或崩溃）", Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(this, "事件: " + event, Toast.LENGTH_SHORT).show();
                }
                if (regs != null && !regs.startsWith("ERR")) {
                    tvDbgRegisters.setText(formatRegisters(regs));
                }
            });
        });
    }

    /** 主进程调用：callCapturedNative，带 JNI 环境和完整参数 */
    private void executeMainProcessCall(int index, String methodName, String[] paramValues) {
        executor.execute(() -> {
            String result;
            try {
                result = NativeInvoker.callCapturedNative(index, paramValues);
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
                new android.app.AlertDialog.Builder(this)
                        .setTitle(title)
                        .setMessage(methodName + "\n\n" + msg)
                        .setPositiveButton("确定", null)
                        .show();
            });
        });
    }

    private java.util.List<String[]> parseJniSigParams(String sig) {
        java.util.List<String[]> params = new java.util.ArrayList<>();
        int i = sig.indexOf('(');
        if (i < 0) return params;
        i++;
        while (i < sig.length() && sig.charAt(i) != ')') {
            char c = sig.charAt(i);
            switch (c) {
                case 'Z': params.add(new String[]{"boolean", "true/false", "false"}); i++; break;
                case 'B': params.add(new String[]{"byte", "0-255", "0"}); i++; break;
                case 'S': params.add(new String[]{"short", "整数", "0"}); i++; break;
                case 'I': params.add(new String[]{"int", "整数", "0"}); i++; break;
                case 'J': params.add(new String[]{"long", "长整数", "0"}); i++; break;
                case 'F': params.add(new String[]{"float", "浮点数", "0.0"}); i++; break;
                case 'D': params.add(new String[]{"double", "双精度", "0.0"}); i++; break;
                case 'L': {
                    int end = sig.indexOf(';', i);
                    String cls = end > 0 ? sig.substring(i + 1, end).replace('/', '.') : "Object";
                    if (cls.equals("java.lang.String")) {
                        params.add(new String[]{"String", "字符串", ""});
                    } else {
                        params.add(new String[]{cls, "null 或值", "null"});
                    }
                    i = end > 0 ? end + 1 : i + 1;
                    break;
                }
                case '[': {
                    params.add(new String[]{"array", "暂不支持，传null", "null"});
                    i++;
                    if (i < sig.length() && sig.charAt(i) == 'L') {
                        int end = sig.indexOf(';', i);
                        i = end > 0 ? end + 1 : i + 1;
                    } else if (i < sig.length()) { i++; }
                    break;
                }
                default: params.add(new String[]{String.valueOf(c), "", "0"}); i++; break;
            }
        }
        return params;
    }

    private char parseJniRetType(String sig) {
        int i = sig.indexOf(')');
        if (i >= 0 && i + 1 < sig.length()) return sig.charAt(i + 1);
        return 'V';
    }

    private String jniTypeToName(char c) {
        switch (c) {
            case 'V': return "void"; case 'Z': return "boolean";
            case 'B': return "byte"; case 'S': return "short";
            case 'I': return "int"; case 'J': return "long";
            case 'F': return "float"; case 'D': return "double";
            case 'L': return "Object"; case '[': return "array";
            default: return String.valueOf(c);
        }
    }

    private void dbgContinue() {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        if (!dbg.isActive()) return;
        executor.execute(() -> {
            dbg.continueExec();
            // 同一线程等待下一个事件
            String event = dbg.waitEvent(10000);
            handler.post(() -> {
                updateDbgStatus();
                if (event != null && event.startsWith("STOP|")) {
                    Toast.makeText(this, "已停下: " + event, Toast.LENGTH_SHORT).show();
                } else if (event != null && event.equals("TIMEOUT")) {
                    Toast.makeText(this, "继续运行中（未命中断点）", Toast.LENGTH_SHORT).show();
                } else if (event != null) {
                    Toast.makeText(this, "事件: " + event, Toast.LENGTH_SHORT).show();
                }
            });
        });
    }

    private void dbgStep() {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        if (!dbg.isActive()) return;
        executor.execute(() -> {
            boolean ok = dbg.singleStep();
            // do_single_step 内部已有 waitpid，返回即表示单步完成
            String regs = ok ? dbg.readRegisters() : null;
            handler.post(() -> {
                updateDbgStatus();
                if (ok) {
                    Toast.makeText(this, "单步完成", Toast.LENGTH_SHORT).show();
                    if (regs != null && !regs.startsWith("ERR")) {
                        tvDbgRegisters.setText(formatRegisters(regs));
                    }
                } else {
                    Toast.makeText(this, "单步失败", Toast.LENGTH_SHORT).show();
                }
            });
        });
    }

    private void dbgDetach() {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        dbg.detach();
        tvDbgStatus.setText("已分离");
        tvDbgPC.setText("PC: --");
        tvDbgBreakpoints.setText("断点: 无");
        syncBreakpointsToAsm();
    }

    private void dbgSetBpByOffset() {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        if (!dbg.isActive()) {
            Toast.makeText(this, "请先启动调试", Toast.LENGTH_SHORT).show();
            return;
        }
        long offset = parseOffset(etDbgOffset.getText().toString());
        if (offset < 0) {
            Toast.makeText(this, "无效偏移", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            boolean set = dbg.toggleBreakpoint(offset);
            handler.post(() -> {
                Toast.makeText(this,
                        set ? String.format("断点已设置 @ 0x%X", offset)
                            : String.format("断点已移除 @ 0x%X", offset),
                        Toast.LENGTH_SHORT).show();
                updateDbgBreakpointList();
                syncBreakpointsToAsm();
            });
        });
    }

    private void updateDbgStatus() {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        tvDbgStatus.setText(dbg.getStatusText());

        // 更新 PC
        executor.execute(() -> {
            long pcOffset = dbg.getCurrentPcOffset();
            handler.post(() -> {
                if (pcOffset >= 0) {
                    tvDbgPC.setText(String.format("PC: 0x%X", pcOffset));
                    // 更新汇编视图的 PC 高亮
                    Fragment f = pagerAdapter.getFragment(0);
                    if (f instanceof AsmFragment) {
                        ((AsmFragment) f).setCurrentPcOffset(pcOffset);
                    }
                } else {
                    tvDbgPC.setText("PC: --");
                }
            });
        });

        updateDbgBreakpointList();
        refreshRegisters();
    }

    private void refreshRegisters() {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        if (!dbg.isActive()) {
            tvDbgRegisters.setText("(未连接)");
            return;
        }
        executor.execute(() -> {
            String raw = dbg.readRegisters();
            handler.post(() -> {
                if (raw == null || raw.startsWith("ERR")) {
                    tvDbgRegisters.setText(raw != null ? raw : "(读取失败)");
                    return;
                }
                // 格式: PC=0x...|SP=0x...|LR=0x...|X0=0x...|X1=0x...|...
                tvDbgRegisters.setText(formatRegisters(raw));
            });
        });
    }

    private String formatRegisters(String raw) {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        long base = dbg.getChildBase();
        // 获取函数列表用于匹配
        java.util.List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();

        String[] parts = raw.split("\\|");
        StringBuilder sb = new StringBuilder();
        for (String part : parts) {
            String[] kv = part.split("=", 2);
            if (kv.length != 2) continue;
            String name = kv[0];
            String val = kv[1];
            long regVal;
            try {
                regVal = Long.parseUnsignedLong(val.replace("0x", ""), 16);
            } catch (Exception e) {
                sb.append(String.format("%-4s %s\n", name, val));
                continue;
            }

            String annotation = annotateRegValue(dbg, base, regVal, funcs);
            if (annotation != null) {
                sb.append(String.format("%-4s %s  %s\n", name, val, annotation));
            } else if (regVal == 0) {
                sb.append(String.format("%-4s %s  (NULL)\n", name, val));
            } else {
                sb.append(String.format("%-4s %s\n", name, val));
            }
        }
        return sb.toString().trim();
    }

    private String annotateRegValue(DebugSessionManager dbg, long base, long val,
                                     java.util.List<NativeFunction> funcs) {
        if (val == 0) return null;
        StringBuilder anno = new StringBuilder();

        // 1) 是否在 SO 范围内 → 显示偏移 + 匹配函数名
        if (base > 0 && val >= base && val < base + 0x10000000L) {
            long off = val - base;
            anno.append(String.format("→ SO+0x%X", off));
            // 匹配函数
            if (funcs != null) {
                for (NativeFunction f : funcs) {
                    if (off >= f.getOffset() && off < f.getOffset() + f.getSize()) {
                        String fname = f.getDemangledName() != null ? f.getDemangledName() : f.getName();
                        long inFuncOff = off - f.getOffset();
                        if (inFuncOff == 0) {
                            anno.append(" [").append(fname).append("]");
                        } else {
                            anno.append(String.format(" [%s+0x%X]", fname, inFuncOff));
                        }
                        break;
                    }
                }
            }
            return anno.toString();
        }

        // 2) 尝试读内存，看是否是可读字符串
        if (dbg.isActive() && val > 0x10000L) {
            try {
                byte[] mem = dbg.readMemory(val, 32);
                if (mem != null && mem.length > 0) {
                    // 检查是否是可打印字符串
                    int strLen = 0;
                    for (int i = 0; i < mem.length; i++) {
                        if (mem[i] == 0) break;
                        if (mem[i] >= 0x20 && mem[i] < 0x7F) strLen++;
                        else { strLen = 0; break; }
                    }
                    if (strLen >= 3) {
                        String s = new String(mem, 0, strLen, java.nio.charset.StandardCharsets.UTF_8);
                        if (s.length() > 20) s = s.substring(0, 20) + "...";
                        return "→ \"" + s + "\"";
                    }
                }
            } catch (Exception e) { /* ignore */ }
        }

        return null;
    }

    private void updateDbgBreakpointList() {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        java.util.Set<Long> bps = dbg.getBreakpointOffsets();
        if (bps.isEmpty()) {
            tvDbgBreakpoints.setText("断点: 无");
        } else {
            StringBuilder sb = new StringBuilder("断点: ");
            for (long offset : bps) {
                long abs = dbg.getChildBase() + offset;
                sb.append(String.format("0x%X(→ 0x%X) ", offset, abs));
            }
            tvDbgBreakpoints.setText(sb.toString().trim());
        }
    }

    private void syncBreakpointsToAsm() {
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        Fragment f = pagerAdapter.getFragment(0);
        if (f instanceof AsmFragment) {
            ((AsmFragment) f).setBreakpointOffsets(dbg.getBreakpointOffsets());
        }
    }

    private void copyCurrentPageContent() {
        int pos = viewPager.getCurrentItem();
        Fragment fragment = pagerAdapter.getFragment(pos);
        String content = null;
        if (fragment instanceof AsmFragment) {
            content = ((AsmFragment) fragment).getAllCode();
        } else if (fragment instanceof PseudoCFragment) {
            content = ((PseudoCFragment) fragment).getAllCode();
        }
        if (content != null && !content.isEmpty()) {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("code", content));
            Toast.makeText(this, "已复制到剪贴板", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "当前页面没有内容可复制", Toast.LENGTH_SHORT).show();
        }
    }

    private void exportCurrentPage() {
        int pos = viewPager.getCurrentItem();
        Fragment fragment = pagerAdapter.getFragment(pos);
        String content = null;
        String label = "";
        String ext = "";
        if (fragment instanceof AsmFragment) {
            content = ((AsmFragment) fragment).getAllCode();
            label = "汇编";
            ext = ".asm";
        } else if (fragment instanceof PseudoCFragment) {
            content = ((PseudoCFragment) fragment).getAllCode();
            label = "伪C";
            ext = ".c";
        }
        if (content == null || content.isEmpty()) {
            Toast.makeText(this, "当前页面没有内容可导出", Toast.LENGTH_SHORT).show();
            return;
        }
        final String finalContent = content;
        final String finalLabel = label;
        final String finalExt = ext;

        executor.execute(() -> {
            try {
                File destDir = new File(android.os.Environment.getExternalStorageDirectory(), "SoSandbox");
                if (!destDir.exists()) destDir.mkdirs();

                String funcName = getIntent().getStringExtra(EXTRA_FUNC_NAME);
                long funcAddr = getIntent().getLongExtra(EXTRA_FUNC_ADDR, 0);
                String safeName = (funcName != null ? funcName : "func_" + Long.toHexString(funcAddr))
                        .replaceAll("[^a-zA-Z0-9_.-]", "_");
                if (safeName.length() > 80) safeName = safeName.substring(0, 80);
                String fileName = safeName + "_0x" + Long.toHexString(funcAddr) + finalExt;
                File destFile = new File(destDir, fileName);

                FileWriter writer = new FileWriter(destFile);
                writer.write(finalContent);
                writer.close();

                final String path = destFile.getAbsolutePath();
                runOnUiThread(() -> new AlertDialog.Builder(this)
                        .setTitle("导出" + finalLabel + "成功")
                        .setMessage(path)
                        .setPositiveButton("复制路径", (d, w) -> {
                            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                            cm.setPrimaryClip(ClipData.newPlainText("导出路径", path));
                            Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
                        })
                        .setNegativeButton("关闭", null)
                        .show());
            } catch (Exception e) {
                runOnUiThread(() -> Toast.makeText(this,
                        "导出失败: " + e.getMessage(), Toast.LENGTH_LONG).show());
            }
        });
    }

    private void saveModifiedSo(boolean finishAfterSave) {
        String soPath = DataHolder.getInstance().getSoPath();

        if (soPath == null || soPath.isEmpty()) {
            Toast.makeText(this, "SO文件路径未知", Toast.LENGTH_SHORT).show();
            return;
        }

        File srcFile = new File(soPath);
        if (!srcFile.exists() || srcFile.length() == 0) {
            Toast.makeText(this, "源 SO 文件不存在或为空: " + soPath, Toast.LENGTH_LONG).show();
            return;
        }

        String srcName = srcFile.getName();
        String newFileName = srcName.endsWith(".so")
                ? srcName.substring(0, srcName.length() - 3) + "_saved.so"
                : srcName + "_saved";
        Toast.makeText(this, "正在保存...", Toast.LENGTH_SHORT).show();

        executor.execute(() -> {
            try {
                // 保存到 sdcard/SoSandbox
                File destDir = new File(android.os.Environment.getExternalStorageDirectory(), "SoSandbox");
                if (!destDir.exists()) destDir.mkdirs();
                File destFile = new File(destDir, newFileName);

                // 直接复制已修改的 SO 文件（修改已在 patch 时写入私有副本）
                try (java.io.FileInputStream fis = new java.io.FileInputStream(srcFile);
                     java.io.FileOutputStream fos = new java.io.FileOutputStream(destFile)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = fis.read(buffer)) != -1) {
                        fos.write(buffer, 0, len);
                    }
                    fos.getFD().sync();
                }

                if (!destFile.exists()) {
                    throw new Exception("保存后文件不存在");
                }

                final File savedFile = destFile;
                handler.post(() -> {
                    DataHolder.getInstance().clearUnsavedChanges();
                    showSaveSuccessDialog(savedFile, finishAfterSave);
                });
            } catch (Exception e) {
                final String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                handler.post(() -> Toast.makeText(this,
                        "保存失败: " + msg, Toast.LENGTH_LONG).show());
            }
        });
    }

    /**
     * 收集所有 Fragment 的修改数据
     */
    private java.util.Map<Long, Byte> collectAllModifications() {
        java.util.Map<Long, Byte> mods = new java.util.HashMap<>();
        
        // 从 AsmFragment 获取汇编修改并转换为字节
        Fragment asmFragment = pagerAdapter.getFragment(0);
        if (asmFragment instanceof AsmFragment) {
            com.example.anative.core.DataHolder holder = com.example.anative.core.DataHolder.getInstance();
            java.util.Map<Long, String> asmMods = holder.getAllModifiedInstructions();
            android.util.Log.d("SaveSo", "AsmFragment modifications: " + asmMods.size());
            
            String soPath = holder.getSoPath();
            if (soPath != null && !asmMods.isEmpty()) {
                for (java.util.Map.Entry<Long, String> entry : asmMods.entrySet()) {
                    long offset = entry.getKey();
                    String assembly = entry.getValue();
                    try {
                        byte[] encoded = com.example.anative.core.NativeInvoker.assembleInstruction(assembly, offset);
                        if (encoded != null && encoded.length > 0) {
                            long fileOffset = com.example.anative.core.ElfParser.virtualAddrToFileOffset(soPath, offset);
                            for (int i = 0; i < encoded.length; i++) {
                                mods.put(fileOffset + i, encoded[i]);
                            }
                        }
                    } catch (Exception e) {
                        android.util.Log.e("SaveSo", "Failed to assemble: " + assembly, e);
                    }
                }
            }
        }
        
        // 从 HexFragment 获取修改
        Fragment hexFragment = pagerAdapter.getFragment(2);
        if (hexFragment instanceof HexFragment) {
            java.util.Map<Long, Byte> hexMods = ((HexFragment) hexFragment).getModifications();
            android.util.Log.d("SaveSo", "HexFragment modifications: " + hexMods.size());
            mods.putAll(hexMods);
        } else {
            android.util.Log.w("SaveSo", "HexFragment not found or not ready");
        }
        return mods;
    }

    private void showSaveSuccessDialog(File savedFile, boolean finishAfterDismiss) {
        String path = savedFile.getAbsolutePath();
        String msg = path + "\n大小: " + savedFile.length() + " 字节";
        new AlertDialog.Builder(this)
                .setTitle("保存成功")
                .setMessage(msg)
                .setPositiveButton("分享", (dialog, which) -> {
                    shareFile(savedFile);
                    if (finishAfterDismiss) finish();
                })
                .setNeutralButton("复制路径", (dialog, which) -> {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(ClipData.newPlainText("SO路径", path));
                    Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
                    if (finishAfterDismiss) finish();
                })
                .setNegativeButton("关闭", (dialog, which) -> {
                    if (finishAfterDismiss) finish();
                })
                .setCancelable(false)
                .show();
    }

    private void shareFile(File file) {
        try {
            Uri uri = androidx.core.content.FileProvider.getUriForFile(
                    this, getPackageName() + ".fileprovider", file);
            Intent share = new Intent(Intent.ACTION_SEND);
            share.setType("application/octet-stream");
            share.putExtra(Intent.EXTRA_STREAM, uri);
            share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(share, "分享 SO 文件"));
        } catch (Exception e) {
            // FileProvider 未配置时 fallback: 直接 file://
            try {
                Intent share = new Intent(Intent.ACTION_SEND);
                share.setType("application/octet-stream");
                share.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(file));
                startActivity(Intent.createChooser(share, "分享 SO 文件"));
            } catch (Exception e2) {
                Toast.makeText(this, "分享失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
