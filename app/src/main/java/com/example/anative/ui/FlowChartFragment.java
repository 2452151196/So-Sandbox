package com.example.anative.ui;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ProgressBar;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import android.util.Log;
import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.example.anative.core.PltEntry;

import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Arrays;

public class FlowChartFragment extends Fragment {

    private static final String ARG_FUNC_ADDR = "func_addr";
    private static final String ARG_FUNC_SIZE = "func_size";

    private long funcAddr;
    private long funcSize;
    private long baseAddress;

    private WebView webView;
    private FlowChartView fallbackView;
    private ProgressBar progressBar;
    private boolean pageReady = false;
    private String pendingJson = null;
    private boolean webViewAvailable = false;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    // 跳转指令集合（本地硬编码，无需服务端）
    private final Set<String> BRANCH_INSNS = new HashSet<>(Arrays.asList(
            "b", "bl", "br", "blr", "ret",
            "cbz", "cbnz", "tbz", "tbnz",
            "b.eq", "b.ne", "b.cs", "b.hs",
            "b.cc", "b.lo", "b.mi", "b.pl",
            "b.vs", "b.vc", "b.hi", "b.ls",
            "b.ge", "b.lt", "b.gt", "b.le", "b.al"
    ));
    private final Set<String> COND_BRANCH_INSNS = new HashSet<>(Arrays.asList(
            "cbz", "cbnz", "tbz", "tbnz",
            "b.eq", "b.ne", "b.cs", "b.hs",
            "b.cc", "b.lo", "b.mi", "b.pl",
            "b.vs", "b.vc", "b.hi", "b.ls",
            "b.ge", "b.lt", "b.gt", "b.le", "b.al"
    ));

    public static FlowChartFragment newInstance(long funcAddr, long funcSize) {
        FlowChartFragment fragment = new FlowChartFragment();
        Bundle args = new Bundle();
        args.putLong(ARG_FUNC_ADDR, funcAddr);
        args.putLong(ARG_FUNC_SIZE, funcSize);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            funcAddr = getArguments().getLong(ARG_FUNC_ADDR);
            funcSize = getArguments().getLong(ARG_FUNC_SIZE);
        }
        baseAddress = DataHolder.getInstance().getBaseAddress();
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        FrameLayout root = new FrameLayout(requireContext());
        root.setBackgroundColor(androidx.core.content.ContextCompat.getColor(requireContext(), R.color.chart_bg));

        try {
            webView = new WebView(requireContext());
            WebSettings ws = webView.getSettings();
            ws.setJavaScriptEnabled(true);
            ws.setDomStorageEnabled(true);
            webView.setWebChromeClient(new WebChromeClient());
            webView.setWebViewClient(new WebViewClient() {
                @Override
                public void onPageFinished(WebView view, String url) {
                    pageReady = true;
                    if (pendingJson != null) {
                        callSetGraph(pendingJson);
                        pendingJson = null;
                    }
                }
            });
            webView.loadUrl("file:///android_asset/flowchart.html");
            webView.setOnTouchListener((v, event) -> {
                switch (event.getActionMasked()) {
                    case android.view.MotionEvent.ACTION_DOWN:
                    case android.view.MotionEvent.ACTION_POINTER_DOWN:
                        v.getParent().requestDisallowInterceptTouchEvent(true);
                        break;
                    case android.view.MotionEvent.ACTION_UP:
                    case android.view.MotionEvent.ACTION_CANCEL:
                        v.getParent().requestDisallowInterceptTouchEvent(false);
                        break;
                }
                return false;
            });
            root.addView(webView, new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
            webViewAvailable = true;
        } catch (Throwable e) {
            // WebView 初始化失败（比如模拟器或 hook 冲突），降级到 Canvas 渲染
            webViewAvailable = false;
            fallbackView = new FlowChartView(requireContext());
            root.addView(fallbackView, new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        }

        progressBar = new ProgressBar(requireContext());
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.gravity = android.view.Gravity.CENTER;
        progressBar.setVisibility(View.GONE);
        root.addView(progressBar, lp);

        return root;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        loadFlowChart();
    }

    private void loadFlowChart() {
        progressBar.setVisibility(View.VISIBLE);

        executor.execute(() -> {
            // 本地生成流程图（无需服务端）
            String asmCode = getDisassembly();
            if (asmCode == null || asmCode.isEmpty()) {
                handler.post(() -> {
                    if (!isAdded()) return;
                    progressBar.setVisibility(View.GONE);
                    android.widget.Toast.makeText(requireContext(),
                            "反汇编失败，无法生成流程图",
                            android.widget.Toast.LENGTH_SHORT).show();
                });
                return;
            }

            List<FlowChartView.BasicBlock> blocks = parseBlocks(asmCode);
            String json = blocksToJson(blocks);
            Log.d("FlowChart", "Local flowchart generated: " + blocks.size() + " blocks, json length=" + json.length());

            handler.post(() -> {
                if (!isAdded()) return;
                progressBar.setVisibility(View.GONE);
                if (blocks.isEmpty()) {
                    android.widget.Toast.makeText(requireContext(),
                            "流程图生成失败：无基本块",
                            android.widget.Toast.LENGTH_SHORT).show();
                    return;
                }
                if (webViewAvailable) {
                    if (pageReady) {
                        callSetGraph(json);
                    } else {
                        pendingJson = json;
                    }
                } else if (fallbackView != null) {
                    fallbackView.setBlocks(blocks);
                }
            });
        });
    }

    private String getDisassembly() {
        List<ElfParser.StringEntry> strs = DataHolder.getInstance().getStrings();
        List<PltEntry> plt = DataHolder.getInstance().getPltEntries();
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();

        String strTable = buildTable(strs);
        String pltTable = buildPltTable(plt);
        String funcTable = buildFuncTable(funcs);

        if (baseAddress == 0) {
            String soPath = DataHolder.getInstance().getSoPath();
            if (soPath == null) return "";
            try {
                long fileOffset = ElfParser.virtualAddrToFileOffset(soPath, funcAddr);
                RandomAccessFile raf = new RandomAccessFile(soPath, "r");
                long size = funcSize;
                if (size == 0) size = 256;
                if (size > 65536) size = 65536;
                if (fileOffset + size > raf.length()) size = raf.length() - fileOffset;
                if (size <= 0) { raf.close(); return ""; }
                byte[] bytes = new byte[(int) size];
                raf.seek(fileOffset);
                raf.readFully(bytes);
                raf.close();
                return NativeInvoker.disassembleBytes(bytes, funcAddr, size, strTable, pltTable, funcTable);
            } catch (Exception e) {
                return "";
            }
        } else {
            return NativeInvoker.disassembleFunctionEx(funcAddr, funcSize, strTable, pltTable, baseAddress, funcTable);
        }
    }

    private List<FlowChartView.BasicBlock> parseBlocks(String asmCode) {
        List<FlowChartView.BasicBlock> blocks = new ArrayList<>();
        if (asmCode == null || asmCode.isEmpty()) return blocks;

        String[] lines = asmCode.split("\n");

        // 第一遍: 收集所有跳转目标地址作为block起点
        Set<Long> blockStarts = new HashSet<>();
        List<long[]> instrAddrs = new ArrayList<>();
        List<String> instrLines = new ArrayList<>();

        for (String line : lines) {
            if (line.startsWith(";") || line.isEmpty()) continue;
            int colonIdx = line.indexOf(':');
            if (colonIdx < 0 || colonIdx > 10) continue;

            try {
                long addr = Long.parseLong(line.substring(0, colonIdx).trim(), 16);
                instrAddrs.add(new long[]{addr});
                instrLines.add(line);

                String mnemonic = extractMnemonic(line);
                if (mnemonic != null && BRANCH_INSNS.contains(mnemonic)) {
                    long target = extractBranchTarget(line);
                    if (target >= 0) {
                        blockStarts.add(target);
                    }
                    // 下一条指令也是一个block起点（对条件跳转）
                    if (COND_BRANCH_INSNS.contains(mnemonic)) {
                        blockStarts.add(addr + 4);
                    }
                }
            } catch (NumberFormatException ignored) {}
        }

        if (instrAddrs.isEmpty()) return blocks;
        blockStarts.add(instrAddrs.get(0)[0]); // 函数入口

        // 第二遍: 根据block起点切分
        FlowChartView.BasicBlock current = null;
        for (int i = 0; i < instrAddrs.size(); i++) {
            long addr = instrAddrs.get(i)[0];
            String line = instrLines.get(i);

            if (blockStarts.contains(addr) || current == null) {
                if (current != null) blocks.add(current);
                current = new FlowChartView.BasicBlock();
                current.startAddr = addr;
                current.label = String.format("Block %d: 0x%X", blocks.size(), addr);
            }
            current.endAddr = addr;

            // 精简显示: 去掉注释头
            String display = line.trim();
            if (display.length() > 50) display = display.substring(0, 50) + "...";
            current.instructions.add(display);
        }
        if (current != null) blocks.add(current);

        // 第三遍: 建立边
        for (int i = 0; i < blocks.size(); i++) {
            FlowChartView.BasicBlock block = blocks.get(i);
            if (block.instructions.isEmpty()) continue;

            String lastLine = block.instructions.get(block.instructions.size() - 1);
            String mnemonic = extractMnemonic(lastLine);

            if (mnemonic != null && BRANCH_INSNS.contains(mnemonic)) {
                long target = extractBranchTarget(lastLine);

                if (mnemonic.equals("ret") || mnemonic.equals("br") || mnemonic.equals("blr")) {
                    // 返回/间接跳转: 无后继(对于ret)或未知
                    if (mnemonic.equals("blr") && i + 1 < blocks.size()) {
                        block.successors.add(i + 1);
                    }
                } else if (mnemonic.equals("b")) {
                    // 无条件跳转
                    int targetIdx = findBlockByAddr(blocks, target);
                    if (targetIdx >= 0) block.successors.add(targetIdx);
                } else if (mnemonic.equals("bl")) {
                    // 函数调用: fallthrough
                    if (i + 1 < blocks.size()) block.successors.add(i + 1);
                } else if (COND_BRANCH_INSNS.contains(mnemonic)) {
                    // 条件跳转: true分支 + false分支
                    block.isConditional = true;
                    int targetIdx = findBlockByAddr(blocks, target);
                    if (targetIdx >= 0) block.successors.add(targetIdx);
                    if (i + 1 < blocks.size()) block.successors.add(i + 1);
                }
            } else {
                // 非跳转结尾: fallthrough
                if (i + 1 < blocks.size()) block.successors.add(i + 1);
            }
        }

        return blocks;
    }

    private int findBlockByAddr(List<FlowChartView.BasicBlock> blocks, long addr) {
        for (int i = 0; i < blocks.size(); i++) {
            if (blocks.get(i).startAddr == addr) return i;
        }
        return -1;
    }

    private String extractMnemonic(String line) {
        int colonIdx = line.indexOf(':');
        if (colonIdx < 0) return null;
        String afterColon = line.substring(colonIdx + 1).trim();
        int spIdx = afterColon.indexOf(' ');
        if (spIdx <= 0) return afterColon.trim().toLowerCase();
        return afterColon.substring(0, spIdx).trim().toLowerCase();
    }

    private long extractBranchTarget(String line) {
        int colonIdx = line.indexOf(':');
        if (colonIdx < 0) return -1;
        String afterColon = line.substring(colonIdx + 1).trim();
        int spIdx = afterColon.indexOf(' ');
        if (spIdx <= 0) return -1;
        String operands = afterColon.substring(spIdx).trim();

        // 取最后一个逗号后面的操作数
        int lastComma = operands.lastIndexOf(',');
        String target = (lastComma >= 0) ? operands.substring(lastComma + 1).trim() : operands.trim();
        // 去掉注释
        int semiIdx = target.indexOf(';');
        if (semiIdx >= 0) target = target.substring(0, semiIdx).trim();

        if (target.startsWith("#0x") || target.startsWith("#-0x")) {
            try {
                String hex = target.replace("#", "").replace("0x", "").replace("-0x", "");
                return Long.parseLong(hex, 16);
            } catch (NumberFormatException e) {
                return -1;
            }
        } else if (target.startsWith("#")) {
            try {
                String numStr = target.substring(1);
                if (numStr.startsWith("0x") || numStr.startsWith("0X")) {
                    return Long.parseLong(numStr.substring(2), 16);
                } else {
                    return Long.parseLong(numStr, 16);
                }
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }

    private String buildTable(List<ElfParser.StringEntry> strings) {
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

    private String buildFuncTable(List<NativeFunction> funcs) {
        if (funcs == null || funcs.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (NativeFunction f : funcs) {
            if (sb.length() > 0) sb.append("|");
            sb.append(String.format("%X", f.getOffset())).append("|").append(f.getDemangledName());
        }
        return sb.toString();
    }

    private void callSetGraph(String json) {
        if (webView == null || !isAdded()) return;
        boolean isDark = (requireContext().getResources().getConfiguration().uiMode
                & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                == android.content.res.Configuration.UI_MODE_NIGHT_YES;
        // JSON字符串需要用单引号包裹，避免JavaScript语法错误
        String escapedJson = json.replace("\\", "\\\\").replace("'", "\\'");
        webView.evaluateJavascript(
                "window.setDarkMode(" + isDark + ");window.setGraph(JSON.parse('" + escapedJson + "'))", null);
    }

    private String blocksToJson(List<FlowChartView.BasicBlock> blocks) {
        StringBuilder sb = new StringBuilder("{\"blocks\":[");
        for (int i = 0; i < blocks.size(); i++) {
            FlowChartView.BasicBlock b = blocks.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"label\":\"").append(jsonEsc(b.label)).append("\",");
            sb.append("\"isConditional\":").append(b.isConditional).append(',');
            sb.append("\"successors\":[");
            for (int j = 0; j < b.successors.size(); j++) {
                if (j > 0) sb.append(',');
                sb.append(b.successors.get(j));
            }
            sb.append("],\"instructions\":[");
            for (int j = 0; j < b.instructions.size(); j++) {
                if (j > 0) sb.append(',');
                sb.append('"').append(jsonEsc(b.instructions.get(j))).append('"');
            }
            sb.append("]}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
        if (webView != null) { webView.destroy(); webView = null; }
    }
}
