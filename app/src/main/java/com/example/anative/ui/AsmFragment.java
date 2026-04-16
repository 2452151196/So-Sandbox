package com.example.anative.ui;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.example.anative.core.PltEntry;
import com.example.anative.core.XRefScanner;

import java.io.RandomAccessFile;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AsmFragment extends Fragment {

    private static final Pattern SYNTHETIC_FUNC_PATTERN = Pattern.compile("sub_([0-9a-fA-F]+)");

    private static final String ARG_FUNC_ADDR = "func_addr";
    private static final String ARG_FUNC_SIZE = "func_size";

    private long funcAddr;
    private long funcSize;
    private long baseAddress;
    private List<ElfParser.StringEntry> stringsList;
    private List<PltEntry> pltList;

    private RecyclerView rvCode;
    private ProgressBar progressBar;
    private CodeLineAdapter codeAdapter;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    public static AsmFragment newInstance(long funcAddr, long funcSize) {
        AsmFragment fragment = new AsmFragment();
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
        stringsList = DataHolder.getInstance().getStrings();
        pltList = DataHolder.getInstance().getPltEntries();
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_code_recycler, container, false);
        rvCode = view.findViewById(R.id.rvCode);
        progressBar = view.findViewById(R.id.progressBar);

        codeAdapter = new CodeLineAdapter();
        codeAdapter.init(requireContext());

        // 构建函数名集合，用于可点击跳转
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        if (funcs != null) {
            Set<String> names = new HashSet<>();
            for (NativeFunction f : funcs) names.add(f.getDemangledName());
            codeAdapter.setFuncNames(names);
        }
        codeAdapter.setOnLineClickListener(this::onFuncNameClicked);

        LinearLayoutManager layoutManager = new LinearLayoutManager(requireContext());
        rvCode.setLayoutManager(layoutManager);
        rvCode.setAdapter(codeAdapter);
        rvCode.setItemAnimator(null); // 禁用动画，更流畅
        rvCode.setHasFixedSize(false);
        rvCode.setNestedScrollingEnabled(false);

        return view;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        loadAssembly();
    }

    private void loadAssembly() {
        progressBar.setVisibility(View.VISIBLE);

        executor.execute(() -> {
            String stringTable = buildStringTable(stringsList);
            String pltTable = buildPltTable(pltList);
            String funcTable = buildFuncTable();
            String result;

            if (baseAddress == 0) {
                result = disassembleFromFile(funcAddr, funcSize, stringTable, pltTable, funcTable);
            } else {
                result = NativeInvoker.disassembleFunctionEx(funcAddr, funcSize, stringTable, pltTable, baseAddress, funcTable);
            }

            final String code = result;
            handler.post(() -> {
                progressBar.setVisibility(View.GONE);
                codeAdapter.setCode(code);
            });
        });
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

    private void onFuncNameClicked(String funcName) {
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        if (funcs == null) return;
        for (NativeFunction f : funcs) {
            if (f.getDemangledName().equals(funcName)) {
                showFuncOptions(f);
                return;
            }
        }

        Matcher matcher = SYNTHETIC_FUNC_PATTERN.matcher(funcName);
        if (matcher.matches()) {
            try {
                long offset = Long.parseLong(matcher.group(1), 16);
                long estimatedSize = estimateSyntheticFunctionSize(offset);
                NativeFunction syntheticFunc = new NativeFunction(funcName, offset, estimatedSize, "disasm_synthetic");
                showFuncOptions(syntheticFunc);
            } catch (NumberFormatException ignored) {
            }
        }
    }

    private long estimateSyntheticFunctionSize(long offset) {
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        if (funcs != null && !funcs.isEmpty()) {
            long nextOffset = Long.MAX_VALUE;
            for (NativeFunction f : funcs) {
                long candidate = f.getOffset();
                if (candidate > offset && candidate < nextOffset) {
                    nextOffset = candidate;
                }
            }
            if (nextOffset != Long.MAX_VALUE) {
                long estimated = nextOffset - offset;
                if (estimated >= 4 && estimated <= 65536) {
                    return estimated;
                }
            }
        }
        return 256;
    }

    private void showFuncOptions(NativeFunction func) {
        if (getContext() == null) return;
        new AlertDialog.Builder(requireContext())
                .setTitle(func.getDemangledName())
                .setItems(new String[]{"跳转到函数", "查找交叉引用"}, (dialog, which) -> {
                    if (which == 0) {
                        navigateToFunction(func);
                    } else {
                        showXRefs(func);
                    }
                })
                .show();
    }

    private void navigateToFunction(NativeFunction func) {
        if (getContext() == null) return;
        long absAddr = baseAddress + func.getOffset();
        Intent intent = new Intent(getContext(), FunctionDetailActivity.class);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_NAME, func.getName());
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_ADDR, absAddr);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_SIZE, func.getSize());
        intent.putExtra(FunctionDetailActivity.EXTRA_DEMANGLED_NAME, func.getDemangledName());
        intent.putExtra(FunctionDetailActivity.EXTRA_SIGNATURE, func.getNativeSignature());
        startActivity(intent);
    }

    private void showXRefs(NativeFunction func) {
        if (getContext() == null) return;
        ProgressDialog pd = new ProgressDialog(requireContext());
        pd.setMessage("正在扫描交叉引用...");
        pd.setCancelable(false);
        pd.show();

        executor.execute(() -> {
            XRefScanner scanner = ensureXRefScanner();
            List<XRefScanner.CallRef> callers = scanner.getCallersOf(func.getOffset());
            List<XRefScanner.CallRef> callees = scanner.getCalleesOf(func.getOffset());

            handler.post(() -> {
                pd.dismiss();
                showXRefResultDialog(func, callers, callees);
            });
        });
    }

    private XRefScanner ensureXRefScanner() {
        String soPath = DataHolder.getInstance().getSoPath();
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        // 确保字符串已加载
        List<ElfParser.StringEntry> strs = DataHolder.getInstance().getStrings();
        if (strs == null && soPath != null) {
            try {
                strs = ElfParser.parseStrings(soPath);
                DataHolder.getInstance().setStrings(strs);
            } catch (Exception e) {
                strs = new java.util.ArrayList<>();
            }
        }
        XRefScanner scanner = DataHolder.getInstance().getXRefScanner();
        // 如果没扫描过，或之前扫描时没有字符串数据但现在有了，重新扫描
        if (scanner == null || !scanner.isScanned()
                || (!scanner.hasStringData() && strs != null && !strs.isEmpty())) {
            scanner = new XRefScanner();
            if (soPath != null && funcs != null) {
                scanner.scan(soPath, funcs, strs);
            }
            DataHolder.getInstance().setXRefScanner(scanner);
        }
        return scanner;
    }

    private void showXRefResultDialog(NativeFunction func,
                                      List<XRefScanner.CallRef> callers,
                                      List<XRefScanner.CallRef> callees) {
        if (getContext() == null) return;

        StringBuilder sb = new StringBuilder();

        sb.append("被以下函数调用 (").append(callers.size()).append("):\n");
        if (callers.isEmpty()) {
            sb.append("  (无)\n");
        } else {
            for (XRefScanner.CallRef ref : callers) {
                sb.append(String.format("  %s @ 0x%X\n", ref.callerFuncName, ref.instrOffset));
            }
        }

        sb.append("\n此函数调用 (").append(callees.size()).append("):\n");
        if (callees.isEmpty()) {
            sb.append("  (无)\n");
        } else {
            for (XRefScanner.CallRef ref : callees) {
                sb.append(String.format("  %s @ 0x%X\n", ref.callerFuncName, ref.instrOffset));
            }
        }

        // 构建可点击列表
        List<NativeFunction> allFuncs = DataHolder.getInstance().getFunctions();
        Map<Long, NativeFunction> funcByOffset = new HashMap<>();
        if (allFuncs != null) {
            for (NativeFunction f : allFuncs) funcByOffset.put(f.getOffset(), f);
        }

        // 合并去重可跳转的函数
        java.util.LinkedHashMap<Long, String> navTargets = new java.util.LinkedHashMap<>();
        for (XRefScanner.CallRef ref : callers) {
            navTargets.put(ref.callerFuncOffset, ref.callerFuncName);
        }
        for (XRefScanner.CallRef ref : callees) {
            navTargets.put(ref.callerFuncOffset, ref.callerFuncName);
        }

        if (navTargets.isEmpty()) {
            new AlertDialog.Builder(requireContext())
                    .setTitle("交叉引用: " + func.getDemangledName())
                    .setMessage(sb.toString())
                    .setPositiveButton("确定", null)
                    .show();
        } else {
            String[] items = new String[navTargets.size()];
            Long[] offsets = new Long[navTargets.size()];
            int idx = 0;
            for (Map.Entry<Long, String> e : navTargets.entrySet()) {
                boolean isCaller = false;
                for (XRefScanner.CallRef ref : callers) {
                    if (ref.callerFuncOffset == e.getKey()) { isCaller = true; break; }
                }
                String prefix = isCaller ? "← " : "→ ";
                items[idx] = prefix + e.getValue() + String.format(" (0x%X)", e.getKey());
                offsets[idx] = e.getKey();
                idx++;
            }

            new AlertDialog.Builder(requireContext())
                    .setTitle("交叉引用: " + func.getDemangledName())
                    .setItems(items, (dialog, which) -> {
                        NativeFunction target = funcByOffset.get(offsets[which]);
                        if (target != null) navigateToFunction(target);
                    })
                    .setPositiveButton("关闭", null)
                    .show();
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
