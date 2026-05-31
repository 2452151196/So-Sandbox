package com.example.anative.ui;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager2.widget.ViewPager2;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.LicenseManager;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.example.anative.core.PltEntry;
import com.example.anative.core.XRefScanner;
import com.example.anative.core.DebugSessionManager;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.HashSet;
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
    private boolean isStaticMode = false;
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

        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        if (funcs != null) {
            Set<String> names = new HashSet<>();
            java.util.Map<Long, String> offsetToName = new java.util.HashMap<>();
            for (NativeFunction f : funcs) {
                names.add(f.getDemangledName());
                // PLT表用文件偏移，函数偏移也要转文件偏移才能匹配
                long fileOffset = (baseAddress > 0 && f.getOffset() >= baseAddress)
                        ? (f.getOffset() - baseAddress) : f.getOffset();
                offsetToName.put(fileOffset, f.getDemangledName());
            }
            codeAdapter.setFuncNames(names);
            codeAdapter.setFuncOffsetMap(offsetToName);
        }
        // 传入 PLT 偏移集合：命中时优先按 PLT 处理，不做函数自动识别
        java.util.Set<Long> pltOffsets = new java.util.HashSet<>();
        if (pltList != null) {
            for (PltEntry e : pltList) {
                if (e != null) pltOffsets.add(e.offset);
            }
        }
        codeAdapter.setPltOffsets(pltOffsets);
        // 当前函数范围 (文件偏移)，用于识别 b #addr 形式的 tail call
        long curFuncStart = (baseAddress > 0 && funcAddr >= baseAddress)
                ? (funcAddr - baseAddress) : funcAddr;
        if (curFuncStart >= 0 && funcSize > 0) {
            codeAdapter.setCurrentFunctionRange(curFuncStart, curFuncStart + funcSize);
        }
        codeAdapter.setOnLineClickListener(this::onFuncNameClicked);
        codeAdapter.setOnElementClickListener(this::onElementClicked);
        codeAdapter.setOnLineLongClickListener(this::onLineLongClicked);

        // 如果调试会话已激活，同步断点状态
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        if (dbg.isActive()) {
            codeAdapter.setBreakpointOffsets(dbg.getBreakpointOffsets());
        }

        LinearLayoutManager layoutManager = new LinearLayoutManager(requireContext());
        rvCode.setLayoutManager(layoutManager);
        rvCode.setAdapter(codeAdapter);
        rvCode.setItemAnimator(null);
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
            long virtualAddr = (baseAddress > 0 && funcAddr >= baseAddress) ? (funcAddr - baseAddress) : funcAddr;
            String result = disassembleFromFile(virtualAddr, funcSize, stringTable, pltTable, funcTable);
            isStaticMode = true;

            if (result != null && result.startsWith("ERR") && baseAddress > 0) {
                isStaticMode = false;
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

    private void onLineLongClicked(long offset) {
        if (getContext() == null) return;
        DebugSessionManager dbg = DebugSessionManager.getInstance();
        if (!dbg.isActive()) {
            // 如果调试未激活，弹出提示：先启动调试
            Toast.makeText(requireContext(), "请先启动动态调试（菜单→动态调试→Spawn调试）", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            boolean set = dbg.toggleBreakpoint(offset);
            handler.post(() -> {
                if (set) {
                    Toast.makeText(requireContext(),
                            String.format("断点已设置 @ 0x%X", offset), Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(requireContext(),
                            String.format("断点已移除 @ 0x%X", offset), Toast.LENGTH_SHORT).show();
                }
                codeAdapter.setBreakpointOffsets(dbg.getBreakpointOffsets());
            });
        });
    }

    private void onElementClicked(CodeLineAdapter.ClickType clickType, String line, long offset,
                                  String mnemonic, String operands, String bytes,
                                  String elementText, int elementIndex) {
        if (getContext() == null) return;
        long normalizedOffset = normalizeOffset(offset);
        switch (clickType) {
            case INSTRUCTION:
                showEditInsnDialog(normalizedOffset, mnemonic, operands, bytes, line, clickType, elementText);
                break;
            case ADDRESS:
                showEditInsnDialog(normalizedOffset, mnemonic, operands, bytes, line, clickType, elementText);
                break;
            case REGISTER:
                showEditInsnDialog(normalizedOffset, mnemonic, operands, bytes, line, clickType, elementText);
                break;
            case IMMEDIATE:
                showEditInsnDialog(normalizedOffset, mnemonic, operands, bytes, line, clickType, elementText);
                break;
            case FUNCTION_CALL:
                showFuncCallOptions(normalizedOffset, mnemonic, operands, bytes, line,
                        elementText);
                break;
        }
    }

    /**
     * 函数跳转目标的 3 选项弹窗：查看交叉引用 / 修改指令 / 跳转到函数
     * @param srcOffset 源指令偏移（当前 bl/b 指令的位置）
     * @param funcName 目标函数名
     */
    private void showFuncCallOptions(long srcOffset, String mnemonic, String operands,
                                     String bytes, String line, String funcName) {
        if (getContext() == null || funcName == null) return;
        NativeFunction target = findFunctionByName(funcName);
        if (target == null) {
            // 找不到目标函数时退化为普通修改
            showEditInsnDialog(srcOffset, mnemonic, operands, bytes, line,
                    CodeLineAdapter.ClickType.INSTRUCTION, null);
            return;
        }

        new AlertDialog.Builder(requireContext())
                .setTitle(funcName)
                .setItems(new String[]{"跳转到函数", "查找交叉引用", "修改此指令"}, (dialog, which) -> {
                    switch (which) {
                        case 0:
                            navigateToFunction(target);
                            break;
                        case 1:
                            showXRefs(target);
                            break;
                        case 2:
                            showEditInsnDialog(srcOffset, mnemonic, operands, bytes, line,
                                    CodeLineAdapter.ClickType.INSTRUCTION, null);
                            break;
                    }
                })
                .show();
    }

    private NativeFunction findFunctionByName(String funcName) {
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        if (funcs == null) return null;
        for (NativeFunction f : funcs) {
            if (f.getDemangledName().equals(funcName) || f.getName().equals(funcName)) {
                return f;
            }
        }
        Matcher matcher = SYNTHETIC_FUNC_PATTERN.matcher(funcName);
        if (matcher.matches()) {
            try {
                long offset = Long.parseLong(matcher.group(1), 16);
                long estimatedSize = estimateSyntheticFunctionSize(offset);
                return new NativeFunction(funcName, offset, estimatedSize, "disasm_synthetic");
            } catch (NumberFormatException ignored) {}
        }
        return null;
    }

    private long normalizeOffset(long offset) {
        if (offset < 0) return offset;
        long funcStartOffset = (baseAddress > 0 && funcAddr >= baseAddress) ? (funcAddr - baseAddress) : funcAddr;
        if (funcStartOffset > 0 && funcSize > 0 && offset < funcSize) {
            return funcStartOffset + offset;
        }
        return offset;
    }

    private String normalizeHexInAssembly(String asm) {
        return asm;
    }

    private void showEditInsnDialog(long offset, String mnemonic, String operands, String bytes,
                                    String originalLine, CodeLineAdapter.ClickType clickType,
                                    String elementText) {
        LayoutInflater inflater = LayoutInflater.from(requireContext());
        View view = inflater.inflate(R.layout.dialog_edit_instruction, null, false);

        EditText etAssembly = view.findViewById(R.id.et_assembly);
        TextView tvOriginalBytes = view.findViewById(R.id.tv_original_bytes);
        TextView tvNewBytes = view.findViewById(R.id.tv_new_bytes);
        TextView tvOriginalLine = view.findViewById(R.id.tv_original_line);
        TextView tvClickType = view.findViewById(R.id.tv_click_type);
        TextView tvSelectedElement = view.findViewById(R.id.tv_selected_element);
        LinearLayout layoutQuickOps = view.findViewById(R.id.layout_quick_operands);

        // 显示原始信息
        if (originalLine != null && !originalLine.isEmpty()) {
            tvOriginalLine.setText(originalLine);
            tvOriginalLine.setVisibility(View.VISIBLE);
        }
        if (bytes != null && !bytes.isEmpty()) {
            tvOriginalBytes.setText(bytes);
        } else {
            tvOriginalBytes.setText("无");
        }

        // 显示点击类型
        String clickTypeStr = "";
        switch (clickType) {
            case ADDRESS: clickTypeStr = "点击位置: 地址"; break;
            case REGISTER: clickTypeStr = "点击位置: 寄存器 " + (elementText != null ? elementText : ""); break;
            case IMMEDIATE: clickTypeStr = "点击位置: 立即数 " + (elementText != null ? elementText : ""); break;
            case INSTRUCTION: clickTypeStr = "点击位置: 指令"; break;
        }
        tvClickType.setText(clickTypeStr);
        tvClickType.setVisibility(View.VISIBLE);

        // 显示选中的元素
        if (elementText != null) {
            tvSelectedElement.setText(elementText);
            tvSelectedElement.setVisibility(View.VISIBLE);
        }

        // 预填充汇编指令
        String currentAsm = (mnemonic != null && !mnemonic.isEmpty())
                ? (mnemonic + (operands != null && !operands.isEmpty() ? " " + operands : ""))
                : "";
        etAssembly.setText(currentAsm);
        tvNewBytes.setText("输入汇编后自动计算");

        // 初始化寄存器编辑框
        initRegisterFields(view, operands);

        // 使用文件虚拟偏移作为PC
        long pcAddr = offset;

        // 实时预览新机器码
        TextWatcherImpl watcher = new TextWatcherImpl(etAssembly, tvNewBytes, pcAddr);
        etAssembly.addTextChangedListener(watcher);

        String title = String.format("编辑指令 (偏移: 0x%X)", offset);
        final long finalOffset = offset;
        new AlertDialog.Builder(requireContext())
                .setTitle(title)
                .setView(view)
                .setPositiveButton("确定", (dialog, which) -> {
                    String newAsm = etAssembly.getText().toString().trim();
                    if (newAsm.isEmpty()) {
                        Toast.makeText(requireContext(), "指令不能为空", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    patchInstruction(finalOffset, newAsm);
                })
                .setNeutralButton("替换整行", (dialog, which) -> {
                    String newAsm = etAssembly.getText().toString().trim();
                    if (newAsm.isEmpty()) return;
                    patchInstruction(finalOffset, newAsm);
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void initRegisterFields(View dialogView, String operands) {
        if (operands == null || operands.isEmpty()) return;

        String[] parts = operands.split(",");
        EditText[] regFields = {
                dialogView.findViewById(R.id.et_reg_x0),
                dialogView.findViewById(R.id.et_reg_x1),
                dialogView.findViewById(R.id.et_reg_x2),
                dialogView.findViewById(R.id.et_reg_x3)
        };

        java.util.regex.Pattern regPat = java.util.regex.Pattern.compile("\\b(sp|lr|xzr|wzr|fp|x[0-9]+|w[0-9]+|v[0-9]+|s[0-9]+|d[0-9]+|q[0-9]+)\\b");
        java.util.regex.Matcher m = regPat.matcher(operands);
        int idx = 0;
        while (m.find() && idx < regFields.length) {
            regFields[idx].setText(m.group());
            idx++;
        }
    }

    private static class TextWatcherImpl implements android.text.TextWatcher {
        private final EditText etAssembly;
        private final TextView tvNewBytes;
        private final Handler handler = new Handler(Looper.getMainLooper());
        private final long virtualOffset;

        TextWatcherImpl(EditText et, TextView tv, long virtualOffset) {
            this.etAssembly = et;
            this.tvNewBytes = tv;
            this.virtualOffset = virtualOffset;
        }

        @Override
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count) {}

        @Override
        public void afterTextChanged(android.text.Editable s) {
            handler.removeCallbacksAndMessages(null);
            handler.postDelayed(() -> {
                String asm = s.toString().trim();
                if (asm.isEmpty()) {
                    tvNewBytes.setText("输入汇编后自动计算");
                    return;
                }
                new Thread(() -> {
                    try {
                        byte[] bytes = com.example.anative.core.NativeInvoker.assembleInstruction(asm, virtualOffset);
                        if (bytes != null && bytes.length > 0) {
                            StringBuilder sb = new StringBuilder();
                            for (byte b : bytes) {
                                sb.append(String.format("%02X ", b & 0xFF));
                            }
                            String finalBytes = sb.toString().trim();
                            handler.post(() -> tvNewBytes.setText(finalBytes));
                        } else {
                            String err = com.example.anative.core.NativeInvoker.getLastAssembleError();
                            final String msg = (err != null && !err.isEmpty()) ? err : "无法汇编";
                            handler.post(() -> tvNewBytes.setText(msg));
                        }
                    } catch (Exception e) {
                        handler.post(() -> tvNewBytes.setText("汇编失败: " + e.getMessage()));
                    }
                }).start();
            }, 500);
        }
    }

    private void updateDisplay() {
        if (codeAdapter != null) {
            // 重新加载汇编代码并显示
            loadAssembly();
        }
        // 通知其他 Fragment 刷新
        notifyRefresh();
    }

    private void notifyRefresh() {
        if (getActivity() instanceof FunctionDetailActivity) {
            FunctionDetailActivity activity = (FunctionDetailActivity) getActivity();
            ViewPager2 viewPager = activity.findViewById(R.id.viewPager);
            if (viewPager != null && viewPager.getAdapter() instanceof FunctionPagerAdapter) {
                ((FunctionPagerAdapter) viewPager.getAdapter()).refreshAllFragments();
            }
        }
    }

    public void refreshDisplay() {
        if (codeAdapter != null) {
            loadAssembly();
        }
    }

    public void setBreakpointOffsets(java.util.Set<Long> offsets) {
        if (codeAdapter != null) {
            codeAdapter.setBreakpointOffsets(offsets);
        }
    }

    public void setCurrentPcOffset(long offset) {
        if (codeAdapter != null) {
            codeAdapter.setCurrentPcOffset(offset);
        }
    }

    public String getAllCode() {
        if (codeAdapter != null) {
            return codeAdapter.getAllCode();
        }
        return null;
    }

    private void patchInstruction(long offset, String assembly) {
        String soPath = DataHolder.getInstance().getSoPath();

        if (soPath == null || soPath.isEmpty()) {
            Toast.makeText(requireContext(), "SO文件路径未知", Toast.LENGTH_SHORT).show();
            return;
        }

        ProgressDialog pd = new ProgressDialog(requireContext());
        pd.setMessage("正在写入当前文件...");
        pd.setCancelable(false);
        pd.show();

        final long virtualOffset = offset;
        final String newAsm = assembly;
        executor.execute(() -> {
            try {
                long fileOffset = ElfParser.virtualAddrToFileOffset(soPath, virtualOffset);
                byte[] encoded = NativeInvoker.assembleInstruction(newAsm, virtualOffset);
                if (encoded == null || encoded.length == 0) {
                    String err = NativeInvoker.getLastAssembleError();
                    throw new Exception(err != null && !err.isEmpty() ? err : "汇编失败");
                }

                try (RandomAccessFile raf = new RandomAccessFile(soPath, "rw")) {
                    raf.seek(fileOffset);
                    raf.write(encoded);
                }

                handler.post(() -> {
                    pd.dismiss();
                    Toast.makeText(requireContext(), "已写入当前文件", Toast.LENGTH_SHORT).show();
                    DataHolder.getInstance().markFileModified();
                    updateDisplay();
                });
            } catch (Exception e) {
                handler.post(() -> {
                    pd.dismiss();
                    Toast.makeText(requireContext(), "写入失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void showSaveSuccessDialog(File savedFile) {
        String path = savedFile.getAbsolutePath();
        new AlertDialog.Builder(requireContext())
                .setTitle("保存成功")
                .setMessage(path)
                .setPositiveButton("复制路径", (dialog, which) -> {
                    ClipboardManager cm = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(ClipData.newPlainText("SO路径", path));
                    Toast.makeText(requireContext(), "已复制", Toast.LENGTH_SHORT).show();
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
                            Toast.makeText(requireContext(), "无法打开目录", Toast.LENGTH_SHORT).show();
                        }
                    }
                })
                .setNegativeButton("关闭", null)
                .show();
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
                .setItems(new String[]{"跳转到函数", "查看交叉引用"}, (dialog, which) -> {
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

            boolean isSynthetic = "plt".equals(func.getSource())
                    || "discovered".equals(func.getSource())
                    || "text_scan".equals(func.getSource())
                    || "init_array".equals(func.getSource())
                    || "fini_array".equals(func.getSource());
            if (isSynthetic || callees.isEmpty()) {
                long size = func.getSize() > 0 ? func.getSize() : estimateSyntheticFunctionSize(func.getOffset());
                List<XRefScanner.CallRef> ranged = scanner.getCalleesInRange(
                        func.getOffset(), func.getOffset() + size);
                if (!ranged.isEmpty()) {
                    callees = ranged;
                }
            }

            final List<XRefScanner.CallRef> finalCallees = callees;
            handler.post(() -> {
                pd.dismiss();
                showXRefResultDialog(func, callers, finalCallees);
            });
        });
    }

    private XRefScanner ensureXRefScanner() {
        String soPath = DataHolder.getInstance().getSoPath();
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
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
        long baseAddress = DataHolder.getInstance().getBaseAddress();
        XRefDialog dialog = XRefDialog.newScannerInstance(func, callers, callees, baseAddress);
        dialog.show(getChildFragmentManager(), "xrefs");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
