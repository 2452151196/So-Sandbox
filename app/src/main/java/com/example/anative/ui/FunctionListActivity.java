package com.example.anative.ui;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.CheckBox;
import android.widget.RadioButton;
import android.widget.Button;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.LicenseManager;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.XRefScanner;
import com.example.anative.databinding.ActivityFunctionListBinding;
import com.google.android.material.textfield.TextInputEditText;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FunctionListActivity extends AppCompatActivity {

    private ActivityFunctionListBinding binding;
    private FunctionAdapter adapter;
    private long baseAddress;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    @SuppressWarnings("unchecked")
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityFunctionListBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // 从DataHolder获取数据 (避免TransactionTooLargeException)
        List<NativeFunction> functions = DataHolder.getInstance().getFunctions();
        baseAddress = DataHolder.getInstance().getBaseAddress();

        // Toolbar返回
        binding.toolbar.setNavigationOnClickListener(v -> finish());

        // 设置RecyclerView
        adapter = new FunctionAdapter();
        adapter.setOnFunctionClickListener(this::showFunctionOptions);
        adapter.setOnFunctionLongClickListener(this::showXRefs);
        binding.rvFunctions.setLayoutManager(new LinearLayoutManager(this));
        binding.rvFunctions.setAdapter(adapter);
        binding.toolbar.setOnMenuItemClickListener(this::onToolbarMenuItemClick);
        syncSortMenuState();

        if (functions != null) {
            adapter.setFunctions(functions);
            updateCount();
        }

        // 搜索
        binding.etSearch.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                adapter.filter(s.toString());
                updateCount();
            }
            @Override public void afterTextChanged(Editable s) {}
        });
    }

    private void updateCount() {
        int count = adapter.getFilteredCount();
        binding.tvCount.setText(String.format("显示 %d 个函数", count));

        binding.rvFunctions.setVisibility(count > 0 ? View.VISIBLE : View.GONE);
        binding.tvEmpty.setVisibility(count > 0 ? View.GONE : View.VISIBLE);
    }

    private boolean onToolbarMenuItemClick(MenuItem item) {
        int itemId = item.getItemId();
        if (itemId == R.id.action_sort_dialog) {
            showMoreActionsDialog();
            return true;
        }
        return false;
    }

    private void syncSortMenuState() {
    }

    private void showMoreActionsDialog() {
        String[] actions = new String[]{"排序方式", "识别地址为函数", "使用教程"};
        new AlertDialog.Builder(this)
                .setTitle("更多")
                .setItems(actions, (dialog, which) -> {
                    if (which == 0) {
                        showSortDialog();
                    } else if (which == 1) {
                        showRecognizeFunctionDialog();
                    } else if (which == 2) {
                        showTutorialDialog();
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void showTutorialDialog() {
        String tutorial = ""
                + "1. 点击函数行：打开函数详情（汇编/伪C/文本等）。\n\n"
                + "2. 长按函数行：扫描并查看交叉引用（谁调用它 / 它调用谁）。\n\n"
                + "3. 顶部搜索框：按函数名实时过滤列表。\n\n"
                + "4. 右上角「更多」→ 排序方式：按地址/函数长度排序，并支持倒序。\n\n"
                + "5. 右上角「更多」→ 识别地址为函数：输入地址后可手动加入函数列表。\n\n"
                + "6. 在交叉引用弹窗中点击条目：可直接跳转到对应函数。";
        new AlertDialog.Builder(this)
                .setTitle("函数列表使用教程")
                .setMessage(tutorial)
                .setPositiveButton("知道了", null)
                .show();
    }

    private void showRecognizeFunctionDialog() {
        android.widget.LinearLayout dialogView = (android.widget.LinearLayout) LayoutInflater.from(this).inflate(R.layout.dialog_simple_input, null, false);
        TextInputEditText etInput = dialogView.findViewById(R.id.et_input);
        etInput.setHint("请输入函数地址，如 0x123456 或 123456");
        etInput.setMinLines(1);
        etInput.setMaxLines(1);
        etInput.setText("0x");
        etInput.setSelection(etInput.getText() != null ? etInput.getText().length() : 0);

        android.widget.CheckBox cbAutoSize = new android.widget.CheckBox(this);
        cbAutoSize.setText("自动估算函数大小（推荐）");
        cbAutoSize.setChecked(true);
        cbAutoSize.setTextColor(androidx.core.content.ContextCompat.getColor(this, R.color.text_primary));
        dialogView.addView(cbAutoSize);

        com.google.android.material.textfield.TextInputLayout tilSize = new com.google.android.material.textfield.TextInputLayout(this, null, com.google.android.material.R.style.Widget_MaterialComponents_TextInputLayout_OutlinedBox);
        tilSize.setHint("函数大小（十六进制字节数，如 0x200）");
        tilSize.setBoxBackgroundColorResource(R.color.bg_surface);
        tilSize.setVisibility(android.view.View.GONE);

        com.google.android.material.textfield.TextInputEditText etSize = new com.google.android.material.textfield.TextInputEditText(this);
        etSize.setText("0x100");
        etSize.setTextColor(androidx.core.content.ContextCompat.getColor(this, R.color.text_primary));
        etSize.setMinLines(1);
        etSize.setMaxLines(1);
        tilSize.addView(etSize, new android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT));
        dialogView.addView(tilSize);

        cbAutoSize.setOnCheckedChangeListener((buttonView, isChecked) -> {
            tilSize.setVisibility(isChecked ? android.view.View.GONE : android.view.View.VISIBLE);
        });

        new AlertDialog.Builder(this)
                .setTitle("识别地址为函数")
                .setMessage("支持输入函数偏移地址；如果输入运行时绝对地址，也会自动尝试减去当前基址。\n\n注意：已支持所有可执行段（不仅限于 .text）。")
                .setView(dialogView)
                .setPositiveButton("识别", (dialog, which) -> {
                    String input = etInput.getText() != null ? etInput.getText().toString().trim() : "";
                    String sizeStr = etSize.getText() != null ? etSize.getText().toString().trim() : "";
                    recognizeFunctionFromInput(input, cbAutoSize.isChecked(), sizeStr);
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void recognizeFunctionFromInput(String input, boolean autoSize, String sizeInput) {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null || soPath.trim().isEmpty()) {
            Toast.makeText(this, "当前没有已加载的 SO", Toast.LENGTH_SHORT).show();
            return;
        }

        Long parsedAddress = parseUserAddress(input);
        if (parsedAddress == null) {
            Toast.makeText(this, "地址格式无效，请输入十六进制地址", Toast.LENGTH_SHORT).show();
            return;
        }

        long manualSize = 0;
        if (!autoSize) {
            Long parsedSize = parseUserAddress(sizeInput);
            if (parsedSize == null || parsedSize <= 0) {
                Toast.makeText(this, "函数大小格式无效，请输入十六进制数值", Toast.LENGTH_SHORT).show();
                return;
            }
            manualSize = parsedSize;
        }

        long offset = normalizeToFunctionOffset(parsedAddress);
        List<NativeFunction> existing = DataHolder.getInstance().getFunctions();
        List<NativeFunction> currentFunctions = existing != null ? new ArrayList<>(existing) : new ArrayList<>();
        for (NativeFunction func : currentFunctions) {
            if (func != null && func.getOffset() == offset) {
                Toast.makeText(this, String.format("函数已存在: 0x%X", offset), Toast.LENGTH_SHORT).show();
                return;
            }
        }

        ProgressDialog pd = new ProgressDialog(this);
        pd.setMessage("正在识别函数...");
        pd.setCancelable(false);
        pd.show();

        final long finalManualSize = manualSize;
        executor.execute(() -> {
            try {
                NativeFunction discovered = ElfParser.recognizeFunctionAtAddress(soPath, offset, currentFunctions, finalManualSize);
                currentFunctions.add(discovered);
                currentFunctions.sort((a, b) -> Long.compare(a.getOffset(), b.getOffset()));
                DataHolder.getInstance().setFunctions(currentFunctions);
                DataHolder.getInstance().setXRefScanner(null);

                handler.post(() -> {
                    pd.dismiss();
                    adapter.setFunctions(currentFunctions);
                    adapter.filter(binding.etSearch.getText() != null ? binding.etSearch.getText().toString() : "");
                    updateCount();
                    Toast.makeText(this,
                            String.format("已添加函数: 0x%X, size=%d", discovered.getOffset(), discovered.getSize()),
                            Toast.LENGTH_LONG).show();
                    showFunctionOptions(discovered);
                });
            } catch (Exception e) {
                handler.post(() -> {
                    pd.dismiss();
                    Toast.makeText(this, "识别失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private Long parseUserAddress(String input) {
        if (input == null) return null;
        String value = input.trim().toLowerCase();
        if (value.isEmpty()) return null;
        if (value.startsWith("0x")) {
            value = value.substring(2);
        }
        if (value.isEmpty() || !value.matches("[0-9a-f]+")) {
            return null;
        }
        try {
            return Long.parseLong(value, 16);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private long normalizeToFunctionOffset(long inputAddress) {
        if (baseAddress > 0 && inputAddress >= baseAddress) {
            return inputAddress - baseAddress;
        }
        return inputAddress;
    }

    private void showSortDialog() {
        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_function_sort, null, false);
        RadioButton rbSortAddress = dialogView.findViewById(R.id.rb_sort_address);
        RadioButton rbSortSize = dialogView.findViewById(R.id.rb_sort_size);
        CheckBox cbReverseSort = dialogView.findViewById(R.id.cb_reverse_sort);

        if (adapter.getSortMode() == FunctionAdapter.SORT_BY_SIZE) {
            rbSortSize.setChecked(true);
        } else {
            rbSortAddress.setChecked(true);
        }
        cbReverseSort.setChecked(adapter.isReverseSort());

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("排序方式")
                .setView(dialogView)
                .setPositiveButton("确定", (d, which) -> {
                    int sortMode = rbSortSize.isChecked()
                            ? FunctionAdapter.SORT_BY_SIZE
                            : FunctionAdapter.SORT_BY_ADDRESS;
                    adapter.setSortMode(sortMode);
                    adapter.setReverseSort(cbReverseSort.isChecked());
                    updateCount();
                })
                .setNegativeButton("取消", null)
                .create();

        dialog.setOnShowListener(d -> {
            int buttonColor = ContextCompat.getColor(this, R.color.accent);
            Button positive = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            Button negative = dialog.getButton(AlertDialog.BUTTON_NEGATIVE);
            if (positive != null) positive.setTextColor(buttonColor);
            if (negative != null) negative.setTextColor(buttonColor);
        });
        dialog.show();
    }

    private void showFunctionOptions(NativeFunction function) {
        long absAddr = baseAddress + function.getOffset();
        Intent intent = new Intent(this, FunctionDetailActivity.class);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_NAME, function.getName());
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_ADDR, absAddr);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_SIZE, function.getSize());
        intent.putExtra(FunctionDetailActivity.EXTRA_DEMANGLED_NAME, function.getDemangledName());
        intent.putExtra(FunctionDetailActivity.EXTRA_SIGNATURE, function.getNativeSignature());
        startActivity(intent);
    }

    private void showXRefs(NativeFunction function) {
        ProgressDialog pd = new ProgressDialog(this);
        pd.setMessage("正在扫描交叉引用...");
        pd.setCancelable(false);
        pd.show();

        executor.execute(() -> {
            XRefScanner scanner = ensureXRefScanner();
            List<XRefScanner.CallRef> callers = scanner.getCallersOf(function.getOffset());
            List<XRefScanner.CallRef> callees = scanner.getCalleesOf(function.getOffset());

            handler.post(() -> {
                pd.dismiss();
                showXRefResultDialog(function, callers, callees);
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
        XRefDialog dialog = XRefDialog.newScannerInstance(func, callers, callees, baseAddress);
        dialog.show(getSupportFragmentManager(), "xrefs");
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
