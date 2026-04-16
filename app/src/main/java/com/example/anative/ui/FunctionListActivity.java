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

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.XRefScanner;
import com.example.anative.databinding.ActivityFunctionListBinding;

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
            showSortDialog();
            return true;
        }
        return false;
    }

    private void syncSortMenuState() {
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

        new AlertDialog.Builder(this, R.style.Theme_Native_Dialog_Rounded)
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
                .show();
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
        Map<Long, NativeFunction> funcByOffset = new HashMap<>();
        List<NativeFunction> allFuncs = DataHolder.getInstance().getFunctions();
        if (allFuncs != null) {
            for (NativeFunction f : allFuncs) funcByOffset.put(f.getOffset(), f);
        }

        // 合并可跳转的函数
        java.util.LinkedHashMap<Long, String> navTargets = new java.util.LinkedHashMap<>();
        for (XRefScanner.CallRef ref : callers) {
            navTargets.put(ref.callerFuncOffset, "← " + ref.callerFuncName + String.format(" (0x%X)", ref.instrOffset));
        }
        for (XRefScanner.CallRef ref : callees) {
            navTargets.put(ref.callerFuncOffset, "→ " + ref.callerFuncName + String.format(" (0x%X)", ref.instrOffset));
        }

        String title = String.format("交叉引用: %s\n被%d个函数调用 | 调用%d个函数",
                func.getDemangledName(), callers.size(), callees.size());

        if (navTargets.isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("交叉引用: " + func.getDemangledName())
                    .setMessage("未找到交叉引用")
                    .setPositiveButton("确定", null)
                    .show();
        } else {
            String[] items = navTargets.values().toArray(new String[0]);
            Long[] offsets = navTargets.keySet().toArray(new Long[0]);

            new AlertDialog.Builder(this)
                    .setTitle(title)
                    .setItems(items, (dialog, which) -> {
                        NativeFunction target = funcByOffset.get(offsets[which]);
                        if (target != null) showFunctionOptions(target);
                    })
                    .setPositiveButton("关闭", null)
                    .show();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
