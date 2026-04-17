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

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
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
            showMoreActionsDialog();
            return true;
        }
        return false;
    }

    private void syncSortMenuState() {
    }

    private void showMoreActionsDialog() {
        String[] actions = new String[]{"排序方式", "使用教程"};
        new AlertDialog.Builder(this)
                .setTitle("更多")
                .setItems(actions, (dialog, which) -> {
                    if (which == 0) {
                        showSortDialog();
                    } else if (which == 1) {
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
                + "5. 在交叉引用弹窗中点击条目：可直接跳转到对应函数。";
        new AlertDialog.Builder(this)
                .setTitle("函数列表使用教程")
                .setMessage(tutorial)
                .setPositiveButton("知道了", null)
                .show();
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
