package com.example.anative.ui;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.LicenseManager;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.XRefScanner;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.textfield.TextInputEditText;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class StringsActivity extends AppCompatActivity {

    private StringAdapter adapter;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean filterInteresting = false;
    private MenuItem filterMenuItem;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_strings);

        RecyclerView rv = findViewById(R.id.rv_strings);
        TextView tvCount = findViewById(R.id.tv_count);
        TextView tvEmpty = findViewById(R.id.tv_empty);
        TextInputEditText etSearch = findViewById(R.id.et_search);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());
        toolbar.setOnMenuItemClickListener(item -> {
            if (item.getItemId() == R.id.action_filter_interesting) {
                filterInteresting = !filterInteresting;
                item.setChecked(filterInteresting);
                item.getIcon().setAlpha(filterInteresting ? 255 : 128);
                adapter.setFilterInteresting(filterInteresting);
                adapter.applyFilters();
                updateCount(tvCount, tvEmpty, rv);
                return true;
            }
            return false;
        });
        filterMenuItem = toolbar.getMenu().findItem(R.id.action_filter_interesting);
        if (filterMenuItem != null) filterMenuItem.getIcon().setAlpha(128);

        List<ElfParser.StringEntry> strings = DataHolder.getInstance().getStrings();
        adapter = new StringAdapter(strings != null ? strings : new ArrayList<>());
        adapter.setOnItemClickListener(this::onStringClicked);

        rv.setLayoutManager(new LinearLayoutManager(this));
        rv.setAdapter(adapter);

        updateCount(tvCount, tvEmpty, rv);

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                adapter.setSearchQuery(s.toString());
                adapter.applyFilters();
                updateCount(tvCount, tvEmpty, rv);
            }
            @Override public void afterTextChanged(Editable s) {}
        });
    }

    private void onStringClicked(ElfParser.StringEntry entry) {
        ProgressDialog pd = new ProgressDialog(this);
        pd.setMessage("正在扫描字符串引用...");
        pd.setCancelable(false);
        pd.show();

        executor.execute(() -> {
            Log.i("StringsActivity", "Starting XRef scan for string: " + entry.value + " @ 0x" + Long.toHexString(entry.virtualAddress));
            XRefScanner scanner = ensureXRefScanner();
            List<XRefScanner.StringRef> refs = scanner.getStringRefsAt(entry.virtualAddress);
            Log.i("StringsActivity", "Scan complete, found " + refs.size() + " refs for string @ 0x" + Long.toHexString(entry.virtualAddress));

            // 调试: 打印所有字符串引用的key, 看是否有地址偏差
            if (refs.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (Long key : scanner.getStringRefKeys()) {
                    sb.append(String.format("0x%X ", key));
                    if (sb.length() > 500) { sb.append("..."); break; }
                }
                Log.i("StringsActivity", "StringRefMap keys (" + scanner.getStringRefKeys().size() + "): " + sb);
                Log.i("StringsActivity", "Looking for: 0x" + Long.toHexString(entry.virtualAddress).toUpperCase());
            }

            handler.post(() -> {
                pd.dismiss();
                if (refs.isEmpty()) {
                    String debugInfo = "已扫描" + scanner.getScannedFuncCount() + "个函数\n"
                            + "找到" + scanner.getStringRefKeys().size() + "个字符串引用\n"
                            + "查找地址: 0x" + Long.toHexString(entry.virtualAddress).toUpperCase();
                    Toast.makeText(this, debugInfo, Toast.LENGTH_LONG).show();
                }
                showStringXRefDialog(entry, refs);
            });
        });
    }

    private XRefScanner ensureXRefScanner() {
        String soPath = DataHolder.getInstance().getSoPath();
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        List<ElfParser.StringEntry> strs = DataHolder.getInstance().getStrings();

        Log.i("StringsActivity", "ensureXRefScanner: soPath=" + (soPath != null ? "yes" : "no")
                + " funcs=" + (funcs != null ? funcs.size() : "null")
                + " strs=" + (strs != null ? strs.size() : "null"));

        // 加载函数列表（如果还没有加载）
        if (funcs == null && soPath != null) {
            try {
                String discoveryMode = getSharedPreferences("app_prefs", MODE_PRIVATE)
                        .getString(SettingsActivity.PREF_FUNCTION_DISCOVERY_MODE, "balanced");
                funcs = ElfParser.parseFunctions(soPath, discoveryMode);
                DataHolder.getInstance().setFunctions(funcs);
                Log.i("StringsActivity", "Parsed " + (funcs != null ? funcs.size() : 0) + " functions");
            } catch (Exception e) {
                Log.e("StringsActivity", "parseFunctions failed", e);
                funcs = new ArrayList<>();
            }
        }

        if (strs == null && soPath != null) {
            try {
                strs = ElfParser.parseStrings(soPath);
                DataHolder.getInstance().setStrings(strs);
                Log.i("StringsActivity", "Parsed " + (strs != null ? strs.size() : 0) + " strings");
            } catch (Exception e) {
                Log.e("StringsActivity", "parseStrings failed", e);
                strs = new ArrayList<>();
            }
        }

        XRefScanner scanner = DataHolder.getInstance().getXRefScanner();
        boolean needRescan = (scanner == null || !scanner.isScanned()
                || (!scanner.hasStringData() && strs != null && !strs.isEmpty())
                || scanner.getScannedFuncCount() == 0); // 如果扫描了但没找到任何函数,强制重新扫描

        if (needRescan) {
            Log.i("StringsActivity", "Creating new XRefScanner and scanning...");
            scanner = new XRefScanner();
            if (soPath != null && funcs != null && !funcs.isEmpty()) {
                scanner.scan(soPath, funcs, strs);
                Log.i("StringsActivity", "Scan complete, funcs found: " + scanner.getScannedFuncCount());
            } else {
                Log.w("StringsActivity", "Cannot scan: soPath=" + soPath + " funcs=" + (funcs != null ? funcs.size() : "null"));
            }
            DataHolder.getInstance().setXRefScanner(scanner);
        } else {
            Log.i("StringsActivity", "Reusing existing XRefScanner with " + scanner.getScannedFuncCount() + " funcs");
        }
        return scanner;
    }

    private void showStringXRefDialog(ElfParser.StringEntry entry, List<XRefScanner.StringRef> refs) {
        if (refs.isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("字符串引用")
                    .setMessage(String.format("\"%s\"\n@ 0x%X\n\n未找到引用此字符串的函数",
                            entry.value, entry.virtualAddress))
                    .setPositiveButton("确定", null)
                    .show();
            return;
        }

        // 构建函数地址映射
        List<NativeFunction> allFuncs = DataHolder.getInstance().getFunctions();
        Map<Long, NativeFunction> funcByOffset = new HashMap<>();
        if (allFuncs != null) {
            for (NativeFunction f : allFuncs) funcByOffset.put(f.getOffset(), f);
        }

        String[] items = new String[refs.size()];
        long[] offsets = new long[refs.size()];
        for (int i = 0; i < refs.size(); i++) {
            XRefScanner.StringRef ref = refs.get(i);
            items[i] = String.format("%s @ 0x%X", ref.funcName, ref.instrOffset);
            offsets[i] = ref.funcOffset;
        }

        String title = entry.value.length() > 30
                ? "\"" + entry.value.substring(0, 30) + "...\"" : "\"" + entry.value + "\"";

        new AlertDialog.Builder(this)
                .setTitle("引用此字符串的函数 (" + refs.size() + ")")
                .setItems(items, (dialog, which) -> {
                    NativeFunction func = funcByOffset.get(offsets[which]);
                    if (func != null) {
                        navigateToFunction(func);
                    }
                })
                .setPositiveButton("关闭", null)
                .show();
    }

    private void navigateToFunction(NativeFunction func) {
        long baseAddr = DataHolder.getInstance().getBaseAddress();
        long absAddr = baseAddr + func.getOffset();
        Intent intent = new Intent(this, FunctionDetailActivity.class);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_NAME, func.getName());
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_ADDR, absAddr);
        intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_SIZE, func.getSize());
        intent.putExtra(FunctionDetailActivity.EXTRA_DEMANGLED_NAME, func.getDemangledName());
        intent.putExtra(FunctionDetailActivity.EXTRA_SIGNATURE, func.getNativeSignature());
        startActivity(intent);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }

    private void updateCount(TextView tvCount, TextView tvEmpty, RecyclerView rv) {
        int count = adapter.getItemCount();
        tvCount.setText(String.format("显示 %d 个字符串", count));
        rv.setVisibility(count > 0 ? View.VISIBLE : View.GONE);
        tvEmpty.setVisibility(count > 0 ? View.GONE : View.VISIBLE);
    }

    // ========== Adapter ==========

    static class StringAdapter extends RecyclerView.Adapter<StringAdapter.VH> {
        private final List<ElfParser.StringEntry> allStrings;
        private List<ElfParser.StringEntry> filtered;
        private OnItemClickListener clickListener;
        private String searchQuery = "";
        private boolean filterInteresting = false;

        interface OnItemClickListener {
            void onItemClick(ElfParser.StringEntry entry);
        }

        StringAdapter(List<ElfParser.StringEntry> strings) {
            this.allStrings = strings;
            this.filtered = new ArrayList<>(strings);
        }

        void setOnItemClickListener(OnItemClickListener listener) {
            this.clickListener = listener;
        }

        void setSearchQuery(String query) {
            this.searchQuery = query != null ? query : "";
        }

        void setFilterInteresting(boolean enabled) {
            this.filterInteresting = enabled;
        }

        void applyFilters() {
            filtered = new ArrayList<>();
            String lower = searchQuery.toLowerCase();
            for (ElfParser.StringEntry e : allStrings) {
                if (filterInteresting && isNoisyString(e)) continue;
                if (!lower.isEmpty() && !e.value.toLowerCase().contains(lower)) continue;
                filtered.add(e);
            }
            notifyDataSetChanged();
        }

        private boolean isNoisyString(ElfParser.StringEntry e) {
            String v = e.value;
            String sec = e.section != null ? e.section : "";
            if (v.startsWith("_Z")) return true;
            if (sec.equals(".dynstr") || sec.equals(".strtab")) return true;
            return false;
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_string, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(@NonNull VH holder, int position) {
            ElfParser.StringEntry entry = filtered.get(position);
            holder.tvValue.setText("\"" + entry.value + "\"");
            holder.tvAddr.setText(String.format("0x%X", entry.virtualAddress));
            holder.tvSection.setText(entry.section);
            holder.itemView.setOnClickListener(v -> {
                if (clickListener != null) clickListener.onItemClick(entry);
            });
            // 长按复制字符串值
            holder.itemView.setOnLongClickListener(v -> {
                copyToClipboard(v.getContext(), entry.value, "字符串已复制");
                return true;
            });
        }

        private void copyToClipboard(Context ctx, String text, String toastMsg) {
            ClipboardManager cm = (ClipboardManager) ctx.getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("text", text));
                Toast.makeText(ctx, toastMsg, Toast.LENGTH_SHORT).show();
            }
        }

        @Override
        public int getItemCount() {
            return filtered.size();
        }

        static class VH extends RecyclerView.ViewHolder {
            TextView tvValue, tvAddr, tvSection;
            VH(View v) {
                super(v);
                tvValue = v.findViewById(R.id.tv_string_value);
                tvAddr = v.findViewById(R.id.tv_string_addr);
                tvSection = v.findViewById(R.id.tv_string_section);
            }
        }
    }
}
