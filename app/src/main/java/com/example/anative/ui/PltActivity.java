package com.example.anative.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
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
import com.example.anative.core.PltEntry;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.textfield.TextInputEditText;

import java.util.ArrayList;
import java.util.List;

public class PltActivity extends AppCompatActivity {

    private RecyclerView recyclerView;
    private TextView tvCount;
    private TextView tvEmpty;
    private PltAdapter adapter;
    private List<PltEntry> pltList = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_plt);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        tvCount = findViewById(R.id.tv_count);
        tvEmpty = findViewById(R.id.tv_empty);
        recyclerView = findViewById(R.id.recycler_view);
        TextInputEditText etSearch = findViewById(R.id.et_search);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        // 从DataHolder获取PLT列表
        List<PltEntry> entries = DataHolder.getInstance().getPltEntries();
        if (entries != null) {
            pltList.addAll(entries);
        }

        adapter = new PltAdapter(pltList);
        recyclerView.setAdapter(adapter);

        updateCount();

        // 搜索功能
        etSearch.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                adapter.setSearchQuery(s.toString());
                adapter.applyFilters();
                updateCount();
            }
            @Override public void afterTextChanged(Editable s) {}
        });
    }

    private void updateCount() {
        int count = adapter.getItemCount();
        tvCount.setText(String.format("显示 %d 个PLT条目", count));
        recyclerView.setVisibility(count > 0 ? View.VISIBLE : View.GONE);
        tvEmpty.setVisibility(count > 0 ? View.GONE : View.VISIBLE);
    }

    static class PltAdapter extends RecyclerView.Adapter<PltAdapter.ViewHolder> {
        private final List<PltEntry> allEntries;
        private List<PltEntry> filtered;
        private String searchQuery = "";

        PltAdapter(List<PltEntry> entries) {
            this.allEntries = entries;
            this.filtered = new ArrayList<>(entries);
        }

        void setSearchQuery(String query) {
            this.searchQuery = query != null ? query : "";
        }

        void applyFilters() {
            filtered = new ArrayList<>();
            String lower = searchQuery.toLowerCase();
            for (PltEntry e : allEntries) {
                if (!lower.isEmpty() && !e.symbolName.toLowerCase().contains(lower)) continue;
                filtered.add(e);
            }
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_plt, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            PltEntry entry = filtered.get(position);
            holder.tvName.setText(entry.symbolName);
            holder.tvInfo.setText(String.format("偏移: 0x%X  |  大小: %d bytes",
                    entry.offset, entry.size));
            // 长按复制符号名
            holder.itemView.setOnLongClickListener(v -> {
                copyToClipboard(v.getContext(), entry.symbolName, "符号名已复制");
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

        static class ViewHolder extends RecyclerView.ViewHolder {
            TextView tvName, tvInfo;

            ViewHolder(View itemView) {
                super(itemView);
                tvName = itemView.findViewById(R.id.tv_name);
                tvInfo = itemView.findViewById(R.id.tv_info);
            }
        }
    }
}
