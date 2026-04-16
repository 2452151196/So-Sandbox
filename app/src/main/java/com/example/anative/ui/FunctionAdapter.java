package com.example.anative.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.NativeFunction;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class FunctionAdapter extends RecyclerView.Adapter<FunctionAdapter.ViewHolder> {

    public static final int SORT_BY_ADDRESS = 0;
    public static final int SORT_BY_SIZE = 1;

    private List<NativeFunction> allFunctions = new ArrayList<>();
    private List<NativeFunction> filteredFunctions = new ArrayList<>();
    private OnFunctionClickListener listener;
    private OnFunctionLongClickListener longClickListener;
    private String currentQuery = "";
    private int sortMode = SORT_BY_ADDRESS;
    private boolean reverseSort = false;

    public interface OnFunctionClickListener {
        void onFunctionClick(NativeFunction function);
    }

    public interface OnFunctionLongClickListener {
        void onFunctionLongClick(NativeFunction function);
    }

    public void setOnFunctionClickListener(OnFunctionClickListener listener) {
        this.listener = listener;
    }

    public void setOnFunctionLongClickListener(OnFunctionLongClickListener listener) {
        this.longClickListener = listener;
    }

    public void setFunctions(List<NativeFunction> functions) {
        this.allFunctions = new ArrayList<>(functions);
        this.filteredFunctions = new ArrayList<>(functions);
        applyFilterAndSort();
    }

    public void filter(String query) {
        currentQuery = query == null ? "" : query;
        applyFilterAndSort();
    }

    public void setSortMode(int sortMode) {
        this.sortMode = sortMode;
        applyFilterAndSort();
    }

    public int getSortMode() {
        return sortMode;
    }

    public void setReverseSort(boolean reverseSort) {
        this.reverseSort = reverseSort;
        applyFilterAndSort();
    }

    public boolean isReverseSort() {
        return reverseSort;
    }

    private void applyFilterAndSort() {
        filteredFunctions.clear();
        if (currentQuery == null || currentQuery.trim().isEmpty()) {
            filteredFunctions.addAll(allFunctions);
        } else {
            String lowerQuery = currentQuery.toLowerCase().trim();
            String normalizedHexQuery = lowerQuery.startsWith("0x") ? lowerQuery.substring(2) : lowerQuery;
            // 尝试解析搜索查询为地址数值，用于范围匹配
            Long searchAddr = parseHexAddress(lowerQuery);
            for (NativeFunction func : allFunctions) {
                boolean nameMatch = func.getName().toLowerCase().contains(lowerQuery) ||
                    func.getDemangledName().toLowerCase().contains(lowerQuery);
                boolean startAddrMatch = func.getOffsetHex().toLowerCase().contains(normalizedHexQuery) ||
                    ("0x" + func.getOffsetHex().toLowerCase()).contains(lowerQuery);
                boolean rangeMatch = false;
                // 如果查询是有效地址，检查是否在函数范围内
                if (searchAddr != null) {
                    long funcStart = func.getOffset();
                    long funcSize = func.getSize();
                    long funcEnd = funcSize > 0 ? funcStart + funcSize : funcStart + 1;
                    if (searchAddr >= funcStart && searchAddr < funcEnd) {
                        rangeMatch = true;
                    }
                }
                if (nameMatch || startAddrMatch || rangeMatch) {
                    filteredFunctions.add(func);
                }
            }
        }

        Comparator<NativeFunction> comparator;
        if (sortMode == SORT_BY_SIZE) {
            comparator = Comparator.comparingLong(NativeFunction::getSize)
                    .thenComparingLong(NativeFunction::getOffset);
        } else {
            comparator = Comparator.comparingLong(NativeFunction::getOffset)
                    .thenComparingLong(NativeFunction::getSize);
        }

        filteredFunctions.sort(comparator);
        if (reverseSort) {
            Collections.reverse(filteredFunctions);
        }
        notifyDataSetChanged();
    }

    public int getFilteredCount() {
        return filteredFunctions.size();
    }

    /**
     * 解析十六进制地址字符串
     * @param query 查询字符串 (支持 "0x5", "5", "0x5a8dc" 等格式)
     * @return 解析后的地址数值，如果不是有效地址则返回 null
     */
    private Long parseHexAddress(String query) {
        if (query == null || query.isEmpty()) return null;
        try {
            String hexStr = query.startsWith("0x") ? query.substring(2) : query;
            // 确保是有效的十六进制数字
            if (hexStr.matches("[0-9a-f]+")) {
                return Long.parseLong(hexStr, 16);
            }
        } catch (NumberFormatException e) {
            // 不是有效数字，忽略
        }
        return null;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_function, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        NativeFunction func = filteredFunctions.get(position);
        holder.tvFuncName.setText(func.getDemangledName());
        holder.tvSignature.setText(func.getSignatureString());
        holder.tvOffset.setText(String.format("0x%s", func.getOffsetHex()));
        holder.tvSize.setText(String.format("%d bytes", func.getSize()));
        String tag = func.getSource();
        if (func.isJni()) tag += " | JNI";
        holder.tvSource.setText(tag);

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) {
                listener.onFunctionClick(func);
            }
        });
        holder.itemView.setOnLongClickListener(v -> {
            if (longClickListener != null) {
                longClickListener.onFunctionLongClick(func);
                return true;
            }
            return false;
        });
    }

    @Override
    public int getItemCount() {
        return filteredFunctions.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvFuncName, tvSignature, tvOffset, tvSize, tvSource;

        ViewHolder(@NonNull View itemView) {
            super(itemView);
            tvFuncName = itemView.findViewById(R.id.tv_func_name);
            tvSignature = itemView.findViewById(R.id.tv_signature);
            tvOffset = itemView.findViewById(R.id.tv_offset);
            tvSize = itemView.findViewById(R.id.tv_size);
            tvSource = itemView.findViewById(R.id.tv_source);
        }
    }
}
