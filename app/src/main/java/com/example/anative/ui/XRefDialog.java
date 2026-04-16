package com.example.anative.ui;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;

import com.example.anative.R;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.XRefAnalyzer;
import com.google.android.material.bottomsheet.BottomSheetDialog;

import java.util.ArrayList;
import java.util.List;

public class XRefDialog extends DialogFragment {

    private NativeFunction function;
    private List<XRefAnalyzer.XRef> callsFrom;
    private List<XRefAnalyzer.XRef> callsTo;
    private long baseAddress;

    public static XRefDialog newInstance(NativeFunction func,
                                          List<XRefAnalyzer.XRef> callsFrom,
                                          List<XRefAnalyzer.XRef> callsTo,
                                          long baseAddress) {
        XRefDialog dialog = new XRefDialog();
        dialog.function = func;
        dialog.callsFrom = callsFrom != null ? callsFrom : new ArrayList<>();
        dialog.callsTo = callsTo != null ? callsTo : new ArrayList<>();
        dialog.baseAddress = baseAddress;
        return dialog;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        BottomSheetDialog dialog = new BottomSheetDialog(requireContext(), R.style.Theme_Native);
        View view = LayoutInflater.from(getContext()).inflate(R.layout.dialog_xrefs, null);

        TextView tvTitle = view.findViewById(R.id.tv_title);
        TextView tvStats = view.findViewById(R.id.tv_stats);
        LinearLayout containerFrom = view.findViewById(R.id.container_calls_from);
        LinearLayout containerTo = view.findViewById(R.id.container_calls_to);

        tvTitle.setText(function.getDemangledName());
        tvStats.setText(String.format("调用 %d 个函数 | 被 %d 个函数调用",
                callsFrom.size(), callsTo.size()));

        // 此函数调用了谁
        if (callsFrom.isEmpty()) {
            addEmptyItem(containerFrom, "无直接调用");
        } else {
            for (XRefAnalyzer.XRef ref : callsFrom) {
                addXRefItem(containerFrom, ref, true);
            }
        }

        // 谁调用了此函数
        if (callsTo.isEmpty()) {
            addEmptyItem(containerTo, "无被调用记录");
        } else {
            for (XRefAnalyzer.XRef ref : callsTo) {
                addXRefItem(containerTo, ref, false);
            }
        }

        dialog.setContentView(view);
        return dialog;
    }

    private void addXRefItem(LinearLayout container, XRefAnalyzer.XRef ref, boolean isOutgoing) {
        View item = LayoutInflater.from(getContext()).inflate(R.layout.item_xref, container, false);

        TextView tvAddr = item.findViewById(R.id.tv_addr);
        TextView tvType = item.findViewById(R.id.tv_type);
        TextView tvTarget = item.findViewById(R.id.tv_target);

        long targetAddr = isOutgoing ? ref.calleeAddr : ref.callerAddr;
        tvAddr.setText(String.format("0x%X", targetAddr));
        tvType.setText(ref.isCall ? "BL" : "B");

        // 查找函数名 (简单显示偏移)
        tvTarget.setText(String.format("@ 0x%X", targetAddr));

        container.addView(item);
    }

    private void addEmptyItem(LinearLayout container, String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextColor(0xFF888888);
        tv.setPadding(16, 8, 16, 8);
        container.addView(tv);
    }
}
