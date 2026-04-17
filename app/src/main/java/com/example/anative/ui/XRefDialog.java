package com.example.anative.ui;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.XRefAnalyzer;
import com.example.anative.core.XRefScanner;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class XRefDialog extends DialogFragment {

    private NativeFunction function;
    private List<XRefAnalyzer.XRef> callsFrom;
    private List<XRefAnalyzer.XRef> callsTo;
    private List<XRefScanner.CallRef> scannerCallers;
    private List<XRefScanner.CallRef> scannerCallees;
    private long baseAddress;

    public static XRefDialog newInstance(NativeFunction func,
                                          List<XRefAnalyzer.XRef> callsFrom,
                                          List<XRefAnalyzer.XRef> callsTo,
                                          long baseAddress) {
        XRefDialog dialog = new XRefDialog();
        dialog.function = func;
        dialog.callsFrom = callsFrom != null ? callsFrom : new ArrayList<>();
        dialog.callsTo = callsTo != null ? callsTo : new ArrayList<>();
        dialog.scannerCallers = Collections.emptyList();
        dialog.scannerCallees = Collections.emptyList();
        dialog.baseAddress = baseAddress;
        return dialog;
    }

    public static XRefDialog newScannerInstance(NativeFunction func,
                                                List<XRefScanner.CallRef> callers,
                                                List<XRefScanner.CallRef> callees,
                                                long baseAddress) {
        XRefDialog dialog = new XRefDialog();
        dialog.function = func;
        dialog.callsFrom = Collections.emptyList();
        dialog.callsTo = Collections.emptyList();
        dialog.scannerCallers = callers != null ? callers : new ArrayList<>();
        dialog.scannerCallees = callees != null ? callees : new ArrayList<>();
        dialog.baseAddress = baseAddress;
        return dialog;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        AlertDialog.Builder builder = new AlertDialog.Builder(requireContext());
        View view = LayoutInflater.from(getContext()).inflate(R.layout.dialog_xrefs, null);

        TextView tvTitle = view.findViewById(R.id.tv_title);
        Button btnCalls = view.findViewById(R.id.btn_calls);
        Button btnCalled = view.findViewById(R.id.btn_called);
        Button btnClose = view.findViewById(R.id.btn_close);
        ListView listCalls = view.findViewById(R.id.list_calls);
        ListView listCalled = view.findViewById(R.id.list_called);
        TextView tvEmpty = view.findViewById(R.id.tv_empty);

        btnClose.setOnClickListener(v -> dismiss());

        boolean useScannerData = scannerCallers != null && scannerCallees != null
                && (!scannerCallers.isEmpty() || !scannerCallees.isEmpty()
                || (callsFrom != null && callsFrom.isEmpty() && callsTo != null && callsTo.isEmpty()));

        tvTitle.setText(function.getDemangledName());

        final int MAX_DISPLAY = 50;

        // 准备调用列表数据
        List<XRefItem> outgoingItems = new ArrayList<>();
        List<?> outgoingList = useScannerData ? scannerCallees : callsFrom;
        if (outgoingList != null) {
            int displayCount = Math.min(outgoingList.size(), MAX_DISPLAY);
            for (int i = 0; i < displayCount; i++) {
                if (useScannerData) {
                    XRefScanner.CallRef ref = (XRefScanner.CallRef) outgoingList.get(i);
                    outgoingItems.add(new XRefItem(ref.callerFuncName, ref.callerFuncOffset, ref.instrOffset));
                } else {
                    XRefAnalyzer.XRef ref = (XRefAnalyzer.XRef) outgoingList.get(i);
                    long targetAddr = ref.calleeAddr;
                    outgoingItems.add(new XRefItem("目标函数", targetAddr - baseAddress, 0));
                }
            }
        }

        // 准备被调用列表数据
        List<XRefItem> incomingItems = new ArrayList<>();
        List<?> incomingList = useScannerData ? scannerCallers : callsTo;
        if (incomingList != null) {
            int displayCount = Math.min(incomingList.size(), MAX_DISPLAY);
            for (int i = 0; i < displayCount; i++) {
                if (useScannerData) {
                    XRefScanner.CallRef ref = (XRefScanner.CallRef) incomingList.get(i);
                    incomingItems.add(new XRefItem(ref.callerFuncName, ref.callerFuncOffset, ref.instrOffset));
                } else {
                    XRefAnalyzer.XRef ref = (XRefAnalyzer.XRef) incomingList.get(i);
                    long callerAddr = ref.callerAddr;
                    incomingItems.add(new XRefItem("调用来源", callerAddr - baseAddress, 0));
                }
            }
        }

        // 设置调用列表适配器
        XRefAdapter adapterCalls = new XRefAdapter(requireContext(), outgoingItems);
        listCalls.setAdapter(adapterCalls);
        listCalls.setOnItemClickListener((parent, view1, position, id) -> {
            XRefItem item = outgoingItems.get(position);
            navigateToFunction(item.funcOffset);
            dismiss();
        });

        // 设置被调用列表适配器
        XRefAdapter adapterCalled = new XRefAdapter(requireContext(), incomingItems);
        listCalled.setAdapter(adapterCalled);
        listCalled.setOnItemClickListener((parent, view1, position, id) -> {
            XRefItem item = incomingItems.get(position);
            navigateToFunction(item.funcOffset);
            dismiss();
        });

        // 初始显示"调用"tab
        updateTabState(btnCalls, btnCalled, true);
        applyEmptyState(listCalls, listCalled, tvEmpty, outgoingItems, true);

        btnCalls.setOnClickListener(v -> {
            updateTabState(btnCalls, btnCalled, true);
            applyEmptyState(listCalls, listCalled, tvEmpty, outgoingItems, true);
        });

        btnCalled.setOnClickListener(v -> {
            updateTabState(btnCalls, btnCalled, false);
            applyEmptyState(listCalls, listCalled, tvEmpty, incomingItems, false);
        });

        builder.setView(view);
        return builder.create();
    }

    private void applyEmptyState(ListView listCalls, ListView listCalled, TextView tvEmpty,
                                 List<XRefItem> items, boolean isCalls) {
        boolean empty = items == null || items.isEmpty();
        if (isCalls) {
            listCalls.setVisibility(empty ? View.GONE : View.VISIBLE);
            listCalled.setVisibility(View.GONE);
        } else {
            listCalled.setVisibility(empty ? View.GONE : View.VISIBLE);
            listCalls.setVisibility(View.GONE);
        }
        tvEmpty.setVisibility(empty ? View.VISIBLE : View.GONE);
        tvEmpty.setText(isCalls ? "该函数未调用任何其他函数" : "没有函数调用此函数");
    }

    @Override
    public void onStart() {
        super.onStart();
        Dialog d = getDialog();
        if (d != null && d.getWindow() != null) {
            android.util.DisplayMetrics dm = getResources().getDisplayMetrics();
            // 固定宽高：宽92%屏幕，高固定450dp（用户可滑动查看内容）
            int w = (int) (dm.widthPixels * 0.92);
            int h = (int) (450 * dm.density);
            d.getWindow().setLayout(w, h);
        }
    }

    private void navigateToFunction(long funcOffset) {
        List<NativeFunction> allFuncs = DataHolder.getInstance().getFunctions();
        if (allFuncs != null) {
            for (NativeFunction f : allFuncs) {
                if (f.getOffset() == funcOffset) {
                    long absAddr = baseAddress + f.getOffset();
                    Intent intent = new Intent(getContext(), FunctionDetailActivity.class);
                    intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_NAME, f.getName());
                    intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_ADDR, absAddr);
                    intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_SIZE, f.getSize());
                    intent.putExtra(FunctionDetailActivity.EXTRA_DEMANGLED_NAME, f.getDemangledName());
                    intent.putExtra(FunctionDetailActivity.EXTRA_SIGNATURE, f.getNativeSignature());
                    startActivity(intent);
                    return;
                }
            }
        }
    }

    private void updateTabState(Button btnCalls, Button btnCalled, boolean showCalls) {
        // 检测夜间模式
        int nightMode = getResources().getConfiguration().uiMode & android.content.res.Configuration.UI_MODE_NIGHT_MASK;
        boolean isNight = nightMode == android.content.res.Configuration.UI_MODE_NIGHT_YES;

        // 夜间模式使用柔和的颜色
        int selectedBg = isNight ? 0xFF1565C0 : 0xFF1976D2;  // 深蓝/亮蓝
        int selectedText = 0xFFFFFFFF;  // 白色文字
        int normalBg = isNight ? 0xFF424242 : 0xFFE0E0E0;   // 深灰/浅灰
        int normalText = isNight ? 0xFFFFFFFF : 0xFF222222; // 白色/深灰

        btnCalls.setBackgroundColor(showCalls ? selectedBg : normalBg);
        btnCalls.setTextColor(showCalls ? selectedText : normalText);
        btnCalled.setBackgroundColor(showCalls ? normalBg : selectedBg);
        btnCalled.setTextColor(showCalls ? normalText : selectedText);
    }

    private static class XRefItem {
        String funcName;
        long funcOffset;
        long instrOffset;

        XRefItem(String funcName, long funcOffset, long instrOffset) {
            this.funcName = funcName;
            this.funcOffset = funcOffset;
            this.instrOffset = instrOffset;
        }
    }

    private static class XRefAdapter extends ArrayAdapter<XRefItem> {
        XRefAdapter(Context context, List<XRefItem> items) {
            super(context, 0, items);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View view = convertView;
            if (view == null) {
                view = LayoutInflater.from(getContext()).inflate(R.layout.item_xref_simple, parent, false);
            }
            TextView tvFuncName = view.findViewById(R.id.tv_func_name);
            TextView tvFuncOffset = view.findViewById(R.id.tv_func_offset);

            XRefItem item = getItem(position);
            if (item != null) {
                tvFuncName.setText(item.funcName);
                tvFuncOffset.setText(String.format("偏移 0x%X", item.funcOffset));
            }
            return view;
        }
    }

    private void addXRefItem(LinearLayout container, XRefAnalyzer.XRef ref, boolean isOutgoing) {
        View item = LayoutInflater.from(getContext()).inflate(R.layout.item_xref, container, false);

        TextView tvAddr = item.findViewById(R.id.tv_addr);
        TextView tvType = item.findViewById(R.id.tv_type);
        TextView tvTarget = item.findViewById(R.id.tv_target);

        long targetAddr = isOutgoing ? ref.calleeAddr : ref.callerAddr;
        tvAddr.setText(String.format("0x%X", targetAddr));
        tvType.setText(ref.isCall ? "BL" : "B");

        long relativeAddr = targetAddr - baseAddress;
        if (isOutgoing) {
            tvTarget.setText(String.format("目标函数偏移 0x%X", relativeAddr));
        } else {
            tvTarget.setText(String.format("调用来源偏移 0x%X", relativeAddr));
        }

        container.addView(item);
    }

    private void addScannerItem(LinearLayout container, XRefScanner.CallRef ref, boolean isOutgoing) {
        View item = LayoutInflater.from(getContext()).inflate(R.layout.item_xref, container, false);

        TextView tvAddr = item.findViewById(R.id.tv_addr);
        TextView tvType = item.findViewById(R.id.tv_type);
        TextView tvTarget = item.findViewById(R.id.tv_target);

        tvTarget.setText(ref.callerFuncName);
        tvAddr.setText(String.format("指令 0x%X", ref.instrOffset));
        tvType.setText(isOutgoing ? "→" : "←");

        container.addView(item);
    }

    private void addSimpleItem(LinearLayout container, String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextColor(0xFF000000);
        tv.setTextSize(14);
        tv.setPadding(0, 4, 0, 4);
        container.addView(tv);
    }

    private void addEmptyItem(LinearLayout container, String text) {
        TextView tv = new TextView(requireContext());
        tv.setText(text);
        tv.setTextColor(0xFF888888);
        tv.setTextSize(14);
        tv.setPadding(0, 4, 0, 4);
        container.addView(tv);
    }
}
