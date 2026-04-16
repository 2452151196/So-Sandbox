package com.example.anative.ui;

import android.app.Dialog;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;

import java.util.List;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.example.anative.core.XRefAnalyzer;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.button.MaterialButton;

public class FunctionOptionsDialog extends DialogFragment {

    private NativeFunction function;
    private long baseAddress;

    public static FunctionOptionsDialog newInstance(NativeFunction func, long baseAddress) {
        FunctionOptionsDialog dialog = new FunctionOptionsDialog();
        dialog.function = func;
        dialog.baseAddress = baseAddress;
        return dialog;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        BottomSheetDialog dialog = new BottomSheetDialog(requireContext(), R.style.Theme_Native);
        View view = LayoutInflater.from(getContext()).inflate(R.layout.dialog_function_options, null);

        TextView tvName = view.findViewById(R.id.tv_func_name);
        TextView tvInfo = view.findViewById(R.id.tv_func_info);
        MaterialButton btnInvoke = view.findViewById(R.id.btn_invoke);
        MaterialButton btnDisasm = view.findViewById(R.id.btn_disasm);
        MaterialButton btnDecompile = view.findViewById(R.id.btn_decompile);
        MaterialButton btnXrefs = view.findViewById(R.id.btn_xrefs);

        tvName.setText(function.getDemangledName());
        tvInfo.setText(function.getSignatureString() +
                String.format("\n偏移: 0x%X  |  大小: %d bytes  |  %s",
                function.getOffset(), function.getSize(), function.getSource()));

        long absAddr = baseAddress + function.getOffset();

        btnInvoke.setOnClickListener(v -> {
            dismiss();
            // 打开调用对话框
            if (getActivity() instanceof FunctionListActivity) {
                InvokeDialog invokeDialog = InvokeDialog.newInstance(function, baseAddress);
                invokeDialog.show(getParentFragmentManager(), "invoke");
            }
        });

        // 查看代码 - 进入新界面，带标签栏切换汇编/伪C/Hex/Text
        btnDisasm.setOnClickListener(v -> {
            dismiss();
            Intent intent = new Intent(getContext(), FunctionDetailActivity.class);
            intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_NAME, function.getName());
            intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_ADDR, absAddr);
            intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_SIZE, function.getSize());
            intent.putExtra(FunctionDetailActivity.EXTRA_DEMANGLED_NAME, function.getDemangledName());
            intent.putExtra(FunctionDetailActivity.EXTRA_SIGNATURE, function.getNativeSignature());
            startActivity(intent);
        });

        btnDecompile.setOnClickListener(v -> {
            dismiss();
            Intent intent = new Intent(getContext(), FunctionDetailActivity.class);
            intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_NAME, function.getName());
            intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_ADDR, absAddr);
            intent.putExtra(FunctionDetailActivity.EXTRA_FUNC_SIZE, function.getSize());
            intent.putExtra(FunctionDetailActivity.EXTRA_DEMANGLED_NAME, function.getDemangledName());
            intent.putExtra(FunctionDetailActivity.EXTRA_SIGNATURE, function.getNativeSignature());
            startActivity(intent);
        });

        // 交叉引用分析
        btnXrefs.setOnClickListener(v -> {
            new Thread(() -> {
                // 获取所有函数地址用于匹配
                long[] allAddrs = DataHolder.getInstance().getFunctions().stream()
                        .mapToLong(f -> baseAddress + f.getOffset())
                        .toArray();

                String result = NativeInvoker.analyzeXRefs(absAddr, function.getSize(), allAddrs);

                // 解析并存储
                XRefAnalyzer xrefs = DataHolder.getInstance().getXRefs();
                if (xrefs == null) {
                    xrefs = new XRefAnalyzer();
                    DataHolder.getInstance().setXRefs(xrefs);
                }
                xrefs.parseXRefString(result, baseAddress);

                // 获取此函数的交叉引用信息
                final List<XRefAnalyzer.XRef> callsFrom = xrefs.getCallsFrom(function.getOffset());
                final List<XRefAnalyzer.XRef> callsTo = xrefs.getCallsTo(function.getOffset());

                requireActivity().runOnUiThread(() -> {
                    dismiss();
                    // 打开XRef展示对话框
                    XRefDialog xrefDialog = XRefDialog.newInstance(function, callsFrom, callsTo, baseAddress);
                    xrefDialog.show(getParentFragmentManager(), "xrefs");
                });
            }).start();
        });

        dialog.setContentView(view);
        return dialog;
    }
}
