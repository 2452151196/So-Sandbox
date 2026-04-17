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
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.XRefScanner;
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
                XRefScanner scanner = ensureXRefScanner();
                final List<XRefScanner.CallRef> callers = scanner.getCallersOf(function.getOffset());
                final List<XRefScanner.CallRef> callees = scanner.getCalleesOf(function.getOffset());

                requireActivity().runOnUiThread(() -> {
                    dismiss();
                    XRefDialog xrefDialog = XRefDialog.newScannerInstance(function, callers, callees, baseAddress);
                    xrefDialog.show(getParentFragmentManager(), "xrefs");
                });
            }).start();
        });

        dialog.setContentView(view);
        return dialog;
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
}
