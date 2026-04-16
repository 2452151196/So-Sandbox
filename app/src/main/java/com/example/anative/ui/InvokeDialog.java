package com.example.anative.ui;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.AdapterView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;

import com.example.anative.R;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;

import java.util.ArrayList;
import java.util.List;

public class InvokeDialog extends DialogFragment {

    private static final String[] TYPES = {"void", "int", "long", "float", "double", "string", "jnienv", "jobject", "javavm"};

    private NativeFunction function;
    private long baseAddress;

    private LinearLayout paramsContainer;
    private Spinner spinnerRetType;
    private TextView tvResultValue;
    private View cardResult;
    private final List<View> paramViews = new ArrayList<>();

    public static InvokeDialog newInstance(NativeFunction function, long baseAddress) {
        InvokeDialog dialog = new InvokeDialog();
        Bundle args = new Bundle();
        args.putSerializable("function", function);
        args.putLong("base_address", baseAddress);
        dialog.setArguments(args);
        return dialog;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setStyle(DialogFragment.STYLE_NO_TITLE, R.style.Theme_Native_Dialog);
        if (getArguments() != null) {
            function = (NativeFunction) getArguments().getSerializable("function");
            baseAddress = getArguments().getLong("base_address", 0);
        }
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_invoke, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        // 绑定视图
        TextView tvFuncName = view.findViewById(R.id.tv_dialog_func_name);
        TextView tvAddress = view.findViewById(R.id.tv_dialog_address);
        spinnerRetType = view.findViewById(R.id.spinner_ret_type);
        paramsContainer = view.findViewById(R.id.params_container);
        cardResult = view.findViewById(R.id.card_result);
        tvResultValue = view.findViewById(R.id.tv_result_value);
        TextView tvResultLabel = view.findViewById(R.id.tv_result_label);

        // 设置函数信息
        long absAddr = NativeInvoker.calcAbsoluteAddress(baseAddress, function.getOffset());
        tvFuncName.setText(function.getName());
        tvAddress.setText(String.format("偏移: 0x%s | 绝对地址: 0x%X", function.getOffsetHex(), absAddr));

        // 设置返回类型Spinner
        ArrayAdapter<String> typeAdapter = new ArrayAdapter<>(
                requireContext(), android.R.layout.simple_spinner_item, TYPES);
        typeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerRetType.setAdapter(typeAdapter);

        // 自动填充推断的签名
        prefillSignature();

        // 添加参数按钮
        view.findViewById(R.id.btn_add_param).setOnClickListener(v -> addParamRow());

        // 调用按钮
        view.findViewById(R.id.btn_invoke).setOnClickListener(v -> invokeFunction());
    }

    private void prefillSignature() {
        if (function == null) return;

        // 设置返回类型
        String retType = function.getReturnType();
        for (int i = 0; i < TYPES.length; i++) {
            if (TYPES[i].equals(retType)) {
                spinnerRetType.setSelection(i);
                break;
            }
        }

        // 填充已推断的参数
        for (NativeFunction.ParamInfo param : function.getParams()) {
            addParamRowWithData(param.type, param.name);
        }
    }

    private void addParamRowWithData(String type, String nameHint) {
        View paramView = LayoutInflater.from(requireContext())
                .inflate(R.layout.item_param, paramsContainer, false);

        int index = paramViews.size();
        TextView tvIndex = paramView.findViewById(R.id.tv_param_index);
        tvIndex.setText(String.valueOf(index));

        Spinner spinnerType = paramView.findViewById(R.id.spinner_param_type);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                requireContext(), android.R.layout.simple_spinner_item, TYPES);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerType.setAdapter(adapter);
        for (int i = 0; i < TYPES.length; i++) {
            if (TYPES[i].equals(type)) {
                spinnerType.setSelection(i);
                break;
            }
        }

        EditText etValue = paramView.findViewById(R.id.et_param_value);
        if (nameHint != null) {
            etValue.setHint(nameHint + " (" + type + ")");
        }

        // jnienv/jobject 自动注入，禁止编辑
        updateAutoInjectState(spinnerType, etValue);
        spinnerType.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                updateAutoInjectState(spinnerType, etValue);
            }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        });

        ImageView btnRemove = paramView.findViewById(R.id.btn_remove_param);
        btnRemove.setOnClickListener(v -> {
            paramsContainer.removeView(paramView);
            paramViews.remove(paramView);
            for (int i = 0; i < paramViews.size(); i++) {
                TextView tv = paramViews.get(i).findViewById(R.id.tv_param_index);
                tv.setText(String.valueOf(i));
            }
        });

        paramsContainer.addView(paramView);
        paramViews.add(paramView);
    }

    private void updateAutoInjectState(Spinner spinner, EditText etValue) {
        String selected = (String) spinner.getSelectedItem();
        boolean autoInject = "jnienv".equals(selected) || "jobject".equals(selected) || "javavm".equals(selected);
        etValue.setEnabled(!autoInject);
        if (autoInject) {
            etValue.setText("");
            if ("jnienv".equals(selected)) {
                etValue.setHint("自动注入 JNIEnv*");
            } else if ("jobject".equals(selected)) {
                etValue.setHint("自动注入 jobject (NULL)");
            } else if ("javavm".equals(selected)) {
                etValue.setHint("自动注入 JavaVM*");
            }
        }
    }

    @Override
    public void onStart() {
        super.onStart();
        Dialog dialog = getDialog();
        if (dialog != null && dialog.getWindow() != null) {
            Window window = dialog.getWindow();
            window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        }
    }

    private void addParamRow() {
        View paramView = LayoutInflater.from(requireContext())
                .inflate(R.layout.item_param, paramsContainer, false);

        int index = paramViews.size();
        TextView tvIndex = paramView.findViewById(R.id.tv_param_index);
        tvIndex.setText(String.valueOf(index));

        Spinner spinnerType = paramView.findViewById(R.id.spinner_param_type);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                requireContext(), android.R.layout.simple_spinner_item, TYPES);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerType.setAdapter(adapter);
        // 默认选择 "int"
        spinnerType.setSelection(1);

        ImageView btnRemove = paramView.findViewById(R.id.btn_remove_param);
        btnRemove.setOnClickListener(v -> {
            paramsContainer.removeView(paramView);
            paramViews.remove(paramView);
            // 重新编号
            for (int i = 0; i < paramViews.size(); i++) {
                TextView tv = paramViews.get(i).findViewById(R.id.tv_param_index);
                tv.setText(String.valueOf(i));
            }
        });

        paramsContainer.addView(paramView);
        paramViews.add(paramView);
    }

    private void invokeFunction() {
        String retType = (String) spinnerRetType.getSelectedItem();

        String[] paramTypes = new String[paramViews.size()];
        String[] paramValues = new String[paramViews.size()];

        for (int i = 0; i < paramViews.size(); i++) {
            View pv = paramViews.get(i);
            Spinner sp = pv.findViewById(R.id.spinner_param_type);
            EditText et = pv.findViewById(R.id.et_param_value);

            paramTypes[i] = (String) sp.getSelectedItem();
            paramValues[i] = et.getText().toString();
        }

        long absAddr = NativeInvoker.calcAbsoluteAddress(baseAddress, function.getOffset());

        // 在后台线程调用
        new Thread(() -> {
            String result;
            try {
                result = NativeInvoker.invokeFunction(absAddr, retType, paramTypes, paramValues);
            } catch (Throwable t) {
                result = "ERR:Java异常: " + t.getMessage();
            }

            final String finalResult = result;
            if (getActivity() != null) {
                getActivity().runOnUiThread(() -> showResult(finalResult));
            }
        }).start();
    }

    private void showResult(String result) {
        cardResult.setVisibility(View.VISIBLE);

        if (result != null && result.startsWith("OK:")) {
            tvResultValue.setTextColor(getResources().getColor(R.color.green_success));
            tvResultValue.setText(result.substring(3));
        } else if (result != null && result.startsWith("ERR:")) {
            tvResultValue.setTextColor(getResources().getColor(R.color.red_error));
            tvResultValue.setText(result.substring(4));
        } else {
            tvResultValue.setTextColor(getResources().getColor(R.color.text_primary));
            tvResultValue.setText(result != null ? result : "null");
        }
    }
}
