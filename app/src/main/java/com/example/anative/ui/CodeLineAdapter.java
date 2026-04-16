package com.example.anative.ui;

import android.content.Context;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ClickableSpan;
import android.text.style.ForegroundColorSpan;
import android.text.method.LinkMovementMethod;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CodeLineAdapter extends RecyclerView.Adapter<CodeLineAdapter.LineVH> {

    public interface OnLineClickListener {
        void onFuncClick(String funcName);
    }

    private final List<String> lines = new ArrayList<>();
    private int cAddr, cInsn, cBranch, cReg, cImm, cComment, cStr, cPlt;
    private Set<String> branchInsns;
    private Set<String> funcNames;
    private OnLineClickListener listener;

    // 预编译正则
    private static final Pattern ADDR_PAT = Pattern.compile("^[0-9a-fA-F]{8}:");
    private static final Pattern INSN_PAT = Pattern.compile("(?<=:\\s\\s)(\\S+)");
    private static final Pattern REG_PAT = Pattern.compile("\\b(sp|lr|xzr|wzr|fp|x[0-9]+|w[0-9]+|v[0-9]+|s[0-9]+|d[0-9]+|q[0-9]+)\\b");
    private static final Pattern IMM_PAT = Pattern.compile("#-?0x[0-9a-fA-F]+|#-?\\d+");
    private static final Pattern STR_PAT = Pattern.compile("; \".*\"");
    private static final Pattern PLT_PAT = Pattern.compile("; \\S+@PLT");
    private static final Pattern CMT_PAT = Pattern.compile(";(?! \")(?! \\S+@PLT).*$");
    private static final Pattern SYNTHETIC_FUNC_PAT = Pattern.compile("sub_[0-9a-fA-F]+");

    public void init(Context ctx) {
        cAddr = ctx.getResources().getColor(R.color.code_addr, ctx.getTheme());
        cInsn = ctx.getResources().getColor(R.color.code_insn, ctx.getTheme());
        cBranch = ctx.getResources().getColor(R.color.code_branch, ctx.getTheme());
        cReg = ctx.getResources().getColor(R.color.code_reg, ctx.getTheme());
        cImm = ctx.getResources().getColor(R.color.code_imm, ctx.getTheme());
        cComment = ctx.getResources().getColor(R.color.code_comment, ctx.getTheme());
        cStr = ctx.getResources().getColor(R.color.code_string, ctx.getTheme());
        cPlt = ctx.getResources().getColor(R.color.code_plt, ctx.getTheme());

        branchInsns = new java.util.HashSet<>(java.util.Arrays.asList(
                "b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz",
                "b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo", "b.mi", "b.pl",
                "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al"));
    }

    public void setFuncNames(Set<String> names) {
        this.funcNames = names;
    }

    public void setOnLineClickListener(OnLineClickListener l) {
        this.listener = l;
    }

    public void setCode(String code) {
        lines.clear();
        if (code != null && !code.isEmpty()) {
            String[] split = code.split("\n");
            for (String s : split) lines.add(s);
        }
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public LineVH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_code_line, parent, false);
        return new LineVH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull LineVH holder, int position) {
        String line = lines.get(position);
        holder.bind(line);
    }

    @Override
    public int getItemCount() {
        return lines.size();
    }

    class LineVH extends RecyclerView.ViewHolder {
        final TextView tv;

        LineVH(View v) {
            super(v);
            tv = v.findViewById(R.id.tvLine);
        }

        void bind(String line) {
            if (line.startsWith(";") || line.isEmpty()) {
                // 注释行或空行，简单着色
                SpannableString ss = new SpannableString(line);
                ss.setSpan(new ForegroundColorSpan(cComment), 0, line.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                tv.setText(ss);
                tv.setMovementMethod(null);
                return;
            }

            SpannableString ss = new SpannableString(line);
            boolean hasClickable = false;

            // 地址
            Matcher m = ADDR_PAT.matcher(line);
            if (m.find()) {
                ss.setSpan(new ForegroundColorSpan(cAddr), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // 指令名
            m = INSN_PAT.matcher(line);
            if (m.find()) {
                String insn = m.group(1).toLowerCase();
                boolean isBranch = branchInsns != null && branchInsns.contains(insn);
                ss.setSpan(new ForegroundColorSpan(isBranch ? cBranch : cInsn),
                        m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // 寄存器
            m = REG_PAT.matcher(line);
            while (m.find()) {
                ss.setSpan(new ForegroundColorSpan(cReg), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // 立即数
            m = IMM_PAT.matcher(line);
            while (m.find()) {
                ss.setSpan(new ForegroundColorSpan(cImm), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // 字符串注释
            m = STR_PAT.matcher(line);
            while (m.find()) {
                ss.setSpan(new ForegroundColorSpan(cStr), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // PLT注释
            m = PLT_PAT.matcher(line);
            while (m.find()) {
                ss.setSpan(new ForegroundColorSpan(cPlt), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // 其他注释
            m = CMT_PAT.matcher(line);
            while (m.find()) {
                ss.setSpan(new ForegroundColorSpan(cComment), m.start(), m.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // 函数名可点击
            if (funcNames != null && listener != null) {
                int colonIdx = line.indexOf(':');
                if (colonIdx >= 0 && colonIdx < 10) {
                    String afterColon = line.substring(colonIdx + 1).trim();
                    int spIdx = afterColon.indexOf(' ');
                    if (spIdx > 0) {
                        String mnemonic = afterColon.substring(0, spIdx).toLowerCase().trim();
                        if (mnemonic.equals("b") || mnemonic.equals("bl") || mnemonic.startsWith("b.")
                                || mnemonic.equals("cbz") || mnemonic.equals("cbnz")
                                || mnemonic.equals("tbz") || mnemonic.equals("tbnz")) {
                            String operands = afterColon.substring(spIdx).trim();
                            int lastComma = operands.lastIndexOf(',');
                            String target = (lastComma >= 0) ? operands.substring(lastComma + 1).trim() : operands.trim();
                            int semiIdx = target.indexOf(';');
                            if (semiIdx >= 0) target = target.substring(0, semiIdx).trim();

                            boolean isKnownFunction = funcNames != null && funcNames.contains(target);
                            boolean isSyntheticFunction = SYNTHETIC_FUNC_PAT.matcher(target).matches();
                            if (!target.startsWith("#") && !target.isEmpty() && (isKnownFunction || isSyntheticFunction)) {
                                int nameIdx = line.lastIndexOf(target);
                                if (nameIdx >= 0) {
                                    final String funcName = target;
                                    ss.setSpan(new ClickableSpan() {
                                        @Override
                                        public void onClick(@NonNull View widget) {
                                            listener.onFuncClick(funcName);
                                        }
                                    }, nameIdx, nameIdx + target.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                                    ss.setSpan(new ForegroundColorSpan(cPlt),
                                            nameIdx, nameIdx + target.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                                    hasClickable = true;
                                }
                            }
                        }
                    }
                }
            }

            tv.setText(ss);
            tv.setMovementMethod(hasClickable ? LinkMovementMethod.getInstance() : null);
        }
    }
}
