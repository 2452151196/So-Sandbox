package com.example.anative.ui;

import android.content.Context;
import android.content.SharedPreferences;
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

    /** 点击的元素类型 */
    public enum ClickType {
        INSTRUCTION,    // 点击整条指令（mnemonic+operands）
        ADDRESS,       // 点击地址
        REGISTER,      // 点击寄存器
        IMMEDIATE,     // 点击立即数
        FUNCTION_CALL, // 点击函数名跳转目标
    }

    public interface OnLineClickListener {
        void onFuncClick(String funcName);
    }

    /**
     * 点击指令/地址/寄存器/立即数时的回调
     * @param clickType 点击的元素类型
     * @param line 完整行文本
     * @param offset 该行指令的偏移地址（虚拟地址）
     * @param mnemonic 指令助记符
     * @param operands 操作数部分
     * @param bytes 原始机器码字节（hex字符串）
     * @param elementText 被点击的具体文本（如寄存器名 x0、立即数 #0x1000）
     * @param elementIndex 操作数中同类元素的索引（如第几个寄存器）
     */
    public interface OnElementClickListener {
        void onElementClick(ClickType clickType, String line, long offset,
                           String mnemonic, String operands, String bytes,
                           String elementText, int elementIndex);
    }

    private final List<String> lines = new ArrayList<>();
    private int cAddr, cInsn, cBranch, cReg, cImm, cComment, cStr, cPlt;
    private float fontSizeSp = 13f;
    private Set<String> branchInsns;
    private Set<String> funcNames;
    private OnLineClickListener listener;
    private OnElementClickListener elementListener;

    // 存储修改的指令: key=offset, value=新的汇编指令字符串
    private java.util.Map<Long, String> modifiedInstructions = new java.util.HashMap<>();
    private int cModifiedInsn;

    // 预编译正则
    private static final Pattern ADDR_PAT = Pattern.compile("^([0-9a-fA-F]{8}):");
    private static final Pattern INSN_PAT = Pattern.compile("(?<=:\\s{2})(\\S+)");
    private static final Pattern REG_PAT = Pattern.compile("\\b(sp|lr|xzr|wzr|fp|x[0-9]+|w[0-9]+|v[0-9]+|s[0-9]+|d[0-9]+|q[0-9]+)\\b");
    private static final Pattern IMM_PAT = Pattern.compile("#-?0x[0-9a-fA-F]+|#-?\\d+");
    private static final Pattern STR_PAT = Pattern.compile("; \".*\"");
    private static final Pattern PLT_PAT = Pattern.compile("; \\S+@plt", Pattern.CASE_INSENSITIVE);
    private static final Pattern CMT_PAT = Pattern.compile(";(?! \")(?! \\S+@plt).*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern SYNTHETIC_FUNC_PAT = Pattern.compile("sub_[0-9a-fA-F]+");
    private static final Pattern INSN_BYTES_PAT = Pattern.compile("^[0-9a-fA-F]{8}:\\s+(([0-9a-fA-F]{2}\\s+)+)");

    public void init(Context ctx) {
        SharedPreferences prefs = ctx.getSharedPreferences("app_prefs", Context.MODE_PRIVATE);
        fontSizeSp = prefs.getFloat(SettingsActivity.PREF_CODE_FONT_SIZE, 13f);
        cAddr = ctx.getResources().getColor(R.color.code_addr, ctx.getTheme());
        cInsn = ctx.getResources().getColor(R.color.code_insn, ctx.getTheme());
        cBranch = ctx.getResources().getColor(R.color.code_branch, ctx.getTheme());
        cReg = ctx.getResources().getColor(R.color.code_reg, ctx.getTheme());
        cImm = ctx.getResources().getColor(R.color.code_imm, ctx.getTheme());
        cComment = ctx.getResources().getColor(R.color.code_comment, ctx.getTheme());
        cStr = ctx.getResources().getColor(R.color.code_string, ctx.getTheme());
        cPlt = ctx.getResources().getColor(R.color.code_plt, ctx.getTheme());
        cModifiedInsn = 0xFF4CAF50;

        branchInsns = new java.util.HashSet<>(java.util.Arrays.asList(
                "b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz",
                "b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo", "b.mi", "b.pl",
                "b.vs", "b.vc", "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al"));

        funcNames = new java.util.HashSet<>();
    }

    public void setFuncNames(Set<String> names) {
        this.funcNames = names != null ? names : new java.util.HashSet<>();
    }

    // 函数偏移 -> 函数名映射，用于识别 bl #0x1234 这类纯地址的跳转目标
    private java.util.Map<Long, String> funcOffsetToName = new java.util.HashMap<>();

    // PLT 偏移集合：命中时优先按 PLT 处理，不做函数自动识别
    private java.util.Set<Long> pltOffsets = new java.util.HashSet<>();

    public void setFuncOffsetMap(java.util.Map<Long, String> map) {
        this.funcOffsetToName = map != null ? map : new java.util.HashMap<>();
    }

    public void setPltOffsets(java.util.Set<Long> offsets) {
        this.pltOffsets = offsets != null ? offsets : new java.util.HashSet<>();
    }

    // 当前函数范围（文件偏移），用于判断 b #addr 是否是 tail call
    private long curFuncStart = -1;
    private long curFuncEnd = -1;

    public void setCurrentFunctionRange(long startOffset, long endOffset) {
        this.curFuncStart = startOffset;
        this.curFuncEnd = endOffset;
    }

    public void setOnLineClickListener(OnLineClickListener l) {
        this.listener = l;
    }

    public void setOnElementClickListener(OnElementClickListener l) {
        this.elementListener = l;
    }

    public void setModifiedInstructions(java.util.Map<Long, String> modified) {
        this.modifiedInstructions = modified != null ? new java.util.HashMap<>(modified) : new java.util.HashMap<>();
        notifyDataSetChanged();
    }

    public void clearModifiedInstructions() {
        this.modifiedInstructions.clear();
        notifyDataSetChanged();
    }

    public void refreshModifiedInstructions() {
        com.example.anative.core.DataHolder holder = com.example.anative.core.DataHolder.getInstance();
        setModifiedInstructions(holder.getAllModifiedInstructions());
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
            tv.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, fontSizeSp);
        }

        void bind(String line) {
            if (line.startsWith(";") || line.isEmpty()) {
                SpannableString ss = new SpannableString(line);
                ss.setSpan(new ForegroundColorSpan(cComment), 0, line.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                tv.setText(ss);
                tv.setMovementMethod(null);
                return;
            }

            long parsedOffset = -1;
            String parsedMnemonic = null;
            String parsedOperands = null;
            String parsedBytes = null;
            String originalLine = line;
            boolean isModifiedLine = false;

            Matcher addrMatcher = ADDR_PAT.matcher(line);
            if (addrMatcher.find()) {
                try {
                    parsedOffset = Long.parseLong(addrMatcher.group(1), 16);
                } catch (NumberFormatException ignored) {}
            }

            final String finalLine = line;
            final long fOffset = parsedOffset;

            // 检查是否有修改后的指令
            if (parsedOffset >= 0 && modifiedInstructions.containsKey(parsedOffset)) {
                String newAsm = modifiedInstructions.get(parsedOffset);
                if (newAsm != null) {
                    int colonIdx = line.indexOf(':');
                    if (colonIdx >= 0) {
                        int semiIdx = line.indexOf(';');
                        String addrPart = line.substring(0, colonIdx + 1);
                        String commentPart = (semiIdx > colonIdx) ? line.substring(semiIdx) : "";
                        line = addrPart + "  " + newAsm + commentPart;
                        isModifiedLine = true;
                    }
                }
            }

            Matcher insnMatcher = INSN_PAT.matcher(line);
            if (insnMatcher.find()) {
                parsedMnemonic = insnMatcher.group(1).toLowerCase();
                int colonIdx = line.indexOf(':');
                if (colonIdx >= 0) {
                    int semiIdx = line.indexOf(';');
                    String afterColon = (semiIdx > colonIdx)
                            ? line.substring(colonIdx + 1, semiIdx).trim()
                            : line.substring(colonIdx + 1).trim();
                    int spaceIdx = afterColon.indexOf(' ');
                    if (spaceIdx > 0) {
                        parsedOperands = afterColon.substring(spaceIdx + 1).trim();
                    }
                }
                Matcher bytesMatcher = INSN_BYTES_PAT.matcher(line);
                if (bytesMatcher.find()) {
                    parsedBytes = bytesMatcher.group(1).trim();
                }
            }

            final String fMnemonic = parsedMnemonic != null ? parsedMnemonic : "";
            final String fOperands = parsedOperands != null ? parsedOperands : "";
            final String fBytes = parsedBytes != null ? parsedBytes : "";

            boolean hasClickable = false;

            // 预先识别"函数调用"跳转目标的字符区间（优先级高于立即数）
            // 同时检测是否是 @PLT 调用（PLT 调用有注释，不当作函数处理）
            int branchTargetStart = -1;
            int branchTargetEnd = -1;
            String branchFuncName = null;
            boolean branchIsSynthetic = false;   // 目标函数不在函数表里（自动识别的）
            boolean lineHasPlt = PLT_PAT.matcher(line).find();
            if (funcNames != null && !lineHasPlt) {
                int colonIdx0 = line.indexOf(':');
                if (colonIdx0 >= 0 && colonIdx0 < 10) {
                    String afterColon0 = line.substring(colonIdx0 + 1).trim();
                    int spIdx0 = afterColon0.indexOf(' ');
                    if (spIdx0 > 0) {
                        String mnem = afterColon0.substring(0, spIdx0).toLowerCase().trim();
                        if (mnem.equals("b") || mnem.equals("bl") || mnem.equals("blr")
                                || mnem.startsWith("b.")
                                || mnem.equals("cbz") || mnem.equals("cbnz")
                                || mnem.equals("tbz") || mnem.equals("tbnz")) {
                            String operands0 = afterColon0.substring(spIdx0).trim();
                            int lastComma0 = operands0.lastIndexOf(',');
                            String target0 = (lastComma0 >= 0) ? operands0.substring(lastComma0 + 1).trim() : operands0.trim();
                            int semiIdx0 = target0.indexOf(';');
                            if (semiIdx0 >= 0) target0 = target0.substring(0, semiIdx0).trim();

                            String resolvedName = null;
                            if (target0.startsWith("#")) {
                                try {
                                    String numStr = target0.substring(1);
                                    long addr = (numStr.startsWith("0x") || numStr.startsWith("0X"))
                                            ? Long.parseLong(numStr.substring(2), 16)
                                            : Long.parseLong(numStr, 16);
                                    // PLT 优先级最高：目标是 PLT 条目则不识别为函数
                                    if (pltOffsets != null && pltOffsets.contains(addr)) {
                                        resolvedName = null;
                                    } else {
                                    resolvedName = funcOffsetToName.get(addr);
                                    if (resolvedName == null) {
                                        boolean isBlLike = mnem.equals("bl") || mnem.equals("blr");
                                        boolean isFarB = mnem.equals("b")
                                                && curFuncStart >= 0 && curFuncEnd > curFuncStart
                                                && (addr < curFuncStart || addr >= curFuncEnd);
                                        if (isBlLike || isFarB) {
                                            resolvedName = String.format("sub_%x", addr);
                                        }
                                    }
                                    }
                                } catch (NumberFormatException ignored) {}
                            } else if (!target0.isEmpty()
                                    && (funcNames.contains(target0) || SYNTHETIC_FUNC_PAT.matcher(target0).matches())) {
                                resolvedName = target0;
                            }

                            if (resolvedName != null) {
                                int idx = line.lastIndexOf(target0);
                                if (idx >= 0) {
                                    branchTargetStart = idx;
                                    branchTargetEnd = idx + target0.length();
                                    branchFuncName = resolvedName;
                                    // 标记: 目标不在函数表里（靠合成 sub_XXXX 识别出的）
                                    branchIsSynthetic = !funcNames.contains(resolvedName);
                                }
                            }
                        }
                    }
                }
            }

            // 如果识别出的函数不在函数表，附加一个"自动识别"提示注释
            int annotationStart = -1;
            int annotationEnd = -1;
            if (branchIsSynthetic && branchFuncName != null) {
                String annotation = "  ; → " + branchFuncName + " (自动识别, 未在函数表)";
                // 如果原行已经有分号注释，追加到末尾；否则直接追加
                annotationStart = line.length();
                line = line + annotation;
                annotationEnd = line.length();
            }

            SpannableString ss = new SpannableString(line);
            if (annotationStart >= 0) {
                ss.setSpan(new ForegroundColorSpan(cComment),
                        annotationStart, annotationEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // === 1. 地址可点击 ===
            addrMatcher = ADDR_PAT.matcher(line);
            if (addrMatcher.find() && fOffset >= 0 && elementListener != null) {
                int addrStart = addrMatcher.start(1);
                int addrEnd = addrMatcher.end(1) + 1;
                final long addrValue = fOffset;
                ss.setSpan(new ClickableSpan() {
                    @Override
                    public void onClick(@NonNull View widget) {
                        elementListener.onElementClick(ClickType.ADDRESS, finalLine, addrValue,
                                fMnemonic, fOperands, fBytes, null, -1);
                    }
                    @Override
                    public void updateDrawState(@NonNull android.text.TextPaint ds) {
                        ds.setColor(cAddr);
                        ds.setUnderlineText(false);
                    }
                }, addrStart, addrEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                ss.setSpan(new ForegroundColorSpan(cAddr), addrStart, addrEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                hasClickable = true;
            }

            // === 2. 指令名可点击 ===
            insnMatcher = INSN_PAT.matcher(line);
            if (insnMatcher.find()) {
                String insn = insnMatcher.group(1).toLowerCase();
                boolean isBranch = branchInsns != null && branchInsns.contains(insn);
                int insnStart = insnMatcher.start();
                int insnEnd = insnMatcher.end();

                final int spanColor;
                if (isModifiedLine) {
                    spanColor = cModifiedInsn;
                } else if (isBranch) {
                    spanColor = cBranch;
                } else {
                    spanColor = cInsn;
                }

                if (fOffset >= 0 && elementListener != null) {
                    ss.setSpan(new ClickableSpan() {
                        @Override
                        public void onClick(@NonNull View widget) {
                            elementListener.onElementClick(ClickType.INSTRUCTION, finalLine, fOffset,
                                    fMnemonic, fOperands, fBytes, null, -1);
                        }
                        @Override
                        public void updateDrawState(@NonNull android.text.TextPaint ds) {
                            ds.setColor(spanColor);
                            ds.setUnderlineText(false);
                        }
                    }, insnStart, insnEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    hasClickable = true;
                }
            }

            // === 3. 寄存器可点击 ===
            Matcher regMatcher = REG_PAT.matcher(line);
            int regIndex = 0;
            while (regMatcher.find() && elementListener != null) {
                int regStart = regMatcher.start();
                int regEnd = regMatcher.end();
                final String regName = regMatcher.group();
                final int currentIndex = regIndex++;
                final int fRegStart = regStart;
                final int fRegEnd = regEnd;

                ss.setSpan(new ClickableSpan() {
                    @Override
                    public void onClick(@NonNull View widget) {
                        if (fOffset >= 0) {
                            elementListener.onElementClick(ClickType.REGISTER, finalLine, fOffset,
                                    fMnemonic, fOperands, fBytes, regName, currentIndex);
                        }
                    }
                    @Override
                    public void updateDrawState(@NonNull android.text.TextPaint ds) {
                        ds.setColor(cReg);
                        ds.setUnderlineText(false);
                    }
                }, regStart, regEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                ss.setSpan(new ForegroundColorSpan(cReg), regStart, regEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                hasClickable = true;
            }

            // === 4. 立即数可点击 ===
            Matcher immMatcher = IMM_PAT.matcher(line);
            int immIndex = 0;
            while (immMatcher.find() && elementListener != null) {
                int immStart = immMatcher.start();
                int immEnd = immMatcher.end();
                // 跳过分支目标：它会作为 FUNCTION_CALL span 处理，避免冲突
                if (branchTargetStart >= 0
                        && immStart >= branchTargetStart && immEnd <= branchTargetEnd) {
                    immIndex++;
                    continue;
                }
                final String immValue = immMatcher.group();
                final int currentIndex = immIndex++;
                final int fImmStart = immStart;
                final int fImmEnd = immEnd;

                ss.setSpan(new ClickableSpan() {
                    @Override
                    public void onClick(@NonNull View widget) {
                        if (fOffset >= 0) {
                            elementListener.onElementClick(ClickType.IMMEDIATE, finalLine, fOffset,
                                    fMnemonic, fOperands, fBytes, immValue, currentIndex);
                        }
                    }
                    @Override
                    public void updateDrawState(@NonNull android.text.TextPaint ds) {
                        ds.setColor(cImm);
                        ds.setUnderlineText(false);
                    }
                }, immStart, immEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                ss.setSpan(new ForegroundColorSpan(cImm), immStart, immEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                hasClickable = true;
            }

            // === 5. 字符串高亮 ===
            Matcher strMatcher = STR_PAT.matcher(line);
            while (strMatcher.find()) {
                ss.setSpan(new ForegroundColorSpan(cStr), strMatcher.start(), strMatcher.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // === 6. PLT 引用高亮 ===
            Matcher pltMatcher = PLT_PAT.matcher(line);
            while (pltMatcher.find()) {
                ss.setSpan(new ForegroundColorSpan(cPlt), pltMatcher.start(), pltMatcher.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // === 7. 注释高亮 ===
            Matcher cmtMatcher = CMT_PAT.matcher(line);
            while (cmtMatcher.find()) {
                ss.setSpan(new ForegroundColorSpan(cComment), cmtMatcher.start(), cmtMatcher.end(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            }

            // === 8. 函数调用跳转目标可点击 ===
            // 使用预先识别的 branchTargetStart/End + branchFuncName
            if (branchFuncName != null && branchTargetStart >= 0
                    && (listener != null || elementListener != null)) {
                final String funcName = branchFuncName;
                final int tStart = branchTargetStart;
                final int tEnd = branchTargetEnd;
                ss.setSpan(new ClickableSpan() {
                    @Override
                    public void onClick(@NonNull View widget) {
                        if (elementListener != null) {
                            elementListener.onElementClick(ClickType.FUNCTION_CALL,
                                    finalLine, fOffset, fMnemonic, fOperands, fBytes,
                                    funcName, -1);
                        } else if (listener != null) {
                            listener.onFuncClick(funcName);
                        }
                    }
                    @Override
                    public void updateDrawState(@NonNull android.text.TextPaint ds) {
                        ds.setColor(cPlt);
                        ds.setUnderlineText(true);
                    }
                }, tStart, tEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                hasClickable = true;
            }

            tv.setText(ss);
            tv.setMovementMethod(hasClickable ? LinkMovementMethod.getInstance() : null);
        }
    }
}
