package com.example.anative.ui;

import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.PltEntry;

import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TextFragment extends Fragment {

    private static final String ARG_FUNC_ADDR = "func_addr";
    private static final String ARG_FUNC_SIZE = "func_size";

    private long funcAddr;
    private long funcSize;
    private TextView tvCode;
    private ProgressBar progressBar;
    private LinearLayout sectionButtons;
    private String addrFmt = "%08X";
    private Button activeButton = null;
    private String selectedSection = null;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    public static TextFragment newInstance(long funcAddr, long funcSize) {
        TextFragment fragment = new TextFragment();
        Bundle args = new Bundle();
        args.putLong(ARG_FUNC_ADDR, funcAddr);
        args.putLong(ARG_FUNC_SIZE, funcSize);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            funcAddr = getArguments().getLong(ARG_FUNC_ADDR);
            funcSize = getArguments().getLong(ARG_FUNC_SIZE);
        }
    }

    // 可解析的段名列表
    private static final String[] SECTION_NAMES = {
        ".text", ".rodata", ".data", ".bss", ".plt",
        ".got", ".got.plt", ".init_array", ".fini_array", ".dynamic"
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_text_view, container, false);
        tvCode = view.findViewById(R.id.tvCode);
        progressBar = view.findViewById(R.id.progressBar);
        sectionButtons = view.findViewById(R.id.sectionButtons);
        return view;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        buildSectionButtons();
        tvCode.setTextSize(TypedValue.COMPLEX_UNIT_SP, SettingsActivity.getCodeFontSizeSp(requireContext()));
        tvCode.setText("点击上方按钮选择要查看的段");
    }

    private void buildSectionButtons() {
        sectionButtons.removeAllViews();

        // "全部"按钮
        addSectionButton("全部", null);

        for (String name : SECTION_NAMES) {
            addSectionButton(name, name);
        }
    }

    private int getResColor(int resId) {
        return androidx.core.content.ContextCompat.getColor(requireContext(), resId);
    }

    private void addSectionButton(String label, String sectionName) {
        Button btn = new Button(requireContext());
        btn.setText(label);
        btn.setTextSize(13);
        btn.setAllCaps(false);
        btn.setTypeface(Typeface.MONOSPACE);
        btn.setTextColor(getResColor(R.color.section_btn_text));
        btn.setBackgroundColor(getResColor(R.color.section_btn_bg));
        btn.setPadding(32, 16, 32, 16);
        btn.setMinimumHeight(0);
        btn.setMinHeight(0);
        btn.setMinimumWidth(0);
        btn.setMinWidth(0);

        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(6, 0, 6, 0);
        btn.setLayoutParams(lp);

        btn.setOnClickListener(v -> {
            if (activeButton != null) {
                activeButton.setBackgroundColor(getResColor(R.color.section_btn_bg));
                activeButton.setTextColor(getResColor(R.color.section_btn_text));
            }
            activeButton = btn;
            btn.setBackgroundColor(getResColor(R.color.section_btn_active_bg));
            btn.setTextColor(getResColor(R.color.section_btn_active_text));
            selectedSection = sectionName;
            loadSection(sectionName);
        });

        sectionButtons.addView(btn);
    }

    private void loadSection(String sectionName) {
        progressBar.setVisibility(View.VISIBLE);
        tvCode.setText("");
        executor.execute(() -> {
            String result = (sectionName == null) ? buildAllSections() : buildSingleSection(sectionName);
            handler.post(() -> {
                progressBar.setVisibility(View.GONE);
                tvCode.setText(highlightLinear(result));
            });
        });
    }

    private List<ElfParser.SectionInfo> ensureSections() {
        List<ElfParser.SectionInfo> sections = DataHolder.getInstance().getSections();
        if (sections == null || sections.isEmpty()) {
            String soPath = DataHolder.getInstance().getSoPath();
            if (soPath == null) return new ArrayList<>();
            try {
                sections = ElfParser.parseSections(soPath);
                DataHolder.getInstance().setSections(sections);
            } catch (Exception e) {
                return new ArrayList<>();
            }
        }
        return sections;
    }

    private ElfParser.SectionInfo findSection(String name) {
        List<ElfParser.SectionInfo> sections = ensureSections();
        for (ElfParser.SectionInfo s : sections) {
            if (s.name.equals(name)) return s;
        }
        return null;
    }

    private void setupAddrFmt(List<ElfParser.SectionInfo> secs) {
        long maxAddr = 0;
        for (ElfParser.SectionInfo s : secs) {
            long end = s.virtualAddress + s.size;
            if (end > maxAddr) maxAddr = end;
        }
        int addrWidth = Math.max(4, Long.toHexString(maxAddr).length());
        addrFmt = "%0" + addrWidth + "X";
    }

    private Map<Long, String> buildFuncMap() {
        Map<Long, String> funcMap = new HashMap<>();
        List<NativeFunction> funcs = DataHolder.getInstance().getFunctions();
        if (funcs != null) {
            for (NativeFunction f : funcs) {
                funcMap.put(f.getOffset(), f.getDemangledName());
            }
        }
        return funcMap;
    }

    private Map<Long, String> buildPltMap() {
        Map<Long, String> pltMap = new HashMap<>();
        List<PltEntry> pltList = DataHolder.getInstance().getPltEntries();
        if (pltList != null) {
            for (PltEntry e : pltList) {
                pltMap.put(e.offset, e.symbolName);
            }
        }
        return pltMap;
    }

    private Map<Long, Long> buildRelaMap() {
        Map<Long, Long> relaMap = new HashMap<>();
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null) return relaMap;
        List<ElfParser.SectionInfo> sections = ensureSections();
        for (ElfParser.SectionInfo s : sections) {
            if (s.name.equals(".rela.dyn") || s.name.equals(".rela.plt")) {
                try (RandomAccessFile tmpRaf = new RandomAccessFile(soPath, "r")) {
                    byte[] relaData = new byte[(int) Math.min(s.size, 1024 * 1024)];
                    tmpRaf.seek(s.offset);
                    tmpRaf.readFully(relaData);
                    for (int ri = 0; ri + 24 <= relaData.length; ri += 24) {
                        long rOffset = readLong(relaData, ri);
                        long rInfo = readLong(relaData, ri + 8);
                        long rAddend = readLong(relaData, ri + 16);
                        int rType = (int) (rInfo & 0xFFFFFFFFL);
                        if (rType == 0x403 && rAddend != 0) {
                            relaMap.put(rOffset, rAddend);
                        }
                    }
                } catch (Exception ignored) {}
            }
        }
        return relaMap;
    }

    private String buildSingleSection(String sectionName) {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null) return "未找到SO文件路径";

        ElfParser.SectionInfo sec = findSection(sectionName);
        if (sec == null) return "未找到段: " + sectionName;

        List<ElfParser.SectionInfo> allSecs = ensureSections();
        setupAddrFmt(allSecs);

        long baseAddr = DataHolder.getInstance().getBaseAddress();
        long funcOffset = funcAddr - baseAddr;
        Map<Long, String> funcMap = buildFuncMap();
        Map<Long, String> pltMap = buildPltMap();

        StringBuilder sb = new StringBuilder();

        try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
            formatOneSection(sb, sec, raf, funcMap, pltMap, funcOffset);
        } catch (Exception e) {
            sb.append("\nERR: ").append(e.getMessage()).append("\n");
        }

        return sb.toString();
    }

    private String buildAllSections() {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null) return "未找到SO文件路径";

        List<ElfParser.SectionInfo> sections = ensureSections();
        if (sections.isEmpty()) return "未找到段信息";

        setupAddrFmt(sections);
        long baseAddr = DataHolder.getInstance().getBaseAddress();
        long funcOffset = funcAddr - baseAddr;
        Map<Long, String> funcMap = buildFuncMap();
        Map<Long, String> pltMap = buildPltMap();

        List<ElfParser.SectionInfo> sorted = new ArrayList<>();
        for (ElfParser.SectionInfo s : sections) {
            if (s.size > 0 && isUsefulSection(s.name)) sorted.add(s);
        }
        Collections.sort(sorted, (a, b) -> Long.compare(a.virtualAddress, b.virtualAddress));

        StringBuilder sb = new StringBuilder();
        try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
            for (ElfParser.SectionInfo sec : sorted) {
                formatOneSection(sb, sec, raf, funcMap, pltMap, funcOffset);
            }
        } catch (Exception e) {
            sb.append("\nERR: ").append(e.getMessage()).append("\n");
        }

        return sb.toString();
    }

    private void formatOneSection(StringBuilder sb, ElfParser.SectionInfo sec,
                                  RandomAccessFile raf, Map<Long, String> funcMap,
                                  Map<Long, String> pltMap, long funcOffset) throws Exception {
        String prefix = fmtAddr(sec.name, sec.virtualAddress);
        sb.append(prefix).append("\n");
        sb.append(prefix).append(" ; Segment type: ").append(getSegType(sec)).append("\n");
        sb.append(prefix).append("                 AREA ").append(sec.name).append(", ").append(getAreaFlags(sec)).append("\n");

        if (sec.offset > 0 && sec.size > 0 && sec.type != 8) {
            long readSize = Math.min(sec.size, 512 * 1024);
            byte[] data = new byte[(int) readSize];
            raf.seek(sec.offset);
            raf.readFully(data);

            if (isDataSection(sec.name)) {
                formatDataSection(sb, sec, data, funcMap);
            } else if (isCodeSection(sec)) {
                formatCodeSection(sb, sec, funcMap, funcOffset);
            } else if (sec.name.equals(".plt")) {
                formatPltSection(sb, sec, pltMap);
            } else if (sec.name.equals(".dynamic")) {
                formatDynamicSection(sb, sec, data);
            } else if (sec.name.equals(".init_array") || sec.name.equals(".fini_array")) {
                Map<Long, Long> relaMap = buildRelaMap();
                formatPointerArray(sb, sec, data, funcMap, relaMap);
            } else if (sec.name.equals(".got") || sec.name.equals(".got.plt")) {
                Map<Long, Long> relaMap = buildRelaMap();
                formatGotSection(sb, sec, data, relaMap, funcMap);
            } else {
                formatHexDump(sb, sec, data);
            }
        } else if (sec.type == 8) {
            sb.append(fmtAddr(sec.name, sec.virtualAddress))
                    .append("                 ; ").append(sec.size).append(" bytes of uninitialized data\n");
        }

        sb.append(fmtAddr(sec.name, sec.virtualAddress + sec.size))
                .append(" ; ").append(sec.name).append(" ends\n");
        sb.append("\n");
    }

    private boolean isUsefulSection(String name) {
        switch (name) {
            case ".text":
            case ".rodata":
            case ".data":
            case ".bss":
            case ".plt":
            case ".got":
            case ".got.plt":
            case ".init_array":
            case ".fini_array":
            case ".dynamic":
                return true;
            default:
                return false;
        }
    }

    private boolean isDataSection(String name) {
        return name.equals(".rodata") || name.equals(".data");
    }

    private boolean isCodeSection(ElfParser.SectionInfo sec) {
        return (sec.flags & 0x4) != 0 && !sec.name.equals(".plt") && !sec.name.equals(".init");
    }

    private String getSegType(ElfParser.SectionInfo sec) {
        if ((sec.flags & 0x4) != 0) return "Pure code";
        if ((sec.flags & 0x1) != 0) return "Pure data (read/write)";
        return "Pure data";
    }

    private String getAreaFlags(ElfParser.SectionInfo sec) {
        StringBuilder f = new StringBuilder();
        if ((sec.flags & 0x4) != 0) f.append("CODE");
        else f.append("DATA");
        if ((sec.flags & 0x1) == 0) f.append(", READONLY");
        if ((sec.flags & 0x2) != 0) f.append(", ALLOC");
        return f.toString();
    }

    private void formatDataSection(StringBuilder sb, ElfParser.SectionInfo sec, byte[] data, Map<Long, String> funcMap) {
        long addr = sec.virtualAddress;
        int i = 0;
        final int MAX_OUTPUT_LINES = 500; // 限制输出行数
        int outputLines = 0;
        
        while (i < data.length && outputLines < MAX_OUTPUT_LINES) {
            // 每处理1000字节检查一次是否超时（防止UI线程卡死）
            if (i % 1000 == 0) {
                Thread.yield();
            }
            
            // Try to find a string
            int strStart = i;
            while (i < data.length && data[i] >= 0x20 && data[i] < 0x7F) i++;

            if (i - strStart >= 4 && i < data.length && data[i] == 0) {
                // Found a null-terminated string
                String str = new String(data, strStart, i - strStart);
                String label = makeLabel(str);
                sb.append(fmtAddr(sec.name, addr + strStart))
                        .append(String.format(" %-16s DCB \"%s\",0\n", label, escapeStr(str)));
                i++; // skip null terminator
                outputLines++;
            } else if (i == strStart) {
                // Not a printable char, show hex bytes (group up to 16)
                int hexStart = i;
                while (i < data.length && i - hexStart < 16) {
                    if (data[i] >= 0x20 && data[i] < 0x7F) {
                        // check if this starts a string
                        int peek = i;
                        while (peek < data.length && data[peek] >= 0x20 && data[peek] < 0x7F) peek++;
                        if (peek - i >= 4 && peek < data.length && data[peek] == 0) break;
                    }
                    i++;
                }
                if (i > hexStart) {
                    StringBuilder hex = new StringBuilder();
                    for (int j = hexStart; j < i; j++) {
                        if (hex.length() > 0) hex.append(", ");
                        hex.append(String.format("0x%02X", data[j] & 0xFF));
                    }
                    sb.append(fmtAddr(sec.name, addr + hexStart))
                            .append("                 DCB ").append(hex).append("\n");
                    outputLines++;
                }
            } else {
                // Short non-string printable sequence, show as hex
                StringBuilder hex = new StringBuilder();
                for (int j = strStart; j < i; j++) {
                    if (hex.length() > 0) hex.append(", ");
                    hex.append(String.format("0x%02X", data[j] & 0xFF));
                }
                sb.append(fmtAddr(sec.name, addr + strStart))
                        .append("                 DCB ").append(hex).append("\n");
                outputLines++;
            }
        }
        
        // 如果数据被截断，添加提示
        if (i < data.length) {
            sb.append(fmtAddr(sec.name, addr + i))
                    .append(String.format("                 ; ... (%d bytes remaining, truncated)\n", data.length - i));
        }
    }

    private void formatCodeSection(StringBuilder sb, ElfParser.SectionInfo sec,
                                   Map<Long, String> funcMap, long funcOffset) {
        // Show function labels within the code section
        long addr = sec.virtualAddress;
        long end = addr + sec.size;

        List<Long> offsets = new ArrayList<>(funcMap.keySet());
        Collections.sort(offsets);

        boolean anyFunc = false;
        for (long off : offsets) {
            if (off >= addr && off < end) {
                anyFunc = true;
                String name = funcMap.get(off);
                boolean isCurrentFunc = (off == funcOffset);
                String marker = isCurrentFunc ? ">> " : "   ";
                sb.append(fmtAddr(sec.name, off)).append("\n");
                sb.append(fmtAddr(sec.name, off)).append(" ; ═══════════════════════════════════════\n");
                sb.append(marker).append(fmtAddr(sec.name, off)).append("                 ").append(name).append("\n");
                sb.append(fmtAddr(sec.name, off)).append(" ; (see 汇编 tab for disassembly)\n");
            }
        }

        if (!anyFunc) {
            sb.append(fmtAddr(sec.name, addr))
                    .append("                 ; ").append(sec.size).append(" bytes of code\n");
        }
    }

    private void formatPltSection(StringBuilder sb, ElfParser.SectionInfo sec, Map<Long, String> pltMap) {
        long addr = sec.virtualAddress;
        // PLT[0] header is typically 32 bytes on AArch64
        sb.append(fmtAddr(sec.name, addr)).append("                 ; PLT header (resolver stub)\n");

        List<Long> pltOffsets = new ArrayList<>(pltMap.keySet());
        Collections.sort(pltOffsets);

        for (long off : pltOffsets) {
            String sym = pltMap.get(off);
            sb.append(fmtAddr(sec.name, off)).append(String.format(" %-24s ; PLT stub\n", sym + "@PLT"));
        }
    }

    private void formatDynamicSection(StringBuilder sb, ElfParser.SectionInfo sec, byte[] data) {
        long addr = sec.virtualAddress;
        // Each Elf64_Dyn is 16 bytes: d_tag(8) + d_val(8)
        for (int i = 0; i + 16 <= data.length; i += 16) {
            long tag = readLong(data, i);
            long val = readLong(data, i + 8);
            if (tag == 0) break; // DT_NULL
            sb.append(fmtAddr(sec.name, addr + i))
                    .append(String.format("                 DCD 0x%X, 0x%X  ; %s\n", tag, val, getDynTagName(tag)));
        }
    }

    private void formatPointerArray(StringBuilder sb, ElfParser.SectionInfo sec,
                                    byte[] data, Map<Long, String> funcMap,
                                    Map<Long, Long> relaMap) {
        long addr = sec.virtualAddress;
        for (int i = 0; i + 8 <= data.length; i += 8) {
            long entryAddr = addr + i;
            // 优先使用重定位表的 addend 作为真实指针值
            Long relocated = relaMap.get(entryAddr);
            long ptr = (relocated != null) ? relocated : readLong(data, i);
            String funcName = funcMap.get(ptr);
            if (funcName != null) {
                sb.append(fmtAddr(sec.name, entryAddr))
                        .append(String.format("                 DCQ sub_%X  ; -> %s\n", ptr, funcName));
            } else if (ptr != 0) {
                sb.append(fmtAddr(sec.name, entryAddr))
                        .append(String.format("                 DCQ sub_%X\n", ptr));
            } else {
                sb.append(fmtAddr(sec.name, entryAddr))
                        .append("                 DCQ 0\n");
            }
        }
    }

    private void formatGotSection(StringBuilder sb, ElfParser.SectionInfo sec, byte[] data,
                                  Map<Long, Long> relaMap, Map<Long, String> funcMap) {
        long addr = sec.virtualAddress;
        for (int i = 0; i + 8 <= data.length; i += 8) {
            long entryAddr = addr + i;
            Long relocated = relaMap.get(entryAddr);
            long val = (relocated != null) ? relocated : readLong(data, i);
            String funcName = funcMap.get(val);
            if (funcName != null) {
                sb.append(fmtAddr(sec.name, entryAddr))
                        .append(String.format("                 DCQ 0x%X  ; -> %s\n", val, funcName));
            } else {
                sb.append(fmtAddr(sec.name, entryAddr))
                        .append(String.format("                 DCQ 0x%X\n", val));
            }
        }
    }

    private void formatHexDump(StringBuilder sb, ElfParser.SectionInfo sec, byte[] data) {
        long addr = sec.virtualAddress;
        int maxLines = 32; // Limit hex dump to 32 lines (512 bytes)
        int shown = 0;
        for (int i = 0; i < data.length && shown < maxLines; i += 16, shown++) {
            StringBuilder hex = new StringBuilder();
            StringBuilder ascii = new StringBuilder();
            for (int j = 0; j < 16 && i + j < data.length; j++) {
                if (j > 0) hex.append(" ");
                byte b = data[i + j];
                hex.append(String.format("%02X", b & 0xFF));
                ascii.append(b >= 0x20 && b < 0x7F ? (char) b : '.');
            }
            sb.append(fmtAddr(sec.name, addr + i))
                    .append(String.format("  %-48s %s\n", hex, ascii));
        }
        if (data.length > maxLines * 16) {
            sb.append(fmtAddr(sec.name, addr + maxLines * 16))
                    .append("  ... (").append(data.length - maxLines * 16).append(" more bytes)\n");
        }
    }

    private String makeLabel(String str) {
        // Generate a short IDA-like label from string content
        String clean = str.replaceAll("[^a-zA-Z0-9_]", "");
        if (clean.length() > 14) clean = clean.substring(0, 14);
        if (clean.isEmpty()) return "";
        return "a" + clean.substring(0, 1).toUpperCase() + clean.substring(1);
    }

    private String fmtAddr(String secName, long addr) {
        return secName + ":" + String.format(addrFmt, addr);
    }

    private String escapeStr(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private long readLong(byte[] data, int off) {
        // Little-endian 64-bit
        long val = 0;
        for (int i = 7; i >= 0; i--) {
            val = (val << 8) | (data[off + i] & 0xFFL);
        }
        return val;
    }

    private String getDynTagName(long tag) {
        if (tag == 1) return "DT_NEEDED";
        if (tag == 5) return "DT_STRTAB";
        if (tag == 6) return "DT_SYMTAB";
        if (tag == 7) return "DT_RELA";
        if (tag == 10) return "DT_STRSZ";
        if (tag == 11) return "DT_SYMENT";
        if (tag == 12) return "DT_INIT";
        if (tag == 13) return "DT_FINI";
        if (tag == 14) return "DT_SONAME";
        if (tag == 23) return "DT_JMPREL";
        if (tag == 25) return "DT_INIT_ARRAY";
        if (tag == 26) return "DT_FINI_ARRAY";
        if (tag == 0x6ffffffb) return "DT_FLAGS_1";
        return String.format("DT_0x%X", tag);
    }

    private SpannableString highlightLinear(String code) {
        SpannableString ss = new SpannableString(code);
        int cAddr = ContextCompat.getColor(requireContext(), R.color.code_addr);
        int cComment = ContextCompat.getColor(requireContext(), R.color.code_comment);
        int cStr = ContextCompat.getColor(requireContext(), R.color.code_string);
        int cHighlight = ContextCompat.getColor(requireContext(), R.color.accent);
        int cType = ContextCompat.getColor(requireContext(), R.color.code_type);
        int cPlt = ContextCompat.getColor(requireContext(), R.color.code_plt);

        String[] lines = code.split("\n");
        int pos = 0;
        for (String line : lines) {
            int lineEnd = pos + line.length();
            if (lineEnd > ss.length()) break;

            if (line.startsWith(">> ") || line.startsWith(">>")) {
                ss.setSpan(new ForegroundColorSpan(cHighlight), pos, lineEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            } else {
                // Section:addr prefix coloring
                int colonIdx = line.indexOf(':');
                if (colonIdx > 0 && colonIdx < 20) {
                    // Section name
                    ss.setSpan(new ForegroundColorSpan(cType), pos, pos + colonIdx, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    // Address (16 hex digits after colon)
                    int addrEnd = colonIdx + 17;
                    if (addrEnd <= line.length()) {
                        ss.setSpan(new ForegroundColorSpan(cAddr), pos + colonIdx, pos + addrEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    }
                }
                // Comment
                int semiIdx = line.indexOf(';');
                if (semiIdx >= 0) {
                    ss.setSpan(new ForegroundColorSpan(cComment), pos + semiIdx, lineEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                }
                // String literals
                int dqStart = line.indexOf('"');
                if (dqStart >= 0) {
                    int dqEnd = line.indexOf('"', dqStart + 1);
                    if (dqEnd > dqStart) {
                        ss.setSpan(new ForegroundColorSpan(cStr), pos + dqStart, pos + dqEnd + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                    }
                }
                // PLT labels
                if (line.contains("@PLT")) {
                    ss.setSpan(new ForegroundColorSpan(cPlt), pos, lineEnd, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                }
            }
            pos = lineEnd + 1;
        }
        return ss;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
