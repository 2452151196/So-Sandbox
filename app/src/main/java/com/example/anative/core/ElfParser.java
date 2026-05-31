package com.example.anative.core;

import android.util.Log;

import net.fornwall.jelf.ElfFile;
import net.fornwall.jelf.ElfSection;
import net.fornwall.jelf.ElfSectionHeader;
import net.fornwall.jelf.ElfSymbol;
import net.fornwall.jelf.ElfSymbolTableSection;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

public class ElfParser {
    private static final String TAG = "ElfParser";

    /**
     * 安全打开ELF文件，处理 e_shnum=0 的情况
     * 当 e_shnum=0 时，真实的 section 数量在 section header[0].sh_size 中
     */
    private static ElfFile safeOpenElf(String soPath) throws IOException {
        try {
            return ElfFile.from(new File(soPath));
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("e_shnum") && msg.contains("SHN_UNDEF")) {
                Log.w(TAG, "e_shnum=0, attempting manual fix");
                return openElfWithFixedShnum(soPath);
            }
            throw e instanceof IOException ? (IOException) e : new IOException(e);
        }
    }

    /**
     * 手动修补 e_shnum=0 的 ELF 文件
     */
    private static ElfFile openElfWithFixedShnum(String soPath) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(soPath, "r");

        // 读取 ELF header 前 64 bytes (ELF64)
        byte[] ehdr = new byte[64];
        raf.readFully(ehdr);

        // 确认是 ELF64 (e_ident[4] = 2)
        boolean is64 = ehdr[4] == 2;
        if (!is64) {
            raf.close();
            throw new IOException("仅支持64位ELF文件");
        }

        // 读取 e_shoff (section header table offset), 位于偏移 40, 8 bytes
        long shoff = readLong64(ehdr, 40);
        // e_shentsize 位于偏移 58, 2 bytes
        int shentsize = (ehdr[58] & 0xFF) | ((ehdr[59] & 0xFF) << 8);
        // e_shnum 位于偏移 60, 2 bytes (此时为0)
        // e_shstrndx 位于偏移 62, 2 bytes

        if (shoff == 0 || shentsize == 0) {
            raf.close();
            throw new IOException("无Section Header Table");
        }

        // 读取 section header[0] 的 sh_size 字段获取真实 section 数量
        // sh_size 在 Elf64_Shdr 的偏移 32, 8 bytes
        raf.seek(shoff + 32);
        byte[] sizeBytes = new byte[8];
        raf.readFully(sizeBytes);
        long realShnum = readLong64(sizeBytes, 0);
        raf.close();

        if (realShnum <= 0 || realShnum > 65535) {
            throw new IOException("无效的section数量: " + realShnum);
        }

        Log.i(TAG, "Real e_shnum from section[0].sh_size = " + realShnum);

        // 创建修补后的临时文件
        File origFile = new File(soPath);
        File fixedFile = new File(origFile.getParent(), "fixed_" + origFile.getName());

        // 复制原文件
        RandomAccessFile src = new RandomAccessFile(soPath, "r");
        java.io.FileOutputStream fos = new java.io.FileOutputStream(fixedFile);
        byte[] buf = new byte[8192];
        int n;
        while ((n = src.read(buf)) > 0) fos.write(buf, 0, n);
        src.close();
        fos.close();

        // 修补 e_shnum 字段 (偏移 60, 2 bytes, little-endian)
        RandomAccessFile fixRaf = new RandomAccessFile(fixedFile, "rw");
        fixRaf.seek(60);
        fixRaf.writeByte((int) (realShnum & 0xFF));
        fixRaf.writeByte((int) ((realShnum >> 8) & 0xFF));
        fixRaf.close();

        ElfFile result = ElfFile.from(fixedFile);
        fixedFile.delete();
        return result;
    }

    /**
     * 解析SO文件，提取所有FUNC类型的符号
     */
    public static List<NativeFunction> parseFunctions(String soPath) throws IOException {
        return parseFunctions(soPath, "balanced");
    }

    public static NativeFunction recognizeFunctionAtAddress(String soPath, long address,
                                                            List<NativeFunction> knownFunctions) throws IOException {
        return recognizeFunctionAtAddress(soPath, address, knownFunctions, 0);
    }

    public static NativeFunction recognizeFunctionAtAddress(String soPath, long address,
                                                            List<NativeFunction> knownFunctions,
                                                            long expectedSize) throws IOException {
        ElfFile elfFile = safeOpenElf(soPath);
        ElfSectionHeader execHdr = null;
        int numSections = elfFile.e_shnum;
        for (int i = 0; i < numSections; i++) {
            ElfSection sec = elfFile.getSection(i);
            ElfSectionHeader header = sec.header;
            if (isExecutableSection(header)
                    && address >= header.sh_addr
                    && address < header.sh_addr + header.sh_size) {
                execHdr = header;
                break;
            }
        }

        if (execHdr == null || execHdr.sh_size <= 0) {
            throw new IOException(String.format("地址 0x%X 不在可执行段内", address));
        }

        long execStart = execHdr.sh_addr;
        long execEnd = execHdr.sh_addr + execHdr.sh_size;

        List<NativeFunction> knownList = knownFunctions != null ? knownFunctions : new ArrayList<>();
        for (NativeFunction existing : knownList) {
            if (existing == null) continue;
            if (existing.getOffset() == address) {
                return existing;
            }
        }

        List<long[]> knownRanges = new ArrayList<>();
        List<Long> sortedKnownOffsets = new ArrayList<>();
        for (NativeFunction f : knownList) {
            if (f == null) continue;
            sortedKnownOffsets.add(f.getOffset());
            if (f.getOffset() == address) continue;
            if (f.getSize() > 0) {
                knownRanges.add(new long[]{f.getOffset(), f.getOffset() + f.getSize()});
            }
        }
        sortedKnownOffsets.sort(Long::compareTo);

        try (RandomAccessFile raf = new RandomAccessFile(new File(soPath), "r")) {
            long fileOff = execHdr.sh_offset + (address - execStart);
            long maxScan = Math.min(execEnd - address, 65536);
            if (maxScan < 4) {
                return new NativeFunction(String.format("sub_%X", address), address, 4, "manual");
            }

            byte[] code = new byte[(int) maxScan];
            raf.seek(fileOff);
            raf.readFully(code);

            long nextKnownStart = findNextVerifiedFunctionStart(address, sortedKnownOffsets, execEnd, code);
            long scanLimit = Math.min(maxScan, nextKnownStart - address);
            if (scanLimit < 4) {
                scanLimit = Math.min(maxScan, 256);
            }

            long estimatedSize;
            if (expectedSize > 0) {
                estimatedSize = Math.min(expectedSize, scanLimit);
                if (estimatedSize < 4) {
                    estimatedSize = Math.min(Math.max(scanLimit, 4), 4);
                }
            } else {
                Set<Integer> reachableOffsets = collectReachableInstructionOffsets(code, address, scanLimit, knownRanges);
                estimatedSize = findFunctionEndViaCFG(code, address, scanLimit, knownRanges, reachableOffsets);
                if (estimatedSize <= 0) {
                    estimatedSize = estimateFunctionSize(code, 0, address, new HashSet<>(sortedKnownOffsets), execEnd);
                }

                if (estimatedSize <= 0) {
                    estimatedSize = Math.min(scanLimit, 256);
                }
            }

            if (nextKnownStart > address) {
                estimatedSize = Math.min(estimatedSize, nextKnownStart - address);
            }
            if (estimatedSize < 4) {
                estimatedSize = Math.min(Math.max(scanLimit, 4), 4);
            }

            return new NativeFunction(String.format("sub_%X", address), address, estimatedSize, "manual");
        }
    }

    private static boolean isExecutableSection(ElfSectionHeader header) {
        return header != null
                && header.sh_size > 0
                && (header.sh_flags & 0x4L) != 0;
    }

    /**
     * 按函数发现模式解析SO文件
     * precise: 仅符号表
     * balanced: 符号表 + init/fini + BL发现（默认）
     * max_coverage: balanced + text扫描
     */
    public static List<NativeFunction> parseFunctions(String soPath, String discoveryMode) throws IOException {
        String resolvedMode = normalizeFunctionDiscoveryMode(discoveryMode);
        boolean preciseMode = "precise".equals(resolvedMode);
        boolean maxCoverageMode = "max_coverage".equals(resolvedMode);

        Set<NativeFunction> funcSet = new LinkedHashSet<>();
        ElfFile elfFile = safeOpenElf(soPath);

        int numSections = elfFile.e_shnum;
        for (int i = 0; i < numSections; i++) {
            ElfSection section = elfFile.getSection(i);
            ElfSectionHeader header = section.header;

            // SHT_SYMTAB = 2, SHT_DYNSYM = 11
            if (header.sh_type == ElfSectionHeader.SHT_SYMTAB ||
                header.sh_type == ElfSectionHeader.SHT_DYNSYM) {

                String source = (header.sh_type == ElfSectionHeader.SHT_DYNSYM) ? "dynsym" : "symtab";
                ElfSymbolTableSection symSection = (ElfSymbolTableSection) section;
                int numSymbols = symSection.symbols.length;

                for (int j = 0; j < numSymbols; j++) {
                    ElfSymbol sym = symSection.symbols[j];

                    // STT_FUNC = 2
                    if (sym.getType() == ElfSymbol.STT_FUNC && sym.st_value != 0) {
                        String name = sym.getName();
                        if (name != null && !name.isEmpty()) {
                            funcSet.add(new NativeFunction(
                                name,
                                sym.st_value,
                                sym.st_size,
                                source
                            ));
                        }
                    }
                }

                Log.i(TAG, "Parsed " + source + ": " + numSymbols + " symbols total");
            }
        }

        Log.i(TAG, "Function discovery mode: " + resolvedMode);

        // precise模式: 仅使用符号表函数
        if (preciseMode) {
            List<NativeFunction> preciseResult = deduplicateFunctionsByOffset(funcSet);
            clampFunctionSizesToNextStart(preciseResult);
            Log.i(TAG, "Total FUNC symbols found (precise): " + preciseResult.size());
            return preciseResult;
        }

        // 从 .init_array / .fini_array 补充未在符号表中的函数（balanced/max_coverage）
        Set<Long> knownOffsets = new java.util.HashSet<>();
        for (NativeFunction f : funcSet) knownOffsets.add(f.getOffset());

        try {
            ElfSectionHeader initHdr = null, finiHdr = null;
            ElfSectionHeader textHdr = null;
            List<ElfSection> relaSections = new ArrayList<>();
            for (int i = 0; i < numSections; i++) {
                ElfSection sec = elfFile.getSection(i);
                String sname = sec.header.getName();
                if (sname == null) sname = "";
                if (sname.equals(".init_array")) initHdr = sec.header;
                else if (sname.equals(".fini_array")) finiHdr = sec.header;
                else if (sname.equals(".text")) textHdr = sec.header;
                else if (sname.equals(".rela.dyn") || sname.equals(".rela.plt"))
                    relaSections.add(sec);
            }

            RandomAccessFile raf = new RandomAccessFile(new File(soPath), "r");

            // 收集重定位覆盖的 init_array/fini_array 槽位地址
            Set<Long> relaSlots = new java.util.HashSet<>();

            // 优先从重定位表解析 (PIE SO 中 init_array 的真实值在重定位条目里)
            if ((initHdr != null || finiHdr != null) && !relaSections.isEmpty()) {
                for (ElfSection relaSec : relaSections) {
                    long relaOff = relaSec.header.sh_offset;
                    long relaSize = relaSec.header.sh_size;
                    byte[] relaData = new byte[(int) Math.min(relaSize, 2 * 1024 * 1024)];
                    raf.seek(relaOff);
                    raf.readFully(relaData);
                    for (int ri = 0; ri + 24 <= relaData.length; ri += 24) {
                        long rOffset = readLong64(relaData, ri);
                        long rInfo = readLong64(relaData, ri + 8);
                        long rAddend = readLong64(relaData, ri + 16);
                        int rType = (int) (rInfo & 0xFFFFFFFFL);
                        if (rType != 0x403 || rAddend == 0) continue; // R_AARCH64_RELATIVE

                        boolean isInit = initHdr != null && rOffset >= initHdr.sh_addr
                                && rOffset < initHdr.sh_addr + initHdr.sh_size;
                        boolean isFini = finiHdr != null && rOffset >= finiHdr.sh_addr
                                && rOffset < finiHdr.sh_addr + finiHdr.sh_size;

                        if (isInit || isFini) {
                            relaSlots.add(rOffset);
                            if (!knownOffsets.contains(rAddend)) {
                                String label = String.format("sub_%X", rAddend);
                                String src = isInit ? "init_array" : "fini_array";
                                funcSet.add(new NativeFunction(label, rAddend, 0, src));
                                knownOffsets.add(rAddend);
                                Log.d(TAG, src + " rela: " + label);
                            }
                        }
                    }
                }
            }

            // 直接读取 init_array/fini_array 内容 (仅读取没有被重定位覆盖的槽位)
            ElfSectionHeader[] arrayHdrs = {initHdr, finiHdr};
            String[] arrayNames = {"init_array", "fini_array"};
            for (int a = 0; a < arrayHdrs.length; a++) {
                ElfSectionHeader hdr = arrayHdrs[a];
                if (hdr == null || hdr.sh_size == 0) continue;
                long off = hdr.sh_offset;
                int count = (int) Math.min(hdr.sh_size, 4096);
                byte[] data = new byte[count];
                raf.seek(off);
                raf.readFully(data);
                for (int p = 0; p + 8 <= count; p += 8) {
                    long slotVa = hdr.sh_addr + p;
                    // 跳过已被重定位覆盖的槽位 (重定位的addend才是真实值)
                    if (relaSlots.contains(slotVa)) continue;
                    long addr = readLong64(data, p);
                    if (addr == 0 || addr == -1) continue;
                    if (!knownOffsets.contains(addr)) {
                        String label = String.format("sub_%X", addr);
                        funcSet.add(new NativeFunction(label, addr, 0, arrayNames[a]));
                        knownOffsets.add(addr);
                        Log.d(TAG, arrayNames[a] + " direct: " + label);
                    }
                }
            }

            // 扫描 text section 识别所有函数 (包括被剥离的)
            long textStart = (textHdr != null) ? textHdr.sh_addr : 0;
            long textEnd = (textHdr != null) ? textHdr.sh_addr + textHdr.sh_size : 0;
            long textFileOff = (textHdr != null) ? textHdr.sh_offset : 0;

            // balanced / max_coverage 都扫描所有可执行段发现函数
            // balanced 保守阈值, max_coverage 激进阈值
            if (!preciseMode) {
                discoverFunctionsInExecutableSections(raf, elfFile, funcSet, knownOffsets, maxCoverageMode);
            }

            List<Long> sortedKnownOffsets = new ArrayList<>(knownOffsets);
            sortedKnownOffsets.sort(Long::compareTo);

            // 扫描 size=0 的函数: 用RET指令确定边界, 用BL指令发现子函数
            // 构建已知函数范围表 (只包含有确切size的符号表函数) 用于排除内部地址
            List<long[]> knownRanges = new ArrayList<>();
            for (NativeFunction f : funcSet) {
                if (f.getSize() > 0) {
                    knownRanges.add(new long[]{f.getOffset(), f.getOffset() + f.getSize()});
                }
            }

            // 多轮: 第一轮扫描init/fini函数, 发现BL子函数后再扫描
            for (int round = 0; round < 3; round++) {
                List<NativeFunction> toScan = new ArrayList<>();
                for (NativeFunction f : funcSet) {
                    if (f.getSize() == 0) toScan.add(f);
                }
                if (toScan.isEmpty()) break;

                boolean discovered = false;
                for (NativeFunction f : toScan) {
                    long va = f.getOffset();
                    if (textHdr == null || va < textStart || va >= textEnd) {
                        f.setSize(256);
                        continue;
                    }

                    long fileOff = textFileOff + (va - textStart);
                    long maxScan = Math.min(textEnd - va, 65536);
                    if (maxScan < 4) { f.setSize(4); continue; }

                    byte[] code = new byte[(int) maxScan];
                    raf.seek(fileOff);
                    raf.readFully(code);

                    long nextKnownStart = findNextKnownFunctionStart(va, sortedKnownOffsets, textEnd);
                    long scanLimit = Math.min(maxScan, nextKnownStart - va);
                    if (scanLimit < 4) scanLimit = Math.min(maxScan, 256);

                    Set<Integer> reachableOffsets = collectReachableInstructionOffsets(code, va, scanLimit, knownRanges);
                    for (Integer off : reachableOffsets) {
                        if (off == null || off < 0 || off + 4 > code.length) continue;
                        int insn = readInt32(code, off);
                        if ((insn & 0xFC000000) == 0x94000000) {
                            long target = resolveBranchTarget(insn, va + off);
                            if (target >= textStart && target < textEnd
                                    && target != va && !knownOffsets.contains(target)
                                    && !isInsideKnownFunction(target, knownRanges)) {
                                String label = String.format("sub_%X", target);
                                funcSet.add(new NativeFunction(label, target, 0, "discovered"));
                                knownOffsets.add(target);
                                discovered = true;
                                Log.d(TAG, "Discovered: " + label + " (from " + f.getName() + ")");
                            }
                        }
                    }

                    long trueEnd = findFunctionEndViaCFG(code, va, scanLimit, knownRanges, reachableOffsets);
                    f.setSize(trueEnd);

                    // 新确定大小的函数加入范围表
                    knownRanges.add(new long[]{va, va + f.getSize()});
                    if (!sortedKnownOffsets.contains(va)) {
                        sortedKnownOffsets.add(va);
                        sortedKnownOffsets.sort(Long::compareTo);
                    }
                }

                if (!discovered) break;
            }

            raf.close();

        } catch (Exception e) {
            Log.w(TAG, "Failed to parse init/fini arrays: " + e.getMessage());
        }

        List<NativeFunction> result = deduplicateFunctionsByOffset(funcSet);
        clampFunctionSizesToNextStart(result);
        Log.i(TAG, "Total FUNC symbols found: " + result.size());
        return result;
    }

    private static String normalizeFunctionDiscoveryMode(String mode) {
        if ("precise".equals(mode) || "balanced".equals(mode) || "max_coverage".equals(mode)) {
            return mode;
        }
        return "balanced";
    }

    private static List<NativeFunction> deduplicateFunctionsByOffset(Set<NativeFunction> funcSet) {
        Map<Long, NativeFunction> bestByOffset = new HashMap<>();
        for (NativeFunction f : funcSet) {
            NativeFunction cur = bestByOffset.get(f.getOffset());
            if (cur == null || isBetterFunctionCandidate(f, cur)) {
                bestByOffset.put(f.getOffset(), f);
            }
        }
        List<NativeFunction> deduped = new ArrayList<>(bestByOffset.values());
        deduped.sort((a, b) -> Long.compare(a.getOffset(), b.getOffset()));
        return collapseNearbySyntheticDuplicates(deduped);
    }

    private static List<NativeFunction> collapseNearbySyntheticDuplicates(List<NativeFunction> funcs) {
        if (funcs.isEmpty()) return funcs;

        List<NativeFunction> result = new ArrayList<>();
        for (NativeFunction cur : funcs) {
            if (result.isEmpty()) {
                result.add(cur);
                continue;
            }

            NativeFunction prev = result.get(result.size() - 1);
            if (areLikelyDuplicateFunctions(prev, cur)) {
                if (isBetterFunctionCandidate(cur, prev)) {
                    result.set(result.size() - 1, cur);
                }
                continue;
            }
            result.add(cur);
        }
        return result;
    }

    private static boolean areLikelyDuplicateFunctions(NativeFunction a, NativeFunction b) {
        long diff = Math.abs(a.getOffset() - b.getOffset());
        if (diff == 0) return true;

        boolean aSynthetic = isSyntheticFunction(a);
        boolean bSynthetic = isSyntheticFunction(b);

        if (!(aSynthetic && bSynthetic)) {
            // 非合成函数（来自符号表）：只在 offset 完全相同时合并
            // 不因 size 偏大造成的 range 重叠而合并，否则相邻合法函数会被吃掉
            return diff == 0;
        }

        // 合成函数：BTI/PAC 前导与真正序言差 4 字节，允许合并
        if (diff <= 4) return true;

        // 合成函数 range 重叠也判重（大 size 已由 clamp 修正，这里是 diff>4 的安全检查）
        return rangesOverlap(a, b);
    }

    /**
     * 把每个函数的 size 裁剪到「下一个函数起始地址 - 当前起始地址」
     * 防止符号表里的 size 偏大，导致一个函数的反汇编视图包含了下一个函数的代码
     */
    private static void clampFunctionSizesToNextStart(List<NativeFunction> sorted) {
        for (int i = 0; i < sorted.size() - 1; i++) {
            NativeFunction cur  = sorted.get(i);
            NativeFunction next = sorted.get(i + 1);
            long gap = next.getOffset() - cur.getOffset();
            if (gap <= 0) continue;
            if (cur.getSize() == 0 || cur.getSize() > gap) {
                Log.d("ElfParser", String.format("clamp %s size %d -> %d",
                        cur.getName(), cur.getSize(), gap));
                cur.setSize(gap);
            }
        }
        // 最后一个函数也加限制
        if (!sorted.isEmpty()) {
            NativeFunction last = sorted.get(sorted.size() - 1);
            if (last.getSize() > MAX_FUNCTION_SIZE) {
                Log.d("ElfParser", String.format("clamp last %s size %d -> %d",
                        last.getName(), last.getSize(), MAX_FUNCTION_SIZE));
                last.setSize(MAX_FUNCTION_SIZE);
            }
        }
    }

    private static boolean isSyntheticFunction(NativeFunction f) {
        String name = f.getName();
        String source = f.getSource();
        boolean syntheticName = name != null && name.startsWith("sub_");
        boolean syntheticSource = "text_scan".equals(source)
                || "discovered".equals(source)
                || "init_array".equals(source)
                || "fini_array".equals(source);
        return syntheticName || syntheticSource;
    }

    private static boolean rangesOverlap(NativeFunction a, NativeFunction b) {
        long aStart = a.getOffset();
        long bStart = b.getOffset();

        long aSize = a.getSize();
        long bSize = b.getSize();

        long aEnd = aSize > 0 ? aStart + aSize : aStart + 1;
        long bEnd = bSize > 0 ? bStart + bSize : bStart + 1;

        return aStart < bEnd && bStart < aEnd;
    }

    private static boolean isBetterFunctionCandidate(NativeFunction candidate, NativeFunction current) {
        int cScore = scoreFunctionCandidate(candidate);
        int curScore = scoreFunctionCandidate(current);
        return cScore > curScore;
    }

    private static int scoreFunctionCandidate(NativeFunction f) {
        int score = 0;
        String name = f.getName();
        String source = f.getSource();
        if (f.getSize() > 0) score += 2;
        if (name != null && !name.startsWith("sub_")) score += 4;
        if ("symtab".equals(source)) score += 4;
        if ("dynsym".equals(source)) score += 3;
        if ("init_array".equals(source) || "fini_array".equals(source)) score += 2;
        if ("discovered".equals(source) || "text_scan".equals(source)) score += 1;
        return score;
    }

    private static boolean isInsideKnownFunction(long addr, List<long[]> ranges) {
        for (long[] r : ranges) {
            if (addr >= r[0] && addr < r[1]) return true;
        }
        return false;
    }

    private static boolean hasStrongEntryPattern(byte[] code, int off) {
        if (off < 0 || off + 4 > code.length) return false;
        int insn0 = readInt32(code, off);
        if ((insn0 & 0xFFC003FF) == 0xA9807BFD || (insn0 & 0xFFC003FF) == 0xA9007BFD) {
            return true;
        }
        if (insn0 == 0x910003FD) {
            return true;
        }
        return isPreludeToStrongPrologue(code, off);
    }

    private static boolean isPreludeToStrongPrologue(byte[] code, int off) {
        if (off < 0 || off + 8 > code.length) return false;
        int insn0 = readInt32(code, off);
        if (insn0 != 0xD503241F && insn0 != 0xD503233F && insn0 != 0xD503233D) {
            return false;
        }
        int insn1 = readInt32(code, off + 4);
        return (insn1 & 0xFFC003FF) == 0xA9807BFD
                || (insn1 & 0xFFC003FF) == 0xA9007BFD
                || insn1 == 0x910003FD;
    }

    private static boolean isLikelyFunctionEntry(byte[] code, int off, long va) {
        return isLikelyFunctionEntry(code, off, va, false);
    }

    private static boolean isLikelyFunctionEntry(byte[] code, int off, long va, boolean aggressive) {
        if (off < 0 || off + 4 > code.length) return false;

        int entryScore = 0;
        int insn0 = readInt32(code, off);
        if (isFunctionPrologue(insn0)) entryScore += 2;

        if (looksLikeDirectTailCall(insn0) || looksLikeUnconditionalBranch(insn0)) {
            return false;
        }

        if (off + 8 <= code.length) {
            int insn1 = readInt32(code, off + 4);
            if (isFunctionPrologue(insn1)) entryScore += 1;
            if (insn0 == 0xD503241F && isFunctionPrologue(insn1)) entryScore += 1;
            if ((insn0 == 0xD503233F || insn0 == 0xD503233D) && isFunctionPrologue(insn1)) entryScore += 1;
        }

        int boundaryScore = 0;
        if (off == 0) {
            boundaryScore += 1;
        } else {
            int prevInsn = readInt32(code, off - 4);
            if (looksLikeFunctionEnd(prevInsn)) boundaryScore += 2;
            if ((va % 16 == 0) && prevInsn == 0xD503201F) boundaryScore += 1;
            if ((va % 16 == 0) || (va % 32 == 0)) boundaryScore += 1;
        }

        if (!hasForwardExecutionWindow(code, off)) {
            return false;
        }

        if (entryScore < 3 || boundaryScore < 2) {
            if (!aggressive) return false;
        }

        if ((va & 3) != 0) return false;

        if (entryScore >= 5) return true;

        if (aggressive) {
            if (entryScore >= 4 && boundaryScore >= 1) return true;
            if (entryScore >= 3 && boundaryScore >= 1 && hasStrongEntryPattern(code, off)) return true;
            if (isPreludeToStrongPrologue(code, off) && boundaryScore >= 1) return true;
        }

        return (entryScore >= 4 && boundaryScore >= 3);
    }

    private static boolean hasReasonableCallTargetShape(byte[] code, int off) {
        if (off < 0 || off + 4 > code.length) return false;
        int insn0 = readInt32(code, off);
        if (isFunctionPrologue(insn0) && hasForwardExecutionWindow(code, off)) return true;

        if (off + 8 <= code.length) {
            int insn1 = readInt32(code, off + 4);
            if (insn0 == 0xD503241F && isFunctionPrologue(insn1) && hasForwardExecutionWindow(code, off)) return true;
            if ((insn0 == 0xD503233F || insn0 == 0xD503233D) && isFunctionPrologue(insn1) && hasForwardExecutionWindow(code, off)) return true;
        }
        return false;
    }

    /**
     * 扫描所有可执行段识别函数 (处理被剥离符号的SO)
     * balanced / max_coverage 都会调用, aggressive 参数控制阈值
     */
    private static void discoverFunctionsInExecutableSections(
            RandomAccessFile raf, ElfFile elfFile,
            Set<NativeFunction> funcSet, Set<Long> knownOffsets,
            boolean aggressive) throws IOException {

        int totalDiscovered = 0;

        for (int i = 0; i < elfFile.e_shnum; i++) {
            ElfSectionHeader h = elfFile.getSection(i).header;
            if (!isExecutableSection(h) || h.sh_size <= 0) continue;

            int discovered = scanSegmentForFunctions(raf, h.sh_addr, h.sh_addr + h.sh_size,
                    h.sh_offset, funcSet, knownOffsets, aggressive);
            totalDiscovered += discovered;
        }

        Log.i(TAG, "Executable scan discovered " + totalDiscovered + " functions total (aggressive=" + aggressive + ")");
    }

    private static int scanSegmentForFunctions(
            RandomAccessFile raf, long segStart, long segEnd, long segFileOff,
            Set<NativeFunction> funcSet, Set<Long> knownOffsets,
            boolean aggressive) throws IOException {

        if (segStart == 0 || segEnd <= segStart) return 0;

        long segSize = segEnd - segStart;
        if (segSize > 50 * 1024 * 1024) segSize = 50 * 1024 * 1024;

        byte[] code = new byte[(int) segSize];
        raf.seek(segFileOff);
        raf.readFully(code);

        List<Long> funcStarts = new ArrayList<>();
        Map<Long, Integer> callTargetCount = new HashMap<>();

        for (int off = 0; off + 4 <= code.length; off += 4) {
            long va = segStart + off;

            if (isLikelyFunctionEntry(code, off, va, aggressive)) {
                if (!knownOffsets.contains(va)) {
                    funcStarts.add(va);
                }
            }

            int insn = readInt32(code, off);
            if ((insn & 0xFC000000) == 0x94000000) {
                int imm26 = insn & 0x03FFFFFF;
                if ((imm26 & 0x02000000) != 0) imm26 |= 0xFC000000;
                long target = va + (long) imm26 * 4;
                if (target >= segStart && target < segEnd) {
                    callTargetCount.put(target, callTargetCount.getOrDefault(target, 0) + 1);
                }
            }
        }

        int blThresh = aggressive ? 2 : 3;
        int blThreshShape = aggressive ? 4 : 6;

        for (Map.Entry<Long, Integer> e : callTargetCount.entrySet()) {
            long target = e.getKey();
            int count = e.getValue();
            if (knownOffsets.contains(target)) continue;
            int targetOff = (int) (target - segStart);
            if (targetOff < 0 || targetOff + 4 > code.length) continue;
            if ((count >= blThresh && isLikelyFunctionEntry(code, targetOff, target, aggressive)) ||
                    (count >= blThreshShape && hasReasonableCallTargetShape(code, targetOff))) {
                funcStarts.add(target);
            }
        }

        // aggressive 模式下额外识别 ADRP 开头的 il2cpp 函数
        if (aggressive) {
            for (int off = 0; off + 8 <= code.length; off += 4) {
                long va = segStart + off;
                if (knownOffsets.contains(va) || funcStarts.contains(va)) continue;

                int insn0 = readInt32(code, off);
                // ADRP: (insn & 0x9F000000) == 0x90000000
                if ((insn0 & 0x9F000000) != 0x90000000) continue;

                int insn1 = readInt32(code, off + 4);
                boolean usesAdrp = false;
                // ADD (immediate, 32/64-bit)
                if ((insn1 & 0x1F000000) == 0x11000000) usesAdrp = true;
                // LDR (literal)
                if ((insn1 & 0x3F000000) == 0x18000000) usesAdrp = true;
                // LDR (unsigned offset, 32-bit)
                if ((insn1 & 0xBFE00C00) == 0xB9400000) usesAdrp = true;
                // STR (unsigned offset, 32-bit)
                if ((insn1 & 0xBFE00C00) == 0xB9000000) usesAdrp = true;

                if (!usesAdrp) continue;

                boolean boundaryOk = false;
                if (off == 0) boundaryOk = true;
                else {
                    int prevInsn = readInt32(code, off - 4);
                    if (looksLikeFunctionEnd(prevInsn)) boundaryOk = true;
                    if (prevInsn == 0xD503201F && (va % 16 == 0)) boundaryOk = true;
                }

                if (boundaryOk && (va % 4 == 0)) {
                    Integer blCount = callTargetCount.get(va);
                    if (blCount != null && blCount >= 1) {
                        funcStarts.add(va);
                    }
                }
            }
        }

        List<Long> normalizedStarts = normalizeFunctionStarts(funcStarts, code, segStart);

        List<Long> validStarts = new ArrayList<>();
        for (long funcAddr : normalizedStarts) {
            int off = (int) (funcAddr - segStart);
            if (off < 0 || off >= code.length) continue;

            long estimatedSize = estimateFunctionSize(code, off, funcAddr, knownOffsets, segEnd);
            if (estimatedSize > 65536) {
                // 超大函数先给 size=0, 后续 BL 扫描再定
                estimatedSize = 0;
            }
            if (estimatedSize > 16384 && !aggressive) {
                Log.d(TAG, "Scan rejected too large (conservative): " + String.format("sub_%X (size=%d)", funcAddr, estimatedSize));
                continue;
            }
            validStarts.add(funcAddr);
        }

        for (long funcAddr : validStarts) {
            String label = String.format("sub_%X", funcAddr);
            funcSet.add(new NativeFunction(label, funcAddr, 0, "text_scan"));
            knownOffsets.add(funcAddr);
            Log.d(TAG, "Text scan discovered: " + label);
        }

        return validStarts.size();
    }

    private static List<Long> normalizeFunctionStarts(List<Long> starts, byte[] code, long textStart) {
        if (starts.isEmpty()) return starts;

        starts.sort(Long::compareTo);

        // 一次归一：把 BTI/PAC 前导链映射到统一入口（最早前导地址）
        LinkedHashMap<Long, Boolean> canonicalStarts = new LinkedHashMap<>();
        for (Long start : starts) {
            if (start == null) continue;
            long canonical = canonicalizeFunctionStart(start, code, textStart);
            canonicalStarts.put(canonical, true);
        }

        // 二次归一：如果多个入口最终指向同一个核心序言（如 STP x29, x30）则折叠
        List<Long> sorted = new ArrayList<>(canonicalStarts.keySet());
        sorted.sort(Long::compareTo);

        List<Long> finalStarts = new ArrayList<>();
        for (Long addr : sorted) {
            if (addr == null) continue;
            if (finalStarts.isEmpty()) {
                finalStarts.add(addr);
                continue;
            }

            long prev = finalStarts.get(finalStarts.size() - 1);
            if (shouldCollapseNearbyStarts(prev, addr, code, textStart)) {
                continue;
            }
            finalStarts.add(addr);
        }

        return finalStarts;
    }

    private static long canonicalizeFunctionStart(long startAddr, byte[] code, long textStart) {
        int off = (int) (startAddr - textStart);
        if (off < 0 || off + 4 > code.length) return startAddr;

        int current = off;
        for (int i = 0; i < 3; i++) {
            int prev = current - 4;
            if (prev < 0 || prev + 4 > code.length) break;
            int prevInsn = readInt32(code, prev);
            if (!isPreludeInsn(prevInsn)) break;
            current = prev;
        }
        return textStart + current;
    }

    private static boolean shouldCollapseNearbyStarts(long prevAddr, long curAddr, byte[] code, long textStart) {
        long diff = curAddr - prevAddr;
        if (diff <= 0) return true;
        if (diff > 12) return false;

        long prevCore = findCorePrologueAddress(prevAddr, code, textStart);
        long curCore = findCorePrologueAddress(curAddr, code, textStart);
        return prevCore > 0 && prevCore == curCore;
    }

    private static long findCorePrologueAddress(long startAddr, byte[] code, long textStart) {
        int off = (int) (startAddr - textStart);
        if (off < 0 || off + 4 > code.length) return -1;

        for (int i = 0; i < 4; i++) {
            int pos = off + i * 4;
            if (pos < 0 || pos + 4 > code.length) break;
            int insn = readInt32(code, pos);
            if (isCoreFunctionPrologue(insn)) {
                return textStart + pos;
            }
            if (!isPreludeInsn(insn)) {
                break;
            }
        }
        return -1;
    }

    private static boolean isPreludeToFunction(byte[] code, long textStart, long preludeAddr, long entryAddr) {
        int preludeOff = (int) (preludeAddr - textStart);
        int entryOff = (int) (entryAddr - textStart);
        if (preludeOff < 0 || entryOff < 0 || preludeOff + 4 > code.length || entryOff + 4 > code.length) {
            return false;
        }

        int preludeInsn = readInt32(code, preludeOff);
        int entryInsn = readInt32(code, entryOff);

        boolean preludeLike = preludeInsn == 0xD503241F // BTI c
                || preludeInsn == 0xD503233F            // PACIASP
                || preludeInsn == 0xD503233D;           // PACIBSP

        return preludeLike && isFunctionPrologue(entryInsn);
    }

    private static boolean isPreludeInsn(int insn) {
        return insn == 0xD503241F // BTI c
                || insn == 0xD503233F // PACIASP
                || insn == 0xD503233D; // PACIBSP
    }

    private static boolean isCoreFunctionPrologue(int insn) {
        if ((insn & 0xFFC003FF) == 0xA9807BFD || (insn & 0xFFC003FF) == 0xA9007BFD) {
            return true;
        }
        return insn == 0x910003FD;
    }

    /**
     * 检查指令是否是 AArch64 函数序言
     * 只识别真正可靠的函数入口特征，避免函数内部的指令被误判
     */
    private static boolean isFunctionPrologue(int insn) {
        // STP x29, x30, [sp, #-16]! - 最标准的函数序言（保存帧指针和返回地址）
        // 0xA9... 范围包含多种 STP 形式
        if ((insn & 0xFFC003FF) == 0xA9807BFD || (insn & 0xFFC003FF) == 0xA9007BFD) {
            return true;
        }
        // STP x29, x30, [sp, #imm] - 部分函数会先保存帧指针/返回地址
        if ((insn & 0xFFC003FF) == 0xA9007BFD) {
            return true;
        }
        // MOV x29, sp (ADD x29, sp, #0) = 0x910003FD - 建立栈帧
        if (insn == 0x910003FD) {
            return true;
        }
        // PACIASP (0xD503233F) 或 PACIBSP - 有指针认证的函数开头
        if (insn == 0xD503233F || insn == 0xD503233D) {
            return true;
        }
        // BTI c (0xD503241F) - Branch Target Identification，编译器插入的函数入口标记
        if (insn == 0xD503241F) {
            return true;
        }
        // 注意：不识别 SUB sp, sp, #imm 和 ADRP，因为它们在函数内部太常见
        // SUB sp 可能在函数中途分配大块栈空间时出现
        // ADRP 用于访问全局变量，几乎遍布整个函数
        return false;
    }

    private static boolean hasForwardExecutionWindow(byte[] code, int off) {
        int remaining = code.length - off;
        if (remaining < 12) return false;
        int checkCount = Math.min(4, remaining / 4);
        int terminalCount = 0;
        for (int i = 0; i < checkCount; i++) {
            int insn = readInt32(code, off + i * 4);
            if (looksLikeFunctionEnd(insn) || looksLikeDirectTailCall(insn)) {
                terminalCount++;
            }
        }
        return terminalCount < checkCount;
    }

    private static boolean looksLikeDirectTailCall(int insn) {
        return (insn & 0xFC000000) == 0x14000000;
    }

    private static boolean looksLikeUnconditionalBranch(int insn) {
        return (insn & 0xFF000010) == 0x54000000 || (insn & 0xFC000000) == 0x14000000;
    }

    private static final long MAX_FUNCTION_SIZE = 16384; // 16KB hard cap

    private static long estimateFunctionSize(byte[] code, int off, long va, Set<Long> knownOffsets, long textEnd) {
        int maxScan = Math.min(code.length - off, (int) MAX_FUNCTION_SIZE);

        // 找到第一个 RET/terminal 指令，并检查其后是否为函数边界
        for (int i = 0; i + 4 <= maxScan; i += 4) {
            int insn = readInt32(code, off + i);
            if (looksLikeFunctionEnd(insn)) {
                long candidateEnd = i + 4;
                // 检查后续是否为新函数入口、对齐NOP或已知函数
                if (candidateEnd >= maxScan) {
                    return candidateEnd;
                }
                int nextOff = off + (int) candidateEnd;
                if (nextOff + 4 > code.length) {
                    return candidateEnd;
                }
                long nextVa = va + candidateEnd;
                // 下一条是已知函数起始
                if (knownOffsets.contains(nextVa)) {
                    return candidateEnd;
                }
                int nextInsn = readInt32(code, nextOff);
                // 下一条是函数 prologue
                if (isFunctionPrologue(nextInsn)) {
                    return candidateEnd;
                }
                // 下一条是 NOP 对齐 (0xD503201F) 或 BTI (0xD503241F)
                if (nextInsn == 0xD503201F || nextInsn == 0xD503241F) {
                    return candidateEnd;
                }
                // 下一条是零填充
                if (nextInsn == 0x00000000) {
                    return candidateEnd;
                }
                // RET 后面是非终止指令，可能是多路径函数，继续扫描
            }
        }
        // 未找到明确终止，返回 maxScan
        return maxScan;
    }

    private static long findNextKnownFunctionStart(long current, List<Long> sortedKnownOffsets, long textEnd) {
        for (Long offset : sortedKnownOffsets) {
            if (offset != null && offset > current) {
                return offset;
            }
        }
        return textEnd;
    }

    private static long findNextVerifiedFunctionStart(long current, List<Long> sortedKnownOffsets, long textEnd, byte[] code) {
        for (Long offset : sortedKnownOffsets) {
            if (offset == null || offset <= current) continue;
            int relOff = (int) (offset - current);
            if (relOff < 0 || relOff >= code.length) continue;

            boolean prologueOk = false;
            boolean prevEndOk = false;

            if (relOff + 4 <= code.length) {
                int insnAtCandidate = readInt32(code, relOff);
                prologueOk = isFunctionPrologue(insnAtCandidate);
            }

            if (relOff >= 4) {
                int prevInsn = readInt32(code, relOff - 4);
                prevEndOk = looksLikeFunctionEnd(prevInsn);
            }

            if (prologueOk && prevEndOk) {
                return offset;
            }
        }
        return textEnd;
    }

    private static Set<Integer> collectReachableInstructionOffsets(byte[] code, long funcStart, long maxScan, List<long[]> knownRanges) {
        Set<Integer> visited = new HashSet<>();
        Queue<Integer> queue = new LinkedList<>();
        queue.add(0);
        visited.add(0);

        while (!queue.isEmpty()) {
            int off = queue.poll();
            if (off < 0 || off + 4 > code.length || off >= maxScan) continue;

            long va = funcStart + off;
            if (off > 0 && isInsideKnownFunction(va, knownRanges)) {
                continue;
            }

            int insn = readInt32(code, off);
            if (isTerminalReturn(insn) || isIndirectBranchTerminator(insn)) {
                continue;
            }

            if (isConditionalBranch(insn)) {
                int targetOff = getBranchTargetOffset(insn, off);
                if (targetOff >= 0 && targetOff < maxScan && !visited.contains(targetOff)) {
                    visited.add(targetOff);
                    queue.add(targetOff);
                }
                int fallthrough = off + 4;
                if (fallthrough < maxScan && !visited.contains(fallthrough)) {
                    visited.add(fallthrough);
                    queue.add(fallthrough);
                }
                continue;
            }

            if (isUnconditionalBranch(insn)) {
                int targetOff = getBranchTargetOffset(insn, off);
                if (targetOff >= 0 && targetOff < maxScan && !visited.contains(targetOff)) {
                    visited.add(targetOff);
                    queue.add(targetOff);
                }
                continue;
            }

            int fallthrough = off + 4;
            if (fallthrough < maxScan && !visited.contains(fallthrough)) {
                visited.add(fallthrough);
                queue.add(fallthrough);
            }
        }

        return visited;
    }

    private static long findFunctionEndViaCFG(byte[] code, long funcStart, long maxScan, List<long[]> knownRanges, Set<Integer> reachableOffsets) {
        if (reachableOffsets == null || reachableOffsets.isEmpty()) return maxScan;

        long farthestEnd = 0;

        for (Integer offObj : reachableOffsets) {
            if (offObj == null) continue;
            int off = offObj;
            if (off < 0 || off + 4 > code.length || off >= maxScan) continue;
            int insn = readInt32(code, off);
            long va = funcStart + off;

            if (off > 0 && isInsideKnownFunction(va, knownRanges)) {
                continue;
            }

            if (isTerminalReturn(insn) || isIndirectBranchTerminator(insn)) {
                farthestEnd = Math.max(farthestEnd, off + 4L);
                continue;
            }

            if (isUnconditionalBranch(insn)) {
                int targetOff = getBranchTargetOffset(insn, off);
                if (targetOff < 0 || targetOff >= maxScan || !reachableOffsets.contains(targetOff)) {
                    farthestEnd = Math.max(farthestEnd, off + 4L);
                }
            }
        }

        if (farthestEnd > 0) return farthestEnd;
        long farthestReachable = 0;
        for (Integer offObj : reachableOffsets) {
            if (offObj == null) continue;
            int off = offObj;
            if (off >= 0 && off < maxScan) {
                farthestReachable = Math.max(farthestReachable, off + 4L);
            }
        }
        return farthestReachable > 0 ? farthestReachable : maxScan;
    }

    private static int getBranchTargetOffset(int insn, int off) {
        if ((insn & 0xFC000000) == 0x14000000) {
            int imm26 = insn & 0x03FFFFFF;
            if ((imm26 & 0x02000000) != 0) imm26 |= 0xFC000000;
            return off + (int) imm26 * 4;
        }
        if ((insn & 0xFF000010) == 0x54000000) {
            int imm19 = insn & 0x0007FFFF;
            imm19 = (imm19 << 13) >> 13;
            return off + (int) imm19 * 4;
        }
        if ((insn & 0x7E000000) == 0x34000000) {
            int imm19 = insn & 0x0007FFFF;
            imm19 = (imm19 << 13) >> 13;
            return off + (int) imm19 * 4;
        }
        if ((insn & 0x7E000000) == 0x36000000) {
            int imm14 = insn & 0x00003FFF;
            imm14 = (imm14 << 18) >> 18;
            return off + (int) imm14 * 4;
        }
        return -1;
    }

    private static long resolveBranchTarget(int insn, long address) {
        if ((insn & 0xFC000000) == 0x14000000 || (insn & 0xFC000000) == 0x94000000) {
            int imm26 = insn & 0x03FFFFFF;
            if ((imm26 & 0x02000000) != 0) imm26 |= 0xFC000000;
            return address + (long) imm26 * 4;
        }
        if ((insn & 0xFF000010) == 0x54000000) {
            int imm19 = insn & 0x0007FFFF;
            imm19 = (imm19 << 13) >> 13;
            return address + (long) imm19 * 4;
        }
        if ((insn & 0x7E000000) == 0x34000000) {
            int imm19 = insn & 0x0007FFFF;
            imm19 = (imm19 << 13) >> 13;
            return address + (long) imm19 * 4;
        }
        if ((insn & 0x7E000000) == 0x36000000) {
            int imm14 = insn & 0x00003FFF;
            imm14 = (imm14 << 18) >> 18;
            return address + (long) imm14 * 4;
        }
        return -1;
    }

    private static boolean isUnconditionalBranch(int insn) {
        return (insn & 0xFC000000) == 0x14000000;
    }

    private static boolean isConditionalBranch(int insn) {
        return (insn & 0xFF000010) == 0x54000000
                || (insn & 0x7E000000) == 0x34000000
                || (insn & 0x7E000000) == 0x36000000;
    }

    private static boolean isTerminalReturn(int insn) {
        return insn == 0xD65F03C0 || (insn & 0xFFFFF000) == 0xD65F0000;
    }

    private static boolean isIndirectBranchTerminator(int insn) {
        return (insn & 0xFFFFFC1F) == 0xD61F0000;
    }

    /**
     * 检查指令是否像函数结尾
     */
    private static boolean looksLikeFunctionEnd(int insn) {
        // RET (0xD65F03C0)
        if (insn == 0xD65F03C0) return true;
        // RETAA/RETAB (0xD65F0FFF, 0xD65F0FFD)
        if ((insn & 0xFFFFF000) == 0xD65F0000) return true;
        // B (无条件跳转) - 0x14000000
        if ((insn & 0xFC000000) == 0x14000000) return true;
        // BR x? (跳转寄存器) - 0xD61F0000
        if ((insn & 0xFFFFFC1F) == 0xD61F0000) return true;
        // CBNZ/CBZ (条件跳转在结尾也可能)
        // NOP - 对齐
        if (insn == 0xD503201F) return true;
        return false;
    }

    private static long readLong64(byte[] data, int off) {
        long val = 0;
        for (int i = 7; i >= 0; i--) {
            val = (val << 8) | (data[off + i] & 0xFFL);
        }
        return val;
    }

    private static int readInt32(byte[] data, int off) {
        return (data[off] & 0xFF) | ((data[off + 1] & 0xFF) << 8)
                | ((data[off + 2] & 0xFF) << 16) | ((data[off + 3] & 0xFF) << 24);
    }

    /**
     * 将虚拟地址转换为文件偏移 (通过读取ELF Program Headers)
     * 用于静态分析模式从文件读取函数字节码
     * @param soPath SO文件路径
     * @param virtualAddr 虚拟地址 (即 st_value)
     * @return 文件偏移, 如果无法转换则返回 virtualAddr 本身
     */
    public static long virtualAddrToFileOffset(String soPath, long virtualAddr) {
        try {
            RandomAccessFile raf = new RandomAccessFile(soPath, "r");
            byte[] ehdr = new byte[64];
            raf.readFully(ehdr);

            boolean is64 = ehdr[4] == 2;
            if (!is64) { raf.close(); return virtualAddr; }

            // e_phoff (偏移 32, 8 bytes), e_phentsize (偏移 54, 2 bytes), e_phnum (偏移 56, 2 bytes)
            long phoff = readLong64(ehdr, 32);
            int phentsize = (ehdr[54] & 0xFF) | ((ehdr[55] & 0xFF) << 8);
            int phnum = (ehdr[56] & 0xFF) | ((ehdr[57] & 0xFF) << 8);

            for (int i = 0; i < phnum; i++) {
                byte[] phdr = new byte[phentsize];
                raf.seek(phoff + (long) i * phentsize);
                raf.readFully(phdr);

                int pType = readInt32(phdr, 0);
                if (pType != 1) continue; // PT_LOAD = 1

                long pOffset = readLong64(phdr, 8);
                long pVaddr = readLong64(phdr, 16);
                long pFilesz = readLong64(phdr, 32);
                long pMemsz = readLong64(phdr, 40);

                if (virtualAddr >= pVaddr && virtualAddr < pVaddr + pFilesz) {
                    raf.close();
                    return pOffset + (virtualAddr - pVaddr);
                }
            }
            raf.close();
        } catch (Exception e) {
            Log.w(TAG, "VA to file offset conversion failed: " + e.getMessage());
        }
        return virtualAddr;
    }

    /**
     * 字符串条目
     */
    public static class StringEntry {
        public final long virtualAddress; // 在内存中的虚拟地址 (基址 + 这个值 = 运行时地址)
        public final String value;
        public final String section;

        public StringEntry(long virtualAddress, String value, String section) {
            this.virtualAddress = virtualAddress;
            this.value = value;
            this.section = section;
        }
    }

    /**
     * 从SO文件中提取可打印字符串 (最短4个字符)
     */
    public static List<StringEntry> parseStrings(String soPath) throws IOException {
        List<StringEntry> strings = new ArrayList<>();
        ElfFile elfFile = safeOpenElf(soPath);
        int numSections = elfFile.e_shnum;

        try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
            for (int i = 0; i < numSections; i++) {
                ElfSection section = elfFile.getSection(i);
                ElfSectionHeader hdr = section.header;
                String secName = hdr.getName();

                // 只搜索可能包含字符串的节
                if (secName == null) continue;
                if (!secName.equals(".rodata") && !secName.equals(".data") &&
                    !secName.equals(".dynstr") && !secName.equals(".strtab") &&
                    !secName.startsWith(".rodata.")) continue;

                long fileOff = hdr.sh_offset;
                long secSize = hdr.sh_size;
                long virtAddr = hdr.sh_addr;

                if (secSize <= 0 || secSize > 10 * 1024 * 1024) continue; // 跳过太大的节

                byte[] data = new byte[(int) secSize];
                raf.seek(fileOff);
                raf.readFully(data);

                // 扫描ASCII字符串 (最短4字节)
                int strStart = -1;
                for (int j = 0; j <= data.length; j++) {
                    boolean isPrintable = j < data.length && data[j] >= 0x20 && data[j] < 0x7F;
                    if (isPrintable) {
                        if (strStart < 0) strStart = j;
                    } else {
                        if (strStart >= 0) {
                            int len = j - strStart;
                            if (len >= 4 && j < data.length && data[j] == 0) {
                                String str = new String(data, strStart, len, "US-ASCII");
                                strings.add(new StringEntry(virtAddr + strStart, str, secName));
                            }
                            strStart = -1;
                        }
                    }
                }
            }
        }

        Log.i(TAG, "Extracted " + strings.size() + " strings");
        return strings;
    }

    /**
     * 段信息
     */
    public static class SectionInfo {
        public final int index;
        public final String name;
        public final int type;
        public final long flags;
        public final long virtualAddress;
        public final long offset;
        public final long size;
        public final long entSize;

        public SectionInfo(int index, String name, int type, long flags,
                           long virtualAddress, long offset, long size, long entSize) {
            this.index = index;
            this.name = name;
            this.type = type;
            this.flags = flags;
            this.virtualAddress = virtualAddress;
            this.offset = offset;
            this.size = size;
            this.entSize = entSize;
        }

        public String getTypeName() {
            switch (type) {
                case 0: return "NULL";
                case 1: return "PROGBITS";
                case 2: return "SYMTAB";
                case 3: return "STRTAB";
                case 4: return "RELA";
                case 5: return "HASH";
                case 6: return "DYNAMIC";
                case 7: return "NOTE";
                case 8: return "NOBITS";
                case 9: return "REL";
                case 11: return "DYNSYM";
                case 14: return "INIT_ARRAY";
                case 15: return "FINI_ARRAY";
                case 0x6ffffff6: return "GNU_HASH";
                case 0x6ffffffd: return "VERDEF";
                case 0x6ffffffe: return "VERNEED";
                case 0x6fffffff: return "VERSYM";
                default: return String.format("0x%X", type);
            }
        }

        public String getFlagsString() {
            StringBuilder sb = new StringBuilder();
            if ((flags & 0x1) != 0) sb.append("W");
            if ((flags & 0x2) != 0) sb.append("A");
            if ((flags & 0x4) != 0) sb.append("X");
            if (sb.length() == 0) sb.append("-");
            return sb.toString();
        }
    }

    /**
     * 解析SO文件的所有段(Section)信息
     */
    public static List<SectionInfo> parseSections(String soPath) throws IOException {
        List<SectionInfo> sections = new ArrayList<>();
        ElfFile elfFile = safeOpenElf(soPath);

        for (int i = 0; i < elfFile.e_shnum; i++) {
            ElfSection section = elfFile.getSection(i);
            ElfSectionHeader hdr = section.header;
            String name = hdr.getName();
            if (name == null) name = "";

            sections.add(new SectionInfo(
                    i,
                    name,
                    hdr.sh_type,
                    hdr.sh_flags,
                    hdr.sh_addr,
                    hdr.sh_offset,
                    hdr.sh_size,
                    hdr.sh_entsize
            ));
        }

        Log.i(TAG, "Parsed " + sections.size() + " sections");
        return sections;
    }

    /**
     * 解析PLT (Procedure Linkage Table)
     * 通过 .rela.plt 重定位表正确关联PLT条目和符号名
     */
    public static List<PltEntry> parsePlt(String soPath) throws IOException {
        List<PltEntry> pltEntries = new ArrayList<>();
        ElfFile elfFile = safeOpenElf(soPath);

        // 获取.dynsym用于解析符号
        ElfSymbolTableSection dynsym = null;
        for (int i = 0; i < elfFile.e_shnum; i++) {
            ElfSection sec = elfFile.getSection(i);
            if (sec.header.sh_type == ElfSectionHeader.SHT_DYNSYM) {
                dynsym = (ElfSymbolTableSection) sec;
                break;
            }
        }

        // 查找.plt节
        ElfSection pltSection = null;
        ElfSection gotPltSection = null;
        for (int i = 0; i < elfFile.e_shnum; i++) {
            ElfSection sec = elfFile.getSection(i);
            String name = sec.header.getName();
            if (".plt".equals(name)) {
                pltSection = sec;
            }
            if (".got.plt".equals(name) || ".got".equals(name)) {
                gotPltSection = sec;
            }
        }

        if (pltSection == null || dynsym == null) {
            Log.w(TAG, "No .plt section or .dynsym found");
            return pltEntries;
        }

        long pltAddr = pltSection.header.sh_addr;
        long pltSize = pltSection.header.sh_size;

        Log.i(TAG, String.format(".plt: addr=0x%X size=0x%X", pltAddr, pltSize));

        // 查找 .rela.plt 重定位表 (SHT_RELA = 4)
        ElfSection relaPltSection = null;
        for (int i = 0; i < elfFile.e_shnum; i++) {
            ElfSection sec = elfFile.getSection(i);
            if (sec.header.sh_type == 4) { // SHT_RELA
                String name = sec.header.getName();
                if (name != null && name.contains("rela.plt")) {
                    relaPltSection = sec;
                    break;
                }
            }
        }

        // 解析 .rela.plt 获取正确的PLT-符号映射
        if (relaPltSection != null) {
            int numEntries = (int)(relaPltSection.header.sh_size / relaPltSection.header.sh_entsize);
            if (numEntries <= 0) {
                Log.w(TAG, "Empty .rela.plt section");
                return pltEntries;
            }
            Log.i(TAG, "Parsing .rela.plt with " + numEntries + " entries");

            // 自动检测PLT条目大小: (总大小 - 估计头部) / 条目数
            // AArch64: PLT头部通常32字节, 条目16字节或20字节(BTI)
            long pltEntrySize = 16;
            long pltHeaderSize = 32; // 默认头部大小

            // 验证: 头部 + 条目数 * 条目大小 = 总大小
            long calcSize16 = 32 + (long)numEntries * 16;
            long calcSize20 = 32 + (long)numEntries * 20;
            if (calcSize16 == pltSize) {
                pltEntrySize = 16;
                pltHeaderSize = 32;
            } else if (calcSize20 == pltSize) {
                pltEntrySize = 20;
                pltHeaderSize = 32;
            } else {
                // 动态计算: 假设头部是 pltSize - numEntries * 16
                pltHeaderSize = pltSize - (long)numEntries * 16;
                if (pltHeaderSize < 0 || pltHeaderSize > 64) {
                    // 尝试20字节条目
                    pltHeaderSize = pltSize - (long)numEntries * 20;
                    if (pltHeaderSize >= 16 && pltHeaderSize <= 64) {
                        pltEntrySize = 20;
                    } else {
                        pltHeaderSize = 32; // 回退
                        pltEntrySize = 16;
                    }
                }
            }
            Log.i(TAG, String.format("PLT: header=%d entrySize=%d stubs=%d", pltHeaderSize, pltEntrySize, numEntries));

            try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
                long fileOff = relaPltSection.header.sh_offset;
                raf.seek(fileOff);

                for (int i = 0; i < numEntries; i++) {
                    // ELF64_Rela 结构: r_offset(8) + r_info(8) + r_addend(8) = 24字节
                    long r_offset = Long.reverseBytes(raf.readLong());
                    long r_info = Long.reverseBytes(raf.readLong());
                    long r_addend = Long.reverseBytes(raf.readLong());

                    int symIdx = (int)((r_info >>> 32) & 0xFFFFFFFFL);

                    long pltEntryAddr = pltAddr + pltHeaderSize + i * pltEntrySize;

                    // 验证PLT条目地址在.plt范围内
                    if (pltEntryAddr < pltAddr || pltEntryAddr >= pltAddr + pltSize) {
                        Log.w(TAG, String.format("PLT[%d] addr 0x%X out of .plt range [0x%X-0x%X]",
                                i, pltEntryAddr, pltAddr, pltAddr + pltSize));
                        continue;
                    }

                    Log.d(TAG, String.format("RELA[%d]: r_offset=0x%X symIdx=%d pltAddr=0x%X",
                            i, r_offset, symIdx, pltEntryAddr));

                    if (symIdx > 0 && symIdx < dynsym.symbols.length) {
                        ElfSymbol sym = dynsym.symbols[symIdx];
                        String symName = sym.getName();

                        if (symName != null && !symName.isEmpty()) {
                            pltEntries.add(new PltEntry(
                                pltEntryAddr,
                                pltEntrySize,
                                symName,
                                r_offset
                            ));
                            Log.i(TAG, String.format("PLT[0x%X] -> %s (sym#%d)",
                                    pltEntryAddr, symName, symIdx));
                        }
                    } else {
                        Log.w(TAG, String.format("Invalid symbol index: %d (max=%d)",
                                symIdx, dynsym.symbols.length));
                    }
                }
            }
        } else {
            Log.w(TAG, "No .rela.plt found, using fallback");
        }

        Log.i(TAG, "Parsed PLT: " + pltEntries.size() + " entries");
        return pltEntries;
    }
}
