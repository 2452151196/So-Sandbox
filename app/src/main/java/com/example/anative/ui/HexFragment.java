package com.example.anative.ui;

import android.app.AlertDialog;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputFilter;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout.LayoutParams;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import com.example.anative.core.NativeInvoker;

import java.io.File;
import java.io.RandomAccessFile;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HexFragment extends Fragment {

    private static final String ARG_FUNC_ADDR = "func_addr";
    private static final String ARG_FUNC_SIZE = "func_size";
    private static final int BYTES_PER_ROW = 8;

    private long funcAddr;
    private long funcSize;
    private byte[] data;
    private boolean[] modified;

    private RecyclerView rvHex;
    private ProgressBar progressBar;
    private LinearLayout editPanel;
    private TextView tvEditInfo;
    private View btnSave;

    private HexAdapter adapter;
    private int selectedRow = -1;
    private int selectedCol = -1;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    public static HexFragment newInstance(long funcAddr, long funcSize) {
        HexFragment fragment = new HexFragment();
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

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_hex_editor, container, false);
        rvHex = view.findViewById(R.id.rv_hex);
        progressBar = view.findViewById(R.id.progressBar);
        editPanel = view.findViewById(R.id.edit_panel);
        tvEditInfo = view.findViewById(R.id.tv_edit_info);
        btnSave = view.findViewById(R.id.btn_save);
        return view;
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        setupRecyclerView();
        loadHexData();

        btnSave.setOnClickListener(v -> saveChanges());
    }

    private void setupRecyclerView() {
        rvHex.setLayoutManager(new LinearLayoutManager(getContext()));
        adapter = new HexAdapter();
        rvHex.setAdapter(adapter);
    }

    private void loadHexData() {
        progressBar.setVisibility(View.VISIBLE);

        executor.execute(() -> {
            int size = (int) Math.min(funcSize, 8192); // 最大 8KB
            data = new byte[size];
            modified = new boolean[size];
            boolean readOk = false;

            // 通过 JNI 读取内存
            try {
                byte[] read = NativeInvoker.readMemory(funcAddr, size);
                if (read != null && read.length > 0) {
                    System.arraycopy(read, 0, data, 0, Math.min(read.length, size));
                    readOk = true;
                }
            } catch (Exception e) {
                // 读取失败
            }

            if (!readOk) {
                readOk = loadFromSoFile(data, size);
            }

            int rowCount = (size + BYTES_PER_ROW - 1) / BYTES_PER_ROW;
            final boolean finalReadOk = readOk;

            handler.post(() -> {
                progressBar.setVisibility(View.GONE);
                adapter.setData(data, modified, funcAddr, rowCount);
                if (!finalReadOk) {
                    Toast.makeText(getContext(), "读取函数内存失败", Toast.LENGTH_SHORT).show();
                }
            });
        });
    }

    private boolean loadFromSoFile(byte[] out, int size) {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null || soPath.isEmpty()) return false;

        long base = DataHolder.getInstance().getBaseAddress();
        long fileOffset = (base > 0 && funcAddr >= base) ? (funcAddr - base) : funcAddr;
        if (fileOffset < 0) return false;

        try (RandomAccessFile raf = new RandomAccessFile(soPath, "r")) {
            if (fileOffset >= raf.length()) return false;
            raf.seek(fileOffset);
            int readLen = raf.read(out, 0, Math.min(size, out.length));
            return readLen > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private void onHexCellClicked(int row, int col, byte value) {
        selectedRow = row;
        selectedCol = col;
        long addr = funcAddr + row * BYTES_PER_ROW + col;

        editPanel.setVisibility(View.VISIBLE);
        tvEditInfo.setText(String.format("编辑地址: 0x%X [%02X]", addr, value & 0xFF));

        // 弹出编辑对话框
        showEditDialog(addr, row, col, value);
    }

    private void showEditDialog(long addr, int row, int col, byte currentValue) {
        EditText input = new EditText(getContext());
        input.setInputType(InputType.TYPE_CLASS_TEXT);
        input.setFilters(new InputFilter[]{new InputFilter.LengthFilter(2)});
        input.setText(String.format("%02X", currentValue & 0xFF));
        input.selectAll();

        new AlertDialog.Builder(getContext())
                .setTitle(String.format("编辑字节 @ 0x%X", addr))
                .setView(input)
                .setPositiveButton("确定", (d, w) -> {
                    String hex = input.getText().toString().trim();
                    try {
                        int newVal = Integer.parseInt(hex, 16);
                        if (newVal >= 0 && newVal <= 255) {
                            int index = row * BYTES_PER_ROW + col;
                            if (index < data.length) {
                                data[index] = (byte) newVal;
                                modified[index] = true;
                                adapter.notifyItemChanged(row);
                                tvEditInfo.setText(String.format("已修改: 0x%X = %02X", addr, newVal));
                            }
                        }
                    } catch (NumberFormatException e) {
                        Toast.makeText(getContext(), "无效的 hex 值", Toast.LENGTH_SHORT).show();
                    }
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void saveChanges() {
        int changeCount = 0;
        for (boolean m : modified) if (m) changeCount++;

        if (changeCount == 0) {
            Toast.makeText(getContext(), "没有修改需要保存", Toast.LENGTH_SHORT).show();
            return;
        }

        final int totalChanges = changeCount;
        // 应用修改到内存
        executor.execute(() -> {
            boolean success = true;
            String exportPath = null;
            for (int i = 0; i < modified.length; i++) {
                if (modified[i]) {
                    try {
                        NativeInvoker.writeMemory(funcAddr + i, data[i]);
                        modified[i] = false; // 清除标记
                    } catch (Exception e) {
                        success = false;
                    }
                }
            }

            if (success) {
                exportPath = exportPatchedSo();
            }

            final boolean finalSuccess = success;
            final String finalExportPath = exportPath;
            handler.post(() -> {
                Toast.makeText(getContext(),
                        finalSuccess ? "已保存 " + totalChanges + " 处修改" : "部分修改保存失败",
                        Toast.LENGTH_SHORT).show();
                if (finalSuccess && finalExportPath != null) {
                    Toast.makeText(getContext(), "已导出: " + finalExportPath, Toast.LENGTH_LONG).show();
                }
                adapter.notifyDataSetChanged();
            });
        });
    }

    private String exportPatchedSo() {
        String soPath = DataHolder.getInstance().getSoPath();
        if (soPath == null || soPath.isEmpty()) return null;

        long base = DataHolder.getInstance().getBaseAddress();
        if (base <= 0) return null;

        File src = new File(soPath);
        File outDir = new File(src.getParentFile(), "patched");
        if (!outDir.exists() && !outDir.mkdirs()) return null;

        File out = new File(outDir, src.getName().replace(".so", "_patched.so"));

        try (RandomAccessFile inRaf = new RandomAccessFile(src, "r");
             RandomAccessFile outRaf = new RandomAccessFile(out, "rw")) {

            byte[] all = new byte[(int) inRaf.length()];
            inRaf.readFully(all);

            for (int i = 0; i < data.length; i++) {
                long abs = funcAddr + i;
                long fileOffset = abs - base;
                if (fileOffset >= 0 && fileOffset < all.length) {
                    all[(int) fileOffset] = data[i];
                }
            }

            outRaf.setLength(0);
            outRaf.write(all);
            return out.getAbsolutePath();
        } catch (Exception e) {
            return null;
        }
    }

    // ========== Adapter ==========

    class HexAdapter extends RecyclerView.Adapter<HexAdapter.VH> {
        private byte[] data;
        private boolean[] modified;
        private long baseAddr;
        private int rowCount;

        void setData(byte[] data, boolean[] modified, long baseAddr, int rowCount) {
            this.data = data;
            this.modified = modified;
            this.baseAddr = baseAddr;
            this.rowCount = rowCount;
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_hex_row, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(@NonNull VH h, int pos) {
            long offset = pos * BYTES_PER_ROW;
            h.tvOffset.setText(String.format("%08X", baseAddr + offset));

            // 构建 hex cells
            h.hexContainer.removeAllViews();
            StringBuilder ascii = new StringBuilder();

            for (int i = 0; i < BYTES_PER_ROW; i++) {
                int index = pos * BYTES_PER_ROW + i;

                TextView tv = new TextView(getContext());
                tv.setTextSize(14f);
                tv.setTypeface(android.graphics.Typeface.MONOSPACE);
                tv.setPadding(0, 6, 0, 6);
                tv.setGravity(android.view.Gravity.CENTER);
                tv.setLayoutParams(new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f));

                if (index < data.length) {
                    byte b = data[index];
                    tv.setText(String.format("%02X", b & 0xFF));

                    // 修改过的高亮
                    if (modified[index]) {
                        GradientDrawable bg = new GradientDrawable();
                        bg.setShape(GradientDrawable.RECTANGLE);
                        bg.setCornerRadius(4f);
                        bg.setColor(0xFF4CAF50);
                        tv.setBackground(bg);
                        tv.setTextColor(0xFFFFFFFF);
                    } else {
                        tv.setTextColor(getResources().getColor(R.color.text_primary));
                    }

                    char c = (b >= 32 && b < 127) ? (char) b : '.';
                    ascii.append(c);

                    // 点击编辑
                    final int row = pos;
                    final int col = i;
                    tv.setOnClickListener(v -> onHexCellClicked(row, col, b));
                } else {
                    tv.setText("  ");
                    ascii.append(' ');
                }

                h.hexContainer.addView(tv);
            }

            h.tvAscii.setText(ascii.toString());
        }

        @Override
        public int getItemCount() {
            return rowCount;
        }

        class VH extends RecyclerView.ViewHolder {
            TextView tvOffset, tvAscii;
            LinearLayout hexContainer;

            VH(View v) {
                super(v);
                tvOffset = v.findViewById(R.id.tv_offset);
                tvAscii = v.findViewById(R.id.tv_ascii);
                hexContainer = v.findViewById(R.id.hex_container);
            }
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
