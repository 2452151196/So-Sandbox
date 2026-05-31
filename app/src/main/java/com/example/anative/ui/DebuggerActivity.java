package com.example.anative.ui;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.anative.R;
import com.example.anative.core.DebugSessionManager;
import com.example.anative.core.NativeDebugger;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DebuggerActivity extends AppCompatActivity {

    public static final String EXTRA_PID = "pid";
    public static final String EXTRA_SO_PATH = "so_path";
    public static final String EXTRA_FUNC_OFFSET = "func_offset";

    private EditText etPid;
    private EditText etBpAddr;
    private EditText etMemAddr;
    private EditText etMemSize;
    private TextView tvStatus;
    private TextView tvBreakpoints;
    private TextView tvRegisters;
    private TextView tvMemory;
    private TextView tvLog;

    private MaterialButton btnAttach;
    private MaterialButton btnDetach;
    private MaterialButton btnSpawn;
    private MaterialButton btnWait;
    private MaterialButton btnContinue;
    private MaterialButton btnStep;
    private MaterialButton btnRefreshRegs;
    private MaterialButton btnSetBp;
    private MaterialButton btnRemoveBp;
    private MaterialButton btnReadMem;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    private int currentPid = 0;
    private boolean isAttached = false;
    private boolean isWaiting = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_debugger);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(v -> finish());

        etPid = findViewById(R.id.et_pid);
        etBpAddr = findViewById(R.id.et_bp_addr);
        etMemAddr = findViewById(R.id.et_mem_addr);
        etMemSize = findViewById(R.id.et_mem_size);
        tvStatus = findViewById(R.id.tv_status);
        tvBreakpoints = findViewById(R.id.tv_breakpoints);
        tvRegisters = findViewById(R.id.tv_registers);
        tvMemory = findViewById(R.id.tv_memory);
        tvLog = findViewById(R.id.tv_log);

        btnAttach = findViewById(R.id.btn_attach);
        btnDetach = findViewById(R.id.btn_detach);
        btnSpawn = findViewById(R.id.btn_spawn);
        btnWait = findViewById(R.id.btn_wait);
        btnContinue = findViewById(R.id.btn_continue);
        btnStep = findViewById(R.id.btn_step);
        btnRefreshRegs = findViewById(R.id.btn_refresh_regs);
        btnSetBp = findViewById(R.id.btn_set_bp);
        btnRemoveBp = findViewById(R.id.btn_remove_bp);
        btnReadMem = findViewById(R.id.btn_read_mem);

        btnAttach.setOnClickListener(v -> doAttach());
        btnDetach.setOnClickListener(v -> doDetach());
        btnSpawn.setOnClickListener(v -> doSpawn());
        btnWait.setOnClickListener(v -> doWait());
        btnContinue.setOnClickListener(v -> doContinue());
        btnStep.setOnClickListener(v -> doSingleStep());
        btnRefreshRegs.setOnClickListener(v -> refreshRegisters());
        btnSetBp.setOnClickListener(v -> doSetBreakpoint());
        btnRemoveBp.setOnClickListener(v -> doRemoveBreakpoint());
        btnReadMem.setOnClickListener(v -> doReadMemory());

        Intent intent = getIntent();
        int prefilledPid = intent.getIntExtra(EXTRA_PID, 0);
        if (prefilledPid > 0) {
            etPid.setText(String.valueOf(prefilledPid));
        }

        updateStatus("未连接");
        appendLog("调试器已启动。需要 Root 权限。\n");
    }

    private void updateStatus(String msg) {
        handler.post(() -> tvStatus.setText("状态: " + msg));
    }

    private void appendLog(String msg) {
        handler.post(() -> {
            String current = tvLog.getText().toString();
            if (current.length() > 8000) {
                current = current.substring(current.length() - 4000);
            }
            tvLog.setText(current + msg);
        });
    }

    private int getPidFromEdit() {
        try {
            return Integer.parseInt(etPid.getText().toString().trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private long parseAddr(String text) {
        String t = text.trim().replace("0x", "").replace("0X", "");
        try {
            return Long.parseLong(t, 16);
        } catch (NumberFormatException e) {
            try {
                return Long.parseLong(t);
            } catch (NumberFormatException e2) {
                return 0;
            }
        }
    }

    private void doAttach() {
        int pid = getPidFromEdit();
        if (pid <= 0) {
            Toast.makeText(this, "请输入有效的 PID", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            appendLog("正在附加 PID " + pid + "...\n");
            boolean ok = NativeDebugger.nativeAttachProcess(pid);
            if (ok) {
                currentPid = pid;
                isAttached = true;
                updateStatus("已附加 PID " + pid);
                appendLog("附加成功。\n");
                refreshRegisters();
                refreshBreakpoints();
            } else {
                updateStatus("附加失败 (检查 Root 权限)");
                appendLog("附加失败。请检查 Root 权限或 PID 是否有效。\n");
            }
        });
    }

    private void doDetach() {
        if (currentPid <= 0) {
            Toast.makeText(this, "未附加任何进程", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            appendLog("正在分离 PID " + currentPid + "...\n");
            boolean ok = NativeDebugger.nativeDetachProcess(currentPid);
            if (ok) {
                isAttached = false;
                updateStatus("已分离");
                appendLog("分离成功。\n");
                currentPid = 0;
            } else {
                updateStatus("分离失败");
                appendLog("分离失败。\n");
            }
        });
    }

    private void doSpawn() {
        Intent intent = getIntent();
        String soPath = intent.getStringExtra(EXTRA_SO_PATH);
        long funcOffset = intent.getLongExtra(EXTRA_FUNC_OFFSET, 0);
        if (soPath == null || soPath.isEmpty()) {
            Toast.makeText(this, "未指定 SO 路径", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            appendLog("正在 Spawn 调试子进程，加载 " + soPath + "\n");
            DebugSessionManager dbg = DebugSessionManager.getInstance();
            boolean ok = dbg.spawnChild(soPath, funcOffset);
            if (ok) {
                currentPid = dbg.getChildPid();
                isAttached = true;
                handler.post(() -> etPid.setText(String.valueOf(currentPid)));
                updateStatus(dbg.getStatusText());
                appendLog("Spawn 成功，PID=" + currentPid + "\n");
                appendLog("Child 加载基址 = 0x" + Long.toHexString(dbg.getChildBase()) + "\n");

                if (funcOffset > 0) {
                    long bpAddr = dbg.getChildBase() + funcOffset;
                    appendLog("自动断点 @ 0x" + Long.toHexString(bpAddr) + " (base+offset)\n");
                    handler.post(() -> etBpAddr.setText("0x" + Long.toHexString(bpAddr)));
                }

                refreshRegisters();
                refreshBreakpoints();
            } else {
                updateStatus("Spawn 失败");
                appendLog("Spawn 失败。\n");
            }
        });
    }

    private void doWait() {
        if (currentPid <= 0) {
            Toast.makeText(this, "未附加进程", Toast.LENGTH_SHORT).show();
            return;
        }
        if (isWaiting) {
            Toast.makeText(this, "已在等待中", Toast.LENGTH_SHORT).show();
            return;
        }
        isWaiting = true;
        executor.execute(() -> {
            appendLog("等待事件中...\n");
            String event = NativeDebugger.nativeWaitEvent(currentPid, 0);
            isWaiting = false;
            if (event == null) event = "null";
            appendLog("事件: " + event + "\n");
            if (event.startsWith("STOP|")) {
                updateStatus("进程已停止: " + event);
                refreshRegisters();
                refreshBreakpoints();
            } else if (event.startsWith("EXIT|")) {
                updateStatus("进程已退出");
                isAttached = false;
                currentPid = 0;
            } else if (event.startsWith("SIGNALED|")) {
                updateStatus("进程被信号终止");
                isAttached = false;
                currentPid = 0;
            }
        });
    }

    private void doContinue() {
        if (currentPid <= 0) {
            Toast.makeText(this, "未附加进程", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            appendLog("发送继续...\n");
            boolean ok = NativeDebugger.nativeContinue(currentPid);
            appendLog(ok ? "继续成功。\n" : "继续失败。\n");
        });
    }

    private void doSingleStep() {
        if (currentPid <= 0) {
            Toast.makeText(this, "未附加进程", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            appendLog("单步执行...\n");
            boolean ok = NativeDebugger.nativeSingleStep(currentPid);
            appendLog(ok ? "单步完成。\n" : "单步失败。\n");
            if (ok) {
                refreshRegisters();
                String event = NativeDebugger.nativeWaitEvent(currentPid, 1000);
                if (event != null) {
                    appendLog("事件: " + event + "\n");
                }
            }
        });
    }

    private void refreshRegisters() {
        if (currentPid <= 0) return;
        executor.execute(() -> {
            String regs = NativeDebugger.nativeReadRegisters(currentPid);
            if (regs != null && regs.startsWith("ERR")) {
                handler.post(() -> tvRegisters.setText("读取失败: " + regs));
            } else {
                handler.post(() -> tvRegisters.setText(formatRegisters(regs)));
            }
        });
    }

    private String formatRegisters(String raw) {
        if (raw == null) return "null";
        StringBuilder sb = new StringBuilder();
        String[] parts = raw.split("\\|");
        for (String p : parts) {
            sb.append(p).append("\n");
        }
        return sb.toString();
    }

    private void doSetBreakpoint() {
        if (currentPid <= 0) {
            Toast.makeText(this, "未附加进程", Toast.LENGTH_SHORT).show();
            return;
        }
        long addr = parseAddr(etBpAddr.getText().toString());
        if (addr == 0) {
            Toast.makeText(this, "请输入有效地址", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            appendLog("设置断点 @ 0x" + Long.toHexString(addr) + "\n");
            boolean ok = NativeDebugger.nativeSetBreakpoint(currentPid, addr);
            appendLog(ok ? "断点设置成功。\n" : "断点设置失败。\n");
            if (ok) refreshBreakpoints();
        });
    }

    private void doRemoveBreakpoint() {
        if (currentPid <= 0) {
            Toast.makeText(this, "未附加进程", Toast.LENGTH_SHORT).show();
            return;
        }
        long addr = parseAddr(etBpAddr.getText().toString());
        if (addr == 0) {
            Toast.makeText(this, "请输入有效地址", Toast.LENGTH_SHORT).show();
            return;
        }
        executor.execute(() -> {
            appendLog("移除断点 @ 0x" + Long.toHexString(addr) + "\n");
            boolean ok = NativeDebugger.nativeRemoveBreakpoint(currentPid, addr);
            appendLog(ok ? "断点移除成功。\n" : "断点移除失败。\n");
            if (ok) refreshBreakpoints();
        });
    }

    private void refreshBreakpoints() {
        if (currentPid <= 0) return;
        executor.execute(() -> {
            String bps = NativeDebugger.nativeGetBreakpoints(currentPid);
            handler.post(() -> {
                if (bps == null || bps.isEmpty()) {
                    tvBreakpoints.setText("当前断点: 无");
                } else {
                    tvBreakpoints.setText("当前断点: " + bps);
                }
            });
        });
    }

    private void doReadMemory() {
        if (currentPid <= 0) {
            Toast.makeText(this, "未附加进程", Toast.LENGTH_SHORT).show();
            return;
        }
        long addr = parseAddr(etMemAddr.getText().toString());
        if (addr == 0) {
            Toast.makeText(this, "请输入有效地址", Toast.LENGTH_SHORT).show();
            return;
        }
        int size = 64;
        try {
            size = Integer.parseInt(etMemSize.getText().toString().trim());
        } catch (NumberFormatException e) {
            // default 64
        }
        if (size <= 0 || size > 4096) size = 64;

        final int finalSize = size;
        executor.execute(() -> {
            appendLog("读取内存 @ 0x" + Long.toHexString(addr) + " 大小=" + finalSize + "\n");
            byte[] data = NativeDebugger.nativeReadMemory(currentPid, addr, finalSize);
            if (data == null) {
                handler.post(() -> tvMemory.setText("读取失败"));
                appendLog("内存读取失败。\n");
            } else {
                String hex = formatHexDump(addr, data);
                handler.post(() -> tvMemory.setText(hex));
                appendLog("读取完成，共 " + data.length + " 字节。\n");
            }
        });
    }

    private String formatHexDump(long baseAddr, byte[] data) {
        StringBuilder sb = new StringBuilder();
        int lines = (data.length + 15) / 16;
        for (int i = 0; i < lines; i++) {
            long lineAddr = baseAddr + i * 16L;
            sb.append(String.format(Locale.US, "%016X  ", lineAddr));
            StringBuilder ascii = new StringBuilder("  ");
            for (int j = 0; j < 16; j++) {
                int idx = i * 16 + j;
                if (idx < data.length) {
                    int b = data[idx] & 0xFF;
                    sb.append(String.format(Locale.US, "%02X ", b));
                    ascii.append((b >= 32 && b < 127) ? (char) b : '.');
                } else {
                    sb.append("   ");
                    ascii.append(' ');
                }
            }
            sb.append(ascii.toString()).append("\n");
        }
        return sb.toString();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (isAttached && currentPid > 0) {
            NativeDebugger.nativeDetachProcess(currentPid);
        }
        executor.shutdown();
    }
}
