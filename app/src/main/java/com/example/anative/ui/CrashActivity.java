package com.example.anative.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.view.WindowManager;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;

import com.example.anative.databinding.ActivityCrashBinding;

public class CrashActivity extends AppCompatActivity {

    private ActivityCrashBinding binding;
    private String crashLog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityCrashBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // 状态栏沉浸，根据夜间模式自动调整图标颜色
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
        boolean isNight = (getResources().getConfiguration().uiMode & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                == android.content.res.Configuration.UI_MODE_NIGHT_YES;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowInsetsControllerCompat controller = WindowCompat.getInsetsController(getWindow(), binding.getRoot());
            if (controller != null) {
                controller.setAppearanceLightStatusBars(!isNight);
            }
        } else {
            int flags = isNight ? 0 : android.view.View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
            getWindow().getDecorView().setSystemUiVisibility(flags);
        }

        // 返回按钮
        binding.btnBack.setOnClickListener(v -> finish());

        // 加载崩溃日志
        crashLog = CrashHandler.getCrashLog(this);
        if (crashLog == null || crashLog.isEmpty()) {
            crashLog = "未找到崩溃日志";
        }
        binding.tvCrashInfo.setText(crashLog);

        // 复制全部
        binding.btnCopy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("crash_log", crashLog));
            Toast.makeText(this, "已复制到剪贴板", Toast.LENGTH_SHORT).show();
        });

        // 清除日志
        binding.btnClear.setOnClickListener(v -> {
            new AlertDialog.Builder(this)
                    .setTitle("确认清除")
                    .setMessage("清除后此崩溃日志将无法恢复，确定吗？")
                    .setPositiveButton("清除", (d, w) -> {
                        CrashHandler.clearCrashLog(this);
                        binding.tvCrashInfo.setText("日志已清除");
                        Toast.makeText(this, "已清除", Toast.LENGTH_SHORT).show();
                    })
                    .setNegativeButton("取消", null)
                    .show();
        });
    }
}
