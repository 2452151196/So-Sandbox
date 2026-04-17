package com.example.anative.ui;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.widget.ViewPager2;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import androidx.fragment.app.FragmentManager;

import com.example.anative.core.ElfParser;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FunctionDetailActivity extends AppCompatActivity {

    public static final String EXTRA_FUNC_NAME = "func_name";
    public static final String EXTRA_FUNC_ADDR = "func_addr";
    public static final String EXTRA_FUNC_SIZE = "func_size";
    public static final String EXTRA_DEMANGLED_NAME = "demangled_name";
    public static final String EXTRA_SIGNATURE = "signature";

    private String funcName;
    private long funcAddr;
    private long funcSize;
    private String demangledName;
    private String signature;
    private long baseAddress;

    private ViewPager2 viewPager;
    private TabLayout tabLayout;
    private FunctionPagerAdapter pagerAdapter;

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_function_detail);

        funcName = getIntent().getStringExtra(EXTRA_FUNC_NAME);
        funcAddr = getIntent().getLongExtra(EXTRA_FUNC_ADDR, 0);
        funcSize = getIntent().getLongExtra(EXTRA_FUNC_SIZE, 0);
        demangledName = getIntent().getStringExtra(EXTRA_DEMANGLED_NAME);
        signature = getIntent().getStringExtra(EXTRA_SIGNATURE);
        baseAddress = DataHolder.getInstance().getBaseAddress();

        androidx.appcompat.widget.Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(demangledName != null ? demangledName : funcName);
            getSupportActionBar().setSubtitle(String.format("0x%X | %d bytes", funcAddr - baseAddress, funcSize));
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        toolbar.setNavigationOnClickListener(v -> finish());

        viewPager = findViewById(R.id.viewPager);
        tabLayout = findViewById(R.id.tabLayout);

        pagerAdapter = new FunctionPagerAdapter(this, funcAddr, funcSize, demangledName, signature);
        viewPager.setAdapter(pagerAdapter);
        viewPager.setOffscreenPageLimit(2);
        viewPager.setUserInputEnabled(true);
        viewPager.setPageTransformer(new DepthPageTransformer());

        String[] tabTitles = {"汇编", "伪C", "Hex", "Sections", "流程图"};
        new TabLayoutMediator(tabLayout, viewPager,
                (tab, position) -> tab.setText(tabTitles[position])
        ).attach();

        // 设置 HexFragment 的刷新监听器，当 hex 修改时刷新 AsmFragment
        viewPager.post(() -> {
            Fragment hexFragment = pagerAdapter.getFragment(2);
            if (hexFragment instanceof HexFragment) {
                ((HexFragment) hexFragment).setOnRefreshListener(() -> {
                    Fragment asmFragment = pagerAdapter.getFragment(0);
                    if (asmFragment instanceof AsmFragment) {
                        ((AsmFragment) asmFragment).refreshDisplay();
                    }
                });
            }
        });

        android.content.SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
        if (prefs.getBoolean(SettingsActivity.PREF_AI_PSEUDOC_ENABLED, false)) {
            viewPager.setCurrentItem(1, false);
        }

        tabLayout.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override public void onTabSelected(TabLayout.Tab tab) {
                viewPager.setCurrentItem(tab.getPosition(), true);
            }
            @Override public void onTabUnselected(TabLayout.Tab tab) {}
            @Override public void onTabReselected(TabLayout.Tab tab) {}
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        // 当从其他页面返回时刷新显示
        if (pagerAdapter != null) {
            pagerAdapter.refreshAllFragments();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_function_detail, menu);
        return true;
    }

    @Override
    public void onBackPressed() {
        if (DataHolder.getInstance().hasUnsavedChanges()) {
            new AlertDialog.Builder(this)
                    .setTitle("有未保存的修改")
                    .setMessage("是否保存已修改的指令？")
                    .setPositiveButton("保存", (dialog, which) -> {
                        saveModifiedSo();
                        finish();
                    })
                    .setNegativeButton("不保存", (dialog, which) -> {
                        DataHolder.getInstance().clearAllModifiedInstructions();
                        finish();
                    })
                    .setNeutralButton("取消", null)
                    .show();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.action_run) {
            saveModifiedSo();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void saveModifiedSo() {
        String soPath = DataHolder.getInstance().getSoPath();

        if (soPath == null || soPath.isEmpty()) {
            Toast.makeText(this, "SO文件路径未知", Toast.LENGTH_SHORT).show();
            return;
        }

        File srcFile = new File(soPath);
        if (!srcFile.exists() || srcFile.length() == 0) {
            Toast.makeText(this, "源 SO 文件不存在或为空: " + soPath, Toast.LENGTH_LONG).show();
            return;
        }

        // 收集所有 Fragment 的修改
        java.util.Map<Long, Byte> allModifications = collectAllModifications();

        if (allModifications.isEmpty()) {
            Toast.makeText(this, "没有检测到修改，将保存原文件副本", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "检测到 " + allModifications.size() + " 处修改，正在保存...", Toast.LENGTH_SHORT).show();
        }

        String srcName = srcFile.getName();
        String newFileName = srcName.endsWith(".so")
                ? srcName.substring(0, srcName.length() - 3) + "_saved.so"
                : srcName + "_saved";
        Toast.makeText(this, "正在保存...", Toast.LENGTH_SHORT).show();

        executor.execute(() -> {
            try {
                // 优先使用外部存储（便于分享），退回到内部缓存
                File destDir = getExternalFilesDir(null);
                if (destDir == null) destDir = getCacheDir();
                if (!destDir.exists()) destDir.mkdirs();
                File destFile = new File(destDir, newFileName);
                final File savedFile = destFile;

                // 复制原始文件并应用修改
                android.util.Log.d("SaveSo", "Applying " + allModifications.size() + " modifications");
                try (java.io.FileInputStream fis = new java.io.FileInputStream(srcFile);
                     java.io.FileOutputStream fos = new java.io.FileOutputStream(destFile)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    long position = 0;
                    int appliedCount = 0;
                    while ((len = fis.read(buffer)) != -1) {
                        // 应用该范围内的修改
                        for (int i = 0; i < len; i++) {
                            Long offset = position + i;
                            Byte newVal = allModifications.get(offset);
                            if (newVal != null) {
                                buffer[i] = newVal;
                                appliedCount++;
                                android.util.Log.v("SaveSo", "Applied mod at offset " + offset + " = " + String.format("%02X", newVal));
                            }
                        }
                        fos.write(buffer, 0, len);
                        position += len;
                    }
                    fos.getFD().sync();
                    android.util.Log.d("SaveSo", "Total modifications applied: " + appliedCount);
                }

                if (!savedFile.exists()) {
                    throw new Exception("保存后文件不存在");
                }

                handler.post(() -> showSaveSuccessDialog(savedFile));
            } catch (Exception e) {
                final String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                handler.post(() -> Toast.makeText(this,
                        "保存失败: " + msg, Toast.LENGTH_LONG).show());
            }
        });
    }

    /**
     * 收集所有 Fragment 的修改数据
     */
    private java.util.Map<Long, Byte> collectAllModifications() {
        java.util.Map<Long, Byte> mods = new java.util.HashMap<>();
        // 从 HexFragment 获取修改
        Fragment hexFragment = pagerAdapter.getFragment(2);
        if (hexFragment instanceof HexFragment) {
            java.util.Map<Long, Byte> hexMods = ((HexFragment) hexFragment).getModifications();
            android.util.Log.d("SaveSo", "HexFragment modifications: " + hexMods.size());
            mods.putAll(hexMods);
        } else {
            android.util.Log.w("SaveSo", "HexFragment not found or not ready");
        }
        return mods;
    }

    private void showSaveSuccessDialog(File savedFile) {
        String path = savedFile.getAbsolutePath();
        String msg = path + "\n大小: " + savedFile.length() + " 字节";
        new AlertDialog.Builder(this)
                .setTitle("保存成功")
                .setMessage(msg)
                .setPositiveButton("分享", (dialog, which) -> shareFile(savedFile))
                .setNeutralButton("复制路径", (dialog, which) -> {
                    ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(ClipData.newPlainText("SO路径", path));
                    Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("关闭", null)
                .show();
    }

    private void shareFile(File file) {
        try {
            Uri uri = androidx.core.content.FileProvider.getUriForFile(
                    this, getPackageName() + ".fileprovider", file);
            Intent share = new Intent(Intent.ACTION_SEND);
            share.setType("application/octet-stream");
            share.putExtra(Intent.EXTRA_STREAM, uri);
            share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(share, "分享 SO 文件"));
        } catch (Exception e) {
            // FileProvider 未配置时 fallback: 直接 file://
            try {
                Intent share = new Intent(Intent.ACTION_SEND);
                share.setType("application/octet-stream");
                share.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(file));
                startActivity(Intent.createChooser(share, "分享 SO 文件"));
            } catch (Exception e2) {
                Toast.makeText(this, "分享失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
