package com.example.anative.ui;

import android.Manifest;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.example.anative.R;
import com.example.anative.core.ElfParser;
import com.example.anative.core.DataHolder;
import com.example.anative.core.NativeFunction;
import com.example.anative.core.NativeInvoker;
import com.example.anative.core.PltEntry;
import com.example.anative.core.SoLoader;
import com.example.anative.databinding.ActivityMainBinding;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;
    private SoLoader soLoader;
    private List<NativeFunction> functions;
    private List<ElfParser.StringEntry> strings;
    private List<PltEntry> pltEntries;
    private List<RecentProject> recentProjects;
    private RecentProjectsAdapter recentAdapter;
    private static final String PREFS_RECENT = "recent_projects";
    private static final int MAX_RECENT = 10;

    private final ActivityResultLauncher<String[]> filePickerLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.OpenDocument(),
                    this::onFilePicked
            );

    // 权限申请相关
    private final ActivityResultLauncher<String[]> permissionLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.RequestMultiplePermissions(),
                    result -> {
                        boolean allGranted = true;
                        for (boolean granted : result.values()) {
                            if (!granted) {
                                allGranted = false;
                                break;
                            }
                        }
                        if (!allGranted) {
                            Toast.makeText(this, "部分权限被拒绝，可能影响文件访问", Toast.LENGTH_LONG).show();
                        }
                    }
            );

    private int currentNightMode;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // 恢复保存的主题
        restoreNightMode();
        currentNightMode = AppCompatDelegate.getDefaultNightMode();
        super.onCreate(savedInstanceState);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        setSupportActionBar(binding.toolbar);
        soLoader = new SoLoader(this);

        // 申请存储权限
        checkAndRequestPermissions();

        // 初始化最近项目列表
        setupRecentProjects();

        // 恢复之前加载的 SO 文件（主题切换后）
        if (savedInstanceState != null) {
            String savedPath = savedInstanceState.getString("loaded_so_path");
            if (savedPath != null && !savedPath.isEmpty()) {
                reloadSoFile(savedPath);
            }
        }

        // 初始化崩溃保护 + RegisterNatives Hook
        try {
            NativeInvoker.initCrashProtection();
            NativeInvoker.hookRegisterNatives();
        } catch (UnsatisfiedLinkError e) {
            // Native lib may not be loaded yet on first run
        }

        binding.btnSelectSo.setOnClickListener(v -> {
            filePickerLauncher.launch(new String[]{"*/*"});
        });

        binding.btnViewFunctions.setOnClickListener(v -> {
            if (functions != null && !functions.isEmpty()) {
                DataHolder.getInstance().setFunctions(functions);
                DataHolder.getInstance().setBaseAddress(soLoader.getBaseAddress());
                // 按需加载字符串和PLT (反汇编需要)
                ensureStringsLoaded();
                ensurePltLoaded();
                DataHolder.getInstance().setStrings(strings);
                DataHolder.getInstance().setPltEntries(pltEntries);
                Intent intent = new Intent(this, FunctionListActivity.class);
                startActivity(intent);
            }
        });

        binding.btnViewStrings.setOnClickListener(v -> {
            if (soLoader.getLoadedSoPath() == null) return;
            showLoading(true);
            new Thread(() -> {
                ensureStringsLoaded();
                runOnUiThread(() -> {
                    showLoading(false);
                    if (strings != null && !strings.isEmpty()) {
                        DataHolder.getInstance().setStrings(strings);
                        Intent intent = new Intent(this, StringsActivity.class);
                        startActivity(intent);
                    } else {
                        Toast.makeText(this, "无字符串数据", Toast.LENGTH_SHORT).show();
                    }
                });
            }).start();
        });

        binding.btnViewPlt.setOnClickListener(v -> {
            if (soLoader.getLoadedSoPath() == null) return;
            showLoading(true);
            new Thread(() -> {
                ensurePltLoaded();
                runOnUiThread(() -> {
                    showLoading(false);
                    if (pltEntries != null && !pltEntries.isEmpty()) {
                        DataHolder.getInstance().setPltEntries(pltEntries);
                        Intent intent = new Intent(this, PltActivity.class);
                        startActivity(intent);
                    } else {
                        Toast.makeText(this, "无PLT数据", Toast.LENGTH_SHORT).show();
                    }
                });
            }).start();
        });

        binding.btnRegisterNatives.setOnClickListener(v -> {
            if (soLoader.getLoadedSoPath() == null) return;
            Intent intent = new Intent(this, RegisterNativesActivity.class);
            startActivity(intent);
        });
    }

    private void setupRecentProjects() {
        recentProjects = loadRecentProjects();
        binding.rvRecentProjects.setLayoutManager(new LinearLayoutManager(this));
        recentAdapter = new RecentProjectsAdapter(recentProjects, this::onRecentProjectClick);
        binding.rvRecentProjects.setAdapter(recentAdapter);

        binding.tvClear.setOnClickListener(v -> {
            new AlertDialog.Builder(this)
                    .setTitle("确认清空")
                    .setMessage("确定要清空所有最近项目吗？")
                    .setPositiveButton("确定", (d, w) -> clearRecentProjects())
                    .setNegativeButton("取消", null)
                    .show();
        });
    }

    private List<RecentProject> loadRecentProjects() {
        SharedPreferences prefs = getSharedPreferences(PREFS_RECENT, MODE_PRIVATE);
        String json = prefs.getString("projects", "[]");
        List<RecentProject> list = new ArrayList<>();
        try {
            org.json.JSONArray arr = new org.json.JSONArray(json);
            for (int i = 0; i < arr.length(); i++) {
                org.json.JSONObject obj = arr.getJSONObject(i);
                RecentProject p = new RecentProject();
                p.path = obj.getString("path");
                p.originalUri = obj.optString("originalUri", "");
                p.name = obj.getString("name");
                p.arch = obj.optString("arch", "ARM64");
                p.size = obj.optString("size", "");
                p.time = obj.optString("time", "");
                p.functions = obj.optString("functions", "");
                list.add(p);
            }
        } catch (Exception e) {
            // ignore
        }
        return list;
    }

    private void saveRecentProjects() {
        SharedPreferences prefs = getSharedPreferences(PREFS_RECENT, MODE_PRIVATE);
        try {
            org.json.JSONArray arr = new org.json.JSONArray();
            for (RecentProject p : recentProjects) {
                org.json.JSONObject obj = new org.json.JSONObject();
                obj.put("path", p.path);
                obj.put("originalUri", p.originalUri != null ? p.originalUri : "");
                obj.put("name", p.name);
                obj.put("arch", p.arch);
                obj.put("size", p.size);
                obj.put("time", p.time);
                obj.put("functions", p.functions);
                arr.put(obj);
            }
            prefs.edit().putString("projects", arr.toString()).apply();
        } catch (Exception e) {
            // ignore
        }
    }

    private void addToRecentProjects(String path, String originalUri, int funcCount) {
        File file = new File(path);
        RecentProject p = new RecentProject();
        p.path = path;
        p.originalUri = originalUri;
        p.name = file.getName();
        p.arch = "ARM64";
        p.size = formatFileSize(file.length());
        p.time = "刚刚";
        p.functions = funcCount > 0 ? "示例函数: " + funcCount + " 个" : "";

        // 移除重复的（按原始URI判断）
        recentProjects.removeIf(r -> originalUri != null && originalUri.equals(r.originalUri));
        // 添加到头部
        recentProjects.add(0, p);
        // 限制数量
        if (recentProjects.size() > MAX_RECENT) {
            recentProjects = recentProjects.subList(0, MAX_RECENT);
        }
        saveRecentProjects();
        recentAdapter.setProjects(recentProjects);
    }

    private String formatFileSize(long size) {
        if (size < 1024) return size + " B";
        if (size < 1024 * 1024) return String.format("%.1f KB", size / 1024.0);
        return String.format("%.1f MB", size / (1024.0 * 1024.0));
    }

    private void clearRecentProjects() {
        recentProjects.clear();
        saveRecentProjects();
        recentAdapter.setProjects(recentProjects);
    }

    private void onRecentProjectClick(RecentProject project) {
        // 使用原始URI重新加载文件
        if (project.originalUri == null || project.originalUri.isEmpty()) {
            Toast.makeText(this, "无法获取原始文件路径", Toast.LENGTH_SHORT).show();
            return;
        }
        
        Uri uri = Uri.parse(project.originalUri);
        
        // 检查是否仍有权限访问此URI
        if (!hasUriPermission(uri)) {
            new AlertDialog.Builder(this)
                    .setTitle("权限已过期")
                    .setMessage("无法访问该文件，权限已过期。请重新选择文件。")
                    .setPositiveButton("重新选择", (d, w) -> filePickerLauncher.launch(new String[]{"*/*"}))
                    .setNegativeButton("取消", null)
                    .show();
            return;
        }
        
        new AlertDialog.Builder(this)
                .setTitle("加载模式")
                .setMessage("选择SO加载方式")
                .setPositiveButton("动态加载", (d, w) -> doLoadSo(uri, false))
                .setNegativeButton("仅静态分析", (d, w) -> doLoadSo(uri, true))
                .setCancelable(true)
                .show();
    }

    /**
     * 检查是否仍有权限访问指定URI
     */
    private boolean hasUriPermission(Uri uri) {
        try {
            // 尝试读取一点数据来验证权限
            getContentResolver().openInputStream(uri).close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 持久化保存URI访问权限
     */
    private void persistUriPermission(Uri uri) {
        try {
            final int takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION |
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION;
            getContentResolver().takePersistableUriPermission(uri, takeFlags);
        } catch (SecurityException e) {
            // 无法持久化权限，忽略（后续会提示用户重新选择）
            Log.w("MainActivity", "无法持久化URI权限: " + e.getMessage());
        }
    }

    private void onFilePicked(Uri uri) {
        if (uri == null) return;

        new AlertDialog.Builder(this)
                .setTitle("加载模式")
                .setMessage("选择SO加载方式")
                .setPositiveButton("动态加载", (d, w) -> doLoadSo(uri, false))
                .setNegativeButton("仅静态分析", (d, w) -> doLoadSo(uri, true))
                .setCancelable(true)
                .show();
    }

    /**
     * 主题切换后恢复 SO 文件（使用静态分析模式）
     */
    private void reloadSoFile(String path) {
        // 先检查文件是否存在
        File soFile = new File(path);
        if (!soFile.exists()) {
            Log.w("MainActivity", "SO 文件已不存在，跳过恢复: " + path);
            return;
        }

        new Thread(() -> {
            try {
                // 从路径创建 Uri
                Uri uri = Uri.fromFile(soFile);
                boolean loaded = soLoader.loadSo(uri, true); // 静态分析模式
                if (!loaded) {
                    Log.w("MainActivity", "恢复 SO 文件失败: " + path);
                    return;
                }

                // 只解析函数列表
                DataHolder.getInstance().setSoPath(path);
                DataHolder.getInstance().setBaseAddress(soLoader.getBaseAddress());
                DataHolder.getInstance().setDlopenHandle(soLoader.getDlopenHandle());
                functions = ElfParser.parseFunctions(path);

                runOnUiThread(() -> {
                    showSoInfo(path, soLoader.getBaseAddress(), functions.size());
                });
            } catch (Exception e) {
                Log.e("MainActivity", "恢复 SO 文件错误: " + e.getMessage());
            }
        }).start();
    }

    private void doLoadSo(Uri uri, boolean staticOnly) {
        showLoading(true);
        hideError();

        // 清除旧数据
        strings = null;
        pltEntries = null;

        new Thread(() -> {
            try {
                boolean loaded = soLoader.loadSo(uri, staticOnly);
                if (!loaded) {
                    runOnUiThread(() -> {
                        showLoading(false);
                        showError("加载SO失败");
                    });
                    return;
                }

                // 只解析函数列表 (其他按需加载)
                String soPath = soLoader.getLoadedSoPath();
                DataHolder.getInstance().setSoPath(soPath);
                DataHolder.getInstance().setBaseAddress(soLoader.getBaseAddress());
                DataHolder.getInstance().setDlopenHandle(soLoader.getDlopenHandle());
                functions = ElfParser.parseFunctions(soPath);

                // 持久化保存URI访问权限
                if (uri != null) {
                    persistUriPermission(uri);
                }

                runOnUiThread(() -> {
                    showLoading(false);
                    showSoInfo(soPath, soLoader.getBaseAddress(), functions.size());
                    // 保存原始URI用于最近项目重新加载
                    String originalUri = uri != null ? uri.toString() : "";
                    addToRecentProjects(soPath, originalUri, functions.size());
                });

            } catch (Exception e) {
                runOnUiThread(() -> {
                    showLoading(false);
                    showError("错误: " + e.getMessage());
                });
            }
        }).start();
    }

    private synchronized void ensureStringsLoaded() {
        if (strings != null) return;
        String soPath = soLoader.getLoadedSoPath();
        if (soPath == null) return;
        try {
            strings = ElfParser.parseStrings(soPath);
        } catch (Exception e) {
            Log.e("MainActivity", "parseStrings failed: " + e.getMessage());
            strings = new ArrayList<>();
        }
    }

    private synchronized void ensurePltLoaded() {
        if (pltEntries != null) return;
        String soPath = soLoader.getLoadedSoPath();
        if (soPath == null) return;
        try {
            pltEntries = ElfParser.parsePlt(soPath);
        } catch (Exception e) {
            Log.e("MainActivity", "parsePlt failed: " + e.getMessage());
            pltEntries = new ArrayList<>();
        }
    }

    private void showSoInfo(String soPath, long baseAddr, int funcCount) {
        binding.cardStatus.setVisibility(View.VISIBLE);

        String fileName = soPath.substring(soPath.lastIndexOf('/') + 1);
        binding.tvSoName.setText(fileName);
        String baseText = baseAddr != 0 ? String.format("基址: 0x%X", baseAddr) : "静态分析模式";
        binding.tvBaseAddr.setText(baseText);
        binding.tvFuncCount.setText(String.format("函数: %d (字符串/PLT按需加载)", funcCount));
    }

    private void showLoading(boolean show) {
        binding.progressBar.setVisibility(show ? View.VISIBLE : View.GONE);
        binding.btnSelectSo.setEnabled(!show);
    }

    private void showError(String msg) {
        binding.tvError.setVisibility(View.VISIBLE);
        binding.tvError.setText(msg);
    }

    private void hideError() {
        binding.tvError.setVisibility(View.GONE);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_settings) {
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onResume() {
        super.onResume();
        // 检查从设置页面返回后，主题是否发生变化
        int newMode = AppCompatDelegate.getDefaultNightMode();
        if (newMode != currentNightMode && newMode != -1) {
            currentNightMode = newMode;
            // 延迟重建，等待生命周期稳定
            binding.getRoot().postDelayed(this::recreate, 100);
        }
    }

    /**
     * 检查并申请存储权限
     */
    private void checkAndRequestPermissions() {
        // Android 11+ (API 30+) 需要 MANAGE_EXTERNAL_STORAGE 特殊权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                // 引导用户到设置页开启权限
                new AlertDialog.Builder(this)
                        .setTitle("需要全部文件访问权限")
                        .setMessage("本应用需要访问全部文件才能分析 SO 文件，请在设置中开启权限。")
                        .setPositiveButton("去设置", (d, w) -> {
                            Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                            intent.setData(Uri.parse("package:" + getPackageName()));
                            startActivity(intent);
                        })
                        .setNegativeButton("取消", null)
                        .setCancelable(false)
                        .show();
                return;
            }
        }

        // Android 6.0 - Android 10 申请普通存储权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            List<String> permissionsToRequest = new ArrayList<>();
            
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) 
                    != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.READ_EXTERNAL_STORAGE);
            }
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P && 
                    ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) 
                            != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.WRITE_EXTERNAL_STORAGE);
            }
            
            if (!permissionsToRequest.isEmpty()) {
                permissionLauncher.launch(permissionsToRequest.toArray(new String[0]));
            }
        }

        // Android 13+ (API 33+) 申请媒体权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            List<String> permissionsToRequest = new ArrayList<>();
            
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_IMAGES) 
                    != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.READ_MEDIA_IMAGES);
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_VIDEO) 
                    != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.READ_MEDIA_VIDEO);
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_AUDIO) 
                    != PackageManager.PERMISSION_GRANTED) {
                permissionsToRequest.add(Manifest.permission.READ_MEDIA_AUDIO);
            }
            
            if (!permissionsToRequest.isEmpty()) {
                permissionLauncher.launch(permissionsToRequest.toArray(new String[0]));
            }
        }
    }

    private void restoreNightMode() {
        SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
        int savedMode = prefs.getInt("night_mode", -1);
        if (savedMode == -1) return; // 未设置过，使用系统默认
        int currentMode = AppCompatDelegate.getDefaultNightMode();
        if (savedMode != currentMode) {
            AppCompatDelegate.setDefaultNightMode(savedMode);
        }
    }

    @Override
    public void onConfigurationChanged(android.content.res.Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        // 夜间模式改变时重新创建 Activity 以完整应用主题
        int currentNightMode = newConfig.uiMode & android.content.res.Configuration.UI_MODE_NIGHT_MASK;
        recreate();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        // 保存当前加载的 SO 文件路径
        if (soLoader != null && soLoader.getLoadedSoPath() != null) {
            outState.putString("loaded_so_path", soLoader.getLoadedSoPath());
        }
    }

    // ========== Recent Project Data Class ==========
    public static class RecentProject {
        String path;           // 复制后的路径（内部使用）
        String originalUri;    // 原始文件URI（用于重新加载）
        String name;
        String arch;
        String size;
        String time;
        String functions;
    }

    // ========== Recent Projects Adapter ==========

    public static class RecentProjectsAdapter extends RecyclerView.Adapter<RecentProjectsAdapter.VH> {
        private List<RecentProject> projects;
        private final OnProjectClickListener clickListener;

        public interface OnProjectClickListener {
            void onClick(RecentProject project);
        }

        public RecentProjectsAdapter(List<RecentProject> projects, OnProjectClickListener clickListener) {
            this.projects = projects;
            this.clickListener = clickListener;
        }

        public void setProjects(List<RecentProject> projects) {
            this.projects = projects;
            notifyDataSetChanged();
        }

        @Override
        public VH onCreateViewHolder(ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_recent_project, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(VH h, int position) {
            RecentProject p = projects.get(position);
            h.tvName.setText(p.name);
            String info = p.arch + "    " + p.time + "    " + p.size;
            h.tvInfo.setText(info);
            h.tvFunctions.setText(p.functions);

            h.itemView.setOnClickListener(v -> clickListener.onClick(p));
        }

        @Override
        public int getItemCount() {
            return projects.size();
        }

        static class VH extends RecyclerView.ViewHolder {
            TextView tvName, tvInfo, tvFunctions;

            VH(View v) {
                super(v);
                tvName = v.findViewById(R.id.tv_project_name);
                tvInfo = v.findViewById(R.id.tv_info);
                tvFunctions = v.findViewById(R.id.tv_functions);
            }
        }
    }
}
