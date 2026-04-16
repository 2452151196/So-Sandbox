package com.example.anative.ui;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Menu;
import android.view.MenuItem;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.viewpager2.widget.ViewPager2;

import com.example.anative.R;
import com.example.anative.core.DataHolder;
import androidx.fragment.app.FragmentManager;
import com.example.anative.core.NativeFunction;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

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

        // 获取数据
        funcName = getIntent().getStringExtra(EXTRA_FUNC_NAME);
        funcAddr = getIntent().getLongExtra(EXTRA_FUNC_ADDR, 0);
        funcSize = getIntent().getLongExtra(EXTRA_FUNC_SIZE, 0);
        demangledName = getIntent().getStringExtra(EXTRA_DEMANGLED_NAME);
        signature = getIntent().getStringExtra(EXTRA_SIGNATURE);
        baseAddress = DataHolder.getInstance().getBaseAddress();

        // 设置 Toolbar
        androidx.appcompat.widget.Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setTitle(demangledName != null ? demangledName : funcName);
            getSupportActionBar().setSubtitle(String.format("0x%X | %d bytes", funcAddr - baseAddress, funcSize));
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }
        toolbar.setNavigationOnClickListener(v -> finish());

        // 设置 ViewPager 和 TabLayout
        viewPager = findViewById(R.id.viewPager);
        tabLayout = findViewById(R.id.tabLayout);

        pagerAdapter = new FunctionPagerAdapter(this, funcAddr, funcSize, demangledName, signature);
        viewPager.setAdapter(pagerAdapter);

        // 优化滑动手感
        viewPager.setOffscreenPageLimit(2); // 预加载相邻页面，切换更流畅
        viewPager.setUserInputEnabled(true); // 确保滑动启用

        // 设置平滑的页面切换动画
        viewPager.setPageTransformer(new DepthPageTransformer());

        // 关联 TabLayout 和 ViewPager
        String[] tabTitles = {"汇编", "伪C", "Hex", "Sections", "流程图"};
        new TabLayoutMediator(tabLayout, viewPager,
                (tab, position) -> tab.setText(tabTitles[position])
        ).attach();

        SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
        if (prefs.getBoolean(SettingsActivity.PREF_AI_PSEUDOC_ENABLED, false)) {
            viewPager.setCurrentItem(1, false);
        }

        // 点击tab时平滑滚动
        tabLayout.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override public void onTabSelected(TabLayout.Tab tab) {
                viewPager.setCurrentItem(tab.getPosition(), true); // true = 平滑动画
            }
            @Override public void onTabUnselected(TabLayout.Tab tab) {}
            @Override public void onTabReselected(TabLayout.Tab tab) {}
        });
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_function_detail, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == R.id.action_run) {
            showInvokeDialog();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void showInvokeDialog() {
        NativeFunction func = new NativeFunction(funcName, funcAddr, funcSize, "symtab");
        InvokeDialog dialog = InvokeDialog.newInstance(func, baseAddress);
        dialog.show(getSupportFragmentManager(), "invoke");
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
