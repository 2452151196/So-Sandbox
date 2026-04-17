package com.example.anative.ui;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import com.example.anative.core.DataHolder;

import java.util.HashMap;
import java.util.Map;

public class FunctionPagerAdapter extends FragmentStateAdapter {

    private final long funcAddr;
    private final long funcSize;
    private final String demangledName;
    private final String signature;

    // 保存 Fragment 引用
    private final Map<Integer, Fragment> fragmentMap = new HashMap<>();

    public FunctionPagerAdapter(@NonNull FragmentActivity activity,
                                long funcAddr, long funcSize,
                                String demangledName, String signature) {
        super(activity);
        this.funcAddr = funcAddr;
        this.funcSize = funcSize;
        this.demangledName = demangledName;
        this.signature = signature;
    }

    public Fragment getFragment(int position) {
        return fragmentMap.get(position);
    }

    public void refreshAllFragments() {
        // 刷新 AsmFragment (position 0)
        Fragment asmFragment = fragmentMap.get(0);
        if (asmFragment instanceof AsmFragment) {
            ((AsmFragment) asmFragment).refreshDisplay();
        }
        // 刷新 HexFragment (position 2)
        Fragment hexFragment = fragmentMap.get(2);
        if (hexFragment instanceof HexFragment) {
            ((HexFragment) hexFragment).refreshFromDataHolder();
        }
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        Fragment fragment;
        switch (position) {
            case 0:
                fragment = AsmFragment.newInstance(funcAddr, funcSize);
                break;
            case 1:
                fragment = PseudoCFragment.newInstance(funcAddr, funcSize, demangledName, signature, DataHolder.getInstance().getBaseAddress());
                break;
            case 2:
                fragment = HexFragment.newInstance(funcAddr, funcSize);
                break;
            case 3:
                fragment = TextFragment.newInstance(funcAddr, funcSize);
                break;
            case 4:
                fragment = FlowChartFragment.newInstance(funcAddr, funcSize);
                break;
            default:
                fragment = AsmFragment.newInstance(funcAddr, funcSize);
                break;
        }
        fragmentMap.put(position, fragment);
        return fragment;
    }

    @Override
    public int getItemCount() {
        return 5;
    }
}
