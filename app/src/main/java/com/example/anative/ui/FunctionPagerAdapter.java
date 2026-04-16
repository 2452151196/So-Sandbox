package com.example.anative.ui;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

import com.example.anative.core.DataHolder;

public class FunctionPagerAdapter extends FragmentStateAdapter {

    private final long funcAddr;
    private final long funcSize;
    private final String demangledName;
    private final String signature;

    public FunctionPagerAdapter(@NonNull FragmentActivity activity,
                                long funcAddr, long funcSize,
                                String demangledName, String signature) {
        super(activity);
        this.funcAddr = funcAddr;
        this.funcSize = funcSize;
        this.demangledName = demangledName;
        this.signature = signature;
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        switch (position) {
            case 0:
                return AsmFragment.newInstance(funcAddr, funcSize);
            case 1:
                return PseudoCFragment.newInstance(funcAddr, funcSize, demangledName, signature, DataHolder.getInstance().getBaseAddress());
            case 2:
                return HexFragment.newInstance(funcAddr, funcSize);
            case 3:
                return TextFragment.newInstance(funcAddr, funcSize);
            case 4:
                return FlowChartFragment.newInstance(funcAddr, funcSize);
            default:
                return AsmFragment.newInstance(funcAddr, funcSize);
        }
    }

    @Override
    public int getItemCount() {
        return 5;
    }
}
