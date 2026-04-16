package com.example.anative.ui;

import android.view.View;

import androidx.annotation.NonNull;
import androidx.viewpager2.widget.ViewPager2;

/**
 * ViewPager2 页面切换动画 - 深度效果
 * 滑动时当前页面淡出缩小，下一页面淡入放大
 */
public class DepthPageTransformer implements ViewPager2.PageTransformer {

    private static final float MIN_SCALE = 0.85f;
    private static final float MIN_ALPHA = 0.5f;

    @Override
    public void transformPage(@NonNull View page, float position) {
        int pageWidth = page.getWidth();

        if (position < -1) { // 屏幕左侧之外
            page.setAlpha(0f);
        } else if (position <= 0) { // 从右向左滑动 [-1, 0]
            // 当前页面：正常透明度，轻微缩放
            page.setAlpha(1f);
            page.setTranslationX(0f);
            page.setTranslationZ(0f);
            page.setScaleX(1f);
            page.setScaleY(1f);
        } else if (position <= 1) { // 从左向右滑动 [0, 1]
            // 下一页面：淡入并放大
            page.setAlpha(1 - position);

            // 抵消默认的滑动动画，添加自定义效果
            page.setTranslationX(pageWidth * -position * 0.5f);
            page.setTranslationZ(-1f); // 置于底层

            // 缩放效果
            float scaleFactor = MIN_SCALE + (1 - MIN_SCALE) * (1 - Math.abs(position));
            page.setScaleX(scaleFactor);
            page.setScaleY(scaleFactor);

            // 淡入淡出
            page.setAlpha(MIN_ALPHA + (1 - MIN_ALPHA) * (1 - position));
        } else { // 屏幕右侧之外
            page.setAlpha(0f);
        }
    }
}
