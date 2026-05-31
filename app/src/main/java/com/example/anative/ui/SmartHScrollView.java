package com.example.anative.ui;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.ViewConfiguration;
import android.widget.HorizontalScrollView;

/**
 * 水平滚动视图，用于代码区域的水平滚动。
 * ViewPager2 已禁用滑动切换，所有水平手势均由此视图处理。
 * 垂直滑动交给内部 RecyclerView 上下滚动。
 */
public class SmartHScrollView extends HorizontalScrollView {

    private float startX, startY;
    private boolean decided;

    public SmartHScrollView(Context context) {
        super(context);
    }

    public SmartHScrollView(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public SmartHScrollView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    @Override
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        switch (ev.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                startX = ev.getX();
                startY = ev.getY();
                decided = false;
                // 阻止 ViewPager2 拦截触摸事件
                getParent().requestDisallowInterceptTouchEvent(true);
                break;
        }
        return super.onInterceptTouchEvent(ev);
    }

    @Override
    public boolean onTouchEvent(MotionEvent ev) {
        switch (ev.getActionMasked()) {
            case MotionEvent.ACTION_MOVE:
                if (!decided) {
                    float dx = Math.abs(ev.getX() - startX);
                    float dy = Math.abs(ev.getY() - startY);
                    if (dx > 12 || dy > 12) {
                        decided = true;
                        // 始终阻止 ViewPager2 拦截
                        getParent().requestDisallowInterceptTouchEvent(true);
                    }
                }
                break;
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                decided = false;
                break;
        }
        return super.onTouchEvent(ev);
    }
}
