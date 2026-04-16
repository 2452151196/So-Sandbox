package com.example.anative.ui;

import android.content.Context;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.ViewConfiguration;
import android.widget.HorizontalScrollView;

/**
 * 智能水平滚动视图，嵌套在ViewPager2中时:
 * - 慢速水平滑动 → 滚动代码内容
 * - 快速水平滑动 → 切换标签页
 * - 垂直滑动 → 交给RecyclerView上下滚动
 */
public class SmartHScrollView extends HorizontalScrollView {

    private float startX, startY;
    private VelocityTracker velocityTracker;
    private boolean decided;          // 是否已决定本次手势归谁
    private boolean letParentHandle;  // true=交给ViewPager切标签

    // 快滑阈值: 超过此速度(px/s)视为"快滑"，触发切标签
    private int flingThreshold;

    public SmartHScrollView(Context context) {
        super(context);
        init(context);
    }

    public SmartHScrollView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public SmartHScrollView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        // 使用系统fling最小速度的 1.8 倍作为"快滑"阈值
        flingThreshold = (int) (ViewConfiguration.get(context).getScaledMinimumFlingVelocity() * 1.8f);
    }

    @Override
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        switch (ev.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                startX = ev.getX();
                startY = ev.getY();
                decided = false;
                letParentHandle = false;
                initVelocityTracker(ev);
                // 按下时先拦住父视图
                getParent().requestDisallowInterceptTouchEvent(true);
                break;
            case MotionEvent.ACTION_MOVE:
                addToVelocityTracker(ev);
                break;
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                recycleVelocityTracker();
                getParent().requestDisallowInterceptTouchEvent(false);
                break;
        }
        return super.onInterceptTouchEvent(ev);
    }

    @Override
    public boolean onTouchEvent(MotionEvent ev) {
        addToVelocityTracker(ev);

        switch (ev.getActionMasked()) {
            case MotionEvent.ACTION_MOVE:
                if (!decided) {
                    float dx = ev.getX() - startX;
                    float dy = ev.getY() - startY;
                    float absDx = Math.abs(dx);
                    float absDy = Math.abs(dy);

                    if (absDx > 12 || absDy > 12) {
                        if (absDy > absDx) {
                            // 垂直滑动 → 自己留着(RecyclerView上下滚)
                            decided = true;
                            letParentHandle = false;
                            getParent().requestDisallowInterceptTouchEvent(true);
                        } else {
                            // 水平滑动 → 看速度
                            velocityTracker.computeCurrentVelocity(1000);
                            float vx = Math.abs(velocityTracker.getXVelocity());

                            if (vx > flingThreshold) {
                                // 快滑 → 切标签
                                decided = true;
                                letParentHandle = true;
                                getParent().requestDisallowInterceptTouchEvent(false);
                            } else if (absDx > 40) {
                                // 慢滑超过一定距离 → 滚动代码
                                decided = true;
                                letParentHandle = false;
                                getParent().requestDisallowInterceptTouchEvent(true);
                            }
                            // 距离和速度都不够 → 继续等待判断
                        }
                    }
                }
                break;

            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                getParent().requestDisallowInterceptTouchEvent(false);
                decided = false;
                letParentHandle = false;
                recycleVelocityTracker();
                break;
        }

        // 如果已决定交给父视图，不消费后续MOVE
        if (letParentHandle) {
            return false;
        }
        return super.onTouchEvent(ev);
    }

    private void initVelocityTracker(MotionEvent ev) {
        if (velocityTracker != null) velocityTracker.recycle();
        velocityTracker = VelocityTracker.obtain();
        velocityTracker.addMovement(ev);
    }

    private void addToVelocityTracker(MotionEvent ev) {
        if (velocityTracker != null) velocityTracker.addMovement(ev);
    }

    private void recycleVelocityTracker() {
        if (velocityTracker != null) {
            velocityTracker.recycle();
            velocityTracker = null;
        }
    }
}
