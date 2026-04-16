package com.example.anative.ui;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.ScaleGestureDetector;
import android.view.View;

import com.example.anative.R;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;

/**
 * IDA Pro 风格的控制流图视图
 * - 条件分支: True向左, False向右 (树形展开)
 * - 方块宽度自适应文字
 * - 箭头: 下方出发→顶部进入, 回边从侧面绕行
 */
public class FlowChartView extends View {

    public static class BasicBlock {
        public String label;
        public List<String> instructions = new ArrayList<>();
        public long startAddr;
        public long endAddr;
        public List<Integer> successors = new ArrayList<>();
        public boolean isConditional;
    }

    // =================== 布局结果 ===================
    private static class BlockLayout {
        float x, y, w, h; // 方块中心x, 顶部y, 宽度, 高度
        int layer;
        int blockIdx;
    }

    private static class Edge {
        int from, to, succIdx;
        boolean isConditional;
        boolean isBackEdge;
        boolean routeOnLeft;
        int routeLane;
    }

    private final List<BasicBlock> blocks = new ArrayList<>();
    private final List<BlockLayout> layouts = new ArrayList<>();
    private final List<Edge> edges = new ArrayList<>();

    // =================== 绘制 Paint ===================
    private final Paint bgPaint = new Paint();
    private final Paint boxPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint headerPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint borderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint titlePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint instrPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint labelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint shadowPaint = new Paint();

    private float scale = 1.0f;
    private float translateX = 0, translateY = 0;
    private float lastTouchX, lastTouchY;
    private ScaleGestureDetector scaleDetector;
    private boolean isScaling = false;

    // 布局常量
    private static final float TEXT_SIZE = 22f;
    private static final float HEADER_SIZE = 24f;
    private static final float PAD = 14f;
    private static final float LINE_H = 28f;
    private static final float V_GAP = 80f;
    private static final float H_GAP = 40f;
    private static final float CORNER_R = 8f;
    private static final float MIN_W = 200f;
    private static final float ARC_R = 10f;
    private static final float BACK_EDGE_LANE_GAP = 28f;

    private int totalW = 800, totalH = 600;

    public FlowChartView(Context context) { super(context); init(context); }
    public FlowChartView(Context context, AttributeSet attrs) { super(context, attrs); init(context); }

    private int resColor(Context ctx, int id) {
        return androidx.core.content.ContextCompat.getColor(ctx, id);
    }

    private void init(Context ctx) {
        bgPaint.setColor(resColor(ctx, R.color.chart_bg)); bgPaint.setStyle(Paint.Style.FILL);
        boxPaint.setColor(resColor(ctx, R.color.chart_box_bg)); boxPaint.setStyle(Paint.Style.FILL);
        headerPaint.setColor(resColor(ctx, R.color.chart_header_bg)); headerPaint.setStyle(Paint.Style.FILL);
        borderPaint.setColor(resColor(ctx, R.color.chart_border)); borderPaint.setStyle(Paint.Style.STROKE); borderPaint.setStrokeWidth(1.5f);
        shadowPaint.setColor(resColor(ctx, R.color.chart_shadow)); shadowPaint.setStyle(Paint.Style.FILL);

        textPaint.setColor(resColor(ctx, R.color.chart_text)); textPaint.setTextSize(TEXT_SIZE);
        textPaint.setTypeface(android.graphics.Typeface.MONOSPACE);
        titlePaint.setTextSize(HEADER_SIZE); titlePaint.setColor(resColor(ctx, R.color.chart_text));
        titlePaint.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);
        instrPaint.setTextSize(TEXT_SIZE); instrPaint.setTypeface(android.graphics.Typeface.MONOSPACE);
        labelPaint.setTextSize(18f); labelPaint.setAntiAlias(true);
        labelPaint.setTypeface(android.graphics.Typeface.DEFAULT_BOLD);

        scaleDetector = new ScaleGestureDetector(getContext(), new ScaleGestureDetector.SimpleOnScaleGestureListener() {
            @Override public boolean onScale(ScaleGestureDetector d) {
                scale *= d.getScaleFactor();
                scale = Math.max(0.15f, Math.min(scale, 5.0f));
                invalidate(); return true;
            }
            @Override public boolean onScaleBegin(ScaleGestureDetector d) { isScaling = true; return true; }
            @Override public void onScaleEnd(ScaleGestureDetector d) { isScaling = false; }
        });
    }

    public void setBlocks(List<BasicBlock> newBlocks) {
        blocks.clear(); blocks.addAll(newBlocks);
        doLayout();
        invalidate();
    }

    // ======================== IDA风格布局 ========================

    private void doLayout() {
        layouts.clear();
        edges.clear();
        if (blocks.isEmpty()) return;

        int n = blocks.size();

        // 1. 计算每个方块的尺寸 (自适应文字宽度)
        float[] blockW = new float[n];
        float[] blockH = new float[n];
        for (int i = 0; i < n; i++) {
            BasicBlock b = blocks.get(i);
            float maxTextW = titlePaint.measureText(b.label);
            for (String instr : b.instructions) {
                float tw = instrPaint.measureText(instr);
                if (tw > maxTextW) maxTextW = tw;
            }
            blockW[i] = Math.max(MIN_W, maxTextW + PAD * 2 + 8);
            blockH[i] = HEADER_SIZE + PAD + PAD * 2 + b.instructions.size() * LINE_H;
        }

        // 2. BFS分层
        int[] layer = new int[n];
        boolean[] visited = new boolean[n];
        for (int i = 0; i < n; i++) layer[i] = -1;

        Queue<Integer> queue = new LinkedList<>();
        queue.add(0); visited[0] = true; layer[0] = 0;
        Set<Long> backEdgeSet = new HashSet<>();

        while (!queue.isEmpty()) {
            int cur = queue.poll();
            for (int succ : blocks.get(cur).successors) {
                if (succ < 0 || succ >= n) continue;
                if (!visited[succ]) {
                    visited[succ] = true;
                    layer[succ] = layer[cur] + 1;
                    queue.add(succ);
                } else if (layer[succ] <= layer[cur]) {
                    backEdgeSet.add(edgeKey(cur, succ));
                }
            }
        }
        // 处理未访问的块(不可达)
        for (int i = 0; i < n; i++) {
            if (layer[i] < 0) layer[i] = i;
        }

        // 3. 统计每层有哪些块
        int maxLayer = 0;
        for (int l : layer) if (l > maxLayer) maxLayer = l;

        List<List<Integer>> layerBlocks = new ArrayList<>();
        for (int l = 0; l <= maxLayer; l++) layerBlocks.add(new ArrayList<>());
        for (int i = 0; i < n; i++) layerBlocks.get(layer[i]).add(i);

        // 4. 层内排序: 条件分支的true在左, false在右
        //    简单启发式: 保持successors的顺序影响同层排列
        for (List<Integer> lb : layerBlocks) {
            // 按块索引排序(保持原始顺序)
            Collections.sort(lb);
        }

        // 5. 分配坐标
        // 每层计算总宽度，居中对齐
        float[] layerY = new float[maxLayer + 1];
        float y = PAD + 20;
        for (int l = 0; l <= maxLayer; l++) {
            layerY[l] = y;
            float maxH = 0;
            for (int bi : layerBlocks.get(l)) {
                if (blockH[bi] > maxH) maxH = blockH[bi];
            }
            y += maxH + V_GAP;
        }

        // 计算每层宽度，分配X
        float maxTotalW = 0;
        for (int l = 0; l <= maxLayer; l++) {
            List<Integer> lb = layerBlocks.get(l);
            float totalLayerW = 0;
            for (int bi : lb) totalLayerW += blockW[bi];
            totalLayerW += (lb.size() - 1) * H_GAP;
            if (totalLayerW > maxTotalW) maxTotalW = totalLayerW;
        }

        float canvasW = Math.max(maxTotalW + 200, 800);

        for (int l = 0; l <= maxLayer; l++) {
            List<Integer> lb = layerBlocks.get(l);
            float totalLayerW = 0;
            for (int bi : lb) totalLayerW += blockW[bi];
            totalLayerW += (lb.size() - 1) * H_GAP;

            float startX = (canvasW - totalLayerW) / 2;
            float cx = startX;
            for (int bi : lb) {
                BlockLayout bl = new BlockLayout();
                bl.blockIdx = bi;
                bl.w = blockW[bi];
                bl.h = blockH[bi];
                bl.x = cx + bl.w / 2; // 中心X
                bl.y = layerY[l];
                bl.layer = l;
                // 确保layouts按blockIdx存储
                while (layouts.size() <= bi) layouts.add(null);
                layouts.set(bi, bl);
                cx += bl.w + H_GAP;
            }
        }

        totalW = (int) (canvasW + 100);
        totalH = (int) (y + 100);

        // 6. 构建边
        for (int i = 0; i < n; i++) {
            BasicBlock b = blocks.get(i);
            for (int si = 0; si < b.successors.size(); si++) {
                int target = b.successors.get(si);
                if (target < 0 || target >= n) continue;
                Edge e = new Edge();
                e.from = i; e.to = target; e.succIdx = si;
                e.isConditional = b.isConditional && b.successors.size() == 2;
                e.isBackEdge = backEdgeSet.contains(edgeKey(i, target));
                edges.add(e);
            }
        }

        int leftLaneCount = 0;
        int rightLaneCount = 0;
        for (Edge e : edges) {
            if (!e.isBackEdge) continue;
            BlockLayout fromBl = getLayout(e.from);
            BlockLayout toBl = getLayout(e.to);
            boolean routeLeft = true;
            if (fromBl != null && toBl != null) {
                routeLeft = toBl.x <= fromBl.x;
            }
            e.routeOnLeft = routeLeft;
            if (routeLeft) {
                e.routeLane = leftLaneCount++;
            } else {
                e.routeLane = rightLaneCount++;
            }
        }
    }

    private long edgeKey(int from, int to) { return ((long) from << 32) | (to & 0xFFFFFFFFL); }

    // ======================== 绘制 ========================

    @Override
    protected void onMeasure(int wSpec, int hSpec) {
        setMeasuredDimension(
                Math.max(totalW, MeasureSpec.getSize(wSpec)),
                Math.max(totalH, MeasureSpec.getSize(hSpec)));
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        canvas.drawRect(0, 0, getWidth(), getHeight(), bgPaint);
        canvas.save();
        canvas.translate(translateX, translateY);
        canvas.scale(scale, scale);

        // 先画边，再画块(块覆盖在边上面)
        drawEdges(canvas);
        for (int i = 0; i < blocks.size(); i++) {
            BlockLayout bl = getLayout(i);
            if (bl != null) drawBlock(canvas, blocks.get(i), bl);
        }

        canvas.restore();
    }

    private BlockLayout getLayout(int idx) {
        return (idx >= 0 && idx < layouts.size()) ? layouts.get(idx) : null;
    }

    private void drawBlock(Canvas canvas, BasicBlock block, BlockLayout bl) {
        float left = bl.x - bl.w / 2, top = bl.y;
        float right = bl.x + bl.w / 2, bottom = bl.y + bl.h;
        RectF rect = new RectF(left, top, right, bottom);

        // 阴影
        canvas.drawRoundRect(left + 3, top + 3, right + 3, bottom + 3, CORNER_R, CORNER_R, shadowPaint);
        // 背景 + 边框
        canvas.drawRoundRect(rect, CORNER_R, CORNER_R, boxPaint);
        canvas.drawRoundRect(rect, CORNER_R, CORNER_R, borderPaint);

        // 标题栏
        float headerBottom = top + HEADER_SIZE + PAD;
        Path hp = new Path();
        hp.addRoundRect(new RectF(left, top, right, headerBottom),
                new float[]{CORNER_R, CORNER_R, CORNER_R, CORNER_R, 0, 0, 0, 0}, Path.Direction.CW);
        canvas.drawPath(hp, headerPaint);
        canvas.drawText(block.label, left + PAD, top + HEADER_SIZE + PAD / 2, titlePaint);

        // 分隔线
        Paint sepPaint = new Paint();
        sepPaint.setColor(0xFF3D5A80);
        sepPaint.setStrokeWidth(1f);
        canvas.drawLine(left, headerBottom, right, headerBottom, sepPaint);

        // 指令 - 不截断，方块已经够宽
        float iy = headerBottom + PAD + LINE_H * 0.8f;
        for (String instr : block.instructions) {
            instrPaint.setColor(getInstrColor(instr));
            canvas.drawText(instr, left + PAD, iy, instrPaint);
            iy += LINE_H;
        }
    }

    private int getInstrColor(String instr) {
        if (instr.contains(";")) return 0xFF6A9955;
        String trimmed = instr.trim();
        int cp = trimmed.indexOf(':');
        if (cp > 0 && cp <= 9) {
            String ac = trimmed.substring(cp + 1).trim();
            int sp = ac.indexOf(' ');
            String m = sp > 0 ? ac.substring(0, sp).toLowerCase() : ac.toLowerCase();
            if (m.startsWith("b") || m.equals("ret") || m.equals("cbz") || m.equals("cbnz")
                    || m.equals("tbz") || m.equals("tbnz")) return 0xFFE06C75;
            if (m.startsWith("ld") || m.startsWith("st") || m.equals("stp") || m.equals("ldp"))
                return 0xFF61AFEF;
            if (m.startsWith("adr") || m.equals("mov") || m.equals("movz") || m.equals("movk"))
                return 0xFFE5C07B;
        }
        return 0xFFABB2BF;
    }

    // ======================== 画边 ========================

    private void drawEdges(Canvas canvas) {
        // 先画回边(虚线/半透明), 再画正常边
        List<Edge> normal = new ArrayList<>(), back = new ArrayList<>();
        for (Edge e : edges) {
            if (e.isBackEdge) back.add(e); else normal.add(e);
        }

        for (Edge e : normal) drawOneEdge(canvas, e, false);
        for (Edge e : back) drawOneEdge(canvas, e, true);
    }

    private void drawOneEdge(Canvas canvas, Edge e, boolean isBack) {
        BlockLayout fromBl = getLayout(e.from);
        BlockLayout toBl = getLayout(e.to);
        if (fromBl == null || toBl == null) return;

        int color;
        if (e.isConditional) {
            color = (e.succIdx == 0) ? 0xFF4EC9B0 : 0xFFE06C75; // green=T, red=F
        } else {
            color = 0xFF569CD6;
        }

        Paint lp = new Paint(Paint.ANTI_ALIAS_FLAG);
        lp.setStyle(Paint.Style.STROKE);
        lp.setStrokeWidth(2.5f);
        lp.setColor(color);
        lp.setStrokeJoin(Paint.Join.ROUND);
        lp.setStrokeCap(Paint.Cap.ROUND);
        if (isBack) lp.setAlpha(180);

        float fromBottom = fromBl.y + fromBl.h;
        float toTop = toBl.y;

        if (!isBack) {
            // 正常边: 从底部出发 → 到顶部中心
            float sx, sy, ex, ey;
            sy = fromBottom;
            ey = toTop;

            if (e.isConditional) {
                // 根据目标位置决定出发点: 目标在左→从左出发, 目标在右→从右出发
                // 避免线条交叉
                if (toBl.x < fromBl.x) {
                    sx = fromBl.x - fromBl.w * 0.25f;
                } else if (toBl.x > fromBl.x) {
                    sx = fromBl.x + fromBl.w * 0.25f;
                } else {
                    sx = (e.succIdx == 0) ? fromBl.x - fromBl.w * 0.25f : fromBl.x + fromBl.w * 0.25f;
                }
            } else {
                sx = fromBl.x;
            }
            ex = toBl.x;

            if (Math.abs(sx - ex) < 3) {
                // 几乎垂直 → 直线
                canvas.drawLine(sx, sy, ex, ey - 10, lp);
                drawArrowDown(canvas, ex, ey - 10, color);
            } else {
                // 有水平偏移 → 贝塞尔曲线 (IDA风格)
                float midY = (sy + ey) / 2;
                Path path = new Path();
                path.moveTo(sx, sy);
                path.cubicTo(sx, midY, ex, midY, ex, ey - 10);
                canvas.drawPath(path, lp);
                drawArrowDown(canvas, ex, ey - 10, color);
            }

            // T/F 标注
            if (e.isConditional) {
                String lbl = (e.succIdx == 0) ? "T" : "F";
                float labelX = (sx < fromBl.x) ? sx - 18 : sx + 12;
                drawEdgeLabel(canvas, lbl, labelX, sy + 18, color);
            }
        } else {
            // 回边: 从底部出发，完全绕到所有方块外侧，从顶部进入目标块
            float sx = fromBl.x;
            float sy = fromBottom;
            float ex = toBl.x;
            float ey = toTop;

            // 找出源和目标之间所有块的最左/最右边界(含自己)
            int minIdx = Math.min(e.from, e.to);
            int maxIdx = Math.max(e.from, e.to);
            float globalLeft = Float.MAX_VALUE, globalRight = Float.MIN_VALUE;
            for (int bi = minIdx; bi <= maxIdx; bi++) {
                BlockLayout bl = getLayout(bi);
                if (bl == null) continue;
                float l = bl.x - bl.w / 2;
                float r = bl.x + bl.w / 2;
                if (l < globalLeft) globalLeft = l;
                if (r > globalRight) globalRight = r;
            }

            float laneOffset = 48f + e.routeLane * BACK_EDGE_LANE_GAP;
            float sideX = e.routeOnLeft ? (globalLeft - laneOffset) : (globalRight + laneOffset);
            float r = ARC_R;

            float exitX = e.routeOnLeft ? (fromBl.x - fromBl.w * 0.35f) : (fromBl.x + fromBl.w * 0.35f);
            float enterX = e.routeOnLeft ? (toBl.x - toBl.w * 0.28f) : (toBl.x + toBl.w * 0.28f);

            Path path = new Path();
            // 1. 从方块底部向下延伸一小段
            path.moveTo(exitX, sy);
            path.lineTo(exitX, sy + 20);
            // 2. 圆角转向侧边
            if (e.routeOnLeft) {
                path.quadTo(exitX, sy + 20 + r, exitX - r, sy + 20 + r);
                path.lineTo(sideX + r, sy + 20 + r);
                path.quadTo(sideX, sy + 20 + r, sideX, sy + 20);
            } else {
                path.quadTo(exitX, sy + 20 + r, exitX + r, sy + 20 + r);
                path.lineTo(sideX - r, sy + 20 + r);
                path.quadTo(sideX, sy + 20 + r, sideX, sy + 20);
            }
            // 5. 竖直向上(在所有方块外侧)
            path.lineTo(sideX, ey - 20);
            // 6. 圆角转向目标侧
            if (e.routeOnLeft) {
                path.quadTo(sideX, ey - 20 - r, sideX + r, ey - 20 - r);
                path.lineTo(enterX - r, ey - 20 - r);
                path.quadTo(enterX, ey - 20 - r, enterX, ey - 20);
            } else {
                path.quadTo(sideX, ey - 20 - r, sideX - r, ey - 20 - r);
                path.lineTo(enterX + r, ey - 20 - r);
                path.quadTo(enterX, ey - 20 - r, enterX, ey - 20);
            }
            // 9. 向下到目标块顶部
            path.lineTo(enterX, ey - 10);

            canvas.drawPath(path, lp);
            drawArrowDown(canvas, enterX, ey - 10, color);

            // T/F 标注 (在侧边通道上)
            if (e.isConditional) {
                String lbl = (e.succIdx == 0) ? "T" : "F";
                float labelX = e.routeOnLeft ? sideX - 16 : sideX + 16;
                drawEdgeLabel(canvas, lbl, labelX, (sy + ey) / 2, color);
            }
        }
    }

    private void drawEdgeLabel(Canvas canvas, String text, float centerX, float baselineY, int color) {
        labelPaint.setColor(color);
        labelPaint.setTextAlign(Paint.Align.CENTER);
        float textW = labelPaint.measureText(text);
        Paint.FontMetrics fm = labelPaint.getFontMetrics();
        float textH = fm.descent - fm.ascent;
        float padX = 10f;
        float padY = 4f;
        float left = centerX - textW / 2f - padX;
        float top = baselineY + fm.ascent - padY;
        float right = centerX + textW / 2f + padX;
        float bottom = baselineY + fm.descent + padY;

        Paint bg = new Paint(Paint.ANTI_ALIAS_FLAG);
        bg.setStyle(Paint.Style.FILL);
        bg.setColor(resColor(getContext(), R.color.chart_box_bg));
        bg.setAlpha(235);

        Paint stroke = new Paint(Paint.ANTI_ALIAS_FLAG);
        stroke.setStyle(Paint.Style.STROKE);
        stroke.setStrokeWidth(1.5f);
        stroke.setColor(color);

        RectF rect = new RectF(left, top, right, bottom);
        canvas.drawRoundRect(rect, 10f, 10f, bg);
        canvas.drawRoundRect(rect, 10f, 10f, stroke);
        canvas.drawText(text, centerX, baselineY, labelPaint);
        labelPaint.setTextAlign(Paint.Align.LEFT);
    }

    // ======================== 箭头 ========================

    private void drawArrowDown(Canvas canvas, float x, float y, int color) {
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        p.setColor(color); p.setStyle(Paint.Style.FILL);
        Path a = new Path();
        a.moveTo(x, y + 10); a.lineTo(x - 5, y); a.lineTo(x + 5, y); a.close();
        canvas.drawPath(a, p);
    }

    // ======================== 触摸 ========================

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        scaleDetector.onTouchEvent(event);
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                lastTouchX = event.getX(); lastTouchY = event.getY();
                // 按下时立即禁止ViewPager2拦截，流程图自己处理所有手势
                getParent().requestDisallowInterceptTouchEvent(true);
                break;
            case MotionEvent.ACTION_MOVE:
                if (!isScaling && event.getPointerCount() == 1) {
                    translateX += event.getX() - lastTouchX;
                    translateY += event.getY() - lastTouchY;
                    invalidate();
                }
                lastTouchX = event.getX(); lastTouchY = event.getY();
                break;
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                getParent().requestDisallowInterceptTouchEvent(false);
                break;
        }
        return true;
    }
}
