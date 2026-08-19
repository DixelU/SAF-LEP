package com.example.saflep;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PixelFormat;
import android.graphics.drawable.Drawable;
import android.util.StateSet;

final class HudPanelDrawable extends Drawable {
    private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Path path = new Path();
    private final int fillColor;
    private final int strokeColor;
    private final int accentColor;
    private final float bevel;
    private final float strokeWidth;

    HudPanelDrawable(
            int fillColor,
            int strokeColor,
            int accentColor,
            float density
    ) {
        this.fillColor = fillColor;
        this.strokeColor = strokeColor;
        this.accentColor = accentColor;
        bevel = 9f * density;
        strokeWidth = Math.max(1f, density);
    }

    @Override
    public void draw(Canvas canvas) {
        float left = getBounds().left + strokeWidth;
        float top = getBounds().top + strokeWidth;
        float right = getBounds().right - strokeWidth;
        float bottom = getBounds().bottom - strokeWidth;

        path.reset();
        path.moveTo(left + bevel, top);
        path.lineTo(right - bevel, top);
        path.lineTo(right, top + bevel);
        path.lineTo(right, bottom - bevel);
        path.lineTo(right - bevel, bottom);
        path.lineTo(left + bevel, bottom);
        path.lineTo(left, bottom - bevel);
        path.lineTo(left, top + bevel);
        path.close();

        boolean enabled = StateSet.stateSetMatches(
                new int[]{android.R.attr.state_enabled},
                getState()
        );
        boolean pressed = StateSet.stateSetMatches(
                new int[]{android.R.attr.state_pressed},
                getState()
        );
        int alpha = enabled ? 255 : 90;

        paint.setStyle(Paint.Style.FILL);
        paint.setColor(pressed ? blend(fillColor, accentColor, 0.18f) : fillColor);
        paint.setAlpha(alpha);
        canvas.drawPath(path, paint);

        paint.setStyle(Paint.Style.STROKE);
        paint.setStrokeWidth(strokeWidth);
        paint.setColor(pressed ? accentColor : strokeColor);
        canvas.drawPath(path, paint);

        if (accentColor != Color.TRANSPARENT) {
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(strokeWidth * 2f);
            paint.setColor(accentColor);
            canvas.drawLine(left + bevel, top, left + (right - left) * 0.38f, top, paint);
            canvas.drawLine(right, bottom - bevel * 2.3f, right, bottom - bevel, paint);
        }
    }

    @Override
    protected boolean onStateChange(int[] state) {
        invalidateSelf();
        return true;
    }

    @Override
    public boolean isStateful() {
        return true;
    }

    @Override
    public void setAlpha(int alpha) {
        paint.setAlpha(alpha);
        invalidateSelf();
    }

    @Override
    public void setColorFilter(ColorFilter colorFilter) {
        paint.setColorFilter(colorFilter);
        invalidateSelf();
    }

    @Override
    public int getOpacity() {
        return PixelFormat.TRANSLUCENT;
    }

    private static int blend(int from, int to, float amount) {
        float inverse = 1f - amount;
        return Color.rgb(
                Math.round(Color.red(from) * inverse + Color.red(to) * amount),
                Math.round(Color.green(from) * inverse + Color.green(to) * amount),
                Math.round(Color.blue(from) * inverse + Color.blue(to) * amount)
        );
    }
}
