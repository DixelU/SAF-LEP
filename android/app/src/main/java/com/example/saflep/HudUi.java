package com.example.saflep;

import android.app.Activity;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

final class HudUi {
    static final int VOID = Color.rgb(10, 14, 18);
    static final int PANEL = Color.rgb(15, 23, 29);
    static final int PANEL_RAISED = Color.rgb(21, 31, 38);
    static final int LINE = Color.rgb(98, 123, 135);
    static final int TEXT = Color.rgb(226, 239, 241);
    static final int MUTED = Color.rgb(132, 155, 161);
    static final int GREEN = Color.rgb(52, 211, 137);
    static final int CYAN = Color.rgb(34, 211, 238);
    static final int BLUE = Color.rgb(18, 118, 255);
    static final int RED = Color.rgb(255, 91, 105);
    static final int AMBER = Color.rgb(250, 184, 64);

    private HudUi() {}

    static final class Screen {
        final ScrollView scroll;
        final LinearLayout content;

        Screen(ScrollView scroll, LinearLayout content) {
            this.scroll = scroll;
            this.content = content;
        }
    }

    static Screen createScreen(Activity activity) {
        configureWindow(activity);
        int horizontal = dp(activity, 18);
        int vertical = dp(activity, 20);

        LinearLayout content = new LinearLayout(activity);
        content.setOrientation(LinearLayout.VERTICAL);

        ScrollView scroll = new ScrollView(activity);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);
        scroll.setBackgroundColor(VOID);
        scroll.addView(content, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        ));

        final int baseLeft = horizontal;
        final int baseTop = vertical;
        final int baseRight = horizontal;
        final int baseBottom = dp(activity, 36);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(
                    baseLeft + insets.getSystemWindowInsetLeft(),
                    baseTop + insets.getSystemWindowInsetTop(),
                    baseRight + insets.getSystemWindowInsetRight(),
                    baseBottom + insets.getSystemWindowInsetBottom()
            );
            // Insets are represented as padding here; children should not add them again.
            return insets.consumeSystemWindowInsets();
        });
        scroll.requestApplyInsets();
        return new Screen(scroll, content);
    }

    static void addHeader(
            Context context,
            LinearLayout parent,
            String eyebrow,
            String title,
            String subtitle
    ) {
        TextView eyebrowView = text(context, eyebrow, 11, GREEN, Typeface.BOLD);
        eyebrowView.setLetterSpacing(0.16f);
        parent.addView(eyebrowView);

        TextView titleView = text(context, title, 28, TEXT, Typeface.BOLD);
        titleView.setLetterSpacing(0.04f);
        parent.addView(titleView, topMargin(context, 4));

        TextView subtitleView = text(context, subtitle, 13, MUTED, Typeface.NORMAL);
        subtitleView.setLineSpacing(0f, 1.15f);
        parent.addView(subtitleView, topMargin(context, 6));

        View rail = new View(context);
        rail.setBackgroundColor(GREEN);
        LinearLayout.LayoutParams railParams = new LinearLayout.LayoutParams(
                dp(context, 72),
                dp(context, 2)
        );
        railParams.topMargin = dp(context, 14);
        railParams.bottomMargin = dp(context, 14);
        parent.addView(rail, railParams);
    }

    static LinearLayout panel(Context context) {
        LinearLayout panel = new LinearLayout(context);
        panel.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(context, 18);
        panel.setPadding(padding, padding, padding, padding);
        panel.setBackground(new HudPanelDrawable(
                PANEL,
                LINE,
                CYAN,
                context.getResources().getDisplayMetrics().density
        ));
        panel.setElevation(dp(context, 3));
        return panel;
    }

    static TextView sectionLabel(Context context, String value) {
        TextView label = text(context, value, 11, CYAN, Typeface.BOLD);
        label.setLetterSpacing(0.14f);
        return label;
    }

    static TextView text(
            Context context,
            String value,
            float size,
            int color,
            int style
    ) {
        TextView view = new TextView(context);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        view.setTypeface(Typeface.create(Typeface.MONOSPACE, style));
        return view;
    }

    static EditText input(Context context, String hint) {
        EditText input = new EditText(context);
        input.setSingleLine(true);
        input.setTextColor(TEXT);
        input.setHintTextColor(MUTED);
        input.setTextSize(15);
        input.setTypeface(Typeface.MONOSPACE);
        input.setHint(hint);
        input.setPadding(dp(context, 14), dp(context, 12), dp(context, 14), dp(context, 12));
        input.setBackground(new HudPanelDrawable(
                PANEL_RAISED,
                BLUE,
                Color.TRANSPARENT,
                context.getResources().getDisplayMetrics().density
        ));
        return input;
    }

    static Button button(Context context, String value, int accentColor) {
        Button button = new Button(context);
        button.setText(value);
        button.setTextColor(TEXT);
        button.setTextSize(13);
        button.setAllCaps(false);
        button.setTypeface(Typeface.create(Typeface.MONOSPACE, Typeface.BOLD));
        button.setLetterSpacing(0.08f);
        button.setGravity(Gravity.CENTER);
        button.setMinHeight(dp(context, 52));
        button.setPadding(dp(context, 14), dp(context, 10), dp(context, 14), dp(context, 10));
        button.setBackground(new HudPanelDrawable(
                PANEL_RAISED,
                accentColor,
                accentColor,
                context.getResources().getDisplayMetrics().density
        ));
        button.setElevation(dp(context, 2));
        return button;
    }

    static LinearLayout.LayoutParams topMargin(Context context, int dp) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.topMargin = dp(context, dp);
        return params;
    }

    static int dp(Context context, int value) {
        return Math.round(value * context.getResources().getDisplayMetrics().density);
    }

    private static void configureWindow(Activity activity) {
        Window window = activity.getWindow();
        window.setStatusBarColor(VOID);
        window.setNavigationBarColor(VOID);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            window.setNavigationBarDividerColor(VOID);
        }
        window.getDecorView().setSystemUiVisibility(0);
    }
}
