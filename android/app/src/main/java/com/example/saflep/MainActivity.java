package com.example.saflep;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST = 1001;
    private static final int NOTIFICATION_REQUEST = 1002;

    private final Handler statusHandler = new Handler(Looper.getMainLooper());
    private final Runnable statusUpdater = new Runnable() {
        @Override
        public void run() {
            refreshStatus();
            statusHandler.postDelayed(this, 500);
        }
    };

    private TextView stateCode;
    private TextView stateHeadline;
    private TextView statusPreview;
    private TextView endpointValue;
    private TextView routeValue;
    private Button actionButton;
    private Intent pendingServiceIntent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(createContentView());
        refreshConfiguration();
        refreshStatus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshConfiguration();
        statusHandler.removeCallbacks(statusUpdater);
        statusHandler.post(statusUpdater);
    }

    @Override
    protected void onPause() {
        statusHandler.removeCallbacks(statusUpdater);
        super.onPause();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VPN_REQUEST) return;

        if (resultCode == RESULT_OK && pendingServiceIntent != null) {
            startVpnService(pendingServiceIntent);
        } else {
            Toast.makeText(this, "VPN permission was not granted.", Toast.LENGTH_LONG).show();
        }
        pendingServiceIntent = null;
    }

    @Override
    public void onRequestPermissionsResult(
            int requestCode,
            String[] permissions,
            int[] grantResults
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == NOTIFICATION_REQUEST && pendingServiceIntent != null) {
            prepareVpnStart();
        }
    }

    private android.view.View createContentView() {
        HudUi.Screen screen = HudUi.createScreen(this);
        LinearLayout content = screen.content;

        HudUi.addHeader(
                this,
                content,
                "SAF // LOW ENTROPY PROTOCOL",
                "TUNNEL CONTROL",
                "Manual link console  •  reconnect policy: disabled"
        );

        LinearLayout statusPanel = HudUi.panel(this);
        statusPanel.addView(HudUi.sectionLabel(this, "LINK STATE // LIVE"));

        stateCode = HudUi.text(this, "00", 44, HudUi.MUTED, Typeface.BOLD);
        stateCode.setLetterSpacing(0.08f);
        statusPanel.addView(stateCode, HudUi.topMargin(this, 12));

        stateHeadline = HudUi.text(this, "OFFLINE", 19, HudUi.TEXT, Typeface.BOLD);
        stateHeadline.setLetterSpacing(0.12f);
        statusPanel.addView(stateHeadline);

        statusPreview = HudUi.text(
                this,
                "Disconnected\nNo active tunnel.",
                12,
                HudUi.MUTED,
                Typeface.NORMAL
        );
        statusPreview.setMaxLines(6);
        statusPreview.setLineSpacing(0f, 1.18f);
        statusPanel.addView(statusPreview, HudUi.topMargin(this, 12));
        content.addView(statusPanel);

        actionButton = HudUi.button(this, "INITIALIZE LINK", HudUi.GREEN);
        actionButton.setContentDescription("Connect or disconnect VPN");
        actionButton.setOnClickListener(view -> handlePrimaryAction());
        content.addView(actionButton, HudUi.topMargin(this, 14));

        LinearLayout endpointPanel = HudUi.panel(this);
        endpointPanel.addView(HudUi.sectionLabel(this, "ACTIVE PROFILE"));
        endpointValue = HudUi.text(this, "REMOTE NODE NOT CONFIGURED", 14, HudUi.TEXT, Typeface.BOLD);
        endpointValue.setLineSpacing(0f, 1.1f);
        endpointPanel.addView(endpointValue, HudUi.topMargin(this, 10));
        routeValue = HudUi.text(this, "ROUTE // --", 11, HudUi.MUTED, Typeface.NORMAL);
        endpointPanel.addView(routeValue, HudUi.topMargin(this, 7));
        content.addView(endpointPanel, HudUi.topMargin(this, 14));

        LinearLayout navigation = new LinearLayout(this);
        navigation.setOrientation(LinearLayout.HORIZONTAL);

        Button settingsButton = HudUi.button(this, "CONFIG", HudUi.BLUE);
        settingsButton.setContentDescription("Open VPN configuration");
        settingsButton.setOnClickListener(
                view -> startActivity(new Intent(this, SettingsActivity.class))
        );
        LinearLayout.LayoutParams leftButton = new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
        );
        navigation.addView(settingsButton, leftButton);

        Button statusButton = HudUi.button(this, "TELEMETRY", HudUi.CYAN);
        statusButton.setContentDescription("Open live tunnel telemetry");
        statusButton.setOnClickListener(
                view -> startActivity(new Intent(this, StatusActivity.class))
        );
        LinearLayout.LayoutParams rightButton = new LinearLayout.LayoutParams(
                0,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                1f
        );
        rightButton.leftMargin = HudUi.dp(this, 10);
        navigation.addView(statusButton, rightButton);
        content.addView(navigation, HudUi.topMargin(this, 10));

        TextView footer = HudUi.text(
                this,
                "USER-INITIATED SESSION // NO BACKGROUND AUTO-RECONNECT",
                10,
                HudUi.MUTED,
                Typeface.NORMAL
        );
        footer.setLetterSpacing(0.08f);
        content.addView(footer, HudUi.topMargin(this, 22));
        return screen.scroll;
    }

    private void handlePrimaryAction() {
        SafLepVpnService.ConnectionState state = SafLepVpnService.getConnectionState();
        if (state == SafLepVpnService.ConnectionState.STARTING
                || state == SafLepVpnService.ConnectionState.CONNECTED) {
            requestVpnStop();
        } else if (state != SafLepVpnService.ConnectionState.STOPPING) {
            requestVpnStart();
        }
    }

    private void requestVpnStart() {
        AppSettings.Config config = AppSettings.load(this);
        String error = AppSettings.validate(config);
        if (error != null) {
            Toast.makeText(this, error, Toast.LENGTH_LONG).show();
            startActivity(new Intent(this, SettingsActivity.class));
            return;
        }

        if (config.seedKey.isEmpty()) {
            Toast.makeText(
                    this,
                    "Seed key is empty; tunnel traffic will not be encrypted.",
                    Toast.LENGTH_LONG
            ).show();
        }

        pendingServiceIntent = AppSettings.createServiceIntent(this, config);
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[]{Manifest.permission.POST_NOTIFICATIONS},
                    NOTIFICATION_REQUEST
            );
            return;
        }
        prepareVpnStart();
    }

    @SuppressWarnings("deprecation")
    private void prepareVpnStart() {
        Intent permissionIntent = VpnService.prepare(this);
        if (permissionIntent != null) {
            startActivityForResult(permissionIntent, VPN_REQUEST);
        } else if (pendingServiceIntent != null) {
            Intent serviceIntent = pendingServiceIntent;
            pendingServiceIntent = null;
            startVpnService(serviceIntent);
        }
    }

    private void startVpnService(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent);
        else startService(intent);
    }

    private void requestVpnStop() {
        Intent intent = new Intent(this, SafLepVpnService.class);
        intent.setAction(SafLepVpnService.ACTION_STOP);
        startService(intent);
        refreshStatus();
    }

    private void refreshConfiguration() {
        if (endpointValue == null) return;
        AppSettings.Config config = AppSettings.load(this);
        endpointValue.setText(config.endpointLabel());
        String route = config.vpnGateway.trim().isEmpty()
                ? "SUBNET // " + config.vpnAddress + "/" + Math.max(0, config.vpnPrefix())
                : "ROUTE // FULL IPV4  VIA  " + config.vpnGateway;
        routeValue.setText(route);
    }

    private void refreshStatus() {
        if (stateCode == null) return;
        SafLepVpnService.ConnectionState state = SafLepVpnService.getConnectionState();
        String code;
        String headline;
        String action;
        int color;
        boolean enabled = true;

        switch (state) {
            case CONNECTED:
                code = "01";
                headline = "LINK ONLINE";
                action = "TERMINATE LINK";
                color = HudUi.GREEN;
                break;
            case STARTING:
                code = "··";
                headline = "NEGOTIATING";
                action = "CANCEL CONNECTION";
                color = HudUi.CYAN;
                break;
            case STOPPING:
                code = "--";
                headline = "SHUTTING DOWN";
                action = "DISCONNECTING";
                color = HudUi.AMBER;
                enabled = false;
                break;
            case FAILED:
                code = "!!";
                headline = "LINK FAULT";
                action = "RETRY LINK";
                color = HudUi.RED;
                break;
            case DISCONNECTED:
            default:
                code = "00";
                headline = "OFFLINE";
                action = "INITIALIZE LINK";
                color = HudUi.MUTED;
                break;
        }

        stateCode.setText(code);
        stateCode.setTextColor(color);
        stateHeadline.setText(headline);
        statusPreview.setText(SafLepVpnService.getStatusSummary());
        actionButton.setText(action);
        actionButton.setEnabled(enabled);
        int actionColor = state == SafLepVpnService.ConnectionState.CONNECTED
                ? HudUi.RED
                : (state == SafLepVpnService.ConnectionState.STOPPING ? HudUi.AMBER : HudUi.GREEN);
        actionButton.setBackground(new HudPanelDrawable(
                HudUi.PANEL_RAISED,
                actionColor,
                actionColor,
                getResources().getDisplayMetrics().density
        ));
        actionButton.setTextColor(enabled ? HudUi.TEXT : Color.rgb(116, 124, 126));
    }
}
