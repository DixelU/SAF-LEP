package com.example.saflep;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class StatusActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable updater = new Runnable() {
        @Override
        public void run() {
            refresh();
            handler.postDelayed(this, 500);
        }
    };

    private TextView stateValue;
    private TextView endpointValue;
    private TextView telemetryValue;
    private TextView guidanceValue;
    private Button disconnectButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(createContentView());
        refresh();
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.removeCallbacks(updater);
        handler.post(updater);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(updater);
        super.onPause();
    }

    private View createContentView() {
        HudUi.Screen screen = HudUi.createScreen(this);
        LinearLayout content = screen.content;

        HudUi.addHeader(
                this,
                content,
                "CONTROL / TELEMETRY",
                "SIGNAL MONITOR",
                "Live service state and native transport counters."
        );

        LinearLayout statePanel = HudUi.panel(this);
        statePanel.addView(HudUi.sectionLabel(this, "SESSION"));
        stateValue = HudUi.text(this, "DISCONNECTED", 20, HudUi.MUTED, Typeface.BOLD);
        stateValue.setLetterSpacing(0.1f);
        statePanel.addView(stateValue, HudUi.topMargin(this, 10));
        endpointValue = HudUi.text(this, "REMOTE NODE NOT CONFIGURED", 12, HudUi.TEXT, Typeface.NORMAL);
        endpointValue.setLineSpacing(0f, 1.1f);
        statePanel.addView(endpointValue, HudUi.topMargin(this, 8));
        content.addView(statePanel);

        LinearLayout telemetryPanel = HudUi.panel(this);
        telemetryPanel.addView(HudUi.sectionLabel(this, "RAW CHANNEL DATA"));
        telemetryValue = HudUi.text(
                this,
                "Disconnected\nNo active tunnel.",
                12,
                HudUi.TEXT,
                Typeface.NORMAL
        );
        telemetryValue.setTextIsSelectable(true);
        telemetryValue.setLineSpacing(0f, 1.18f);
        telemetryPanel.addView(telemetryValue, HudUi.topMargin(this, 12));
        content.addView(telemetryPanel, HudUi.topMargin(this, 14));

        LinearLayout guidancePanel = HudUi.panel(this);
        guidancePanel.addView(HudUi.sectionLabel(this, "OPERATOR NOTE"));
        guidanceValue = HudUi.text(this, "Awaiting state...", 11, HudUi.MUTED, Typeface.NORMAL);
        guidanceValue.setLineSpacing(0f, 1.18f);
        guidancePanel.addView(guidanceValue, HudUi.topMargin(this, 9));
        content.addView(guidancePanel, HudUi.topMargin(this, 14));

        disconnectButton = HudUi.button(this, "TERMINATE LINK", HudUi.RED);
        disconnectButton.setOnClickListener(view -> requestStop());
        content.addView(disconnectButton, HudUi.topMargin(this, 16));

        Button returnButton = HudUi.button(this, "RETURN TO CONTROL", HudUi.LINE);
        returnButton.setOnClickListener(view -> finish());
        content.addView(returnButton, HudUi.topMargin(this, 9));
        return screen.scroll;
    }

    private void refresh() {
        if (stateValue == null) return;
        SafLepVpnService.ConnectionState state = SafLepVpnService.getConnectionState();
        String summary = SafLepVpnService.getStatusSummary();
        AppSettings.Config config = AppSettings.load(this);

        stateValue.setText(state.name().replace('_', ' '));
        endpointValue.setText(config.endpointLabel());
        telemetryValue.setText(summary);

        int stateColor;
        String guidance;
        switch (state) {
            case CONNECTED:
                stateColor = HudUi.GREEN;
                if (summary.contains("Peer traffic: none yet")) {
                    guidance = "The TUN and UDP socket are active, but the server has not replied. Check UDP exposure, matching LEP version, seed key, and server firewall.";
                } else {
                    guidance = "Peer traffic is present. TX/RX and TUN counters refresh once per second in the VPN service.";
                }
                break;
            case STARTING:
                stateColor = HudUi.CYAN;
                guidance = "Resolving the remote node and establishing Android's TUN interface. You can cancel safely from either control screen.";
                break;
            case STOPPING:
                stateColor = HudUi.AMBER;
                guidance = "Native I/O, the duplicated TUN descriptor, and the foreground notification are being closed in order.";
                break;
            case FAILED:
                stateColor = HudUi.RED;
                guidance = "Review the failure above, then verify the endpoint and profile. Verbose native logging is available under CONFIG.";
                break;
            case DISCONNECTED:
            default:
                stateColor = HudUi.MUTED;
                guidance = "No tunnel owns the VPN interface. SAF-LEP will remain offline until INITIALIZE LINK is pressed; unsolicited service starts are ignored.";
                break;
        }
        stateValue.setTextColor(stateColor);
        guidanceValue.setText(guidance);
        disconnectButton.setEnabled(
                state == SafLepVpnService.ConnectionState.STARTING
                        || state == SafLepVpnService.ConnectionState.CONNECTED
        );
    }

    private void requestStop() {
        Intent intent = new Intent(this, SafLepVpnService.class);
        intent.setAction(SafLepVpnService.ACTION_STOP);
        startService(intent);
        disconnectButton.setEnabled(false);
    }
}
