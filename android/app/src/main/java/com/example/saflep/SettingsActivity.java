package com.example.saflep;

import android.app.Activity;
import android.content.res.ColorStateList;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.text.InputType;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

public final class SettingsActivity extends Activity {
    private EditText hostInput;
    private EditText portInput;
    private Spinner encodingInput;
    private EditText keyInput;
    private CheckBox showKeyInput;
    private CheckBox rememberKeyInput;
    private EditText vpnAddressInput;
    private EditText vpnMaskInput;
    private EditText vpnGatewayInput;
    private CheckBox verboseInput;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(createContentView());
        loadSettings();
    }

    private View createContentView() {
        HudUi.Screen screen = HudUi.createScreen(this);
        LinearLayout content = screen.content;

        HudUi.addHeader(
                this,
                content,
                "CONTROL / CONFIGURATION",
                "LINK PROFILE",
                "Connection parameters are applied to the next session."
        );

        LinearLayout remotePanel = HudUi.panel(this);
        remotePanel.addView(HudUi.sectionLabel(this, "01 // REMOTE NODE"));
        hostInput = addField(remotePanel, "HOSTNAME OR IPV4", "gateway.example.net", 12);
        hostInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        portInput = addField(remotePanel, "UDP PORT", "14578", 12);
        portInput.setInputType(InputType.TYPE_CLASS_NUMBER);

        remotePanel.addView(fieldLabel("LEP ENCODING"), HudUi.topMargin(this, 12));
        encodingInput = new Spinner(this);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                this,
                android.R.layout.simple_spinner_dropdown_item,
                new String[]{"LEP v0  // compatible", "LEP v1"}
        );
        encodingInput.setAdapter(adapter);
        encodingInput.setPopupBackgroundDrawable(new ColorDrawable(HudUi.PANEL_RAISED));
        encodingInput.setPadding(
                HudUi.dp(this, 10),
                HudUi.dp(this, 6),
                HudUi.dp(this, 10),
                HudUi.dp(this, 6)
        );
        encodingInput.setBackground(new HudPanelDrawable(
                HudUi.PANEL_RAISED,
                HudUi.BLUE,
                android.graphics.Color.TRANSPARENT,
                getResources().getDisplayMetrics().density
        ));
        remotePanel.addView(encodingInput, HudUi.topMargin(this, 5));
        content.addView(remotePanel);

        LinearLayout authPanel = HudUi.panel(this);
        authPanel.addView(HudUi.sectionLabel(this, "02 // SEED MATERIAL"));
        keyInput = addField(authPanel, "SEED KEY", "optional", 12);
        keyInput.setInputType(
                InputType.TYPE_CLASS_TEXT
                        | InputType.TYPE_TEXT_VARIATION_PASSWORD
                        | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        );
        keyInput.setTransformationMethod(PasswordTransformationMethod.getInstance());

        showKeyInput = checkbox("SHOW SEED KEY");
        showKeyInput.setOnCheckedChangeListener((button, checked) -> {
            int selection = keyInput.getSelectionStart();
            keyInput.setTransformationMethod(checked
                    ? HideReturnsTransformationMethod.getInstance()
                    : PasswordTransformationMethod.getInstance());
            if (selection >= 0) keyInput.setSelection(selection);
        });
        authPanel.addView(showKeyInput, HudUi.topMargin(this, 7));

        rememberKeyInput = checkbox("REMEMBER IN PRIVATE APP STORAGE");
        authPanel.addView(rememberKeyInput);
        TextView keyHelp = HudUi.text(
                this,
                "A blank seed disables encryption. Stored seeds are private to the app, not hardware-backed.",
                11,
                HudUi.MUTED,
                Typeface.NORMAL
        );
        keyHelp.setLineSpacing(0f, 1.15f);
        authPanel.addView(keyHelp, HudUi.topMargin(this, 6));
        content.addView(authPanel, HudUi.topMargin(this, 14));

        LinearLayout routePanel = HudUi.panel(this);
        routePanel.addView(HudUi.sectionLabel(this, "03 // TUN ROUTING"));
        vpnAddressInput = addField(routePanel, "CLIENT IPV4", "10.0.0.2", 12);
        vpnAddressInput.setInputType(InputType.TYPE_CLASS_PHONE);
        vpnMaskInput = addField(routePanel, "NETMASK", "255.255.255.0", 12);
        vpnMaskInput.setInputType(InputType.TYPE_CLASS_PHONE);
        vpnGatewayInput = addField(routePanel, "GATEWAY / LEAVE BLANK FOR SUBNET ONLY", "10.0.0.1", 12);
        vpnGatewayInput.setInputType(InputType.TYPE_CLASS_PHONE);

        TextView routeHelp = HudUi.text(
                this,
                "Android has no VPN next-hop field. A gateway value selects the full IPv4 route; blank captures only the configured subnet.",
                11,
                HudUi.MUTED,
                Typeface.NORMAL
        );
        routeHelp.setLineSpacing(0f, 1.15f);
        routePanel.addView(routeHelp, HudUi.topMargin(this, 10));
        content.addView(routePanel, HudUi.topMargin(this, 14));

        LinearLayout diagnosticsPanel = HudUi.panel(this);
        diagnosticsPanel.addView(HudUi.sectionLabel(this, "04 // DIAGNOSTICS"));
        verboseInput = checkbox("VERBOSE NATIVE LOGGING");
        diagnosticsPanel.addView(verboseInput, HudUi.topMargin(this, 8));
        content.addView(diagnosticsPanel, HudUi.topMargin(this, 14));

        Button saveButton = HudUi.button(this, "COMMIT PROFILE", HudUi.GREEN);
        saveButton.setOnClickListener(view -> saveAndFinish());
        content.addView(saveButton, HudUi.topMargin(this, 16));

        Button cancelButton = HudUi.button(this, "RETURN WITHOUT CHANGES", HudUi.LINE);
        cancelButton.setOnClickListener(view -> finish());
        content.addView(cancelButton, HudUi.topMargin(this, 9));
        return screen.scroll;
    }

    private EditText addField(
            LinearLayout parent,
            String label,
            String hint,
            int topMargin
    ) {
        parent.addView(fieldLabel(label), HudUi.topMargin(this, topMargin));
        EditText input = HudUi.input(this, hint);
        parent.addView(input, HudUi.topMargin(this, 5));
        return input;
    }

    private TextView fieldLabel(String value) {
        TextView label = HudUi.text(this, value, 10, HudUi.MUTED, Typeface.BOLD);
        label.setLetterSpacing(0.1f);
        return label;
    }

    private CheckBox checkbox(String value) {
        CheckBox box = new CheckBox(this);
        box.setText(value);
        box.setTextColor(HudUi.TEXT);
        box.setTextSize(11);
        box.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        box.setButtonTintList(new ColorStateList(
                new int[][]{
                        new int[]{android.R.attr.state_checked},
                        new int[]{}
                },
                new int[]{HudUi.GREEN, HudUi.LINE}
        ));
        return box;
    }

    private void loadSettings() {
        AppSettings.Config config = AppSettings.load(this);
        hostInput.setText(config.host);
        portInput.setText(config.port);
        encodingInput.setSelection(config.encoding);
        keyInput.setText(config.seedKey);
        rememberKeyInput.setChecked(config.rememberKey);
        vpnAddressInput.setText(config.vpnAddress);
        vpnMaskInput.setText(config.vpnMask);
        vpnGatewayInput.setText(config.vpnGateway);
        verboseInput.setChecked(config.verbose);
    }

    private void saveAndFinish() {
        AppSettings.Config config = new AppSettings.Config();
        config.host = value(hostInput);
        config.port = value(portInput);
        config.encoding = encodingInput.getSelectedItemPosition();
        config.seedKey = keyInput.getText().toString();
        config.rememberKey = rememberKeyInput.isChecked();
        config.vpnAddress = value(vpnAddressInput);
        config.vpnMask = value(vpnMaskInput);
        config.vpnGateway = value(vpnGatewayInput);
        config.verbose = verboseInput.isChecked();

        String error = AppSettings.validate(config);
        if (error != null) {
            markInvalidField(config);
            Toast.makeText(this, error, Toast.LENGTH_LONG).show();
            return;
        }

        AppSettings.save(this, config);
        Toast.makeText(this, "Link profile saved.", Toast.LENGTH_SHORT).show();
        finish();
    }

    private void markInvalidField(AppSettings.Config config) {
        if (config.host.isEmpty()) hostInput.setError("Remote server is required");
        else if (config.numericPort() < 1 || config.numericPort() > 65535) {
            portInput.setError("Enter a port from 1 to 65535");
        } else if (!AppSettings.isValidIpv4(config.vpnAddress)) {
            vpnAddressInput.setError("Enter an IPv4 address");
        } else if (AppSettings.netmaskToPrefix(config.vpnMask) < 0) {
            vpnMaskInput.setError("Enter a contiguous IPv4 netmask");
        } else if (!config.vpnGateway.isEmpty()
                && !AppSettings.isValidIpv4(config.vpnGateway)) {
            vpnGatewayInput.setError("Enter IPv4 or leave blank");
        }
    }

    private static String value(EditText input) {
        return input.getText().toString().trim();
    }
}
