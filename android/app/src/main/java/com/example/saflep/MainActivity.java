package com.example.saflep;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.text.method.HideReturnsTransformationMethod;
import android.text.method.PasswordTransformationMethod;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST = 1001;
    private static final int NOTIFICATION_REQUEST = 1002;
    private static final String PREFS_NAME = "saf_lep_settings";

    private final Handler statusHandler = new Handler(Looper.getMainLooper());
    private final Runnable statusUpdater = new Runnable() {
        @Override
        public void run() {
            refreshStatus();
            statusHandler.postDelayed(this, 750);
        }
    };

    private EditText hostInput;
    private EditText portInput;
    private EditText keyInput;
    private Spinner encodingInput;
    private EditText vpnAddressInput;
    private EditText vpnMaskInput;
    private EditText vpnGatewayInput;
    private CheckBox rememberKeyInput;
    private CheckBox showKeyInput;
    private CheckBox verboseInput;
    private TextView statusText;
    private Button startButton;
    private Button stopButton;
    private Intent pendingServiceIntent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(createContentView());
        loadSettings();
        refreshStatus();

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                    new String[]{Manifest.permission.POST_NOTIFICATIONS},
                    NOTIFICATION_REQUEST
            );
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        statusHandler.removeCallbacks(statusUpdater);
        statusHandler.post(statusUpdater);
    }

    @Override
    protected void onPause() {
        statusHandler.removeCallbacks(statusUpdater);
        saveSettings();
        super.onPause();
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VPN_REQUEST) return;

        if (resultCode == RESULT_OK) {
            startVpnService(pendingServiceIntent != null
                    ? pendingServiceIntent
                    : createServiceIntent());
        } else {
            statusText.setText("VPN permission was not granted.");
        }
        pendingServiceIntent = null;
    }

    private ScrollView createContentView() {
        float density = getResources().getDisplayMetrics().density;
        int padding = (int) (24 * density);
        int spacing = (int) (12 * density);

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);

        TextView title = new TextView(this);
        title.setText("SAF-LEP VPN");
        title.setTextSize(28);
        title.setTypeface(title.getTypeface(), Typeface.BOLD);
        content.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Low-entropy UDP tunnel client");
        subtitle.setTextSize(16);
        content.addView(subtitle, marginParams(spacing));

        addSectionLabel(content, "Remote peer", spacing);
        hostInput = addInput(content, "Server hostname or IP", "", spacing / 2);
        hostInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        portInput = addInput(content, "Server port", "14578", spacing);
        portInput.setInputType(InputType.TYPE_CLASS_NUMBER);

        TextView encodingLabel = new TextView(this);
        encodingLabel.setText("LEP encoding");
        content.addView(encodingLabel, marginParams(spacing));
        encodingInput = new Spinner(this);
        ArrayAdapter<String> encodingAdapter = new ArrayAdapter<>(
                this,
                android.R.layout.simple_spinner_item,
                new String[]{"LEP v0 (compatible)", "LEP v1"}
        );
        encodingAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        encodingInput.setAdapter(encodingAdapter);
        content.addView(encodingInput);

        keyInput = addInput(content, "Seed key (optional)", "", spacing);
        keyInput.setInputType(
                InputType.TYPE_CLASS_TEXT
                        | InputType.TYPE_TEXT_VARIATION_PASSWORD
                        | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        );
        keyInput.setTransformationMethod(PasswordTransformationMethod.getInstance());

        showKeyInput = new CheckBox(this);
        showKeyInput.setText("Show seed key");
        showKeyInput.setOnCheckedChangeListener((button, checked) -> {
            int selection = keyInput.getSelectionStart();
            keyInput.setTransformationMethod(checked
                    ? HideReturnsTransformationMethod.getInstance()
                    : PasswordTransformationMethod.getInstance());
            if (selection >= 0) keyInput.setSelection(selection);
        });
        content.addView(showKeyInput);

        rememberKeyInput = new CheckBox(this);
        rememberKeyInput.setText("Remember seed key in this app's private settings");
        content.addView(rememberKeyInput);

        addSectionLabel(content, "Tunnel addressing", spacing);
        vpnAddressInput = addInput(content, "VPN IP (--ip)", "10.0.0.2", spacing / 2);
        vpnAddressInput.setInputType(InputType.TYPE_CLASS_PHONE);
        vpnMaskInput = addInput(content, "Netmask (--mask)", "255.255.255.0", spacing);
        vpnMaskInput.setInputType(InputType.TYPE_CLASS_PHONE);
        vpnGatewayInput = addInput(
                content,
                "VPN gateway (--gw; blank = subnet only)",
                "10.0.0.1",
                spacing
        );
        vpnGatewayInput.setInputType(InputType.TYPE_CLASS_PHONE);

        TextView gatewayHelp = new TextView(this);
        gatewayHelp.setText(
                "On Android, a non-empty --gw enables the full IPv4 VPN route; "
                        + "the OS does not expose a separate next-hop setting for VPN TUN routes."
        );
        gatewayHelp.setTextSize(12);
        content.addView(gatewayHelp, marginParams(spacing / 2));

        verboseInput = new CheckBox(this);
        verboseInput.setText("Verbose native logging");
        content.addView(verboseInput, marginParams(spacing));

        startButton = new Button(this);
        startButton.setText("Connect");
        startButton.setOnClickListener(view -> requestVpnStart());
        content.addView(startButton, marginParams(spacing));

        stopButton = new Button(this);
        stopButton.setText("Disconnect");
        stopButton.setOnClickListener(view -> requestVpnStop());
        content.addView(stopButton, marginParams(spacing / 2));

        addSectionLabel(content, "Tunnel status", spacing);
        statusText = new TextView(this);
        statusText.setTextSize(14);
        statusText.setTypeface(Typeface.MONOSPACE);
        statusText.setTextIsSelectable(true);
        content.addView(statusText, marginParams(spacing / 2));

        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        return scroll;
    }

    private void addSectionLabel(LinearLayout parent, String text, int topMargin) {
        TextView label = new TextView(this);
        label.setText(text);
        label.setTextSize(18);
        label.setTypeface(label.getTypeface(), Typeface.BOLD);
        parent.addView(label, marginParams(topMargin));
    }

    private EditText addInput(
            LinearLayout parent,
            String hint,
            String value,
            int topMargin
    ) {
        EditText input = new EditText(this);
        input.setHint(hint);
        input.setText(value);
        input.setSingleLine(true);
        parent.addView(input, marginParams(topMargin));
        return input;
    }

    private LinearLayout.LayoutParams marginParams(int topMargin) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
        );
        params.topMargin = topMargin;
        return params;
    }

    private void requestVpnStart() {
        if (!validateInputs()) return;

        saveSettings();
        if (keyInput.getText().length() == 0) {
            Toast.makeText(
                    this,
                    "Warning: traffic will not be encrypted",
                    Toast.LENGTH_LONG
            ).show();
        }

        Intent serviceIntent = createServiceIntent();
        Intent permissionIntent = VpnService.prepare(this);
        if (permissionIntent != null) {
            pendingServiceIntent = serviceIntent;
            startActivityForResult(permissionIntent, VPN_REQUEST);
        } else {
            startVpnService(serviceIntent);
        }
    }

    private void requestVpnStop() {
        statusText.setText("Stopping tunnel...");
        Intent intent = new Intent(this, SafLepVpnService.class);
        intent.setAction(SafLepVpnService.ACTION_STOP);
        startService(intent);
    }

    private boolean validateInputs() {
        String host = hostInput.getText().toString().trim();
        int port = parseInteger(portInput, 0);
        String vpnAddress = vpnAddressInput.getText().toString().trim();
        String vpnMask = vpnMaskInput.getText().toString().trim();
        String vpnGateway = vpnGatewayInput.getText().toString().trim();

        if (host.isEmpty()) {
            hostInput.setError("Server is required");
            return false;
        }
        if (port < 1 || port > 65535) {
            portInput.setError("Enter a port from 1 to 65535");
            return false;
        }
        if (!isValidIpv4(vpnAddress)) {
            vpnAddressInput.setError("Enter an IPv4 address");
            return false;
        }
        if (netmaskToPrefix(vpnMask) < 0) {
            vpnMaskInput.setError("Enter a contiguous IPv4 netmask");
            return false;
        }
        if (!vpnGateway.isEmpty() && !isValidIpv4(vpnGateway)) {
            vpnGatewayInput.setError("Enter an IPv4 address or leave blank");
            return false;
        }
        return true;
    }

    private Intent createServiceIntent() {
        Intent intent = new Intent(this, SafLepVpnService.class);
        intent.setAction(SafLepVpnService.ACTION_START);
        intent.putExtra(
                SafLepVpnService.EXTRA_SERVER_IP,
                hostInput.getText().toString().trim()
        );
        intent.putExtra(SafLepVpnService.EXTRA_SERVER_PORT, parseInteger(portInput, 0));
        intent.putExtra(SafLepVpnService.EXTRA_SEED_KEY, keyInput.getText().toString());
        intent.putExtra(
                SafLepVpnService.EXTRA_ENCODING_SCHEME,
                encodingInput.getSelectedItemPosition()
        );
        intent.putExtra(SafLepVpnService.EXTRA_VERBOSE, verboseInput.isChecked());
        intent.putExtra(
                SafLepVpnService.EXTRA_VPN_ADDRESS,
                vpnAddressInput.getText().toString().trim()
        );
        intent.putExtra(
                SafLepVpnService.EXTRA_VPN_PREFIX,
                netmaskToPrefix(vpnMaskInput.getText().toString().trim())
        );
        intent.putExtra(
                SafLepVpnService.EXTRA_VPN_GATEWAY,
                vpnGatewayInput.getText().toString().trim()
        );
        return intent;
    }

    private void startVpnService(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        statusText.setText("Starting VPN service...");
    }

    private void refreshStatus() {
        if (statusText == null) return;
        statusText.setText(SafLepVpnService.getStatusSummary());
        boolean active = SafLepVpnService.isActiveOrStarting();
        startButton.setEnabled(!active);
        stopButton.setEnabled(active);
    }

    private void loadSettings() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        hostInput.setText(prefs.getString("host", ""));
        portInput.setText(prefs.getString("port", "14578"));
        encodingInput.setSelection(Math.max(0, Math.min(1, prefs.getInt("encoding", 0))));
        vpnAddressInput.setText(prefs.getString("vpn_ip", "10.0.0.2"));
        vpnMaskInput.setText(prefs.getString("vpn_mask", "255.255.255.0"));
        vpnGatewayInput.setText(prefs.getString("vpn_gateway", "10.0.0.1"));
        verboseInput.setChecked(prefs.getBoolean("verbose", false));
        rememberKeyInput.setChecked(prefs.getBoolean("remember_key", true));
        if (rememberKeyInput.isChecked()) {
            keyInput.setText(prefs.getString("seed_key", ""));
        }
    }

    private void saveSettings() {
        if (hostInput == null) return;
        SharedPreferences.Editor editor = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
                .edit()
                .putString("host", hostInput.getText().toString().trim())
                .putString("port", portInput.getText().toString().trim())
                .putInt("encoding", encodingInput.getSelectedItemPosition())
                .putString("vpn_ip", vpnAddressInput.getText().toString().trim())
                .putString("vpn_mask", vpnMaskInput.getText().toString().trim())
                .putString("vpn_gateway", vpnGatewayInput.getText().toString().trim())
                .putBoolean("verbose", verboseInput.isChecked())
                .putBoolean("remember_key", rememberKeyInput.isChecked());
        if (rememberKeyInput.isChecked()) {
            editor.putString("seed_key", keyInput.getText().toString());
        } else {
            editor.remove("seed_key");
        }
        editor.apply();
    }

    private int parseInteger(EditText input, int fallback) {
        try {
            return Integer.parseInt(input.getText().toString().trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static boolean isValidIpv4(String value) {
        String[] octets = value.split("\\.", -1);
        if (octets.length != 4) return false;
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) return false;
            for (int index = 0; index < octet.length(); ++index) {
                if (!Character.isDigit(octet.charAt(index))) return false;
            }
            try {
                int number = Integer.parseInt(octet);
                if (number < 0 || number > 255) return false;
            } catch (NumberFormatException ignored) {
                return false;
            }
        }
        return true;
    }

    private static int netmaskToPrefix(String value) {
        if (!isValidIpv4(value)) return -1;
        String[] octets = value.split("\\.");
        int mask = 0;
        for (String octet : octets) {
            mask = (mask << 8) | Integer.parseInt(octet);
        }

        int prefix = 0;
        boolean sawZero = false;
        for (int bit = 31; bit >= 0; --bit) {
            boolean set = ((mask >>> bit) & 1) != 0;
            if (set && sawZero) return -1;
            if (set) prefix++;
            else sawZero = true;
        }
        return prefix;
    }
}
