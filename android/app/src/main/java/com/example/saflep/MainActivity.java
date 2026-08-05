package com.example.saflep;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

public final class MainActivity extends Activity {
    private static final int VPN_REQUEST = 1001;
    private static final int NOTIFICATION_REQUEST = 1002;

    private EditText hostInput;
    private EditText portInput;
    private EditText keyInput;
    private Spinner encodingInput;
    private CheckBox verboseInput;
    private TextView statusText;
    private Intent pendingServiceIntent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(createContentView());

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
    @SuppressWarnings("deprecation")
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VPN_REQUEST) return;

        if (resultCode == RESULT_OK) {
            startVpnService(pendingServiceIntent != null
                    ? pendingServiceIntent
                    : createServiceIntent());
        } else {
            statusText.setText("VPN permission was not granted");
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

        hostInput = addInput(content, "Server hostname or IP", "", spacing);
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
        encodingInput.setSelection(0);
        content.addView(encodingInput);

        keyInput = addInput(content, "Encryption key (optional)", "", spacing);
        keyInput.setInputType(
                InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD
        );

        verboseInput = new CheckBox(this);
        verboseInput.setText("Verbose logging");
        content.addView(verboseInput, marginParams(spacing));

        Button startButton = new Button(this);
        startButton.setText("Connect");
        startButton.setOnClickListener(view -> requestVpnStart());
        content.addView(startButton, marginParams(spacing));

        Button stopButton = new Button(this);
        stopButton.setText("Disconnect");
        stopButton.setOnClickListener(view -> {
            stopService(new Intent(this, SafLepVpnService.class));
            statusText.setText("Disconnected");
        });
        content.addView(stopButton, marginParams(spacing / 2));

        statusText = new TextView(this);
        statusText.setText("Disconnected");
        statusText.setTextSize(16);
        content.addView(statusText, marginParams(spacing));

        ScrollView scroll = new ScrollView(this);
        scroll.addView(content);
        return scroll;
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
        String host = hostInput.getText().toString().trim();
        int port;
        try {
            port = Integer.parseInt(portInput.getText().toString());
        } catch (NumberFormatException ignored) {
            port = 0;
        }

        if (host.isEmpty()) {
            hostInput.setError("Server is required");
            return;
        }
        if (port < 1 || port > 65535) {
            portInput.setError("Enter a port from 1 to 65535");
            return;
        }
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

    private Intent createServiceIntent() {
        int port;
        try {
            port = Integer.parseInt(portInput.getText().toString());
        } catch (NumberFormatException ignored) {
            port = 0;
        }

        Intent intent = new Intent(this, SafLepVpnService.class);
        intent.putExtra(SafLepVpnService.EXTRA_SERVER_IP, hostInput.getText().toString().trim());
        intent.putExtra(SafLepVpnService.EXTRA_SERVER_PORT, port);
        intent.putExtra(SafLepVpnService.EXTRA_SEED_KEY, keyInput.getText().toString());
        intent.putExtra(
                SafLepVpnService.EXTRA_ENCODING_SCHEME,
                encodingInput.getSelectedItemPosition()
        );
        intent.putExtra(SafLepVpnService.EXTRA_VERBOSE, verboseInput.isChecked());
        intent.putExtra(SafLepVpnService.EXTRA_VPN_ADDRESS, "10.0.0.2");
        intent.putExtra(SafLepVpnService.EXTRA_VPN_PREFIX, 24);
        return intent;
    }

    private void startVpnService(Intent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent);
        } else {
            startService(intent);
        }
        statusText.setText("Connecting…");
    }
}
