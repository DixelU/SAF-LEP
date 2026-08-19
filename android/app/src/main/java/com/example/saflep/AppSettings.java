package com.example.saflep;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

public final class AppSettings {
    private static final String PREFS_NAME = "saf_lep_settings";

    private AppSettings() {}

    public static final class Config {
        public String host = "";
        public String port = "14578";
        public int encoding;
        public String seedKey = "";
        public boolean rememberKey = true;
        public String vpnAddress = "10.0.0.2";
        public String vpnMask = "255.255.255.0";
        public String vpnGateway = "10.0.0.1";
        public boolean verbose;

        public int numericPort() {
            try {
                return Integer.parseInt(port.trim());
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }

        public int vpnPrefix() {
            return netmaskToPrefix(vpnMask);
        }

        public String protocolName() {
            if (encoding == 2) return "RAW";
            return encoding == 1 ? "LEP v1" : "LEP v0";
        }

        public String endpointLabel() {
            if (host.trim().isEmpty()) return "REMOTE NODE NOT CONFIGURED";
            return host.trim() + ":" + port.trim() + "  //  " + protocolName();
        }
    }

    public static Config load(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        Config config = new Config();
        config.host = prefs.getString("host", "");
        config.port = prefs.getString("port", "14578");
        config.encoding = Math.max(0, Math.min(2, prefs.getInt("encoding", 0)));
        config.vpnAddress = prefs.getString("vpn_ip", "10.0.0.2");
        config.vpnMask = prefs.getString("vpn_mask", "255.255.255.0");
        config.vpnGateway = prefs.getString("vpn_gateway", "10.0.0.1");
        config.verbose = prefs.getBoolean("verbose", false);
        config.rememberKey = prefs.getBoolean("remember_key", true);
        if (config.rememberKey) config.seedKey = prefs.getString("seed_key", "");
        return config;
    }

    public static void save(Context context, Config config) {
        SharedPreferences.Editor editor = context.getSharedPreferences(
                        PREFS_NAME,
                        Context.MODE_PRIVATE
                )
                .edit()
                .putString("host", config.host.trim())
                .putString("port", config.port.trim())
                .putInt("encoding", Math.max(0, Math.min(2, config.encoding)))
                .putString("vpn_ip", config.vpnAddress.trim())
                .putString("vpn_mask", config.vpnMask.trim())
                .putString("vpn_gateway", config.vpnGateway.trim())
                .putBoolean("verbose", config.verbose)
                .putBoolean("remember_key", config.rememberKey);
        if (config.rememberKey) editor.putString("seed_key", config.seedKey);
        else editor.remove("seed_key");
        editor.apply();
    }

    public static String validate(Config config) {
        if (config.host.trim().isEmpty()) return "Set a remote server first.";
        if (config.numericPort() < 1 || config.numericPort() > 65535) {
            return "Server port must be between 1 and 65535.";
        }
        if (config.encoding == 2 && config.seedKey.isEmpty()) {
            return "Raw packet encoding requires a seed key.";
        }
        if (!isValidIpv4(config.vpnAddress.trim())) return "VPN address is not valid IPv4.";
        if (netmaskToPrefix(config.vpnMask.trim()) < 0) return "VPN netmask is not contiguous.";
        if (!config.vpnGateway.trim().isEmpty()
                && !isValidIpv4(config.vpnGateway.trim())) {
            return "VPN gateway is not valid IPv4.";
        }
        return null;
    }

    public static Intent createServiceIntent(Context context, Config config) {
        Intent intent = new Intent(context, SafLepVpnService.class);
        intent.setAction(SafLepVpnService.ACTION_START);
        intent.putExtra(SafLepVpnService.EXTRA_SERVER_IP, config.host.trim());
        intent.putExtra(SafLepVpnService.EXTRA_SERVER_PORT, config.numericPort());
        intent.putExtra(SafLepVpnService.EXTRA_SEED_KEY, config.seedKey);
        intent.putExtra(SafLepVpnService.EXTRA_ENCODING_SCHEME, config.encoding);
        intent.putExtra(SafLepVpnService.EXTRA_VERBOSE, config.verbose);
        intent.putExtra(SafLepVpnService.EXTRA_VPN_ADDRESS, config.vpnAddress.trim());
        intent.putExtra(SafLepVpnService.EXTRA_VPN_PREFIX, config.vpnPrefix());
        intent.putExtra(SafLepVpnService.EXTRA_VPN_GATEWAY, config.vpnGateway.trim());
        return intent;
    }

    public static boolean isValidIpv4(String value) {
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

    public static int netmaskToPrefix(String value) {
        if (!isValidIpv4(value)) return -1;
        String[] octets = value.split("\\.");
        int mask = 0;
        for (String octet : octets) mask = (mask << 8) | Integer.parseInt(octet);

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
