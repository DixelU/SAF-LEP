package com.example.saflep;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Locale;

public final class SafLepVpnService extends VpnService {
    private static final String TAG = "SafLepVpnService";
    private static final String NOTIFICATION_CHANNEL_ID = "saf_lep_vpn";
    private static final int NOTIFICATION_ID = 1;

    public static final String ACTION_START = "com.example.saflep.action.START";
    public static final String ACTION_STOP = "com.example.saflep.action.STOP";

    public static final String EXTRA_SERVER_IP = "server_ip";
    public static final String EXTRA_SERVER_PORT = "server_port";
    public static final String EXTRA_SEED_KEY = "seed_key";
    public static final String EXTRA_ENCODING_SCHEME = "encoding_scheme";
    public static final String EXTRA_VERBOSE = "verbose";
    public static final String EXTRA_VPN_ADDRESS = "vpn_address";
    public static final String EXTRA_VPN_PREFIX = "vpn_prefix";
    public static final String EXTRA_VPN_GATEWAY = "vpn_gateway";
    public static final String EXTRA_MTU = "mtu";

    private static volatile String statusSummary =
            "Disconnected\nNo active tunnel.";
    private static volatile boolean activeOrStarting = false;

    static {
        System.loadLibrary("saf-lep");
    }

    private final Object lifecycleLock = new Object();
    private final Object nativeLifecycleLock = new Object();
    private final Handler statusHandler = new Handler(Looper.getMainLooper());
    private final Runnable statusReporter = new Runnable() {
        @Override
        public void run() {
            if (!isVpnRunning()) return;
            publishStatus("Tunnel active", runningConfiguration + "\n" + getNativeStatus(), true);
            updateNotification("Tunnel active");
            statusHandler.postDelayed(this, 1000);
        }
    };

    private ParcelFileDescriptor tunInterface;
    private Thread startupThread;
    private volatile boolean stopRequested;
    private volatile boolean startupFailed;
    private volatile String runningConfiguration = "";

    private native boolean startNativeVpn(
            int fd,
            String serverIp,
            int serverPort,
            String seedKey,
            int encodingScheme,
            boolean verbose
    );

    private native void stopNativeVpn();
    private native boolean isVpnRunning();
    private native int getLocalPort();
    private native String getNativeStatus();
    private native String getNativeLastError();

    public static String getStatusSummary() {
        return statusSummary;
    }

    public static boolean isActiveOrStarting() {
        return activeOrStarting;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;

        if (ACTION_STOP.equals(intent.getAction())) {
            publishStatus("Stopping tunnel", "Closing the VPN interface and UDP transport...", true);
            stopRequested = true;
            stopSelf();
            return START_NOT_STICKY;
        }

        synchronized (lifecycleLock) {
            if (isVpnRunning() || (startupThread != null && startupThread.isAlive())) {
                Log.w(TAG, "Ignoring duplicate VPN start");
                publishStatus(
                        "Tunnel already active",
                        runningConfiguration.isEmpty()
                                ? "A connection attempt is already in progress."
                                : runningConfiguration,
                        true
                );
                return START_NOT_STICKY;
            }
            stopRequested = false;
            startupFailed = false;
        }

        startForeground(NOTIFICATION_ID, createNotification("Preparing tunnel..."));

        String serverHost = stringExtra(intent, EXTRA_SERVER_IP, "").trim();
        int serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 0);
        String seedKey = stringExtra(intent, EXTRA_SEED_KEY, "");
        int encodingScheme = intent.getIntExtra(EXTRA_ENCODING_SCHEME, 0) == 1 ? 1 : 0;
        boolean verbose = intent.getBooleanExtra(EXTRA_VERBOSE, false);
        String vpnAddress = stringExtra(intent, EXTRA_VPN_ADDRESS, "10.0.0.2").trim();
        int vpnPrefix = intent.getIntExtra(EXTRA_VPN_PREFIX, 24);
        String vpnGateway = stringExtra(intent, EXTRA_VPN_GATEWAY, "10.0.0.1").trim();
        int mtu = intent.getIntExtra(EXTRA_MTU, 1500);

        publishStatus(
                "Resolving server",
                serverHost + ":" + serverPort + "\nDNS is resolved before the VPN route is installed.",
                true
        );

        startupThread = new Thread(
                () -> startTunnel(
                        serverHost,
                        serverPort,
                        seedKey,
                        encodingScheme,
                        verbose,
                        vpnAddress,
                        vpnPrefix,
                        vpnGateway,
                        mtu
                ),
                "saf-lep-start"
        );
        startupThread.start();
        return START_NOT_STICKY;
    }

    private void startTunnel(
            String serverHost,
            int serverPort,
            String seedKey,
            int encodingScheme,
            boolean verbose,
            String vpnAddress,
            int vpnPrefix,
            String vpnGateway,
            int mtu
    ) {
        try {
            if (serverHost.isEmpty() || serverPort < 1 || serverPort > 65535) {
                throw new IllegalArgumentException("Invalid server host or port");
            }
            if (vpnPrefix < 0 || vpnPrefix > 32) {
                throw new IllegalArgumentException("Invalid VPN prefix length: " + vpnPrefix);
            }
            if (mtu < 576 || mtu > 9000) {
                throw new IllegalArgumentException("Invalid MTU: " + mtu);
            }

            String resolvedServerIp = resolveIpv4(serverHost);
            if (stopRequested) return;

            String protocol = encodingScheme == 1 ? "LEP v1" : "LEP v0";
            String routeMode = vpnGateway.isEmpty()
                    ? "VPN subnet only"
                    : "full IPv4 via " + vpnGateway;
            runningConfiguration = String.format(
                    Locale.US,
                    "Server: %s:%d -> %s:%d\nProtocol: %s\nVPN: %s/%d (%s)",
                    serverHost,
                    serverPort,
                    resolvedServerIp,
                    serverPort,
                    protocol,
                    vpnAddress,
                    vpnPrefix,
                    routeMode
            );
            publishStatus("Establishing VPN interface", runningConfiguration, true);
            updateNotification("Establishing VPN interface...");

            Builder builder = new Builder()
                    .setSession("SAF-LEP VPN")
                    .addAddress(vpnAddress, vpnPrefix)
                    .setMtu(mtu)
                    .setBlocking(false);

            if (vpnGateway.isEmpty()) {
                builder.addRoute(networkAddress(vpnAddress, vpnPrefix), vpnPrefix);
            } else {
                builder.addRoute("0.0.0.0", 0);
            }

            ParcelFileDescriptor established = builder.establish();
            if (established == null) {
                throw new IOException("Android refused to establish the VPN interface");
            }

            synchronized (lifecycleLock) {
                if (stopRequested) {
                    established.close();
                    return;
                }
                tunInterface = established;
            }

            publishStatus(
                    "Starting native tunnel",
                    runningConfiguration + "\nProtecting the UDP socket from the VPN route...",
                    true
            );

            boolean success;
            String nativeError = "";
            synchronized (nativeLifecycleLock) {
                success = startNativeVpn(
                        established.getFd(),
                        resolvedServerIp,
                        serverPort,
                        seedKey,
                        encodingScheme,
                        verbose
                );
                if (success && stopRequested) {
                    stopNativeVpn();
                    return;
                }
                if (success) {
                    Log.i(TAG, "Native VPN started on UDP port " + getLocalPort());
                    publishStatus(
                            "Tunnel active",
                            runningConfiguration + "\n" + getNativeStatus(),
                            true
                    );
                    updateNotification("Tunnel active");
                    statusHandler.removeCallbacks(statusReporter);
                    statusHandler.post(statusReporter);
                } else {
                    nativeError = getNativeLastError();
                }
            }
            if (!success) {
                throw new IOException(nativeError.isEmpty()
                        ? "Native tunnel initialization failed"
                        : nativeError);
            }
        } catch (Exception error) {
            if (stopRequested) return;
            startupFailed = true;
            String message = error.getMessage() == null
                    ? error.getClass().getSimpleName()
                    : error.getMessage();
            Log.e(TAG, "Failed to start VPN", error);
            publishStatus(
                    "Connection failed",
                    message + "\nCheck the server address/port, LEP version, seed key, and server firewall.",
                    false
            );
            updateNotification("Connection failed");
            stopSelf();
        }
    }

    @Override
    public void onDestroy() {
        stopRequested = true;
        statusHandler.removeCallbacks(statusReporter);

        synchronized (nativeLifecycleLock) {
            if (isVpnRunning()) stopNativeVpn();
        }

        ParcelFileDescriptor descriptor;
        synchronized (lifecycleLock) {
            descriptor = tunInterface;
            tunInterface = null;
        }
        try {
            if (descriptor != null) descriptor.close();
        } catch (IOException error) {
            Log.e(TAG, "Error closing VPN interface", error);
        }

        stopForeground(STOP_FOREGROUND_REMOVE);
        if (!startupFailed) {
            publishStatus("Disconnected", "No active tunnel.", false);
        } else {
            activeOrStarting = false;
        }
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        publishStatus("VPN permission revoked", "Android revoked the VPN interface.", false);
        stopSelf();
    }

    private String resolveIpv4(String host) throws IOException {
        InetAddress[] addresses = InetAddress.getAllByName(host);
        for (InetAddress address : addresses) {
            if (address instanceof Inet4Address) return address.getHostAddress();
        }
        throw new IOException("No IPv4 address found for " + host);
    }

    private static String networkAddress(String address, int prefix) {
        String[] octets = address.split("\\.");
        int value = 0;
        for (String octet : octets) value = (value << 8) | Integer.parseInt(octet);
        int mask = prefix == 0 ? 0 : -1 << (32 - prefix);
        int network = value & mask;
        return String.format(
                Locale.US,
                "%d.%d.%d.%d",
                (network >>> 24) & 0xff,
                (network >>> 16) & 0xff,
                (network >>> 8) & 0xff,
                network & 0xff
        );
    }

    private static void publishStatus(String title, String details, boolean active) {
        statusSummary = title + "\n" + details;
        activeOrStarting = active;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;

        NotificationChannel channel = new NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "SAF-LEP VPN",
                NotificationManager.IMPORTANCE_LOW
        );
        channel.setDescription("VPN connection status");
        channel.setShowBadge(false);
        getSystemService(NotificationManager.class).createNotificationChannel(channel);
    }

    private Notification createNotification(String status) {
        PendingIntent contentIntent = PendingIntent.getActivity(
                this,
                0,
                new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );
        Intent stopIntent = new Intent(this, SafLepVpnService.class).setAction(ACTION_STOP);
        PendingIntent stopPendingIntent = PendingIntent.getService(
                this,
                1,
                stopIntent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, NOTIFICATION_CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        return builder
                .setContentTitle("SAF-LEP VPN")
                .setContentText(status)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentIntent(contentIntent)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", stopPendingIntent)
                .setOngoing(true)
                .build();
    }

    private void updateNotification(String status) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) manager.notify(NOTIFICATION_ID, createNotification(status));
    }

    private static String stringExtra(Intent intent, String name, String fallback) {
        String value = intent.getStringExtra(name);
        return value != null ? value : fallback;
    }
}
