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

    public enum ConnectionState {
        DISCONNECTED,
        STARTING,
        AWAITING_PEER,
        CONNECTED,
        PEER_SILENT,
        STOPPING,
        FAILED;

        /** True while a session exists that a disconnect request can stop. */
        public boolean isStoppable() {
            return this == STARTING
                    || this == AWAITING_PEER
                    || this == CONNECTED
                    || this == PEER_SILENT;
        }
    }

    // Values returned by getLinkPhase(); keep in sync with link_phase in native-lib.cpp.
    private static final int LINK_NO_REPLY = 0;
    private static final int LINK_UNREADABLE = 1;
    private static final int LINK_VERIFIED = 2;
    private static final int LINK_PEER_SILENT = 3;

    private static volatile String statusSummary =
            "Disconnected\nNo active tunnel.";
    private static volatile ConnectionState connectionState = ConnectionState.DISCONNECTED;

    static {
        System.loadLibrary("saf-lep");
    }

    private final Object lifecycleLock = new Object();
    private final Object nativeLifecycleLock = new Object();
    private final Object notificationLock = new Object();
    private final Handler statusHandler = new Handler(Looper.getMainLooper());
    private final Runnable statusReporter = new Runnable() {
        @Override
        public void run() {
            if (!isVpnRunning() || stopRequested) return;
            publishLinkStatus();
            statusHandler.postDelayed(this, 1000);
        }
    };

    private ParcelFileDescriptor tunInterface;
    private Thread startupThread;
    private Thread shutdownThread;
    private volatile boolean stopRequested;
    private volatile String runningConfiguration = "";
    private long lifecycleGeneration;
    private int latestStartId;
    // A start requested while the previous session is still tearing down; it is
    // replayed once the teardown finishes instead of being dropped.
    private Intent pendingStartIntent;
    private int pendingStartId;
    private boolean inForeground;
    private String notificationText = "";

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
    private native int getLinkPhase();
    private native String getNativeStatus();
    private native String getNativeLastError();

    public static String getStatusSummary() {
        return statusSummary;
    }

    public static boolean isActiveOrStarting() {
        return connectionState.isStoppable()
                || connectionState == ConnectionState.STOPPING;
    }

    public static ConnectionState getConnectionState() {
        return connectionState;
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
            synchronized (lifecycleLock) {
                latestStartId = Math.max(latestStartId, startId);
                pendingStartIntent = null;
            }
            beginShutdown(
                    "Disconnected",
                    "No active tunnel.",
                    ConnectionState.DISCONNECTED,
                    true
            );
            return START_NOT_STICKY;
        }

        // Android can start a VpnService itself, notably when always-on VPN is
        // configured. A tunnel must only be created by an explicit user action;
        // otherwise a manual disconnect can look like an immediate reconnect.
        if (!ACTION_START.equals(intent.getAction())) {
            Log.w(TAG, "Ignoring non-user VPN start action: " + intent.getAction());
            stopSelfResult(startId);
            return START_NOT_STICKY;
        }

        handleStart(intent, startId);
        return START_NOT_STICKY;
    }

    private void handleStart(Intent intent, int startId) {
        final long generation;
        synchronized (lifecycleLock) {
            // Recorded under the same lock the teardown uses to pick its stop id,
            // so a teardown finishing concurrently cannot stop this new session.
            // A replayed start may be older than a command handled since.
            latestStartId = Math.max(latestStartId, startId);
            if (shutdownThread != null && shutdownThread.isAlive()) {
                // Typically RETRY pressed right after a failure, while the failed
                // session is still being torn down. Starting now would race that
                // teardown and its stopSelf, so replay the request afterwards.
                Log.i(TAG, "Deferring VPN start until the previous session has stopped");
                pendingStartIntent = intent;
                pendingStartId = startId;
                return;
            }
            if (isVpnRunning() || (startupThread != null && startupThread.isAlive())) {
                // The service is already in the foreground for that session, which
                // also satisfies this startForegroundService() call.
                Log.w(TAG, "Ignoring duplicate VPN start");
                return;
            }
            stopRequested = false;
            generation = ++lifecycleGeneration;
        }

        showForeground("Preparing tunnel...");

        String serverHost = stringExtra(intent, EXTRA_SERVER_IP, "").trim();
        int serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 0);
        String seedKey = stringExtra(intent, EXTRA_SEED_KEY, "");
        int encodingScheme = Math.max(0, Math.min(2, intent.getIntExtra(EXTRA_ENCODING_SCHEME, 0)));
        boolean verbose = intent.getBooleanExtra(EXTRA_VERBOSE, false);
        String vpnAddress = stringExtra(intent, EXTRA_VPN_ADDRESS, "10.0.0.2").trim();
        int vpnPrefix = intent.getIntExtra(EXTRA_VPN_PREFIX, 24);
        String vpnGateway = stringExtra(intent, EXTRA_VPN_GATEWAY, "10.0.0.1").trim();
        int mtu = intent.getIntExtra(EXTRA_MTU, 1500);

        publishStatus(
                "Resolving server",
                serverHost + ":" + serverPort + "\nDNS is resolved before the VPN route is installed.",
                ConnectionState.STARTING
        );

        startupThread = new Thread(
                () -> {
                    try {
                        startTunnel(
                                generation,
                                serverHost,
                                serverPort,
                                seedKey,
                                encodingScheme,
                                verbose,
                                vpnAddress,
                                vpnPrefix,
                                vpnGateway,
                                mtu
                        );
                    } finally {
                        synchronized (lifecycleLock) {
                            if (Thread.currentThread() == startupThread) startupThread = null;
                        }
                    }
                },
                "saf-lep-start"
        );
        startupThread.start();
    }

    private void startTunnel(
            long generation,
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
            if (!isCurrentGeneration(generation)) return;

            String protocol = encodingScheme == 2 ? "RAW"
                    : encodingScheme == 1 ? "LEP v1" : "LEP v0";
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
            publishStatus(
                    "Establishing VPN interface",
                    runningConfiguration,
                    ConnectionState.STARTING
            );
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
                if (!isCurrentGenerationLocked(generation)) {
                    established.close();
                    return;
                }
                tunInterface = established;
            }

            publishStatus(
                    "Starting native tunnel",
                    runningConfiguration + "\nProtecting the UDP socket from the VPN route...",
                    ConnectionState.STARTING
            );

            boolean success;
            String nativeError = "";
            synchronized (nativeLifecycleLock) {
                if (!isCurrentGeneration(generation)) return;
                success = startNativeVpn(
                        established.getFd(),
                        resolvedServerIp,
                        serverPort,
                        seedKey,
                        encodingScheme,
                        verbose
                );
                if (success && !isCurrentGeneration(generation)) {
                    stopNativeVpn();
                    return;
                }
                if (success) {
                    Log.i(TAG, "Native VPN started on UDP port " + getLocalPort());
                    // The link is only reported online once the server has
                    // answered; until then this publishes AWAITING_PEER.
                    publishLinkStatus();
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
            if (!isCurrentGeneration(generation)) return;
            String message = error.getMessage() == null
                    ? error.getClass().getSimpleName()
                    : error.getMessage();
            Log.e(TAG, "Failed to start VPN", error);
            String details =
                    message + "\nCheck the server address/port, LEP version, seed key, and server firewall.";
            publishStatus(
                    "Connection failed",
                    details,
                    ConnectionState.FAILED
            );
            updateNotification("Connection failed");
            beginShutdown(
                    "Connection failed",
                    details,
                    ConnectionState.FAILED,
                    false
            );
        }
    }

    @Override
    public void onDestroy() {
        stopRequested = true;
        synchronized (lifecycleLock) {
            ++lifecycleGeneration;
        }
        statusHandler.removeCallbacks(statusReporter);
        tearDownTunnel();
        hideForeground();
        if (connectionState != ConnectionState.FAILED
                && connectionState != ConnectionState.DISCONNECTED) {
            publishStatus(
                    "Disconnected",
                    "The VPN service was stopped by Android.",
                    ConnectionState.DISCONNECTED
            );
        }
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        beginShutdown(
                "VPN permission revoked",
                "Android revoked the VPN interface.",
                ConnectionState.DISCONNECTED,
                false
        );
    }

    private void beginShutdown(
            String finalTitle,
            String finalDetails,
            ConnectionState finalState,
            boolean announceStopping
    ) {
        synchronized (lifecycleLock) {
            if (shutdownThread != null && shutdownThread.isAlive()) return;
            stopRequested = true;
            ++lifecycleGeneration;
            if (announceStopping) {
                publishStatus(
                        "Stopping tunnel",
                        "Closing the VPN interface and UDP transport...",
                        ConnectionState.STOPPING
                );
            }
            shutdownThread = new Thread(() -> {
                statusHandler.removeCallbacks(statusReporter);
                tearDownTunnel();
                hideForeground();
                publishStatus(finalTitle, finalDetails, finalState);

                Intent restartIntent;
                int restartId;
                int stopId;
                synchronized (lifecycleLock) {
                    restartIntent = pendingStartIntent;
                    restartId = pendingStartId;
                    pendingStartIntent = null;
                    stopId = latestStartId;
                    if (Thread.currentThread() == shutdownThread) shutdownThread = null;
                }
                if (restartIntent != null) {
                    statusHandler.post(() -> handleStart(restartIntent, restartId));
                } else {
                    // Fails harmlessly if a newer start arrived after stopId was read.
                    stopSelfResult(stopId);
                }
            }, "saf-lep-stop");
            shutdownThread.start();
        }
    }

    private void tearDownTunnel() {
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
    }

    private boolean isCurrentGeneration(long generation) {
        synchronized (lifecycleLock) {
            return isCurrentGenerationLocked(generation);
        }
    }

    private boolean isCurrentGenerationLocked(long generation) {
        return !stopRequested && lifecycleGeneration == generation;
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

    private static void publishStatus(
            String title,
            String details,
            ConnectionState state
    ) {
        statusSummary = title + "\n" + details;
        connectionState = state;
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
                .setSmallIcon(R.drawable.ic_notification)
                .setContentIntent(contentIntent)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", stopPendingIntent)
                .setOngoing(true)
                .build();
    }

    private void showForeground(String status) {
        synchronized (notificationLock) {
            notificationText = status;
            startForeground(NOTIFICATION_ID, createNotification(status));
            inForeground = true;
        }
    }

    private void hideForeground() {
        synchronized (notificationLock) {
            inForeground = false;
            stopForeground(STOP_FOREGROUND_REMOVE);
        }
    }

    private void updateNotification(String status) {
        synchronized (notificationLock) {
            // A notify() racing stopForeground() would leave an ongoing,
            // undismissable notification behind for a service that has stopped.
            if (!inForeground || status.equals(notificationText)) return;
            notificationText = status;
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.notify(NOTIFICATION_ID, createNotification(status));
        }
    }

    private void publishLinkStatus() {
        String details = runningConfiguration + "\n" + getNativeStatus();
        switch (getLinkPhase()) {
            case LINK_VERIFIED:
                publishStatus("Tunnel active", details, ConnectionState.CONNECTED);
                updateNotification("Tunnel active");
                break;
            case LINK_PEER_SILENT:
                publishStatus("Server silent", details, ConnectionState.PEER_SILENT);
                updateNotification("Server silent, re-probing...");
                break;
            case LINK_UNREADABLE:
                publishStatus("Server replies not decodable", details, ConnectionState.AWAITING_PEER);
                updateNotification("Waiting for the server...");
                break;
            case LINK_NO_REPLY:
            default:
                publishStatus("Waiting for the server", details, ConnectionState.AWAITING_PEER);
                updateNotification("Waiting for the server...");
                break;
        }
    }

    private static String stringExtra(Intent intent, String name, String fallback) {
        String value = intent.getStringExtra(name);
        return value != null ? value : fallback;
    }
}
