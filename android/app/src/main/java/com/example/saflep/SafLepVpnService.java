package com.example.saflep;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.IOException;

public final class SafLepVpnService extends VpnService {
    private static final String TAG = "SafLepVpnService";
    private static final String NOTIFICATION_CHANNEL_ID = "saf_lep_vpn";
    private static final int NOTIFICATION_ID = 1;

    public static final String EXTRA_SERVER_IP = "server_ip";
    public static final String EXTRA_SERVER_PORT = "server_port";
    public static final String EXTRA_SEED_KEY = "seed_key";
    public static final String EXTRA_ENCODING_SCHEME = "encoding_scheme";
    public static final String EXTRA_VERBOSE = "verbose";
    public static final String EXTRA_VPN_ADDRESS = "vpn_address";
    public static final String EXTRA_VPN_PREFIX = "vpn_prefix";
    public static final String EXTRA_MTU = "mtu";

    static {
        System.loadLibrary("saf-lep");
    }

    private ParcelFileDescriptor tunInterface;

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

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;
        if (isVpnRunning()) {
            Log.w(TAG, "Ignoring duplicate VPN start");
            return START_NOT_STICKY;
        }

        startForeground(NOTIFICATION_ID, createNotification());

        String serverIp = stringExtra(intent, EXTRA_SERVER_IP, "");
        int serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 0);
        String seedKey = stringExtra(intent, EXTRA_SEED_KEY, "");
        int encodingScheme = intent.getIntExtra(EXTRA_ENCODING_SCHEME, 0);
        boolean verbose = intent.getBooleanExtra(EXTRA_VERBOSE, false);
        String vpnAddress = stringExtra(intent, EXTRA_VPN_ADDRESS, "10.0.0.2");
        int vpnPrefix = intent.getIntExtra(EXTRA_VPN_PREFIX, 24);
        int mtu = intent.getIntExtra(EXTRA_MTU, 1500);

        try {
            tunInterface = new Builder()
                    .setSession("SAF-LEP VPN")
                    .addAddress(vpnAddress, vpnPrefix)
                    .addRoute("0.0.0.0", 0)
                    .setMtu(mtu)
                    .setBlocking(false)
                    .establish();

            ParcelFileDescriptor tun = tunInterface;
            if (tun == null) {
                Log.e(TAG, "Failed to establish VPN interface");
                stopSelf();
                return START_NOT_STICKY;
            }

            new Thread(() -> {
                boolean success = startNativeVpn(
                        tun.getFd(), serverIp, serverPort, seedKey, encodingScheme, verbose
                );
                if (success) {
                    Log.i(TAG, "Native VPN started on UDP port " + getLocalPort());
                } else {
                    Log.e(TAG, "Failed to start native VPN");
                    new Handler(getMainLooper()).post(this::stopSelf);
                }
            }, "saf-lep-start").start();
        } catch (Exception error) {
            Log.e(TAG, "Exception while starting VPN", error);
            stopSelf();
            return START_NOT_STICKY;
        }

        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        if (isVpnRunning()) stopNativeVpn();
        try {
            if (tunInterface != null) tunInterface.close();
        } catch (IOException error) {
            Log.e(TAG, "Error closing VPN interface", error);
        }
        tunInterface = null;
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        stopSelf();
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

    private Notification createNotification() {
        PendingIntent contentIntent = PendingIntent.getActivity(
                this,
                0,
                new Intent(this, MainActivity.class),
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
                .setContentText("Tunnel is active")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentIntent(contentIntent)
                .setOngoing(true)
                .build();
    }

    private static String stringExtra(Intent intent, String name, String fallback) {
        String value = intent.getStringExtra(name);
        return value != null ? value : fallback;
    }
}
