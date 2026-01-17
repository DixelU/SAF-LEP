/**
 * SAF-LEP VPN Service for Android
 *
 * This is a sample implementation of the Android VpnService that bridges
 * to the native C++ tunnel implementation via JNI.
 *
 * USAGE:
 * 1. Copy this file to your Android project's kotlin source directory
 * 2. Update the package name to match your application
 * 3. Register the service in AndroidManifest.xml (see below)
 * 4. Request VPN permission before starting the service
 *
 * AndroidManifest.xml entry:
 * <service
 *     android:name=".SafLepVpnService"
 *     android:permission="android.permission.BIND_VPN_SERVICE"
 *     android:exported="false">
 *     <intent-filter>
 *         <action android:name="android.net.VpnService" />
 *     </intent-filter>
 * </service>
 *
 * Starting the VPN (from an Activity):
 * val intent = VpnService.prepare(this)
 * if (intent != null) {
 *     startActivityForResult(intent, VPN_REQUEST_CODE)
 * } else {
 *     // Permission already granted, start service
 *     startService(Intent(this, SafLepVpnService::class.java).apply {
 *         putExtra("server_ip", "1.2.3.4")
 *         putExtra("server_port", 14578)
 *         putExtra("seed_key", "your-secret-key")
 *     })
 * }
 */

package com.example.saflep

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.IOException

class SafLepVpnService : VpnService() {

    companion object {
        private const val TAG = "SafLepVpnService"
        private const val NOTIFICATION_CHANNEL_ID = "saf_lep_vpn"
        private const val NOTIFICATION_ID = 1

        // Load native library
        init {
            System.loadLibrary("saf-lep")
        }
    }

    // The TUN interface file descriptor
    private var tunInterface: ParcelFileDescriptor? = null

    // Native methods (implemented in native-lib.cpp)
    private external fun startNativeVpn(
        fd: Int,
        serverIp: String,
        serverPort: Int,
        seedKey: String,
        verbose: Boolean
    ): Boolean

    private external fun stopNativeVpn()
    private external fun isVpnRunning(): Boolean
    private external fun getLocalPort(): Int
    private external fun connectToPeer(peerIp: String, peerPort: Int)
    private external fun setEncryptionKey(seedKey: String)
    private external fun setVerbose(verbose: Boolean)

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Service created")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "Service starting")

        // Extract configuration from intent
        val serverIp = intent?.getStringExtra("server_ip") ?: ""
        val serverPort = intent?.getIntExtra("server_port", 0) ?: 0
        val seedKey = intent?.getStringExtra("seed_key") ?: ""
        val verbose = intent?.getBooleanExtra("verbose", false) ?: false

        // VPN interface configuration
        val vpnAddress = intent?.getStringExtra("vpn_address") ?: "10.0.0.2"
        val vpnPrefix = intent?.getIntExtra("vpn_prefix", 24) ?: 24
        val mtu = intent?.getIntExtra("mtu", 1500) ?: 1500

        // Start as foreground service (required for long-running VPN)
        startForeground(NOTIFICATION_ID, createNotification())

        // Configure and establish the VPN interface
        try {
            tunInterface = Builder()
                .setSession("SAF-LEP VPN")
                .addAddress(vpnAddress, vpnPrefix)
                .addRoute("0.0.0.0", 0)  // Route all traffic through VPN
                .setMtu(mtu)
                .setBlocking(true)
                .establish()

            if (tunInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return START_NOT_STICKY
            }

            val fd = tunInterface!!.fd
            Log.i(TAG, "VPN interface established, fd=$fd")

            // Start native tunnel in a separate thread
            Thread {
                val success = startNativeVpn(fd, serverIp, serverPort, seedKey, verbose)
                if (!success) {
                    Log.e(TAG, "Failed to start native VPN")
                    // Post to main thread to stop service
                    mainLooper.queue.addIdleHandler {
                        stopSelf()
                        false
                    }
                } else {
                    Log.i(TAG, "Native VPN started, local port: ${getLocalPort()}")
                }
            }.start()

        } catch (e: Exception) {
            Log.e(TAG, "Exception starting VPN", e)
            stopSelf()
            return START_NOT_STICKY
        }

        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "Service destroying")

        // Stop native tunnel
        stopNativeVpn()

        // Close TUN interface
        try {
            tunInterface?.close()
        } catch (e: IOException) {
            Log.e(TAG, "Error closing TUN interface", e)
        }
        tunInterface = null

        super.onDestroy()
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked")
        stopSelf()
    }

    /**
     * Called from native code to protect a socket from being routed through the VPN.
     * This prevents the encrypted UDP packets from being routed back into the tunnel,
     * which would cause an infinite loop.
     */
    override fun protect(socket: Int): Boolean {
        val result = super.protect(socket)
        Log.d(TAG, "Protected socket $socket: $result")
        return result
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "SAF-LEP VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN connection status"
                setShowBadge(false)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE
        )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }.apply {
            setContentTitle("SAF-LEP VPN")
            setContentText("Connected")
            setSmallIcon(android.R.drawable.ic_dialog_info) // Replace with your icon
            setContentIntent(pendingIntent)
            setOngoing(true)
        }.build()
    }
}
