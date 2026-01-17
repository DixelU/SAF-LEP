/**
 * SAF-LEP Android JNI Bridge
 *
 * This file provides the JNI interface between the Android VpnService (Java/Kotlin)
 * and the C++ core tunnel implementation.
 *
 * Usage from Kotlin/Java:
 *   external fun startNativeVpn(fd: Int, serverIp: String, serverPort: Int, seedKey: String): Boolean
 *   external fun stopNativeVpn()
 *   external fun isVpnRunning(): Boolean
 *   external fun protectSocket(socketFd: Int)  // Called back from C++ to protect UDP socket
 */

#include <jni.h>
#include <string>
#include <memory>
#include <thread>
#include <atomic>

#include <android/log.h>

// Include the tunnel headers
#include "../../udp_tunnel/tunnel.h"
#include "../../udp_tunnel/global_flags.h"

#define LOG_TAG "SAF-LEP-JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

namespace
{

// Global instances (simplified for single VPN connection)
std::shared_ptr<dixelu::udp::p2p_tunnel> g_tunnel;
std::unique_ptr<dixelu::udp::vpn_interface> g_vpn;
std::atomic<bool> g_running{false};

// Java VM reference for callbacks
JavaVM* g_jvm = nullptr;
jobject g_vpn_service = nullptr;
jmethodID g_protect_method = nullptr;

/**
 * Call back to Java to protect a socket from being routed through the VPN.
 * This is critical to prevent routing loops.
 */
bool protectSocket(int socketFd)
{
	if (!g_jvm || !g_vpn_service || !g_protect_method)
	{
		LOGW("Cannot protect socket: JNI not fully initialized");
		return false;
	}

	JNIEnv* env = nullptr;
	bool attached = false;

	int status = g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6);
	if (status == JNI_EDETACHED)
	{
		if (g_jvm->AttachCurrentThread(&env, nullptr) != 0)
		{
			LOGE("Failed to attach thread to JVM");
			return false;
		}
		attached = true;
	}
	else if (status != JNI_OK)
	{
		LOGE("Failed to get JNI environment");
		return false;
	}

	jboolean result = env->CallBooleanMethod(g_vpn_service, g_protect_method, socketFd);

	if (env->ExceptionCheck())
	{
		env->ExceptionDescribe();
		env->ExceptionClear();
		result = JNI_FALSE;
	}

	if (attached)
		g_jvm->DetachCurrentThread();

		return result == JNI_TRUE;
	}
}

extern "C"
{

/**
 * Called when the native library is loaded.
 */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
	g_jvm = vm;
	LOGI("SAF-LEP native library loaded");
	return JNI_VERSION_1_6;
}

/**
 * Called when the native library is unloaded.
 */
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved)
{
	g_jvm = nullptr;
	LOGI("SAF-LEP native library unloaded");
}

/**
 * Start the native VPN tunnel.
 *
 * @param env JNI environment
 * @param thiz The VpnService instance (for protect() callback)
 * @param tun_fd The TUN file descriptor from VpnService.Builder.establish()
 * @param server_ip The server IP address to connect to
 * @param server_port The server port
 * @param seed_key The encryption seed key (empty string for no encryption)
 * @param verbose Enable verbose logging
 * @return true if started successfully
 */
JNIEXPORT jboolean JNICALL
Java_com_example_saflep_SafLepVpnService_startNativeVpn(
	JNIEnv* env,
	jobject thiz,
	jint tun_fd,
	jstring server_ip,
	jint server_port,
	jstring seed_key,
	jboolean verbose)
{

	if (g_running.exchange(true))
	{
		LOGW("VPN already running");
		return JNI_FALSE;
	}

	LOGI("Starting native VPN: fd=%d, port=%d", tun_fd, server_port);

	// Set verbose mode
	VERBOSE_MODE = verbose;

	// Store VpnService reference for protect() callback
	g_vpn_service = env->NewGlobalRef(thiz);
	jclass clazz = env->GetObjectClass(thiz);
	g_protect_method = env->GetMethodID(clazz, "protect", "(I)Z");
	if (!g_protect_method)
	{
		LOGE("Failed to find protect() method");
		env->DeleteGlobalRef(g_vpn_service);
		g_vpn_service = nullptr;
		g_running = false;
		return JNI_FALSE;
	}

	// Convert Java strings
	const char* ip_cstr = env->GetStringUTFChars(server_ip, nullptr);
	const char* key_cstr = env->GetStringUTFChars(seed_key, nullptr);
	std::string ip_str(ip_cstr);
	std::string key_str(key_cstr);
	env->ReleaseStringUTFChars(server_ip, ip_cstr);
	env->ReleaseStringUTFChars(seed_key, key_cstr);

	try
	{
		// Create the P2P tunnel
		// Use port 0 to let the OS assign a port
		g_tunnel = std::make_shared<dixelu::udp::p2p_tunnel>(0);

		// Set encryption key if provided
		if (!key_str.empty())
		{
			g_tunnel->set_encryption_key(key_str);
			LOGI("Encryption key set");
		}

		// Create the VPN interface
		g_vpn = std::make_unique<dixelu::udp::vpn_interface>(g_tunnel);

		// Start the tunnel (async I/O)
		g_tunnel->start();
		g_tunnel->run_in_thread();

		// Start the VPN interface with the TUN file descriptor
		if (!g_vpn->start_android(tun_fd))
		{
			LOGE("Failed to start VPN interface");
			g_tunnel->stop();
			g_tunnel.reset();
			g_vpn.reset();
			env->DeleteGlobalRef(g_vpn_service);
			g_vpn_service = nullptr;
			g_running = false;
			return JNI_FALSE;
		}

		// Connect to the server if IP is provided
		if (!ip_str.empty() && server_port > 0)
		{
			LOGI("Connecting to peer: %s:%d", ip_str.c_str(), server_port);
			g_tunnel->connect_to_peer(ip_str, std::to_string(server_port));
		}

		LOGI("Native VPN started successfully");
		return JNI_TRUE;

	}
	catch (const std::exception& e)
	{
		LOGE("Exception starting VPN: %s", e.what());
		g_tunnel.reset();
		g_vpn.reset();
		env->DeleteGlobalRef(g_vpn_service);
		g_vpn_service = nullptr;
		g_running = false;
		return JNI_FALSE;
	}
}

/**
 * Stop the native VPN tunnel.
 */
JNIEXPORT void JNICALL
Java_com_example_saflep_SafLepVpnService_stopNativeVpn(JNIEnv* env, jobject thiz) {
	if (!g_running.exchange(false))
	{
		LOGW("VPN not running");
		return;
	}

	LOGI("Stopping native VPN");

	try
	{
		if (g_vpn)
		{
			g_vpn->stop();
			g_vpn.reset();
		}

		if (g_tunnel)
		{
			g_tunnel->stop();
			g_tunnel.reset();
		}

		if (g_vpn_service)
		{
			env->DeleteGlobalRef(g_vpn_service);
			g_vpn_service = nullptr;
		}

		LOGI("Native VPN stopped");

	}
	catch (const std::exception& e)
	{
		LOGE("Exception stopping VPN: %s", e.what());
	}
}

/**
 * Check if the VPN is currently running.
 */
JNIEXPORT jboolean JNICALL
Java_com_example_saflep_SafLepVpnService_isVpnRunning(JNIEnv* env, jobject thiz)
{
	return g_running ? JNI_TRUE : JNI_FALSE;
}

/**
 * Get the local UDP port that the tunnel is listening on.
 * This can be useful for NAT traversal / hole punching.
 */
JNIEXPORT jint JNICALL
Java_com_example_saflep_SafLepVpnService_getLocalPort(JNIEnv* env, jobject thiz)
{
	if (!g_tunnel)
		return -1;

	return static_cast<jint>(g_tunnel->get_local_endpoint().port());
}

/**
 * Connect to an additional peer (for mesh networking scenarios).
 */
JNIEXPORT void JNICALL
Java_com_example_saflep_SafLepVpnService_connectToPeer(
	JNIEnv* env,
	jobject thiz,
	jstring peer_ip,
	jint peer_port)
{

	if (!g_tunnel || !g_running) {
		LOGW("Cannot connect to peer: VPN not running");
		return;
	}

	const char* ip_cstr = env->GetStringUTFChars(peer_ip, nullptr);
	std::string ip_str(ip_cstr);
	env->ReleaseStringUTFChars(peer_ip, ip_cstr);

	LOGI("Connecting to additional peer: %s:%d", ip_str.c_str(), peer_port);
	g_tunnel->connect_to_peer(ip_str, std::to_string(peer_port));
}

/**
 * Set the encryption key after initialization.
 * Note: Changing the key while connected may cause packet loss.
 */
JNIEXPORT void JNICALL
Java_com_example_saflep_SafLepVpnService_setEncryptionKey(
	JNIEnv* env,
	jobject thiz,
	jstring seed_key)
{

	if (!g_tunnel)
	{
		LOGW("Cannot set key: tunnel not initialized");
		return;
	}

	const char* key_cstr = env->GetStringUTFChars(seed_key, nullptr);
	std::string key_str(key_cstr);
	env->ReleaseStringUTFChars(seed_key, key_cstr);

	g_tunnel->set_encryption_key(key_str);
	LOGI("Encryption key updated");
}

/**
 * Enable or disable verbose logging.
 */
JNIEXPORT void JNICALL
Java_com_example_saflep_SafLepVpnService_setVerbose(JNIEnv* env, jobject thiz, jboolean verbose)
{
	VERBOSE_MODE = verbose;
	LOGI("Verbose mode: %s", verbose ? "enabled" : "disabled");
}

} // extern "C"
