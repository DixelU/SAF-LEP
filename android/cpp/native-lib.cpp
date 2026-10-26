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
#include <stdexcept>
#include <mutex>
#include <sstream>

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

// Global instances (simplified for single VPN connection). The status poller
// runs on the UI thread while start/stop run on service worker threads, so the
// pointers are only swapped or copied under g_state_mutex.
std::mutex g_state_mutex;
std::shared_ptr<dixelu::udp::p2p_tunnel> g_tunnel;
std::unique_ptr<dixelu::udp::vpn_interface> g_vpn;
std::atomic<bool> g_running{false};
std::mutex g_error_mutex;
std::string g_last_error;

// Java VM reference for callbacks
JavaVM* g_jvm = nullptr;
jobject g_vpn_service = nullptr;
jmethodID g_protect_method = nullptr;

void setLastError(const std::string& message)
{
	std::lock_guard<std::mutex> lock(g_error_mutex);
	g_last_error = message;
}

std::string getLastError()
{
	std::lock_guard<std::mutex> lock(g_error_mutex);
	return g_last_error;
}

std::shared_ptr<dixelu::udp::p2p_tunnel> currentTunnel()
{
	std::lock_guard<std::mutex> lock(g_state_mutex);
	return g_tunnel;
}

// Coarse link state reported to Java; keep in sync with SafLepVpnService.
enum link_phase : jint
{
	LINK_NO_REPLY = 0,      // nothing received from the server yet
	LINK_UNREADABLE = 1,    // datagrams arrive but none proved a shared key/scheme
	LINK_VERIFIED = 2,      // the server answered with decodable tunnel traffic
	LINK_PEER_SILENT = 3,   // verified earlier, now timed out and being re-probed
};

link_phase linkPhase(const dixelu::udp::p2p_tunnel& tunnel)
{
	const auto& stats = tunnel.get_stats();
	const bool verified = stats.verified_handshake_replies.load() > 0 ||
		stats.packets_received.load() > 0;
	if (!verified)
		return stats.bytes_received.load() > 0 ? LINK_UNREADABLE : LINK_NO_REPLY;
	return tunnel.get_connected_peers().empty() ? LINK_PEER_SILENT : LINK_VERIFIED;
}

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

} // namespace

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
 * @param encoding_scheme Packet encoding scheme (0=LEP v0, 1=LEP v1, 2=raw)
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
	jint encoding_scheme,
	jboolean verbose)
{

	if (g_running.exchange(true))
	{
		LOGW("VPN already running");
		setLastError("Native VPN is already running");
		return JNI_FALSE;
	}
	setLastError("");

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
		setLastError("Android VpnService.protect() is unavailable");
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

	std::shared_ptr<dixelu::udp::p2p_tunnel> tunnel;
	std::unique_ptr<dixelu::udp::vpn_interface> vpn;
	try
	{
		// Java resolves the host before establishing the catch-all VPN route. Use
		// the numeric endpoint directly here so no DNS lookup can be trapped in TUN.
		if (ip_str.empty() || server_port <= 0 || server_port > 65535)
			throw std::runtime_error("Invalid server endpoint");
		const boost::asio::ip::udp::endpoint server_endpoint(
			boost::asio::ip::make_address_v4(ip_str),
			static_cast<unsigned short>(server_port));

		// Create the P2P tunnel
		// Use port 0 to let the OS assign a port
		const auto scheme = encoding_scheme == 2
			? dixelu::udp::encode_scheme::raw
			: encoding_scheme == 1 ? dixelu::udp::encode_scheme::lep_v1
			                       : dixelu::udp::encode_scheme::lep_v0;
		tunnel = std::make_shared<dixelu::udp::p2p_tunnel>(0, scheme);
		const int socket_fd = tunnel->get_socket_fd();
		if (socket_fd < 0 || !protectSocket(socket_fd))
		{
			throw std::runtime_error("Failed to protect the tunnel UDP socket");
		}

		// Set encryption key if provided
		if (!key_str.empty())
		{
			tunnel->set_encryption_key(key_str);
			LOGI("Encryption key set");
		}

		// Create the VPN interface
		vpn = std::make_unique<dixelu::udp::vpn_interface>(tunnel);

		// Arm the receive loop, then register the server before anything reads
		// the TUN. Android queues the apps' first packets (DNS queries, TCP
		// sockets it just reset for the new route) as soon as establish()
		// returns, and broadcast() discards everything while no peer is
		// connected, so reading first would throw that initial burst away.
		tunnel->start();
		LOGI("Connecting to peer: %s:%d", ip_str.c_str(), server_port);
		tunnel->connect_to_peer(server_endpoint);

		// start_android() installs the tunnel's packet callback. Doing it before
		// the IO thread exists means the callback is never reassigned while a
		// receive handler might be reading it.
		if (!vpn->start_android(tun_fd))
		{
			throw std::runtime_error("Failed to duplicate or start the Android TUN interface");
		}

		tunnel->run_in_thread();
	}
	catch (const std::exception& e)
	{
		LOGE("Exception starting VPN: %s", e.what());
		setLastError(e.what());
		// The VPN interface goes first: it joins the TUN reader, which still
		// forwards into the tunnel.
		vpn.reset();
		tunnel.reset();
		env->DeleteGlobalRef(g_vpn_service);
		g_vpn_service = nullptr;
		g_running = false;
		return JNI_FALSE;
	}

	{
		std::lock_guard<std::mutex> lock(g_state_mutex);
		g_tunnel = std::move(tunnel);
		g_vpn = std::move(vpn);
	}

	LOGI("Native VPN started successfully");
	return JNI_TRUE;
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

	// Detach the instances first so a concurrent status query either sees none
	// or keeps its own reference alive; the blocking joins happen unlocked.
	std::shared_ptr<dixelu::udp::p2p_tunnel> tunnel;
	std::unique_ptr<dixelu::udp::vpn_interface> vpn;
	{
		std::lock_guard<std::mutex> lock(g_state_mutex);
		tunnel = std::move(g_tunnel);
		vpn = std::move(g_vpn);
	}

	try
	{
		if (vpn)
		{
			vpn->stop();
			vpn.reset();
		}

		if (tunnel)
		{
			tunnel->stop();
			tunnel.reset();
		}

		LOGI("Native VPN stopped");

	}
	catch (const std::exception& e)
	{
		LOGE("Exception stopping VPN: %s", e.what());
	}

	if (g_vpn_service)
	{
		env->DeleteGlobalRef(g_vpn_service);
		g_vpn_service = nullptr;
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
	const auto tunnel = currentTunnel();
	if (!tunnel)
		return -1;

	return static_cast<jint>(tunnel->get_local_endpoint().port());
}

/**
 * Return the coarse link phase (see link_phase) for the status UI.
 */
JNIEXPORT jint JNICALL
Java_com_example_saflep_SafLepVpnService_getLinkPhase(JNIEnv* env, jobject thiz)
{
	const auto tunnel = currentTunnel();
	if (!tunnel || !g_running)
		return LINK_NO_REPLY;

	return linkPhase(*tunnel);
}

/**
 * Return human-readable live transport counters for the activity status panel.
 */
JNIEXPORT jstring JNICALL
Java_com_example_saflep_SafLepVpnService_getNativeStatus(JNIEnv* env, jobject thiz)
{
	const auto tunnel = currentTunnel();
	if (!tunnel || !g_running)
		return env->NewStringUTF("Native tunnel is not running.");

	const char* peer_state = "none yet";
	switch (linkPhase(*tunnel))
	{
		case LINK_NO_REPLY: peer_state = "none yet"; break;
		case LINK_UNREADABLE: peer_state = "undecodable (LEP version / seed key mismatch?)"; break;
		case LINK_VERIFIED: peer_state = "verified"; break;
		case LINK_PEER_SILENT: peer_state = "silent, re-probing"; break;
	}

	const auto endpoint = tunnel->get_local_endpoint();
	const auto& stats = tunnel->get_stats();
	std::ostringstream text;
	text << "Local UDP: " << endpoint.port() << '\n'
		 << "Peer traffic: " << peer_state << '\n'
		 << "UDP bytes: TX " << stats.bytes_sent.load()
		 << " / RX " << stats.bytes_received.load() << '\n'
		 << "IP bytes: TUN->peer " << stats.tap_bytes_in.load()
		 << " / peer->TUN " << stats.tap_bytes_out.load() << '\n'
		 << "Peers (local state): " << tunnel->get_connected_peers().size()
		 << " / " << tunnel->get_peer_count() << '\n'
		 << "Packets dropped before a peer: " << stats.broadcast_drops.load();
	return env->NewStringUTF(text.str().c_str());
}

/**
 * Return the most recent native initialization failure.
 */
JNIEXPORT jstring JNICALL
Java_com_example_saflep_SafLepVpnService_getNativeLastError(JNIEnv* env, jobject thiz)
{
	const auto error = getLastError();
	return env->NewStringUTF(error.c_str());
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

	const auto tunnel = currentTunnel();
	if (!tunnel || !g_running) {
		LOGW("Cannot connect to peer: VPN not running");
		return;
	}

	const char* ip_cstr = env->GetStringUTFChars(peer_ip, nullptr);
	std::string ip_str(ip_cstr);
	env->ReleaseStringUTFChars(peer_ip, ip_cstr);

	LOGI("Connecting to additional peer: %s:%d", ip_str.c_str(), peer_port);
	tunnel->connect_to_peer(ip_str, std::to_string(peer_port));
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

	const auto tunnel = currentTunnel();
	if (!tunnel)
	{
		LOGW("Cannot set key: tunnel not initialized");
		return;
	}

	const char* key_cstr = env->GetStringUTFChars(seed_key, nullptr);
	std::string key_str(key_cstr);
	env->ReleaseStringUTFChars(seed_key, key_cstr);

	tunnel->set_encryption_key(key_str);
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
