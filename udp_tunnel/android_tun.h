#pragma once

#if defined(__ANDROID__)

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>

namespace dixelu {
namespace udp {

/**
 * Android TUN Adapter
 *
 * Unlike Linux TunAdapter, this class does NOT open /dev/net/tun.
 * Instead, it accepts a pre-opened file descriptor from Android's VpnService.
 * The FD is created by VpnService.Builder.establish() in Java/Kotlin.
 */
class AndroidTunAdapter {
public:
	AndroidTunAdapter();
	~AndroidTunAdapter();

	/**
	 * Initialize with a file descriptor from Android VpnService.
	 * @param fd The TUN file descriptor from ParcelFileDescriptor.getFd()
	 * @return true if successful
	 */
	bool set_fd(int fd);

	/**
	 * Open is a no-op for Android - the FD is already open from Java.
	 * This exists only for interface compatibility.
	 */
	bool open(const std::string& dev_name = "");

	/**
	 * Configure is a no-op for Android - configuration is done in VpnService.Builder.
	 * This exists only for interface compatibility.
	 */
	bool configure(const std::string& ip_address, const std::string& netmask, const std::string& gateway = "");

	/**
	 * Read a packet from the TUN device.
	 * Uses standard POSIX read() on the file descriptor.
	 * @return Raw IP packet (no Ethernet header, Layer 3)
	 */
	std::vector<uint8_t> read();

	/**
	 * Write a packet to the TUN device.
	 * Uses standard POSIX write() on the file descriptor.
	 * @param data Raw IP packet to write
	 * @return true if successful
	 */
	bool write(const std::vector<uint8_t>& data);

	/**
	 * Get the adapter name (returns "android-vpn" for identification).
	 */
	std::string get_adapter_name() const;

	/**
	 * Check if the adapter has a valid file descriptor.
	 */
	bool is_valid() const;

	/**
	 * Set status is a no-op for Android - managed by VpnService.
	 */
	bool set_status(bool connected);

	/**
	 * Close the file descriptor.
	 * Note: Normally, the Java layer should close the ParcelFileDescriptor.
	 * Only call this if explicitly taking ownership.
	 */
	void close_fd();

	/**
	 * Get the raw file descriptor (for socket protection via JNI callback).
	 */
	int get_fd() const { return fd_; }

private:
	int fd_;
	std::atomic<bool> owns_fd_;  // Whether we should close the FD on destruction
};

// Type alias for compatibility with existing code
using TunAdapter = AndroidTunAdapter;

} // namespace udp
} // namespace dixelu

#endif // __ANDROID__
