#include "android_tun.h"

#if defined(__ANDROID__)

#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <cstring>

#include <android/log.h>

#include "global_flags.h"

#define LOG_TAG "SAF-LEP-TUN"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGV(...) if (VERBOSE_MODE) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)

namespace dixelu
{
namespace udp
{

AndroidTunAdapter::AndroidTunAdapter()
	: fd_(-1)
{
}

AndroidTunAdapter::~AndroidTunAdapter()
{
	close_fd();
}

bool AndroidTunAdapter::set_fd(int fd)
{
	if (fd < 0)
	{
		LOGE("Invalid file descriptor: %d", fd);
		return false;
	}

	const int duplicate = ::dup(fd);
	if (duplicate < 0)
	{
		LOGE("Failed to duplicate TUN file descriptor: %s (errno=%d)", strerror(errno), errno);
		return false;
	}

	const int previous = fd_.exchange(duplicate);
	if (previous >= 0)
		::close(previous);

	LOGI("TUN file descriptor duplicated: java=%d native=%d", fd, duplicate);
	return true;
}

bool AndroidTunAdapter::open(const std::string& dev_name)
{
	// No-op for Android - FD is provided by VpnService
	// This method exists for interface compatibility
	if (fd_.load() < 0)
	{
		LOGE("open() called but no FD set. Call set_fd() first.");
		return false;
	}
	LOGV("open() called (no-op on Android, FD already set)");
	return true;
}

bool AndroidTunAdapter::configure(const std::string& ip_address, const std::string& netmask, const std::string& gateway)
{
	// No-op for Android - configuration is done in VpnService.Builder
	// The Java layer handles:
	// - builder.addAddress(ip, prefix)
	// - builder.addRoute(...)
	// - builder.setMtu(...)
	LOGV("configure() called (no-op on Android, configured via VpnService.Builder)");
	return true;
}

std::vector<uint8_t> AndroidTunAdapter::read()
{
	const int fd = fd_.load();
	if (fd < 0)
	{
		return {};
	}

	pollfd descriptor{fd, POLLIN, 0};
	int poll_result;
	do
	{
		poll_result = ::poll(&descriptor, 1, 250);
	}
	while (poll_result < 0 && errno == EINTR);

	if (poll_result <= 0 || (descriptor.revents & POLLIN) == 0)
		return {};

	// MTU is typically 1500, but allocate extra for safety
	std::vector<uint8_t> buffer(2048);

	ssize_t nread = ::read(fd, buffer.data(), buffer.size());

	if (nread < 0)
	{
		if (errno != EAGAIN && errno != EWOULDBLOCK)
		{
			LOGE("Read from TUN failed: %s (errno=%d)", strerror(errno), errno);
		}
		return {};
	}

	if (nread == 0)
	{
		// EOF - VPN was stopped
		LOGI("TUN read returned 0 (EOF)");
		return {};
	}

	buffer.resize(nread);

	LOGV("Read %zd bytes from TUN", nread);

	return buffer;
}

bool AndroidTunAdapter::write(const std::vector<uint8_t>& data)
{
	const int fd = fd_.load();
	if (fd < 0)
	{
		LOGE("write() called but FD is invalid");
		return false;
	}

	if (data.empty())
	{
		return true;  // Nothing to write
	}

	ssize_t nwritten = ::write(fd, data.data(), data.size());

	if (nwritten < 0)
	{
		LOGE("Write to TUN failed: %s (errno=%d, size=%zu, first_byte=0x%02x)",
			strerror(errno), errno, data.size(), data[0]);
		return false;
	}

	if (static_cast<size_t>(nwritten) != data.size())
	{
		LOGE("Partial write to TUN: wrote %zd of %zu bytes", nwritten, data.size());
		return false;
	}

	LOGV("Wrote %zd bytes to TUN", nwritten);

	return true;
}

std::string AndroidTunAdapter::get_adapter_name() const
{
	return "android-vpn";
}

bool AndroidTunAdapter::is_valid() const
{
	return fd_.load() >= 0;
}

bool AndroidTunAdapter::set_status(bool connected)
{
	// No-op for Android - status is managed by VpnService lifecycle
	LOGV("set_status(%s) called (no-op on Android)", connected ? "true" : "false");
	return true;
}

void AndroidTunAdapter::close_fd()
{
	const int fd = fd_.exchange(-1);
	if (fd >= 0)
	{
		::close(fd);
		LOGI("TUN file descriptor closed");
	}
}

} // namespace udp
} // namespace dixelu

#endif // __ANDROID__
