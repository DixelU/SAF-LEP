#pragma once

#ifndef _WIN32

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace dixelu {
namespace udp {

class TunAdapter {
public:
	TunAdapter();
	~TunAdapter();

	// Open the TUN device
	bool open(const std::string& dev_name = "tun0");

	// Configure IP address and subnet mask
	bool configure(const std::string& ip_address, const std::string& netmask, const std::string& gateway = "");

	// Read a packet from the adapter
	std::vector<uint8_t> read();

	// Write a packet to the adapter
	bool write(const std::vector<uint8_t>& data);

	// Get the name of the opened adapter
	std::string get_adapter_name() const;

	// Check if adapter is valid
	bool is_valid() const;

	// Set status to connected (up)
	bool set_status(bool connected);

private:
	int fd_;
	std::string dev_name_;
};

} // namespace udp
} // namespace dixelu

#endif // !_WIN32
