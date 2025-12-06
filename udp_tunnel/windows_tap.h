#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

#ifdef _WIN32

namespace dixelu {
namespace udp {

class TapAdapter {
public:
	TapAdapter();
	~TapAdapter();

	// Open the first available TAP-Windows adapter
	bool open(const std::string& device_guid = "");

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

#ifdef _WIN32

	// Get MAC address
	std::vector<uint8_t> get_mac() const;

#endif // _WIN32

	// Set status to connected
	bool set_status(bool connected);

private:
	void* handle_;
	std::string adapter_name_;
	std::string adapter_guid_;

	std::string get_device_guid(const std::string& adapter_name);
	std::vector<std::pair<std::string, std::string>> get_all_tap_adapters();
};

} // namespace udp
} // namespace dixelu

#endif // _WIN32
