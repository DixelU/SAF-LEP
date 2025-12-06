#include "windows_tap.h"

#define WIN32_LEAN_AND_MEAN 

#include <iostream>
#include <array>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <winioctl.h>

#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32")

// TAP-Windows IOCTLs
#define TAP_WIN_IOCTL(x) CTL_CODE(FILE_DEVICE_UNKNOWN, x, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define TAP_WIN_IOCTL_GET_MAC				TAP_WIN_IOCTL(1)
#define TAP_WIN_IOCTL_GET_VERSION			TAP_WIN_IOCTL(2)
#define TAP_WIN_IOCTL_GET_MTU				TAP_WIN_IOCTL(3)
#define TAP_WIN_IOCTL_GET_INFO				TAP_WIN_IOCTL(4)
#define TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT		TAP_WIN_IOCTL(5)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS			TAP_WIN_IOCTL(6)
#define TAP_WIN_IOCTL_CONFIG_DHCP_MASQ			TAP_WIN_IOCTL(7)
#define TAP_WIN_IOCTL_GET_LOG_LINE			TAP_WIN_IOCTL(8)
#define TAP_WIN_IOCTL_CONFIG_DHCP_SET_OPT		TAP_WIN_IOCTL(9)
#define TAP_WIN_IOCTL_CONFIG_TUN			TAP_WIN_IOCTL(10)

#ifdef _WIN32

namespace dixelu
{
namespace udp
{

TapAdapter::TapAdapter() :
	handle_(INVALID_HANDLE_VALUE)
{}

TapAdapter::~TapAdapter()
{
	if (handle_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(handle_);
	}
}

std::vector<std::pair<std::string, std::string>> TapAdapter::get_all_tap_adapters()
{
	std::vector<std::pair<std::string, std::string>> adapters;

	HKEY adapters_key;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}", 0, KEY_READ, &adapters_key) != ERROR_SUCCESS)
	{
		return adapters;
	}

	DWORD subkey_count = 0;
	RegQueryInfoKey(adapters_key, NULL, NULL, NULL, &subkey_count, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	for (DWORD i = 0; i < subkey_count; i++)
	{
		char subkey_name[256];
		DWORD subkey_len = sizeof(subkey_name);
		if (RegEnumKeyExA(adapters_key, i, subkey_name, &subkey_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
			continue;

		HKEY adapter_key;
		if (RegOpenKeyExA(adapters_key, subkey_name, 0, KEY_READ, &adapter_key) != ERROR_SUCCESS)
			continue;

		char component_id[256] = { 0 };
		DWORD type, len = sizeof(component_id);
		if (RegQueryValueExA(adapter_key, "ComponentId", NULL, &type, (LPBYTE)component_id, &len) == ERROR_SUCCESS)
		{
			if (std::string(component_id) == "tap0901")
			{
				char net_cfg_instance_id[256] = { 0 };
				len = sizeof(net_cfg_instance_id);
				if (RegQueryValueExA(adapter_key, "NetCfgInstanceId", NULL, &type, (LPBYTE)net_cfg_instance_id, &len) == ERROR_SUCCESS)
				{
					// Now get the human readable name
					std::string guid = net_cfg_instance_id;
					std::string connection_key_path = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + guid + "\\Connection";

					HKEY connection_key;
					if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, connection_key_path.c_str(), 0, KEY_READ, &connection_key) == ERROR_SUCCESS)
					{
						char name[256] = { 0 };
						len = sizeof(name);
						if (RegQueryValueExA(connection_key, "Name", NULL, &type, (LPBYTE)name, &len) == ERROR_SUCCESS)
						{
							adapters.push_back({ std::string(name), guid });
						}

						RegCloseKey(connection_key);
					}
				}
			}
		}

		RegCloseKey(adapter_key);
	}

	RegCloseKey(adapters_key);
	return adapters;
}

bool TapAdapter::open(const std::string& device_guid_in)
{
	std::string device_guid = device_guid_in;

	if (device_guid.empty())
	{
		auto adapters = get_all_tap_adapters();
		if (adapters.empty())
		{
			std::cerr << "No TAP-Windows adapters found." << std::endl;
			return false;
		}

		// Just pick the first one for now
		adapter_name_ = adapters[0].first;
		device_guid = adapters[0].second;
		std::cout << "Found TAP adapter: " << adapter_name_ << " (" << device_guid << ")" << std::endl;
	}

	adapter_guid_ = device_guid;
	std::string device_path = "\\\\.\\Global\\" + device_guid + ".tap";

	handle_ = CreateFileA(device_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);

	if (handle_ == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to open TAP device: " << GetLastError() << std::endl;
		return false;
	}

	return true;
}

bool TapAdapter::configure(const std::string& ip_address, const std::string& netmask, const std::string& gateway)
{
	// We will use netsh for simplicity to configure the IP
	// Command: netsh interface ip set address "Adapter Name" static IP Mask Gateway

	std::string cmd = "netsh interface ip set address \"" + adapter_name_ + "\" static " + ip_address + " " + netmask;
	// Note: We don't add gateway here to avoid default route metric issues initially
	// We will add routes manually later

	std::cout << "Configuring IP: " << cmd << std::endl;
	if (system(cmd.c_str()) != 0) return false;

	// Set MTU to 1500 to match our fragmentation logic
	std::string mtu_cmd = "netsh interface ipv4 set subinterface \"" + adapter_name_ + "\" mtu=1500 store=persistent";
	std::cout << "Configuring MTU: " << mtu_cmd << std::endl;
	system(mtu_cmd.c_str());

	if (!gateway.empty())
	{
		std::cout << "Configuring Gateway: " << gateway << std::endl;
		
		// Clear potential old routes first to avoid "Object already exists" errors
		std::string del_cmd1 = "route delete 0.0.0.0 mask 128.0.0.0";
		std::string del_cmd2 = "route delete 128.0.0.0 mask 128.0.0.0";
		system(del_cmd1.c_str());
		system(del_cmd2.c_str());

		// Add routes for 0.0.0.0/1 and 128.0.0.0/1 to override default route
		// route add 0.0.0.0 mask 128.0.0.0 <GATEWAY> metric 1
		// route add 128.0.0.0 mask 128.0.0.0 <GATEWAY> metric 1

		std::string route_cmd1 = "route add 0.0.0.0 mask 128.0.0.0 " + gateway + " metric 1";
		std::string route_cmd2 = "route add 128.0.0.0 mask 128.0.0.0 " + gateway + " metric 1";

		std::cout << "Adding routes: " << std::endl;
		std::cout << "  " << route_cmd1 << std::endl;
		system(route_cmd1.c_str());
		std::cout << "  " << route_cmd2 << std::endl;
		system(route_cmd2.c_str());
	}

	return true;
}

bool TapAdapter::set_status(bool connected)
{
	if (handle_ == INVALID_HANDLE_VALUE) return false;

	uint32_t status = connected ? 1 : 0;
	DWORD len;
	return DeviceIoControl(handle_, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL);
}

std::vector<uint8_t> TapAdapter::read()
{
	if (handle_ == INVALID_HANDLE_VALUE)
		return {};

	std::vector<uint8_t> buffer(2048);
	DWORD bytes_read;
	OVERLAPPED overlapped = { 0 };
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (!ReadFile(handle_, buffer.data(), buffer.size(), &bytes_read, &overlapped))
	{
		if (GetLastError() == ERROR_IO_PENDING)
		{
			WaitForSingleObject(overlapped.hEvent, INFINITE);
			GetOverlappedResult(handle_, &overlapped, &bytes_read, FALSE);
		}
		else
		{
			CloseHandle(overlapped.hEvent);
			return {};
		}
	}

	CloseHandle(overlapped.hEvent);
	buffer.resize(bytes_read);
	return buffer;
}

bool TapAdapter::write(const std::vector<uint8_t>& data)
{
	if (handle_ == INVALID_HANDLE_VALUE) return false;

	DWORD bytes_written;
	OVERLAPPED overlapped = { 0 };
	overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (!WriteFile(handle_, data.data(), data.size(), &bytes_written, &overlapped))
	{
		if (GetLastError() == ERROR_IO_PENDING)
		{
			WaitForSingleObject(overlapped.hEvent, INFINITE);
			GetOverlappedResult(handle_, &overlapped, &bytes_written, FALSE);
		}
		else
		{
			CloseHandle(overlapped.hEvent);
			return false;
		}
	}

	CloseHandle(overlapped.hEvent);
	return bytes_written == data.size();
}

std::string TapAdapter::get_adapter_name() const
{
	return adapter_name_;
}

bool TapAdapter::is_valid() const
{
	return handle_ != INVALID_HANDLE_VALUE;
}

} // namespace udp
} // namespace dixelu

#endif // _WIN32
