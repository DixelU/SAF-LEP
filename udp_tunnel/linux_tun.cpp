#include "linux_tun.h"

#ifndef _WIN32

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

namespace dixelu {
namespace udp {

TunAdapter::TunAdapter() : fd_(-1) {}

TunAdapter::~TunAdapter() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

bool TunAdapter::open(const std::string& dev_name) {
    struct ifreq ifr;
    int fd, err;

    if ((fd = ::open("/dev/net/tun", O_RDWR)) < 0) {
        std::cerr << "Failed to open /dev/net/tun: " << strerror(errno) << std::endl;
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // IFF_TUN = TUN device (no Ethernet headers), IFF_NO_PI = No packet info
    
    if (!dev_name.empty()) {
        strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        std::cerr << "ioctl(TUNSETIFF) failed: " << strerror(errno) << std::endl;
        close(fd);
        return false;
    }

    fd_ = fd;
    dev_name_ = ifr.ifr_name;
    std::cout << "Opened TUN device: " << dev_name_ << std::endl;
    return true;
}

bool TunAdapter::configure(const std::string& ip_address, const std::string& netmask, const std::string& gateway) {
    // Using 'ip' command is easier than netlink for now
    // ip addr add 10.0.0.1/24 dev tun0
    
    // Convert netmask to CIDR prefix length (simple approximation)
    int prefix_len = 0;
    struct in_addr mask_addr;
    if (inet_pton(AF_INET, netmask.c_str(), &mask_addr) == 1) {
        uint32_t mask = ntohl(mask_addr.s_addr);
        while (mask & 0x80000000) {
            prefix_len++;
            mask <<= 1;
        }
    } else {
        prefix_len = 24; // Default
    }

    std::string cmd = "ip addr add " + ip_address + "/" + std::to_string(prefix_len) + " dev " + dev_name_;
    std::cout << "Configuring IP: " << cmd << std::endl;
    if (system(cmd.c_str()) != 0) return false;

    // Bring interface UP before adding routes
    if (!set_status(true)) return false;

    if (!gateway.empty())
    {
        std::cout << "Configuring Gateway: " << gateway << std::endl;
        // Add routes for 0.0.0.0/1 and 128.0.0.0/1 to override default route
        // without deleting the original one (which preserves the connection to the VPN server)
        std::string route_cmd1 = "ip route add 0.0.0.0/1 via " + gateway;
        std::string route_cmd2 = "ip route add 128.0.0.0/1 via " + gateway;
        
        system(route_cmd1.c_str());
        system(route_cmd2.c_str());
    }

    return true;
}

bool TunAdapter::set_status(bool connected) {
    std::string cmd = "ip link set " + dev_name_ + (connected ? " up" : " down");
    return system(cmd.c_str()) == 0;
}

std::vector<uint8_t> TunAdapter::read() {
    if (fd_ < 0) return {};

    std::vector<uint8_t> buffer(2048);
    ssize_t nread = ::read(fd_, buffer.data(), buffer.size());
    
    if (nread < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "Read from TUN failed: " << strerror(errno) << std::endl;
        }
        return {};
    }

    buffer.resize(nread);
    return buffer;
}

bool TunAdapter::write(const std::vector<uint8_t>& data) {
    if (fd_ < 0) return false;

    ssize_t nwritten = ::write(fd_, data.data(), data.size());
    if (nwritten < 0) {
        std::cerr << "Write to TUN failed: " << strerror(errno) 
                  << " (size=" << data.size() << ", first_byte=0x" 
                  << std::hex << (int)data[0] << std::dec << ")" << std::endl;
        return false;
    }

    return nwritten == static_cast<ssize_t>(data.size());
}

std::string TunAdapter::get_adapter_name() const {
    return dev_name_;
}

bool TunAdapter::is_valid() const {
    return fd_ >= 0;
}

} // namespace udp
} // namespace dixelu

#endif // !_WIN32
