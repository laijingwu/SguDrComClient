#include "def.h"
#include "get_device_addr.h"
#include "sgudrcom_exception.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>

std::vector<uint8_t> get_mac_address(std::string device)
{
    int sock;
    struct ifreq dev;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        throw sgudrcom_exception("get_mac_address: socket failed");
    }
    
    strncpy(dev.ifr_name, device.c_str(), sizeof(dev.ifr_name));
    dev.ifr_name[sizeof(dev.ifr_name)-1] = '\0';
    
    if (ioctl(sock, SIOCGIFHWADDR, &dev) < 0) {
        throw sgudrcom_exception("get_mac_address: ioctl failed");
    }
    
    std::vector<uint8_t> ret(6, 0);
    memcpy(&ret[0], dev.ifr_hwaddr.sa_data, 6);
    return ret;
}

std::string get_ip_address(std::string device)
{
    struct ifaddrs *ifaddr = NULL;
    std::string ip;
    
    if (getifaddrs(&ifaddr) < 0) {
        throw sgudrcom_exception("get_ip_address: getifaddrs failed");
    }
    bool found = false;
    struct ifaddrs * ifa;
    for( ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (!strcmp(ifa->ifa_name, device.c_str()))
            if (ifa->ifa_addr->sa_family == AF_INET) // only deal with IPv4
            {
                ip = inet_ntoa(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr);
                found = true; break;
            }
    }
    
    if (!found) {
        throw sgudrcom_exception("get_ip_address: NIC '" + device + "' not found.");
    }
    return ip;
}
