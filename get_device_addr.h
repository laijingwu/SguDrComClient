#ifndef GET_DEVICE_ADDR_H_
#define GET_DEVICE_ADDR_H_

#include <stdint.h>
#include <vector>
#include <string.h>
using namespace std;

std::vector<uint8_t> get_mac_address(std::string device);

std::string get_ip_address(std::string device);

#endif