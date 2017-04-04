#ifndef GET_DEVICE_ADDR_H_
#define GET_DEVICE_ADDR_H_

#include <stdint.h>
#include <vector>
#include <string.h>
using namespace std;

vector<uint8_t> get_mac_address(string device);

string get_ip_address(string device);

#endif