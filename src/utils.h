#ifndef HEADER_UTILS_H_
#define HEADER_UTILS_H_

#include <iostream>
#include <stdint.h>
#include <vector>
#include <string.h>
#include <stdlib.h>
#include <time.h>
using namespace std;

// We don't know why some version of OpenWrt defines LITTLE ENDIAN but actually use BIG ENDIAN.
#ifdef OPENWRT
    #define UINT16_LITTLE_ENDIAN(n) (((((unsigned int)(n) & 0x00FF)) << 8) |   \
                                    ((((unsigned int)(n) & 0xFF00)) >> 8))
    #define UINT32_LITTLE_ENDIAN(n) (((((unsigned long)(n) & 0xFF)) << 24) |   \
                                    ((((unsigned long)(n) & 0xFF00)) << 8) |   \
                                    ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                                    ((((unsigned long)(n) & 0xFF000000)) >> 24))
#endif

vector<uint8_t> get_md5_digest(vector<uint8_t>& data);
string hex_to_str(uint8_t *hex, size_t len, char separator);
void hex_dump(vector<uint8_t> hex);
vector<string> split_string(string src, char delimiter = ' ', bool append_last = true);
vector<uint8_t> str_ip_to_vec(string ip);
vector<uint8_t> str_mac_to_vec(string mac);
vector<uint8_t> str_to_vec(string str);
uint32_t xsrand();

#endif