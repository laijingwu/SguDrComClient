#include "utils.h"
#include "get_device_addr.h"
#include "md5.h"
#include "log.h"
#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>

// We don't know why some version of OpenWrt defines LITTLE ENDIAN but actually use BIG ENDIAN.
// #ifdef OPENWRT
//     #define TO_LITTLE_ENDIAN(n) (((((unsigned long)(n) & 0xFF)) << 24) |        \
//                                 ((((unsigned long)(n) & 0xFF00)) << 8) |        \
//                                 ((((unsigned long)(n) & 0xFF0000)) >> 8) |      \
//                                 ((((unsigned long)(n) & 0xFF000000)) >> 24))
// #endif

vector<uint8_t> get_md5_digest(vector<uint8_t>& data) {
    md5_byte_t digest[16];
    md5_state_t state;
    
    md5_init(&state);
    md5_append(&state, &data[0], (int) data.size());
    md5_finish(&state, digest);
    
    return vector<uint8_t>(digest, digest + 16);
}

string hex_to_str(uint8_t *hex, size_t len, char separator) {
    char buf[1024] = {0};
    for (size_t i = 0; i < len; i++)
        sprintf(buf + strlen(buf), "%02x%c", hex[i], (i < len - 1) ? separator : 0);
    
    return string(buf);
}

void hex_dump(vector<uint8_t> hex) {
    char buf[1024];
    
    for (size_t i = 0; i < hex.size(); i += 16)
    {
        sprintf(buf, "%08x: ", (int)i);
        for (int j = 0; j < 16; j++)
        {
            if (i + j < hex.size())
                sprintf(buf + strlen(buf), "%02x ", hex[i+j]);
            else
                strcat(buf, "   ");
            
            if (j == 7) strcat(buf, " ");
        }
        
        strcat(buf, " ");
        for (int j = 0; j < 16; j++)
            if (i + j < hex.size())
                sprintf(buf + strlen(buf), "%c", isprint(hex[i+j]) ? hex[i+j] : '.');
        
        cout << buf << endl;
    }
}

vector<string> split_string(string src, char delimiter, bool append_last) {
    string::size_type pos = 0;
    vector<string> ret;
    
    while ((pos = src.find(delimiter)) != string::npos)
    {
        ret.push_back(src.substr(0, pos));
        src = src.substr(pos + 1);
    }
    
    // the last element
    if (append_last) ret.push_back(src);
    
    return ret;
}

vector<uint8_t> str_ip_to_vec(string ip) {
    vector<uint8_t> ret(4, 0);
    
    auto vec_addr = split_string(ip, '.');
    if (vec_addr.size() < 4)
        return ret;
    
    unsigned long addr = (atol(vec_addr[0].c_str()) << 24) + (atol(vec_addr[1].c_str()) << 16) + (atol(vec_addr[2].c_str()) << 8) + atol(vec_addr[3].c_str());
    addr = ntohl(addr);
    
    memcpy(&ret[0], &addr, 4);
    
    return ret;
}

vector<uint8_t> str_mac_to_vec(string mac) {
    vector<uint8_t> ret;
    
    auto chartohex = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9')
            return c - '0';
        
        if (c >= 'a' && c <= 'f')
            return (c - 'a') + 0x0a;
        
        if (c >= 'A' && c <= 'F')
            return (c - 'A') + 0x0a;
        
        return 0xFF;
    };
    
    for (int i = 0; i <= 15; i += 3)
    {
        uint8_t b = (chartohex(mac[i]) << 4) + chartohex(mac[i+1]);
        ret.push_back(b);
    }
    
    return ret;
}

vector<uint8_t> str_to_vec(string str) {
    vector<uint8_t> ret(str.length(), 0);
    memcpy(&ret[0], &str[0], str.length());
    return ret;
}

uint32_t xsrand() {
    srand(time(NULL));
    return (
     (((uint32_t)rand()<<4)&0xFFFF0000u)
    | ((uint32_t)rand()&0x0000FFFFu));
}