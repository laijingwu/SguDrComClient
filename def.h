#ifndef HEADER_DEF_H_
#define HEADER_DEF_H_

#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>
#include <string.h>

struct drcom_config
{
    std::string device;
    std::string username;
    std::string password;
    std::string authserver_ip;
    uint16_t udp_alive_port;
};

struct eap_header
{
    uint8_t eapol_version;
    uint8_t eapol_type; // 0x01 - Start, 0x02 - Logoff, 0x00 - EAP Packet
    uint16_t eapol_length; // equal to eap_length
    uint8_t eap_code;
    uint8_t eap_id;
    uint16_t eap_length;
    uint8_t eap_type;
    uint8_t eap_md5_value_size;
    uint8_t eap_md5_value[16];
};

enum ONLINE_STATE
{
    OFFLINE_PROCESSING,
    OFFLINE,
    ONLINE_PROCESSING,
    ONLINE
};

#endif