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

// struct ether_header
// {
//   uint8_t  ether_dhost[ETH_ALEN];  /* destination eth addr */
//   uint8_t  ether_shost[ETH_ALEN];  /* source ether addr    */
//   uint16_t ether_type;             /* packet type ID field */
// }

// struct iphdr
// {
//     uint32_t ihl;
//     uint32_t version;
//     uint8_t tos;
//     uint16_t tot_len;
//     uint16_t id;
//     uint16_t frag_off;
//     uint8_t ttl;
//     uint8_t protocol;
//     uint16_t check;
//     uint32_t saddr;
//     uint32_t daddr;
// };

// struct udphdr
// {
//     uint16_t source;
//     uint16_t dest;
//     uint16_t len;
//     uint16_t check;
// };

struct psd_header
{
    u_long sourceip; // 源IP地址
    u_long destip; // 目的IP地址
    char mbz; // 置空(0)
    char ptcl; // 协议类型
    u_short plen; // TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节)
};

enum ONLINE_STATE
{
    OFFLINE_PROCESSING,
    OFFLINE_NOTIFY,
    OFFLINE,
    ONLINE_PROCESSING,
    ONLINE,
};

#endif