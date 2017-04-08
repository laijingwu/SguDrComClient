#ifndef HEADER_DEF_H_
#define HEADER_DEF_H_

#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <vector>
#include <string.h>

// #define SGUDRCOM_DEBUG
// #define OPENWRT
const int SOCKET_TIMEOUT_MILISEC = 5000;
const int MAX_RETRY_TIME = 2;
const int RETRY_SLEEP_TIME = 2;

struct drcom_config
{
    std::string device;
    std::string username;
    std::string password;
    std::string authserver_ip;
    uint16_t udp_alive_port;
};

enum ONLINE_STATE
{
    OFFLINE_PROCESSING,
    OFFLINE,
    ONLINE_PROCESSING,
    ONLINE
};

#endif