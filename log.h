#ifndef HEADER_LOG_H_
#define HEADER_LOG_H_

#include <stddef.h>
#include <iostream>
#include <string.h>
#include <sstream>
#include <stdio.h>

#define SGUDRCOM_DEBUG
// #define SGUDRCOM_PRINT_DBG_ON_SCREEN

static inline std::string log_now()
{
    time_t now = time(NULL);

    struct tm* time = localtime(&now);
    
    char buf[128];
    sprintf(buf, "%4d-%02d-%02d %02d:%02d:%02d",
    	1900 + time->tm_year,
		1 + time->tm_mon,
		time->tm_mday,
		time->tm_hour,
		time->tm_min,
		time->tm_sec);
    
    std::string str(buf);
    return str;
}

#define LOG {                                                        \
    std::stringstream for_log_use_stream;                            \
    for_log_use_stream

#define PRINT_INFO                                                   \
    std::cout << log_now() << " " << for_log_use_stream.str();
#define PRINT_ERR                                                    \
    std::cout << log_now() << " " << for_log_use_stream.str();
#define PRINT_DBG                                                	 \
    std::cout << log_now() << " " << for_log_use_stream.str();

#define LOG_INFO(section, info)                                      \
    LOG << "[" << section << " Info] " << info; PRINT_INFO }
#define LOG_ERR(section, err)                                        \
    LOG << "[" << section << " Error] " << err; PRINT_ERR }
#ifdef SGUDRCOM_DEBUG
    #define LOG_DBG(section, db)                                     \
        LOG << "[" << section << " Debug] " << db; PRINT_DBG }
#else
    #define LOG_DBG(section, db)
#endif

#define U38_LOG_INFO(info)    LOG_INFO("U38", info)
#define U38_LOG_ERR(err)      LOG_ERR("U38", err)
#define U38_LOG_DBG(db)       LOG_DBG("U38", db)

#define U40_2_LOG_INFO(info)  LOG_INFO("U40_2", info)
#define U40_2_LOG_ERR(err)    LOG_ERR("U40_2", err)
#define U40_2_LOG_DBG(db)     LOG_DBG("U40_2", db)

#define U40_1_LOG_INFO(info)  LOG_INFO("U40_1", info)
#define U40_1_LOG_ERR(err)    LOG_ERR("U40_1", err)
#define U40_1_LOG_DBG(db)     LOG_DBG("U40_1", db)

#define U244_LOG_INFO(info)   LOG_INFO("U244", info)
#define U244_LOG_ERR(err)     LOG_ERR("U244", err)
#define U244_LOG_DBG(db)      LOG_DBG("U244", db)

#define U8_LOG_INFO(info)     LOG_INFO("U8", info)
#define U8_LOG_ERR(err)       LOG_ERR("U8", err)
#define U8_LOG_DBG(db)        LOG_DBG("U8", db)

#define SOCKET_LOG_INFO(info)    LOG_INFO("SOCKET", info)
#define SOCKET_LOG_ERR(err)      LOG_ERR("SOCKET", err)
#define SOCKET_LOG_DBG(db)       LOG_DBG("SOCKET", db)

#define EAP_LOG_INFO(info)    LOG_INFO("EAP", info)
#define EAP_LOG_ERR(err)      LOG_ERR("EAP", err)
#define EAP_LOG_DBG(db)       LOG_DBG("EAP", db)

#define SYS_LOG_INFO(info)    LOG_INFO("SguDrCom", info)
#define SYS_LOG_ERR(err)      LOG_ERR("SguDrCom", err)
#define SYS_LOG_DBG(db)       LOG_DBG("SguDrCom", db)

#endif