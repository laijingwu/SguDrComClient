#ifndef HEADER_LOG_H_
#define HEADER_LOG_H_

#include <stddef.h>
#include <string>
#include <fstream>
#include <exception>
#include <iostream>
#include <stdio.h>
#include <sstream>
using namespace std;

class log_exception : public exception
{
public:
    log_exception(const string& message) : message(message) { }
    log_exception(const string& message, int err) { // system error
        stringstream stream;
        stream << message << ", errno = " << err << ", desc: " << strerror(err);
        this->message = stream.str();
    }
    const char * what() const throw() { return message.c_str(); }
    virtual ~log_exception() throw() { }

private:
    string message;
};

class log
{
public:
    log() : fs() {
        time_t now = time(NULL);
        struct tm* time = localtime(&now);

        char filename[32];
        sprintf(filename, "%4d-%02d-%02d.log", 1900 + time->tm_year, 1 + time->tm_mon, time->tm_mday);

        fs.open(filename, ios::app|ios::out);
        if (fs.bad())
            throw log_exception("Failed to save log.", errno);
    };
    void write(string linelog) { fs << linelog; }
    static void print(string linelog) { cout << linelog; } // cout << linelog << endl;
    ~log() { fs.close(); };
    
private:
    ofstream fs;
};

static inline string log_now()
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
    
    string str(buf);
    return str;
}

static void print_log(string content)
{
    log *drcom_log;
    try
    {
        drcom_log = new log();
        drcom_log->write(content);
    }
    catch(log_exception &e)
    {
        std::stringstream error_ss;
        error_ss << log_now() << " [Log Error] " << e.what() << endl;
        log::print(error_ss.str());
    }
    log::print(content);
    if (drcom_log != NULL) delete drcom_log;
}

#define LOG {                                                        \
    std::stringstream for_log_use_stream;                            \
    for_log_use_stream

#define PRINT_INFO print_log(for_log_use_stream.str());
#define PRINT_ERR print_log(for_log_use_stream.str());
#define PRINT_DBG print_log(for_log_use_stream.str());

#define LOG_INFO(section, info)                                      \
    LOG << log_now() << " [" << section << " Info] " << info; PRINT_INFO }
#define LOG_ERR(section, err)                                        \
    LOG << log_now() << " [" << section << " Error] " << err; PRINT_ERR }
#ifdef SGUDRCOM_DEBUG
    #define LOG_DBG(section, db)                                     \
        LOG << log_now() << " [" << section << " Debug] " << db; PRINT_DBG }
#else
    #define LOG_DBG(section, db)
#endif

#define U40_3_LOG_INFO(info)  LOG_INFO("U40_3", info)
#define U40_3_LOG_ERR(err)    LOG_ERR("U40_3", err)
#define U40_3_LOG_DBG(db)     LOG_DBG("U40_3", db)

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