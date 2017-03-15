#include "config.h"

int main()
{
    int port;
    const char ConfigFile[]= "test.conf";
    config configSettings(ConfigFile);
      
    port = configSettings.Read("port1", 61440);
    std::string ipAddress = configSettings.Read("ipAddress", ipAddress);
    std::string username = configSettings.Read("username", username);
    std::string password = configSettings.Read("password", password);
    std::cout << "port1:" << port << std::endl;
    std::cout << "ipAddress:" << ipAddress << std::endl;
    std::cout << "username:" << username << std::endl;
    std::cout << "password:" << password << std::endl;

    return 0;
}