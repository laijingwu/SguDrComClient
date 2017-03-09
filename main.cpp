// #include <pcap.h>
// #include <net/ethernet.h>
// #include <netinet/in.h>
#include "def.h"
#include <string.h>
#include "log.h"
#include "config.h"
#include "get_device_addr.h"
#include "eap_dealer.h"
#include "udp_dealer.h"
using namespace std;

int main(int argc, char *argv[])
{
	if (argc < 1) {
		cerr << "require a config file path." << endl;
		return 1;
	}

    config configSettings(argv[1]);
    string device = configSettings.Read("device", "ens33");
    string username = configSettings.Read("username");
    string password = configSettings.Read("password");
    string authserver_ip = configSettings.Read("authserver_ip", "192.168.127.129");
    uint16_t udp_alive_port = 61440;
    udp_alive_port = configSettings.Read("udp_alive_port", udp_alive_port);


    string local_ip = "192.168.197.64";
    vector<uint8_t> local_mac= { 0xd4, 0x3d, 0x7e, 0x54, 0x95, 0x36 };
    vector<uint8_t> broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    vector<uint8_t> fujianst_mac = { 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 };
    vector<uint8_t> hangzhou_mac = { 0x58, 0x6a, 0xb1, 0x56, 0x78, 0x00 };

    cout << "******** Drcom Info ********" << endl;
    cout << "device: " << device << endl;
    cout << "username: " << username << endl;
    cout << "password: " << password << endl;
    cout << "local ip: " << local_ip << endl;
    cout << "local mac: " << local_mac[0] << endl;
    cout << "****************************" << endl;

    
	return 0;
}