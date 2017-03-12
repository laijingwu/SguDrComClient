// #include <pcap.h>
// #include <net/ethernet.h>
// #include <netinet/in.h>
#include "def.h"
#include <string.h>
#include <pthread.h>
#include "log.h"
#include "config.h"
#include "get_device_addr.h"
#include "eap_dealer.h"
#include "udp_dealer.h"
using namespace std;

eap_dealer *global_eap_dealer;

bool eap_login()
{
	global_eap_dealer->logoff(broadcast_mac);
	global_eap_dealer->logoff(broadcast_mac);
	if (!global_eap_dealer->start(broadcast_mac)) {
		return false;
	}
	if (global_eap_dealer->response_identity()) {
		return false;
	}
}

void * thread_eap(void *ptr)
{
}

void * thread_udp(void *ptr)
{
}

int main(int argc, char *argv[])
{
	if (argc < 1) {
		cerr << "require a config file path." << endl;
		return 1;
	}

	// get config from config file
    config configSettings(argv[1]);
    string device = configSettings.Read("device", "ens33");
    string username = configSettings.Read("username");
    string password = configSettings.Read("password");
    string authserver_ip = configSettings.Read("authserver_ip", "192.168.127.129");
    uint16_t udp_alive_port = 61440;
    udp_alive_port = configSettings.Read("udp_alive_port", udp_alive_port);


    string local_ip = get_ip_address(device); //"192.168.197.64";
    vector<uint8_t> local_mac = get_mac_address(device); // { 0xd4, 0x3d, 0x7e, 0x54, 0x95, 0x36 };
    vector<uint8_t> broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    vector<uint8_t> hangzhou_mac = { 0x58, 0x6a, 0xb1, 0x56, 0x78, 0x00 };

    // print system info
    cout << "******** Drcom Info ********" << endl;
    cout << "device: " << device << endl;
    cout << "username: " << username << endl;
    cout << "password: " << password << endl;
    cout << "local ip: " << local_ip << endl;
    cout << "local mac: " << local_mac[0] << endl;
    cout << "****************************" << endl;


	global_eap_dealer = new eap_dealer(device, local_mac, local_ip, username, password);
	while (!eap_login()) {
	}

	// create eap thread

 //    pthread_t id;
 //    int ret = pthread_create(&id, NULL, thread, NULL);
	// if (ret) {
	// 	cout << "Create pthread error!" << endl;
	// 	return 1;
	// }
	
	if (global_eap_dealer != NULL)
    	delete global_eap_dealer;

	return 0;
}