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

bool eap_login(drcom_config *conf);
void * thread_eap(void *ptr);
void * thread_udp(void *ptr);

eap_dealer *global_eap_dealer;
udp_dealer *global_udp_dealer;
pthread_t t_udp_id, t_eap_id;
ONLINE_STATE drcom_status = OFFLINE;

bool eap_login(drcom_config *conf)
{
	global_eap_dealer->logoff();
	global_eap_dealer->logoff();
	sleep(5); // for completing log off.
	if (!global_eap_dealer->start())
		return false;

	if (!global_eap_dealer->response_identity())
		return false;

	if (!global_eap_dealer->response_md5_challenge())
		return false;

    // success
    drcom_status = ONLINE;
    // create udp thread
    int ret = pthread_create(&t_udp_id, NULL, thread_udp, (void *)conf);
    if (ret) {
        cout << "Create udp thread error!" << endl;
    }
	return true;
}

void * thread_eap(void *ptr)
{
    drcom_config *conf = (drcom_config *)ptr;
    while (drcom_status == ONLINE)
    {
        switch(global_eap_dealer->recv_gateway_returns())
        {
            case -2:           // catch the wrong packet, continue capturing packets.
            case -1: continue; // receive packet timeout, continue capturing packets.
            case 1: {
                drcom_status = OFFLINE; // receive the failure packet, try to reconnect
                while (!eap_login(conf)) {
                }
                break;
            }
            case 0: global_eap_dealer->alive_identity(); //request identity and send alive
                break;
        }
    }
    pthread_exit(NULL);
}

void * thread_udp(void *ptr)
{
    drcom_config *conf = (drcom_config *)ptr;
    global_udp_dealer->send_u8_pkt();
    cout << "test 1" << endl;
    global_udp_dealer->send_u244_pkt(conf->username, conf->password, "223.5.5.5", "114.114.114.114");
    cout << "test 2" << endl;
    sleep(1);
    while(drcom_status == ONLINE)
    {
        global_udp_dealer->sendalive_u40_1_pkt();
        global_udp_dealer->sendalive_u40_2_pkt();
        sleep(10);
        global_udp_dealer->sendalive_u38_pkt();
        sleep(5);
    }
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
	if (argc < 1) {
		cerr << "require a config file path." << endl;
		return 1;
	}

	// get config from config file
    config configSettings(argv[1]);
    drcom_config conf;
    conf.device = configSettings.Read("device", string("ens33"));
    conf.username = configSettings.Read("username", string("15115011018"));
    conf.password = configSettings.Read("password", string("111111"));
    conf.authserver_ip = configSettings.Read("authserver_ip", string("192.168.127.129"));
    conf.udp_alive_port = 61440;
    conf.udp_alive_port = configSettings.Read("udp_alive_port", conf.udp_alive_port);


    string local_ip = get_ip_address(conf.device); //"192.168.197.64";
    vector<uint8_t> local_mac = get_mac_address(conf.device); // { 0xd4, 0x3d, 0x7e, 0x54, 0x95, 0x36 };
    vector<uint8_t> broadcast_mac(6, 0xff);
    vector<uint8_t> hangzhou_mac = { 0x58, 0x6a, 0xb1, 0x56, 0x79, 0x00 };

    // print system info
    cout << "******** Drcom Info ********" << endl;
    cout << "device: " << conf.device << endl;
    cout << "username: " << conf.username << endl;
    cout << "password: " << conf.password << endl;
    cout << "local ip: " << local_ip << endl;
    //cout << "local mac: " << local_mac[0] << endl;
    cout << "****************************" << endl;

	global_eap_dealer = new eap_dealer(conf.device, broadcast_mac, local_mac, local_ip, conf.username, conf.password);
    global_udp_dealer = new udp_dealer(conf.device, local_mac, local_ip, hangzhou_mac, conf.authserver_ip, conf.udp_alive_port);
	while (!eap_login(&conf)) {
	}

	// create eap thread
    int ret = pthread_create(&t_eap_id, NULL, thread_eap, (void *)&conf);
	if (ret) {
		cout << "Create eap thread error!" << endl;
		return 2;
	}

    // control pannel
    string s;
    while (true)
    {
        cin >> s;
        if (s == "quit") {
            drcom_status = OFFLINE;
            pthread_join(t_udp_id, NULL); // main thread blocked, waiting the udp thread exit
            SYS_LOG_INFO("UDP has closed.");
            pthread_join(t_eap_id, NULL); // main thread blocked, waiting the eap thread exit
            SYS_LOG_INFO("EAP has closed.");
            global_eap_dealer->logoff();
            global_eap_dealer->logoff();
            SYS_LOG_INFO("Logoff sent.");
            break;
        }
    }

    // Clean up task, delete all class object and release all resources
    if (global_eap_dealer != NULL)
        delete global_eap_dealer;
    if (global_udp_dealer != NULL)
        delete global_udp_dealer;

    SYS_LOG_INFO("Clean has done.");

	return 0;
}