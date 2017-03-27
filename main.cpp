#include "def.h"
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include "log.h"
#include "config.h"
#include "utils.h"
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
pthread_mutex_t mutex_status;
ONLINE_STATE drcom_status = OFFLINE;

bool eap_login(drcom_config *conf)
{
    if (t_udp_id != 0)
        pthread_join(t_udp_id, NULL);

	global_eap_dealer->logoff();
	global_eap_dealer->logoff();
	sleep(3); // for completing log off.
	if (!global_eap_dealer->start())
		return false;

	if (!global_eap_dealer->response_identity())
		return false;

	if (!global_eap_dealer->response_md5_challenge())
		return false;

    // success
    pthread_mutex_lock(&mutex_status);
    drcom_status = ONLINE;
    pthread_mutex_unlock(&mutex_status);
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
    EAP_LOG_INFO("Binding for gateway returns." << std::endl);
    while (pthread_mutex_lock(&mutex_status), drcom_status == ONLINE)
    {
        pthread_mutex_unlock(&mutex_status);
        switch(global_eap_dealer->recv_gateway_returns())
        {
            case -2:           // catch the wrong packet, continue capturing packets.
            case -1: return NULL; // receive packet timeout, continue capturing packets.
            case 1: {
                pthread_mutex_lock(&mutex_status);
                drcom_status = OFFLINE; // receive the failure packet, try to reconnect
                pthread_mutex_unlock(&mutex_status);
                while (!eap_login(conf)) { // relogin
                }
                break;
            }
            case 0: global_eap_dealer->alive_identity(); //request identity and send alive
                break;
        }
    }
}

void * thread_udp(void *ptr)
{
    int counter = 1;
    drcom_config *conf = (drcom_config *)ptr;
    global_udp_dealer->send_u8_pkt();
    global_udp_dealer->send_u244_pkt(conf->username, "DrCom.Fucker", "223.5.5.5", "114.114.114.114");
    sleep(1);
    while(pthread_mutex_lock(&mutex_status), drcom_status == ONLINE)
    {
        pthread_mutex_unlock(&mutex_status);
        global_udp_dealer->sendalive_u40_1_pkt();
        usleep(50000); // 50ms
        global_udp_dealer->sendalive_u40_2_pkt();
        sleep(6);
        global_udp_dealer->sendalive_u38_pkt(global_eap_dealer->md5_value);
        sleep(3);
        if (counter >= 10)
        {
            global_udp_dealer->sendalive_u40_3_pkt();
            counter = 1;
            sleep(1);
        }
        else
            counter++;
    }
}

int main(int argc, char *argv[])
{
    config configSettings;
	if (argc < 2) {
		config configSettings();
	} else {
        // get config from config file
        config configSettings(argv[1]);
    }

    drcom_config conf;
    conf.device = configSettings.Read("device", string("ens33"));
    conf.username = configSettings.Read("username", string("15115011018"));
    conf.password = configSettings.Read("password", string("111111"));
    conf.authserver_ip = configSettings.Read("authserver_ip", string("192.168.127.129"));
    conf.udp_alive_port = 61440;
    conf.udp_alive_port = configSettings.Read("udp_alive_port", conf.udp_alive_port);


    string local_ip = get_ip_address(conf.device);
    vector<uint8_t> local_mac = get_mac_address(conf.device);
    vector<uint8_t> broadcast_mac(6, 0xff);

    // print system info
    uint8_t local_mac_array[6];
    memcpy(&local_mac_array[0], &local_mac[0], 6);
    cout << "******** Drcom Info ********" << endl;
    cout << "device: " << conf.device << endl;
    cout << "username: " << conf.username << endl;
    cout << "password: " << conf.password << endl;
    cout << "local ip: " << local_ip << endl;
    cout << "local mac: " << hex_to_str(local_mac_array, local_mac.size(), ':') << endl;
    cout << "****************************" << endl;

	global_eap_dealer = new eap_dealer(conf.device, broadcast_mac, local_mac, local_ip, conf.username, conf.password);
    global_udp_dealer = new udp_dealer(local_mac, local_ip, conf.authserver_ip, conf.udp_alive_port);
    pthread_mutex_init(&mutex_status, NULL);
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
            pthread_mutex_lock(&mutex_status);
            drcom_status = OFFLINE;
            pthread_mutex_unlock(&mutex_status);
            pthread_join(t_udp_id, NULL); // main thread blocked, waiting the udp thread exit
            SYS_LOG_INFO("UDP thread has closed. [Done]" << endl);
            pthread_kill(t_eap_id, SIGQUIT);
            SYS_LOG_INFO("EAP thread has closed. [Done]" << endl);
            global_eap_dealer->logoff();
            SYS_LOG_INFO("Logoff. [Done]" << endl);
            break;
        }
    }

    // Clean up task, delete all class object and release all resources
    if (global_udp_dealer != NULL)
        delete global_udp_dealer;
    if (global_eap_dealer != NULL)
        delete global_eap_dealer;

    SYS_LOG_INFO("Clean up. [Done]" << endl);

	return 0;
}