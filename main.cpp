#include <pthread.h>
#include "def.h"
#include "log.h"
#include "utils.h"
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
pthread_mutex_t mutex_status;
ONLINE_STATE drcom_status = OFFLINE;

bool eap_login(drcom_config *conf)
{
    if (t_udp_id != 0)
        pthread_join(t_udp_id, NULL);

    pthread_mutex_lock(&mutex_status);
    drcom_status = ONLINE_PROCESSING;

	global_eap_dealer->logoff();
	global_eap_dealer->logoff();
	sleep(3); // for completing log off.
	if (!global_eap_dealer->start() ||
        !global_eap_dealer->response_identity() ||
        !global_eap_dealer->response_md5_challenge()
    ) {
        drcom_status = OFFLINE;
        pthread_mutex_unlock(&mutex_status);
		return eap_login(conf);
    }

    // success
    drcom_status = ONLINE;
    pthread_mutex_unlock(&mutex_status);
    // create udp thread
    if (pthread_create(&t_udp_id, NULL, thread_udp, (void *)conf)) {
        cerr << "Create udp thread error!" << endl;
        return false;
    }
	return true;
}

void * thread_eap(void *ptr)
{
    drcom_config *conf = (drcom_config *)ptr;

    EAP_LOG_INFO("Binding for gateway returns." << endl);

    int ret;
    while (drcom_status == ONLINE)
    {
        ret = global_eap_dealer->recv_gateway_returns();
        if (ret == 1) // receive failure packet
        {
            if (drcom_status == OFFLINE_PROCESSING) return NULL;
            EAP_LOG_INFO("Gateway Returns: Failure." << endl);
            pthread_mutex_lock(&mutex_status);
            drcom_status = OFFLINE; // receive the failure packet, try to reconnect
            pthread_mutex_unlock(&mutex_status);
            eap_login(conf); // login again
        }
        else if (ret == 0) // request identity and send alive
        {
            global_eap_dealer->alive_identity();
        }
        // -2: catch the wrong packet, continue capturing packets.
        // -1: receive packet timeout, continue capturing packets. 
    }
}

void * thread_udp(void *ptr)
{
    int counter = 1;
    drcom_config *conf = (drcom_config *)ptr;

    global_udp_dealer->clear_udp_param();
    global_udp_dealer->send_u8_pkt();
    global_udp_dealer->send_u244_pkt(conf->username, "DrCom.Fucker", "223.5.5.5", "114.114.114.114");
    sleep(1);
    while(drcom_status == ONLINE)
    {
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
    config settings;
    drcom_config conf;
    const string config_filename = "drcom.conf";
    try
    {
        // get config from config file
        if (argc > 2)
            settings.ReadFile(argv[1]);
        else
            settings.ReadFile(config_filename);

        SYS_LOG_INFO("Loaded configuration successfully." << endl);
    }
    catch(exception &e)
    {
        SYS_LOG_ERR(e.what() << endl);
        SYS_LOG_INFO("Loading default configuration." << endl);
    }

    // load configuration
    conf.device = settings.Read("device", string("ens33"));
    conf.username = settings.Read("username", string("15115011018"));
    conf.password = settings.Read("password", string("111111"));
    conf.authserver_ip = settings.Read("authserver_ip", string("192.168.127.129"));
    conf.udp_alive_port = settings.Read("udp_alive_port", 61440);

    // get vf info
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

    pthread_mutex_init(&mutex_status, NULL);
	global_eap_dealer = new eap_dealer(conf.device, broadcast_mac, local_mac, local_ip, conf.username, conf.password);
    global_udp_dealer = new udp_dealer(local_mac, local_ip, conf.authserver_ip, conf.udp_alive_port);
    
    // login
	eap_login(&conf);

	// create eap thread
	if (pthread_create(&t_eap_id, NULL, thread_eap, (void *)&conf)) {
		cerr << "Create eap thread error!" << endl;
		return 1;
	}

    // control pannel
    string s;
    while (true)
    {
        cin >> s;
        if (s == "quit") break;
        if (s == "version") cout << "Sgu DrCom Client v1.0" << endl;
    }

    pthread_mutex_lock(&mutex_status);
    drcom_status = OFFLINE_PROCESSING;

    pthread_join(t_udp_id, NULL); // main thread blocked, waiting the udp thread exit
    SYS_LOG_INFO("UDP thread has closed. [Done]" << endl);
    pthread_join(t_eap_id, NULL); // main thread blocked, waiting the udp thread exit
    SYS_LOG_INFO("EAP thread has closed. [Done]" << endl);
    global_eap_dealer->logoff();
    SYS_LOG_INFO("Logoff. [Done]" << endl);

    drcom_status = OFFLINE;
    pthread_mutex_unlock(&mutex_status);
    pthread_mutex_destroy(&mutex_status);

    // Clean up task, delete all class object and release all resources
    if (global_udp_dealer != NULL)
        delete global_udp_dealer;
    if (global_eap_dealer != NULL)
        delete global_eap_dealer;

    SYS_LOG_INFO("Clean up. [Done]" << endl);

	return 0;
}