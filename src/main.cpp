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
    if (t_udp_id != 0) {
        pthread_cancel(t_udp_id);
        pthread_join(t_udp_id, NULL);
    }

    pthread_mutex_lock(&mutex_status);
    drcom_status = ONLINE_PROCESSING;

	global_eap_dealer->logoff();
	global_eap_dealer->logoff();

    // need to sleep for 4 sec to complete log off, otherwise cannot recieve the start returning packet.
	sleep(4);

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
        SYS_LOG_ERR("Create udp thread error!");
        return false;
    }
	return true;
}

void * thread_eap(void *ptr)
{
    drcom_config *conf = (drcom_config *)ptr;

    EAP_LOG_INFO("Binding for gateway returns.");

    int ret;
    while (drcom_status == ONLINE)
    {
        ret = global_eap_dealer->recv_gateway_returns();
        if (ret == 1) // receive failure packet
        {
            if (drcom_status == OFFLINE_PROCESSING) return NULL;
            EAP_LOG_INFO("Gateway Returns: Failure.");
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
        if (drcom_status == OFFLINE_PROCESSING) return NULL;
        if (!global_udp_dealer->sendalive_u40_1_pkt()) {
            if (drcom_status != ONLINE) return NULL;
            global_eap_dealer->logoff();
            SOCKET_LOG_INFO("Called to re-login.");
            return NULL;
        }
        usleep(50000); // 50ms
        if (!global_udp_dealer->sendalive_u40_2_pkt()) {
            if (drcom_status != ONLINE) return NULL;
            global_eap_dealer->logoff();
            SOCKET_LOG_INFO("Called to re-login.");
            return NULL;
        }
        sleep(6);
        if (!global_udp_dealer->sendalive_u38_pkt(global_eap_dealer->md5_value)) {
            if (drcom_status != ONLINE) return NULL;
            global_eap_dealer->logoff();
            SOCKET_LOG_INFO("Called to re-login.");
            return NULL;
        }
        sleep(3);
        if (counter >= 10)
        {
            if (!global_udp_dealer->sendalive_u40_3_pkt()) {
                if (drcom_status != ONLINE) return NULL;
                global_eap_dealer->logoff();
                SOCKET_LOG_INFO("Called to re-login.");
                return NULL;
            }
            counter = 1;
            sleep(1);
        }
        else
            counter++;
    }
}

int main(int argc, char *argv[])
{
	sleep(2);
    config settings;
    drcom_config conf;
    const string config_filename = "drcom.conf";
    try
    {
        // get config from config file
        if (argc >= 2)
            settings.ReadFile(argv[1]);
        else
            settings.ReadFile(config_filename);

        SYS_LOG_INFO("Loaded configuration successfully.");
    }
    catch(exception &e)
    {
        SYS_LOG_ERR(e.what());
        SYS_LOG_INFO("Loading default configuration.");
    }

    // load configuration
    conf.device = settings.Read("device", string("ens33"));
    conf.username = settings.Read("username", string("15110000000"));
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
    cout << "password: " << "*******" << endl; // conf.password
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
		SYS_LOG_ERR("Create eap thread error!");
		return 1;
	}

    // control pannel
    string s;
    while (cin >> s)
    {
        if (s == "quit") break;
        if (s == "version") cout << "Sgu DrCom Client v1.0" << endl;
    }

    while (s != "quit") {
      sleep(1000);
    }

    pthread_mutex_lock(&mutex_status);
    drcom_status = OFFLINE_PROCESSING;

    pthread_cancel(t_udp_id);
    pthread_join(t_udp_id, NULL); // main thread blocked, waiting the udp thread exit
    SYS_LOG_INFO("UDP thread has closed. [Done]");
    pthread_cancel(t_eap_id);
    pthread_join(t_eap_id, NULL); // main thread blocked, waiting the udp thread exit
    SYS_LOG_INFO("EAP thread has closed. [Done]");
    global_eap_dealer->logoff();
    SYS_LOG_INFO("Logoff. [Done]");

    drcom_status = OFFLINE;
    pthread_mutex_unlock(&mutex_status);
    pthread_mutex_destroy(&mutex_status);

    // Clean up task, delete all class object and release all resources
    if (global_udp_dealer != NULL)
        delete global_udp_dealer;
    if (global_eap_dealer != NULL)
        delete global_eap_dealer;

    SYS_LOG_INFO("Clean up. [Done]");

	return 0;
}
