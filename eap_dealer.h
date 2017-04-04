#ifndef EAP_DEALER_H_
#define EAP_DEALER_H_

#include "def.h"
#include "pcap_dealer.h"
using namespace std;

#define DRCOM_EAP_FRAME_SIZE    (0x60)
#define EAP_MD5_VALUE_SIZE      (0x10)

#define EAP_SHOW_PACKET_TYPE(step)                                                             \
    EAP_LOG_DBG("Recevied after " << step << ", "                                              \
        << "eapol_type = 0x" << std::hex << (int) eap_header->eapol_type                       \
        << ", eap_id = 0x" << std::hex << (int) eap_header->eap_id                             \
        << ", eap_type = 0x" << std::hex << (int) eap_header->eap_type                         \
        << ", eap_length = " << (int) eap_header->eap_length);

class eap_dealer
{
public:
	eap_dealer(string device, vector<uint8_t> gateway_mac_init, vector<uint8_t> local_mac, string local_ip, string identity, string key);

	struct ether_header get_eth_header(vector<uint8_t> gateway_mac_t, vector<uint8_t> local_mac);
	
	bool start();
	void logoff();
	bool response_identity();
	bool alive_identity();
	bool response_md5_challenge();
	int recv_gateway_returns();

	vector<uint8_t> md5_value;

	virtual ~eap_dealer();

private:
	pcap_dealer pcap;
	int resp_eap_id;
	int resp_md5_eap_id; // Recved from Request, MD5-Challenge EAP
	uint8_t response[128]; // 数据包
	int begintime;

	vector<uint8_t> gateway_mac;
	vector<uint8_t> local_mac; // Const
	vector<uint8_t> resp_id, resp_md5_id, key;
	vector<uint8_t> alive_data;
	vector<uint8_t> resp_md5_attach_key; // Recved from Request, Identity
};

#endif