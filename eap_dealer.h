#ifndef EAP_DEALER_H_
#define EAP_DEALER_H_

#include <string.h>
#include "def.h"
#include "pcap_dealer.h"
using namespace std;

#define DRCOM_EAP_FRAME_SIZE    (0x60)
#define EAP_MD5_VALUE_SIZE      (0x10)
#define MAX_RETRY_TIME 2

#define EAP_SHOW_PACKET_TYPE(step)                                                             \
    EAP_LOG_DBG("Recevied after " << step << ", "                                              \
        << "eapol_type = 0x" << std::hex << (int) eap_header->eapol_type                       \
        << ", eap_id = 0x" << std::hex << (int) eap_header->eap_id                             \
        << ", eap_type = 0x" << std::hex << (int) eap_header->eap_type                         \
        << ", eap_length = " << (int) eap_header->eap_length << std::endl);

#define EAP_HANDLE_ERROR(step)  EAP_LOG_ERR(step << ": " << error << std::endl)


class eap_dealer
{
public:
	eap_dealer(string device, vector<uint8_t> local_mac, std::string local_ip, std::string identity, std::string key);

	struct ether_header get_eth_header(std::vector<uint8_t> gateway_mac, std::vector<uint8_t> local_mac);
	bool start(std::vector<uint8_t> gateway_mac);
	void logoff(std::vector<uint8_t> gateway_mac);
	bool response_identity(std::vector<uint8_t> gateway_mac);
	bool alive_identity(std::vector<uint8_t> gateway_mac);
	bool response_md5_challenge(std::vector<uint8_t> gateway_mac);

	virtual ~eap_dealer();

private:
	pcap_dealer pcap;
	int resp_eap_id;
	int resp_md5_eap_id; // Recved from Request, MD5-Challenge EAP
	uint8_t response[128]; // 数据包
	int begintime;

	std::vector<uint8_t> local_mac; // Const
	std::vector<uint8_t> resp_id, resp_md5_id, key;
	std::vector<uint8_t> alive_data;
	std::vector<uint8_t> resp_md5_attach_key; // Recved from Request, Identity
};

#endif