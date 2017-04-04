#include "eap_dealer.h"
#include "log.h"
#include "utils.h"
#include <net/ethernet.h>
#include <netinet/in.h>
using namespace std;

eap_dealer::eap_dealer(
	string device,
	vector<uint8_t> gateway_mac_init,
	vector<uint8_t> local_mac,
	string local_ip,
	string identity,
	string key)
	: pcap(device, local_mac),
	resp_eap_id(0),
	resp_md5_eap_id(0),
	gateway_mac(gateway_mac_init),
	local_mac(local_mac),
	key(str_to_vec(key))
{

	begintime = time(0);
	vector<uint8_t> ip = str_ip_to_vec(local_ip);

	resp_id = str_to_vec(identity);

	resp_id.insert(resp_id.end(),0x00);   //0x00, 0x44, 0x61, 0x00, 0x00
	resp_id.insert(resp_id.end(),0x44);
	resp_id.insert(resp_id.end(),0x61);
	resp_id.insert(resp_id.end(),0x00);
	resp_id.insert(resp_id.end(),0x00);

	resp_id.insert(resp_id.end(), ip.begin(), ip.end());

	resp_md5_id = str_to_vec(identity);

	resp_md5_id.insert(resp_md5_id.end(),0x00);    //0x00 ,0x44, 0x61, 0x0a, 0x00 );
	resp_md5_id.insert(resp_md5_id.end(),0x44);
	resp_md5_id.insert(resp_md5_id.end(),0x61);
	resp_md5_id.insert(resp_md5_id.end(),0x24); // 0a
	resp_md5_id.insert(resp_md5_id.end(),0x00);

	resp_md5_id.insert(resp_md5_id.end(), ip.begin(), ip.end());

}

struct ether_header eap_dealer::get_eth_header(vector<uint8_t> gateway_mac_t, vector<uint8_t> local_mac) {
	struct ether_header eth_header;

	memcpy(eth_header.ether_dhost, &gateway_mac_t[0], 6);
	memcpy(eth_header.ether_shost, &local_mac[0], 6);
	eth_header.ether_type = htons(0x888e); // 802.1X Authentication (0x888e)

	return eth_header;
}

bool eap_dealer::start() {
    EAP_LOG_INFO("EAP Start." << endl);
    vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);
    uint8_t eapol_start[] = {
	    0x01,             // Version: 802.1X-2001
	    0x01,             // Type: Start
	    0x00, 0x00        // Length: 0
    };
    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    memcpy(&pkt_data[sizeof(eth_header)], eapol_start, 4);

   	vector<uint8_t> success;
   	string error;

	int retry_times = 0;
	bool ret;

	while ((ret = pcap.send(pkt_data, &success, &error)) == false && retry_times < MAX_RETRY_TIME)
	{
		retry_times++;
		EAP_LOG_ERR("Failed to perform " << "Start" << ", retry times = " << retry_times << endl);
		EAP_LOG_INFO("Try to perform " << "Start" << " after 2 seconds." << endl);
		sleep(2);
	}
	if (retry_times == MAX_RETRY_TIME)
	{
		EAP_LOG_ERR("Failed to perfrom " << "Start" << ", stopped." << endl);
		return false;
	}
	if(ret) {
		struct ether_header *eth_header; // 网络头
		struct eap_header *eap_header;
		while (true) {
			eth_header = (struct ether_header*) &success[0];
			eap_header = (struct eap_header*) (&success[0] + sizeof(struct ether_header));

			// just for debug
			// EAP_SHOW_PACKET_TYPE("Start");

			if (eap_header->eapol_type != 0x00) // EAP Packet
				return false;
			// EAP Request                  // EAP Failure
			if (eap_header->eap_code != 0x01) //&& eap_header->eap_code != 0x04
			{
				EAP_LOG_INFO("Gateway returns: Failue. Try to recv start packet again." << endl);
				success.clear();
				pcap.recv(&success, &error);
				continue;
			}
			// Now, only eap_code = 0x01 packets, select eap_type = 0x01 packet
			if (eap_header->eap_type != 0x01) // Request, Identity
				return false;
			break;
		}
		
		EAP_LOG_INFO("Gateway returns: Request, Identity" << endl);
		resp_eap_id = eap_header->eap_id;
		// get and save gateway mac address
		// gateway_mac.clear();
		memcpy(&gateway_mac[0], &(eth_header->ether_shost), 6);
		return true;
	}
	return ret;
}

bool eap_dealer::response_identity() {

	EAP_LOG_INFO("Response, Identity." << endl);
	vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);

	vector<uint8_t> eap_resp_id = {
		0x01,           // Version: 802.1X-2001
		0x00,           // Type: EAP Packet
		0x00, 0x00,     // EAP Length
		0x02,           // Code: Reponse
		(uint8_t) resp_eap_id,    // Id
		0x00, 0x00,     // EAP Length
		0x01            // Type: Identity
	};   //-std=c++11

	uint16_t eap_length = htons(5 + resp_id.size());
	memcpy(&eap_resp_id[2], &eap_length, 2);
	memcpy(&eap_resp_id[6], &eap_length, 2);

	struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);

	memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
	memcpy(&pkt_data[sizeof(eth_header)], &eap_resp_id[0], eap_resp_id.size());
	memcpy(&pkt_data[sizeof(eth_header) + eap_resp_id.size()], &resp_id[0], resp_id.size());
	alive_data=pkt_data;
	for(int j=0;j<96;j++){
		response[j]=alive_data[j];
	}

	vector<uint8_t> success;
	string error;

	int retry_times = 0;
	bool ret;

	while ((ret = pcap.send(pkt_data, &success, &error)) == false && retry_times < MAX_RETRY_TIME)  //这里有问题。
	{
		retry_times++;
		EAP_LOG_ERR("Failed to perform " << "Response, Identity" << ", retry times = " << retry_times << endl);
		EAP_LOG_INFO("Try to perform " << "Response, Identity" << " after 2 seconds." << endl);
		sleep(2);
	}
	if (retry_times == MAX_RETRY_TIME)
	{
		EAP_LOG_ERR("Failed to perfrom " << "Response, Identity" << ", stopped." << endl);
		return false;
	}
	if(ret) {
		//struct ether_header *eth_header;
		struct eap_header *eap_header;

		//eth_header = (struct ether_header*) &success[0];
		eap_header = (struct eap_header*) (&success[0] + sizeof(struct ether_header));

		// just for debug
		// EAP_SHOW_PACKET_TYPE("Response, Identity");

		if (eap_header->eapol_type != 0x00) // EAP Packet
			return false;
		// EAP Request                  // EAP Failure
		if (eap_header->eap_code != 0x01) //&& eap_header->eap_code != 0x04
			return false;
		EAP_LOG_INFO("Gateway returns: Request, MD5-Challenge EAP" << endl);
		resp_md5_eap_id = eap_header->eap_id;
		resp_md5_attach_key = vector<uint8_t>(eap_header->eap_md5_value, eap_header->eap_md5_value + EAP_MD5_VALUE_SIZE);
	}
	resp_eap_id++;
	return ret;
}

bool eap_dealer::response_md5_challenge() {

	EAP_LOG_INFO("Response, MD5-Challenge EAP." << endl);
	vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);

	vector<uint8_t> eap_resp_md5_ch = {
		0x01,               // Version: 802.1X-2001
		0x00,               // Type: EAP Packet
		0x00, 0x00,         // EAP Length
		0x02,               // Code: Reponse
		(uint8_t) resp_md5_eap_id,    // Idchallenge
		0x00, 0x00,         // EAP Length
		0x04,               // Type: MD5-Challenge EAP
		EAP_MD5_VALUE_SIZE  // EAP-MD5 Value-Size = 16
	};     //-std=c++11

	uint16_t eap_length = htons(6 + EAP_MD5_VALUE_SIZE + resp_md5_id.size());

	memcpy(&eap_resp_md5_ch[2], &eap_length, 2);
	memcpy(&eap_resp_md5_ch[6], &eap_length, 2);

	struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);

	memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
	memcpy(&pkt_data[sizeof(eth_header)], &eap_resp_md5_ch[0], eap_resp_md5_ch.size());

	vector<uint8_t> eap_key(1 + key.size() + EAP_MD5_VALUE_SIZE);
	eap_key[0] = resp_md5_eap_id;
	memcpy(&eap_key[1], &key[0], key.size());
	memcpy(&eap_key[1 + key.size()], &resp_md5_attach_key[0], EAP_MD5_VALUE_SIZE);

	md5_value = get_md5_digest(eap_key);
	memcpy(&pkt_data[sizeof(eth_header) + eap_resp_md5_ch.size()], &md5_value[0], md5_value.size());

	memcpy(&pkt_data[sizeof(eth_header) + eap_resp_md5_ch.size() + EAP_MD5_VALUE_SIZE], &resp_md5_id[0], resp_md5_id.size());


	vector<uint8_t> success;
	string error;
	int retry_times = 0;
	bool ret;
	while ((ret = pcap.send(pkt_data, &success, &error)) == false && retry_times < MAX_RETRY_TIME)
	{
		retry_times++;
		EAP_LOG_ERR("Failed to perform " << "Response, MD5-Challenge EAP" << ", retry times = " << retry_times << endl);
		EAP_LOG_INFO("Try to perform " << "Response, MD5-Challenge EAP" << " after 2 seconds." << endl);
		sleep(2);
	}
	if (retry_times == MAX_RETRY_TIME)
	{
		EAP_LOG_ERR("Failed to perfrom " << "Response, MD5-Challenge EAP" << ", stopped." << endl);
		return false;
	}
	if (ret) {
		//struct ether_header *eth_header;
		struct eap_header *eap_header;

		//eth_header = (struct ether_header*) &success[0];
		eap_header = (struct eap_header*) (&success[0] + sizeof(struct ether_header));

		// just for debug
		// EAP_SHOW_PACKET_TYPE("Response, MD5-Challenge EAP");

		if (eap_header->eapol_type != 0x00) // EAP Packet
			return false;
		// Request                      // Success
		if (eap_header->eap_code != 0x01 && eap_header->eap_code != 0x03)
			return false;
		if (eap_header->eap_code == 0x01) // Request
		{
			if (eap_header->eap_type != 0x02) // Notification
				return false;

			string noti(ntohs(eap_header->eap_length) - 5, 0); // 1 for NULL Terminator
			memcpy(&noti[0], ((uint8_t*)eap_header + 4 + 5), // 4 - EAPol Header, 5 - EAP Header
				   ntohs(eap_header->eap_length) - 5);

			EAP_LOG_INFO("Gateway returns: Request, Notification: " << noti << endl);

			if (!noti.compare("userid error1"))
				EAP_LOG_INFO("Tips: Account or password authentication fails, the system does not exist in this account." << endl);

			if (!noti.compare("userid error3"))
				EAP_LOG_INFO("Tips: Account or password authentication fails, the system does not exist in this account or your account has arrears down." << endl);
			logoff(); // Need to send a logoff, or the gateway will always send notification
			return 1; // Don't retry when notification
		}

		// In fact, this condition is always true
		if (eap_header->eap_code == 0x03) // Success
			EAP_LOG_INFO("Gateway returns: Success" << endl);
		return true;
	}
	return ret;
}

int eap_dealer::recv_gateway_returns() {
	
	vector<uint8_t> success;
	string error;

	if (!pcap.recv(&success, &error))
	{
		return -1;
	}

	struct ether_header *eth_header; // 网络头
	struct eap_header *eap_header;

	eth_header = (struct ether_header*) &success[0];
	eap_header = (struct eap_header*) (&success[0] + sizeof(struct ether_header));

	// just for debug
	// EAP_SHOW_PACKET_TYPE("Success");

	if (eap_header->eapol_type != 0x00) // EAP Packet
		return -2;
	if (eap_header->eap_code == 0x04) // EAP Failure
		return 1;
	// EAP Request
	if (eap_header->eap_type == 0x01) {
		EAP_LOG_INFO("Gateway returns: Request, Identity" << endl);
		resp_eap_id = eap_header->eap_id;
		return 0;
	} // Request, Identity
	// Now, only eap_code = 0x01 packets, select eap_type = 0x01 packet
	return -2;
}

bool eap_dealer::alive_identity() {
	string error;
	// send heartbeat packet
	vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);
	vector<uint8_t> eap_resp_id = {
		0x01,           // Version: 802.1X-2001
		0x00,           // Type: EAP Packet
		0x00, 0x00,     // EAP Length
		0x02,           // Code: Reponse
		(uint8_t) resp_eap_id,    // Id
		0x00, 0x00,     // EAP Length
		0x01            // Type: Identity
	};   //-std=c++11

	uint16_t eap_length = htons(5 + resp_id.size());
	memcpy(&eap_resp_id[2], &eap_length, 2);
	memcpy(&eap_resp_id[6], &eap_length, 2);

	struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);

	memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
	memcpy(&pkt_data[sizeof(eth_header)], &eap_resp_id[0], eap_resp_id.size());
	memcpy(&pkt_data[sizeof(eth_header) + eap_resp_id.size()], &resp_id[0], resp_id.size());
	alive_data=pkt_data;
	for(int j=0;j<96;j++){
		response[j]=alive_data[j];
	}

	pcap.send_without_response(alive_data, &error);

	EAP_LOG_INFO("Active! Response, Identity." << endl);

	char ctime[20];
	sprintf(ctime, "%d", (int)(time(0)-begintime));
	SYS_LOG_INFO("Heartbeat Packet sent. Online time: " + string(ctime) + "s\n");
	return true;	
}

void eap_dealer::logoff() {

	EAP_LOG_INFO("Logoff." << endl);

	vector<uint8_t> pkt_data(DRCOM_EAP_FRAME_SIZE, 0);

	uint8_t eapol_logoff[] = {
		0x01,             // Version: 802.1X-2001
		0x02,             // Type: Logoff
		0x00, 0x00        // Length: 0
	};

	struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
	memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
	memcpy(&pkt_data[sizeof(eth_header)], eapol_logoff, 4);

	string error;
	pcap.send_without_response(pkt_data, &error);
}

eap_dealer::~eap_dealer() {
}
