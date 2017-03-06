#ifndef UDP_DEALER_H_
#define UDP_DEALER_H_

#include "def.h"
#include "pcap_dealer.h"
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
using namespace std;

#define DRCOM_U8_FRAME_SIZE    50
#define DRCOM_U244_FRAME_SIZE    286
#define DRCOM_U40_FRAME_SIZE    82
#define DRCOM_U38_FRAME_SIZE    80
#define IP_HEADER_SIZE    20
#define UDP_HEADER_SIZE    8

struct pkt_u244
	{
		uint8_t drcom_identify;
		uint8_t counter;
		uint16_t data_length;
		uint8_t unknown;
		uint8_t username_length;
		uint8_t local_mac[6];
		uint8_t local_ip[4];
		uint8_t fixedchar[4];
		uint8_t from_firstpkt_byte[4];
		uint8_t check[4];
		uint8_t username[11];
	
};

class udp_dealer
{
public:
	udp_dealer(std::string device, std::vector<uint8_t> local_mac, std::string source_ip, std::vector<uint8_t> gateway_mac, std::string dst_ip, uint16_t port);

	struct ether_header get_eth_header(std::vector<uint8_t> gateway_mac, std::vector<uint8_t> local_mac);
	struct iphdr get_ip_header(const char *source, const char *dest, uint16_t total_length);
	struct udphdr get_udp_header(uint16_t port_from, uint16_t port_to, uint16_t udp_total_length);
	uint16_t in_cksum(uint16_t * addr, int len);

	void send_u8_pkt();
	void send_u244_pkt();
	void sendalive_u40_1_pkt();
	void sendalive_u40_2_pkt();
	void sendalive_u38_pkt();

	virtual ~udp_dealer();

private:
	pcap_dealer pcap;
	int ip_pkt_id;
    string device;
    uint16_t port_to;
	uint16_t reserved_byte;
	uint8_t udp_pkt_id;

	std::vector<uint8_t> local_mac;
	std::vector<uint8_t> gateway_mac;
	std::string source_ip;
	std::string dst_ip;
};

#endif