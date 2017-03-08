#ifndef UDP_DEALER_H_
#define UDP_DEALER_H_

#include "def.h"
#include "pcap_dealer.h"
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
using namespace std;

#define DRCOM_U8_FRAME_SIZE    50
#define DRCOM_U244_FRAME_SIZE    286
#define DRCOM_U40_FRAME_SIZE    82
#define DRCOM_U38_FRAME_SIZE    80
#define IP_HEADER_SIZE    20
#define UDP_HEADER_SIZE    8

class udp_dealer
{
public:
	udp_dealer(std::string device, std::vector<uint8_t> local_mac, std::string local_ip, std::vector<uint8_t> gateway_mac, std::string dst_ip, uint16_t port);

	struct ether_header get_eth_header(std::vector<uint8_t> gateway_mac, std::vector<uint8_t> local_mac);
	struct iphdr get_ip_header(const char *source, const char *dest, uint16_t total_length);
	struct udphdr get_udp_header(uint16_t port_from, uint16_t port_to, uint16_t udp_total_length);
	uint16_t in_cksum(uint16_t * addr, int len);

	void send_u8_pkt();
	void send_u244_pkt(std::string login_username, std::string hostname, std::string local_dns_1, std::string local_dns_2);
	void sendalive_u40_1_pkt();
	void sendalive_u40_2_pkt();
	void sendalive_u38_pkt();

	void generate_244_chksum(std::vector<uint8_t> &data_buf);
	void generate_40_chksum(std::vector<uint8_t> &data_buf);
	void u244_retrieved_u8();
	void u40_retrieved_last();
	void u38_retrieved_u244resp();

	virtual ~udp_dealer();
	
private:
	pcap_dealer pcap;
	uint16_t ip_pkt_id;
    std::string device;
    uint16_t port_to;
	uint8_t udp_pkt_id;

	std::vector<uint8_t> local_mac;
	std::vector<uint8_t> gateway_mac;
	std::string local_ip;
	std::string dst_ip;
	std::vector<uint8_t> md5_challenge_value;

	uint16_t random_byte;
	std::vector<uint8_t> u244_checksum;
	std::vector<uint8_t> u244_retrieved_byte; // u8 response packet(8-11bit)
	std::vector<uint8_t> u40_retrieved_byte;
	std::vector<uint8_t> u38_reserved_byte; // calculated by the retrieved byte from u244 response packet(25-26 and 31 bit)
};

#endif