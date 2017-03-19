#ifndef UDP_DEALER_H_
#define UDP_DEALER_H_

#include "def.h"
#include "socket_dealer.h"
#include <time.h>
using namespace std;

class udp_dealer
{
public:
	udp_dealer(std::vector<uint8_t> local_mac, std::string local_ip, std::string dst_ip, uint16_t port);

	void send_u8_pkt();
	void send_u244_pkt(std::string login_username, std::string hostname, std::string local_dns_1, std::string local_dns_2);
	void sendalive_u40_1_pkt();
	void sendalive_u40_2_pkt();
	void sendalive_u38_pkt(std::vector<uint8_t> md5_challenge_value);
	void sendalive_u40_3_pkt();
	uint8_t udp_id_counter();

	void generate_244_chksum(std::vector<uint8_t> &data_buf);
	void generate_40_chksum(std::vector<uint8_t> &data_buf);
	void u244_retrieved_u8();
	void u40_retrieved_last();
	void u38_retrieved_u244resp();

	virtual ~udp_dealer();
	
private:
	socket_dealer sock;
    uint16_t port_to;
	uint8_t udp_pkt_id;

	std::vector<uint8_t> local_mac;
	std::string local_ip;
	std::string dst_ip;

	uint32_t random_byte;
	std::vector<uint8_t> u244_checksum;
	std::vector<uint8_t> u244_retrieved_byte; // u8 response packet(8-11bit)
	std::vector<uint8_t> u40_retrieved_byte;
	uint8_t u38_reserved_byte[3]; // calculated by the retrieved byte from u244 response packet(25-26 and 31 bit)
};

#endif