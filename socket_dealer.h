#ifndef SOCKET_DEALER_H_
#define SOCKET_DEALER_H_

#include "def.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
using namespace std;

#define RECV_BUFF_LEN 512

class socket_dealer
{
public:
	socket_dealer(std::string local_ip, uint16_t m_port);
	bool send_udp_pkt(const char *dest, uint16_t port, std::vector<uint8_t> &udp_data_set);
	bool recv_udp_pkt(std::vector<uint8_t> &pkt_data);

	virtual ~socket_dealer();

private:
	int client_fd;
	uint16_t port;
	
};

#endif