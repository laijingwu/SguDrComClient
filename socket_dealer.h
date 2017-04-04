#ifndef SOCKET_DEALER_H_
#define SOCKET_DEALER_H_

#include "def.h"
// #include <sys/socket.h>
// #include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
using namespace std;

const size_t RECV_BUFF_LEN = 2048;

class socket_dealer
{
public:
	socket_dealer(string gateway_ip, uint16_t gateway_port, string local_ip);
	bool send_udp_pkt(vector<uint8_t> &udp_data_set, vector<uint8_t> &recv, string &error);
	int wait_for_socket(int timeout_milisec = SOCKET_TIMEOUT_MILISEC);

	virtual ~socket_dealer();

private:
	int client_fd;
	struct sockaddr_in gateway;
	
};

#endif