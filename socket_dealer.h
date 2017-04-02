#ifndef SOCKET_DEALER_H_
#define SOCKET_DEALER_H_

#include "def.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <functional>
using namespace std;

#define RECV_BUFF_LEN 512
const size_t buffer_size = 2048;

class socket_dealer
{
public:
	socket_dealer(string gateway_ip, uint32_t gateway_port, std::string local_ip);

	bool send_udp_pkt(const char *dest, uint16_t port, std::vector<uint8_t> &udp_data_set);
	bool recv_udp_pkt(std::vector<uint8_t> &pkt_data);

	int post(std::vector<uint8_t> &data, std::function<int(std::vector<uint8_t>)> success, std::function<void(std::string)> error = nullptr);
	int wait_socket(int timeout_sec = 10);

	virtual ~socket_dealer();

private:
	int sock;
    struct sockaddr_in gateway;
	
};

#endif