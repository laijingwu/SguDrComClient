#include "socket_dealer.h"
#include "sgudrcom_exception.h"
#include "log.h"

socket_dealer::socket_dealer(string gateway_ip, uint32_t gateway_port, std::string local_ip)
{
	sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        throw sgudrcom_exception("socket", errno);

    auto flag = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flag | O_NONBLOCK);

	struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_port = 0; // system defined
    local.sin_addr.s_addr = inet_addr(local_ip.c_str());
    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0)
        throw sgudrcom_exception("bind", errno);
    
    gateway.sin_family = AF_INET;
    gateway.sin_port = htons(gateway_port);
    gateway.sin_addr.s_addr = inet_addr(gateway_ip.c_str());
}

int socket_dealer::post(std::vector<uint8_t>& data, std::function<int(std::vector<uint8_t>)> success, std::function<void(std::string)> error)
{
    try
    {
        int total = 0;
        int left = (int) data.size();
        while (total < data.size())
        {
            int len = (int) sendto(sock, &data[0], data.size(), MSG_NOSIGNAL, (struct sockaddr *)&gateway, sizeof(gateway));
            if (len < 0)
            {
                if (errno == EWOULDBLOCK && left > 0)
                    continue;
                else
                    throw sgudrcom_exception("sendto", errno);
            }
            
            total += len;
            left -= len;
        }
        
        int ret = wait_socket();
        if (ret < 0)
            throw sgudrcom_exception("select", errno);
        if (ret == 0)
            throw sgudrcom_exception("select: timeout");
        
        std::vector<uint8_t> recv;
        while (true)
        {
            std::vector<uint8_t> buf(buffer_size, 0);
            int len = (int) ::recv(sock, (char*) &buf[0], buffer_size, 0);
            
            if (len <= 0)
                break; // connection closed
            
            buf.resize(len);
            recv.insert(recv.end(), buf.begin(), buf.end());
            
            if (len < buffer_size)
                break;
        }
        
        return success(recv);
    }
    catch (std::exception& e)
    {
        if (error != nullptr)
            error(e.what());
            
        return -1;
    }
}

int socket_dealer::wait_socket(int timeout_sec)
{
    fd_set fds;
    struct timeval tv;
    
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    
    tv.tv_usec = 0;
    tv.tv_sec = timeout_sec / 1000;
    
    return select(sock + 1, &fds, NULL, NULL, &tv);
}

bool socket_dealer::send_udp_pkt(const char *dest, uint16_t port, std::vector<uint8_t> &udp_data_set)
{
	struct sockaddr_in server_addr;
	try
	{
		memset(&server_addr, 0, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = inet_addr(dest);
		server_addr.sin_port = htons(port);

		socklen_t len = sizeof(server_addr);
		size_t data_len = udp_data_set.size();
		char *buf = new char[data_len];
		memcpy(buf, &udp_data_set[0], data_len);

		ssize_t ret = sendto(sock, buf, data_len, 0, (struct sockaddr *)&server_addr, len);
		delete[] buf;
		if (ret < 0)
			throw sgudrcom_exception("failed to send udp packet.");
	}
	catch(sgudrcom_exception &e)
	{
		SOCKET_LOG_ERR(e.what());
		return false;
	}
	return true;
}

bool socket_dealer::recv_udp_pkt(std::vector<uint8_t> &pkt_data)
{
	struct sockaddr_in src_addr;
	socklen_t len;
	try
	{
		char *buf = new char[RECV_BUFF_LEN];
		memset(buf, 0, RECV_BUFF_LEN);
		len = sizeof(src_addr);

		ssize_t ret = recvfrom(sock, buf, RECV_BUFF_LEN, 0, (struct sockaddr *)&src_addr, &len);
		if (ret < 0)
			throw sgudrcom_exception("failed to recv packets.");

		pkt_data.insert(pkt_data.end(), RECV_BUFF_LEN, 0x00);
		memcpy(&pkt_data[0], &buf[0], RECV_BUFF_LEN);
		delete[] buf;
	}
	catch(sgudrcom_exception &e)
	{
		SOCKET_LOG_ERR(e.what());
		return false;
	}
	return true;
}

socket_dealer::~socket_dealer()
{
	close(sock); // close socket
}
