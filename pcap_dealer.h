#ifndef PCAP_DEALER_H_
#define PCAP_DEALER_H_

#include <unistd.h>
#include <pcap.h>
#include <vector>
#include <string.h>
using namespace std;

class pcap_dealer
{
public:
	pcap_dealer(std::string device, std::vector<uint8_t> mac); // EAP/EAPOL
	pcap_dealer(std::string device, uint16_t port); // UDP
	bool init(std::string device, char filter[]);
	bool send(std::vector<uint8_t> data, std::vector<uint8_t> *success, std::string *error);
	void send_without_response(std::vector<uint8_t> data, std::string *error);
	bool recv(std::vector<uint8_t> *success, std::string *error);
	virtual ~pcap_dealer();

private:
	pcap_t *handle;
	
};

#endif