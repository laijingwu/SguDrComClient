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
	pcap_dealer(string device, vector<uint8_t> mac); // EAP/EAPOL
	pcap_dealer(string device, uint16_t port); // UDP
	bool init(string device, char filter[]);
	bool send(vector<uint8_t> data, vector<uint8_t> *success, string *error);
	void send_without_response(vector<uint8_t> data, string *error);
	bool recv(vector<uint8_t> *success, string *error);
	virtual ~pcap_dealer();

private:
	pcap_t *handle;
	
};

#endif