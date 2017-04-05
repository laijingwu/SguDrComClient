#include "def.h"
#include "pcap_dealer.h"
#include "sgudrcom_exception.h"
#include "log.h"

pcap_dealer::pcap_dealer(string device, vector<uint8_t> mac) {
    char filter[100];
    sprintf(filter, "ether dst %02x:%02x:%02x:%02x:%02x:%02x and ether proto 0x888e", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    init(device, filter);
}

pcap_dealer::pcap_dealer(string device, uint16_t port) {
    char filter[100];
    sprintf(filter, "udp port %d", port);
    init(device, filter);
}

bool pcap_dealer::init(string device, char filter[]) {
    const int SNAP_LEN = 1518;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    struct bpf_program fp;

    try
    {
        handle = pcap_open_live(device.c_str(), SNAP_LEN, 1, 1000, errbuf);

        if (handle == NULL) {
            cout << "Please ensure you have the access to the network devices." << endl;
            throw sgudrcom_exception("pcap_open_live: " + string(errbuf));
        }

        if (pcap_datalink(handle) != DLT_EN10MB) {
            cout << "Please ensure you have chosen the correct device! You can adjust your setting in drcom.conf!" << endl;
            throw sgudrcom_exception("pcap_datalink: not an Ethernet device.");
        }

        if (pcap_compile(handle, &fp, filter, 0, 0) == -1) {
            throw sgudrcom_exception(string("pcap_compile: ") + pcap_geterr(handle));
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            throw sgudrcom_exception(string("pcap_setfilter: ") + pcap_geterr(handle));
        }
    }
    catch(exception &e)
    {
        PCAP_LOG_ERR(e.what());
        exit(2);
    }

    pcap_set_timeout(handle, 4000);

    pcap_freecode(&fp);
    return true;
}

bool pcap_dealer::send(vector<uint8_t> data, vector<uint8_t> *success, string *error) {
	try
    {
        if (pcap_sendpacket(handle, &data[0], (int)data.size()) != 0) {
            throw sgudrcom_exception("pcap_sendpacket: " + string(pcap_geterr(handle)));
        }
        struct pcap_pkthdr *header;
        const uint8_t *pkt_data;

        int ret = pcap_next_ex(handle, &header, &pkt_data);
        switch (ret) {
            case 0: // Timeout
                throw sgudrcom_exception("pcap_next_ex: timeout.");
                break;
            case 1: // Success
                (*success).resize(header->len);
                memcpy(&(*success)[0], pkt_data, header->len);
                break;
            default: {
                throw sgudrcom_exception(string("pcap_next_ex: ") + pcap_geterr(handle));
            }
        }
    }
    catch (exception &e)
    {
        *error = e.what();
        PCAP_LOG_INFO(*error);
        return false;
    }
    return true;
}

void pcap_dealer::send_without_response(vector<uint8_t> data, string *error) {
    try
    {
        if (pcap_sendpacket(handle, &data[0], (int)data.size()) != 0) {
            throw sgudrcom_exception("pcap_sendpacket: " + string(pcap_geterr(handle)));
        }
    }
    catch (sgudrcom_exception &e)
    {
        *error = e.what();
        PCAP_LOG_INFO(*error);
    }
}


bool pcap_dealer::recv(vector<uint8_t> *success, string *error) {
    int ret = -1;
    try
    {
        struct pcap_pkthdr *header;
        const uint8_t *pkt_data;
        ret = pcap_next_ex(handle, &header, &pkt_data);
        switch (ret) {
            case 0: // Timeout
                throw sgudrcom_exception("pcap_next_ex: timeout.");
                break;
            case 1: // Success
                (*success).resize(header->len);
                memcpy(&(*success)[0], pkt_data, header->len);
                break;
            default:
                throw sgudrcom_exception(string("pcap_next_ex: ") + pcap_geterr(handle));
                break;
        }
    }
    catch (sgudrcom_exception &e)
    {
        *error = e.what();
        return false;
    }
    return true;
}

pcap_dealer::~pcap_dealer() {
    if (handle)
        pcap_close(handle);
}
