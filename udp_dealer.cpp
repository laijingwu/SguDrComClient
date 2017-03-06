#include "udp_dealer.h"
#include "log.h"
#include "get_device_addr.h"
#include "utils.h"

udp_dealer::udp_dealer(
        std::string device,
        std::vector<uint8_t> local_mac,
        std::string source_ip,
        std::vector<uint8_t> gateway_mac,
        std::string dst_ip,
        uint16_t port
    ) : pcap(device, port),
        local_mac(local_mac),
        gateway_mac(gateway_mac),
        device(device),
        ip_pkt_id(0x1000),
        port_to(port),
        source_ip(source_ip),
        dst_ip(dst_ip) {
}

struct ether_header udp_dealer::get_eth_header(std::vector<uint8_t> gateway_mac, std::vector<uint8_t> local_mac) {
	struct ether_header eth_header;

	memcpy(eth_header.ether_dhost, &gateway_mac[0], 6);
	memcpy(eth_header.ether_shost, &local_mac[0], 6);
	eth_header.ether_type = htons(ETHERTYPE_IP); // IP 0x0800

	return eth_header;
}

void udp_dealer::send_u8_pkt() {
    uint16_t data_length = 8;
    std::vector<uint8_t> pkt_data(DRCOM_U8_FRAME_SIZE - data_length, 0);

    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(source_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    // Data
    pkt_data.insert(pkt_data.end(), { 0x07, 0x00, 0x08, 0x00, 0x01 } );
    pkt_data.insert(pkt_data.end(), 3, 0x00);

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U8_LOG_INFO("Sent UDP package [size = 8].");
    
    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

void udp_dealer::send_u244_pkt() {
    // uint16_t data_length = 244;
    // std::vector<uint8_t> pkt_data(DRCOM_U244_FRAME_SIZE - data_length, 0);

    // struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    // memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    // struct iphdr ip_header = get_ip_header(source_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    // memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    // struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    // memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    // // Data
    // pkt_data.insert(pkt_data.end(), { 0x07, 0x01, 0xf4, 0x00, 0x01 } );
    // pkt_data.insert(pkt_data.end(), 3, 0x00);
    
//    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
//        printf("%02x ", *iter);
//    printf("\n");
}

void udp_dealer::sendalive_u40_1_pkt() {
    uint16_t data_length = 40;
    std::vector<uint8_t> pkt_data(DRCOM_U40_FRAME_SIZE - data_length, 0);

    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(source_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    //Data set
    pkt_data.push_back(0x07); // Code fixed
    pkt_data.push_back(udp_pkt_id); //packet id
    pkt_data.insert(pkt_data.end(), { 0x28, 0x00 }); // Packet Size 40 byte data per frame
    pkt_data.insert(pkt_data.end(), { 0x0b, 0x01 }); // Step,the rare set of data is self increment
    pkt_data.insert(pkt_data.end(), { 0xdc, 0x02 }); // Client Version(Uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    pkt_data.insert(pkt_data.end(), { 0x00, 0x00 }); //Unknown but not fixed, changing data!!!(According to the reference of some related material online, it seems this set of data won't affect the process of authentication)

    pkt_data.insert(pkt_data.end(), { 0x00, 0x00, 0x00, 0x00 }); // some time
    pkt_data.insert(pkt_data.end(), { 0x00, 0x00 }); // Fixed Unknown
    pkt_data.insert(pkt_data.end(), 4, 0x00);
    pkt_data.insert(pkt_data.end(), 8, 0x00); // Fixed Unknown, 0x00 *8
    pkt_data.insert(pkt_data.end(), 4, 0x00); // Fixed, default ip addr:0.0.0.0
    pkt_data.insert(pkt_data.end(), 8, 0x00); // Fixed Unknown, 0x00 *8
    //Data set end

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U40_1_LOG_INFO("Sent UDP package [size = 40].");

    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}


void udp_dealer::sendalive_u40_2_pkt() {
    uint16_t data_length = 40;
    std::vector<uint8_t> pkt_data(DRCOM_U40_FRAME_SIZE - data_length, 0);

    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(source_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    //Data set
    pkt_data.push_back(0x07); // Code fixed
    pkt_data.push_back(udp_pkt_id); //packet id
    pkt_data.insert(pkt_data.end(), { 0x28, 0x00 }); // Packet Size 40 byte data per frame
    pkt_data.insert(pkt_data.end(), { 0x0B, 0x03 }); // Step,the rare set of data is self increment
    pkt_data.insert(pkt_data.end(), { 0xdc, 0x02 }); // Client Version(Uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    pkt_data.insert(pkt_data.end(), { 0x00, 0x00 }); //Unknown but not fixed, changing data!!!(According to the reference of some related material online, it seems this set of data won't affect the process of authentication)

    pkt_data.insert(pkt_data.end(), { 0x00, 0x00, 0x00, 0x00 }); // some time
    pkt_data.insert(pkt_data.end(), { 0x00, 0x00 }); // Fixed Unknown

    pkt_data.insert(pkt_data.end(), 4, 0x00);
    memcpy( &pkt_data[], &reserved_byte, 4 );  //need to certain the position to copy the data

    pkt_data.insert(pkt_data.end(), 4, 0x00);
    memcpy( &pkt_data[], &in_cksum, 4 );

    pkt_data.insert( pkt_data.end(), local_ip.begin(), local_ip.end() );

    pkt_data.insert(pkt_data.end(), 8, 0x00);
    //Data set end

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U40_2_LOG_INFO("Sent UDP package [size = 40].");

    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");

}

void udp_dealer::sendalive_u38_pkt() {
}

struct iphdr udp_dealer::get_ip_header(const char *source, const char *dest, uint16_t total_length) {
	struct iphdr ip_header;

    ip_header.version = IPVERSION;
	ip_header.ihl = sizeof(iphdr) / 4;
    ip_header.tos = 0;
    ip_header.tot_len = htons(total_length);
    ip_header.id = htons((uint16_t)ip_pkt_id);
    ip_header.frag_off = htons(0);
    ip_header.ttl = 0x40;
    ip_header.protocol = IPPROTO_UDP;
    ip_header.check = 0;
    ip_header.saddr = inet_addr(source);
    ip_header.daddr = inet_addr(dest);
    ip_header.check  = in_cksum((uint16_t *)&ip_header, sizeof(iphdr));
    return ip_header;
}

struct udphdr udp_dealer::get_udp_header(uint16_t port_from, uint16_t port_to, uint16_t udp_total_length) {
	struct udphdr udp_header;

    udp_header.source = htons(port_from);
    udp_header.dest = htons(port_to);
    udp_header.len = htons(udp_total_length);
    udp_header.check = 0;
    udp_header.check = in_cksum((uint16_t *)&udp_header, sizeof(udphdr));

    return udp_header;
}

uint16_t udp_dealer::in_cksum(uint16_t * addr, int len) {  
    int nleft = len;  
    uint32_t sum = 0;  
    uint16_t *w = addr;  
    uint16_t answer = 0;  
  
    /* 
    * Our algorithm is simple, using a 32 bit accumulator (sum), we add 
    * sequential 16 bit words to it, and at the end, fold back all the 
    * carry bits from the top 16 bits into the lower 16 bits. 
    */  
    while (nleft > 1) {  
        sum += *w++;  
        nleft -= 2;  
    }  
    /* mop up an odd byte, if necessary */  
    if (nleft == 1) {  
        * (unsigned char *) (&answer) = * (unsigned char *) w;  
        sum += answer;  
    }  
  
    /* add back carry outs from top 16 bits to low 16 bits */  
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */  
    sum += (sum >> 16);     /* add carry */  
    answer = ~sum;     /* truncate to 16 bits */  
    return (answer);  
}  

udp_dealer::~udp_dealer() {
}