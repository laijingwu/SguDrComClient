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

    ///// Data set /////
    pkt_data.insert(pkt_data.end(), { 0x07, 0x00, 0x08, 0x00, 0x01 } );
    pkt_data.insert(pkt_data.end(), 3, 0x00);
    ///// Data set end /////

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U8_LOG_INFO("Sent UDP package [size = 8].");
    
    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

void udp_dealer::send_u244_pkt(std::vector<uint8_t> local_mac, std::vector<uint8_t> login_username, string local_ip, string local_dns_1, string local_dns_2) {
     uint16_t data_length = 244;
     std::vector<uint8_t> pkt_data(DRCOM_U244_FRAME_SIZE - data_length, 0);

     struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
     memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
     struct iphdr ip_header = get_ip_header(source_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
     memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
     struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
     memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));



    ///////////////////////////////Data set begin/////////////////////////////////
    std::vector<uint8_t> udp_data_set(data_length,0);

    /****************************Packet info part********************************/
    udp_data_set.insert(udp_data_set.end(), { 0x07, 0x01, 0xf4, 0x00, 0x03, 0x0b } );
    /****************************Packet info part********************************/

    /*****************************Address part***********************************/
    udp_data_set.insert(udp_data_set.end(), 6, 0x00); //local mac
    memcpy( &udp_data_set[6], &local_mac[0], 6 );
    udp_data_set.insert(udp_data_set.end(), 6, 0x00); //local ip
    memcpy( &udp_data_set[12], str_ip_to_vec(local_ip), 4 );
    /*****************************Address part***********************************/

    udp_data_set.insert(udp_data_set.end(), { 0x02, 0x22, 0x00, 0x26 } );

    /*****************************Protocol part**********************************/
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy( &udp_data_set[20], &reserved_byte, 4 );
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy( &udp_data_set[24], &udp_cksum, 4 );
    /*****************************Protocol part**********************************/

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);

    /****************************Basic info part*********************************/
    udp_data_set.insert(udp_data_set.end(), 11, 0x00);
    memcpy( &udp_data_set[32], &login_username, 11 );
    udp_data_set.insert(udp_data_set.end(), 15, 0x00); //Fixed
    memcpy(&udp_data_set[43], &hostname, hostname.length());
    /****************************Basic info part*********************************/

    udp_data_set.insert(udp_data_set.end(), 17, 0x00);


    /*******************************DNS part*************************************/
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy( &udp_data_set[75], str_ip_to_vec(local_dns_1), 4 );
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy( &udp_data_set[83], str_ip_to_vec(local_dns_2), 4 );
    /*******************************DNS part************************************/


    /******************************Fixed data***********************************/
    udp_data_set.insert(udp_data_set.end(), 8, 0x00);
    udp_data_set.push_back(0x94);
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    udp_data_set.push_back(0x06);
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    udp_data_set.push_back(0x02);
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    udp_data_set.insert(udp_data_set.end(), { 0xf0, 0x23, 0x00, 0x00, 0x02});
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    udp_data_set.insert(pkt_data.end(), { 0x44, 0x74, 0x43, 0x4f, 0x4d } ); //String Dr.com
    udp_data_set.insert(udp_data_set.end(), { 0x00, 0xb8, 0x01, 0x26 });
    udp_data_set.insert(udp_data_set.end(), 55, 0x00);//Fixed
    ///Fixed data copied from same version of official client, Version information of the module Maybe!!!///
    udp_data_set.insert(udp_data_set.end(), { 0x39, 0x31, 0x39, 0x31, 0x36, 0x31, 0x63, 0x33, 0x64, 0x61,
                                              0x62, 0x34, 0x33, 0x35, 0x32, 0x31, 0x35, 0x64, 0x63, 0x30,
                                              0x31, 0x33, 0x30, 0x38, 0x35, 0x65, 0x39, 0x35, 0x32, 0x66,
                                              0x64, 0x62, 0x63, 0x36, 0x66, 0x35, 0x62, 0x65, 0x36, 0x36 });
    ///Fixed data copied from same version of official client, Version information of the module Maybe!!!///
    udp_data_set.insert(udp_data_set.end(), 25, 0x00);
    /******************************Fixed data***********************************/


    ///////////////////////////////Data set begin/////////////////////////////////

     for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
         printf("%02x ", *iter);
     printf("\n");
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

    /****************************Data set*******************************/
    std::vector<uint8_t> udp_data_set(data_length,0);
    udp_data_set.push_back(0x07); // Code fixed
    udp_data_set.push_back(udp_pkt_id); //packet id
    udp_data_set.insert(udp_data_set.end(), { 0x28, 0x00 }); // Packet Size 40 byte data per frame
    udp_data_set.insert(udp_data_set.end(), { 0x0b, 0x01 }); // Step,the rare set of data is self increment
    udp_data_set.insert(udp_data_set.end(), { 0xdc, 0x02 }); // Client Version(Uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    udp_data_set.insert(pkt_data.end(), { 0x00, 0x00 }); //Generate by the random function!
    memcpy( &udp_data_set[8], &random_byte, 2 );

    udp_data_set.insert(udp_data_set.end(), { 0x00, 0x00, 0x00, 0x00 }); // some time
    udp_data_set.insert(udp_data_set.end(), { 0x00, 0x00 }); // Fixed Unknown

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);

    udp_data_set.insert(udp_data_set.end(), 8, 0x00); // Fixed Unknown, 0x00 *8
    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // Fixed, default ip addr:0.0.0.0
    udp_data_set.insert(udp_data_set.end(), 8, 0x00); // Fixed Unknown, 0x00 *8
    /****************************Data set*******************************/

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U40_1_LOG_INFO("Sent UDP package [size = 40].");

    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

void udp_dealer::sendalive_u40_2_pkt(string local_ip) {
    uint16_t data_length = 40;
    std::vector<uint8_t> pkt_data(DRCOM_U40_FRAME_SIZE - data_length, 0);


    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(source_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    /****************************Data set*******************************/
    std::vector<uint8_t> udp_data_set(data_length,0);
    udp_data_set.push_back(0x07); // Code fixed
    udp_data_set.push_back(udp_pkt_id); //packet id
    udp_data_set.insert(pkt_data.end(), { 0x28, 0x00 }); // Packet Size 40 byte data per frame
    udp_data_set.insert(pkt_data.end(), { 0x0b, 0x03 }); // Step,the rare set of data is self increment
    udp_data_set.insert(pkt_data.end(), { 0xdc, 0x02 }); // Client Version(Uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    udp_data_set.insert(pkt_data.end(), { 0x00, 0x00 }); //Generate by the random function!
    memcpy( &udp_data_set[16], &random_byte, 2 );

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    udp_data_set.insert(udp_data_set.end(), 2, 0x00);

    udp_data_set.insert(pkt_data.end(), 4, 0x00);
    memcpy( &udp_data_set[16], &reserved_byte, 4 );  //need to certain the position to copy the data

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy( &udp_data_set[20], &udp_cksum, 4 );

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy( &udp_data_set[24], str_ip_to_vec(local_ip), 4 );

    udp_data_set.insert(pkt_data.end(), 8, 0x00);
    /****************************Data set*******************************/

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U40_2_LOG_INFO("Sent UDP package [size = 40].");

    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

void udp_dealer::sendalive_u38_pkt() {

    uint16_t data_length = 38;
    std::vector<uint8_t> pkt_data(DRCOM_U40_FRAME_SIZE - data_length, 0);


    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(source_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    ///// Data set /////
    std::vector<uint8_t> udp_data_set(data_length,0);

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