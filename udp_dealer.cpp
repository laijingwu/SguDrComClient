#include "udp_dealer.h"
#include "log.h"
#include "get_device_addr.h"
#include "utils.h"

udp_dealer::udp_dealer(
        std::string device,
        std::vector<uint8_t> local_mac,
        std::string local_ip,
        std::vector<uint8_t> gateway_mac,
        std::string dst_ip,
        uint16_t port
    ) : pcap(device, port),
        local_mac(local_mac),
        gateway_mac(gateway_mac),
        device(device),
        ip_pkt_id(0x1000),
        port_to(port),
        local_ip(local_ip),
        dst_ip(dst_ip),
        udp_pkt_id(1u),
        u40_retrieved_byte(4, 0) {
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
    struct iphdr ip_header = get_ip_header(local_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    ////////////////////////////// Data set begin ////////////////////////////////
    pkt_data.insert(pkt_data.end(), { 0x07, 0x00, 0x08, 0x00, 0x01 } );
    pkt_data.insert(pkt_data.end(), 3, 0x00);
    /////////////////////////////// Data set end /////////////////////////////////

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U8_LOG_INFO("Sent UDP packet [size = 8].");
    
    // debug
    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

void udp_dealer::send_u244_pkt(std::string login_username, std::string hostname, std::string local_dns_1, std::string local_dns_2) {
    uint16_t data_length = 244;
    std::vector<uint8_t> pkt_data(DRCOM_U244_FRAME_SIZE, 0);

    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(local_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    ////////////////////////////// Data set begin ////////////////////////////////
    std::vector<uint8_t> udp_data_set;

    /*************************** Packet info part *******************************/
    udp_data_set.push_back(0x07); // fixed
    udp_data_set.push_back(udp_pkt_id); // packet counter
    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[2], &data_length, 2); // data length
    udp_data_set.push_back(0x03); // fixed
    udp_data_set.push_back(0x00);
    udp_data_set.push_back((uint8_t)login_username.length()); // username length

    /**************************** Address part **********************************/
    udp_data_set.insert(udp_data_set.end(), 6, 0x00);
    memcpy(&udp_data_set[6], &local_mac[0], 6); // local mac
    std::vector<uint8_t> vec_local_ip = str_ip_to_vec(local_ip);
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[12], &vec_local_ip[0], 4); // local ip

    udp_data_set.insert(udp_data_set.end(), { 0x02, 0x22, 0x00, 0x26 } ); // fixed unknown

    /**************************** Protocol part *********************************/
    // 4 bytes data retrieve from u8 resoponse packet(8-11bit)
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[20], &u244_retrieved_byte[0], 4);

    // udp_244_chksum, generate by function named generate_244_chksum
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);

    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // fixed

    /*************************** Basic info part ********************************/
    std::vector<uint8_t> vec_username = str_to_vec(login_username);
    udp_data_set.insert(udp_data_set.end(), 11, 0x00);
    memcpy(&udp_data_set[32], &vec_username[0], 11); // username

    std::vector<uint8_t> vec_hostname = str_to_vec(hostname);
    udp_data_set.insert(udp_data_set.end(), 15, 0x00); // fixed
    memcpy(&udp_data_set[43], &hostname[0], (hostname.size() >= 15 ? 15 : hostname.size()) );

    udp_data_set.insert(udp_data_set.end(), 17, 0x00);


    /****************************** DNS part ************************************/
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    std::vector<uint8_t> vec_dns_1 = str_ip_to_vec(local_dns_1);
    memcpy(&udp_data_set[75], &vec_dns_1[0], 4); // local dns 1

    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // fixed

    std::vector<uint8_t> vec_dns_2 = str_ip_to_vec(local_dns_2);
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[83], &vec_dns_2[0], 4); // local dns 2


    /***************************** Fixed data **********************************/
    udp_data_set.insert(udp_data_set.end(), 8, 0x00);
    udp_data_set.push_back(0x94);
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    udp_data_set.push_back(0x06);
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    udp_data_set.push_back(0x02);
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    udp_data_set.insert(udp_data_set.end(), { 0xf0, 0x23, 0x00, 0x00, 0x02 });
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    udp_data_set.insert(pkt_data.end(), { 0x44, 0x74, 0x43, 0x4f, 0x4d } ); // string 'DrCom'
    udp_data_set.insert(udp_data_set.end(), { 0x00, 0xb8, 0x01, 0x26 }); // version information of the module maybe!!!
    udp_data_set.insert(udp_data_set.end(), 55, 0x00); // fixed
    // fixed data copied from same version of official client, 
    // file hash of the auth module which was discovered in the log file. 'AuthModuleFileHash'
    udp_data_set.insert(udp_data_set.end(), { 0x39, 0x31, 0x39, 0x31, 0x36, 0x31, 0x63, 0x33, 0x64, 0x61,
                                              0x62, 0x34, 0x33, 0x35, 0x32, 0x31, 0x35, 0x64, 0x63, 0x30,
                                              0x31, 0x33, 0x30, 0x38, 0x35, 0x65, 0x39, 0x35, 0x32, 0x66,
                                              0x64, 0x62, 0x63, 0x36, 0x66, 0x35, 0x62, 0x65, 0x36, 0x36 });
    udp_data_set.insert(udp_data_set.end(), 25, 0x00);
    /////////////////////////////// Data set end /////////////////////////////////
    
    generate_244_chksum(udp_data_set); // fill in the checksum bits of 244 bytes packet.
    memcpy(&u244_checksum[0], &udp_data_set[24], 4); // save the checksum for 38 bytes packet.

    memcpy(&pkt_data[DRCOM_U244_FRAME_SIZE - data_length], &udp_data_set[0], data_length);

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U244_LOG_INFO("Sent UDP packet [size = 244].");

    // debug
    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

void udp_dealer::sendalive_u40_1_pkt() {
    uint16_t data_length = 40;
    std::vector<uint8_t> pkt_data(DRCOM_U40_FRAME_SIZE - data_length, 0);

    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(local_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    ////////////////////////////// Data set begin ////////////////////////////////
    std::vector<uint8_t> udp_data_set;
    udp_data_set.push_back(0x07); // fixed
    udp_data_set.push_back(udp_pkt_id); // packet counter
    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[2], &data_length, 2); // data length
    udp_data_set.push_back(0x0b); // fixed
    udp_data_set.push_back(0x01); // packet type
    udp_data_set.insert(udp_data_set.end(), { 0xdc, 0x02 }); // client version(uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    udp_data_set.insert(pkt_data.end(), 2, 0x00);
    // random_byte = random_func(); TODO
    memcpy(&udp_data_set[8], &random_byte, 2); // generate 2 bit by the random function!

    udp_data_set.insert(udp_data_set.end(), 6, 0x00); // fixed

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[16], &u40_retrieved_byte[0], 4); // retrieved from last u40 packet(16-19bit)

    udp_data_set.insert(udp_data_set.end(), 8, 0x00); // fixed
    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // fixed, default ip addr:0.0.0.0
    udp_data_set.insert(udp_data_set.end(), 8, 0x00); // fixed
    /////////////////////////////// Data set end /////////////////////////////////
    
    memcpy(&pkt_data[DRCOM_U40_FRAME_SIZE - data_length], &udp_data_set[0], data_length);

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U40_1_LOG_INFO("Sent UDP U40_1 alive packet [size = 40].");

    // debug
    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

void udp_dealer::sendalive_u40_2_pkt() {
    uint16_t data_length = 40;
    std::vector<uint8_t> pkt_data(DRCOM_U40_FRAME_SIZE - data_length, 0);

    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(local_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    ////////////////////////////// Data set begin ////////////////////////////////
    std::vector<uint8_t> udp_data_set;
    udp_data_set.push_back(0x07); // fixed
    udp_data_set.push_back(udp_pkt_id); // packet counter
    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[2], &data_length, 2); // data length
    udp_data_set.push_back(0x0b); // fixed
    udp_data_set.push_back(0x03); // packet type
    udp_data_set.insert(udp_data_set.end(), { 0xdc, 0x02 } ); // client version(uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    udp_data_set.insert(pkt_data.end(), 2, 0x00);
    // random_byte = random_func(); TODO
    memcpy(&udp_data_set[8], &random_byte, 2); // generate 2 bit by the random function!

    udp_data_set.insert(udp_data_set.end(), 6, 0x00); // fixed

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[16], &u40_retrieved_byte[0], 4); // retrieved from last u40 packet(16-19bit)

    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // fixed
    // udp_40_chksum, generate by function named generate_40_chksum.
    udp_data_set.insert(udp_data_set.end(), 4, 0x00); 

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    std::vector<uint8_t> vec_local_ip = str_ip_to_vec(local_ip);
    memcpy(&udp_data_set[28], &vec_local_ip[0], 4); // local ip

    udp_data_set.insert(pkt_data.end(), 8, 0x00); // fixed
    /////////////////////////////// Data set end /////////////////////////////////

    generate_40_chksum(udp_data_set); //Fill in the 40 byte packet checksum;

    memcpy(&pkt_data[DRCOM_U40_FRAME_SIZE - data_length], &udp_data_set[0], data_length);

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U40_2_LOG_INFO("Sent UDP U40_2 alive packet [size = 40].");

    // debug
    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

void udp_dealer::sendalive_u38_pkt() {
    uint16_t data_length = 38;
    std::vector<uint8_t> pkt_data(DRCOM_U38_FRAME_SIZE - data_length, 0);


    struct ether_header eth_header = get_eth_header(gateway_mac, local_mac);
    memcpy(&pkt_data[0], &eth_header, sizeof(eth_header));
    struct iphdr ip_header = get_ip_header(local_ip.c_str(), dst_ip.c_str(), IP_HEADER_SIZE + UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header)], &ip_header, sizeof(iphdr));
    struct udphdr udp_header = get_udp_header(port_to, port_to, UDP_HEADER_SIZE + data_length);
    memcpy(&pkt_data[sizeof(eth_header) + sizeof(iphdr)], &udp_header, sizeof(udphdr));

    ////////////////////////////// Data set begin ////////////////////////////////
    std::vector<uint8_t> udp_data_set;
    udp_data_set.push_back(0xff); //fixed

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[1], &u244_checksum[0], 4); //fill in u244 checksum

    udp_data_set.insert(udp_data_set.end(), 12, 0x00);
    memcpy(&udp_data_set[5], &md5_challenge_value[0], 12); //fill in the last 12 bit data of md5 challenge

    udp_data_set.insert(udp_data_set.end(), 3, 0x00); //fixed
    udp_data_set.insert(udp_data_set.end(), { 0x44, 0x72, 0x63, 0x6f }); //fixed string "Drco"

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    std::vector<uint8_t> vec_server_ip = str_ip_to_vec(dst_ip);
    memcpy(&udp_data_set[24], &vec_server_ip[0], 4); // server ip

    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[28], &u38_reserved_byte[0], 2);


    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    std::vector<uint8_t> vec_local_ip = str_ip_to_vec(local_ip);
    memcpy(&udp_data_set[30], &vec_local_ip[0], 4); // local ip

    udp_data_set.push_back(0x01); //fixed

    udp_data_set.push_back(0x00);
    memcpy(&udp_data_set[35], &u38_reserved_byte[2], 1);


     udp_data_set.insert(udp_data_set.end(), 2, 0x00);
     time_t current_time = time(0);
     memcpy(&udp_data_set[36], &current_time, 2);  //last 2 bit of the unix time system

    /////////////////////////////// Data set end /////////////////////////////////
    
    memcpy(&pkt_data[DRCOM_U38_FRAME_SIZE - data_length], &udp_data_set[0], data_length);

    std::string error;
    pcap.send_without_response(pkt_data, &error);
    U38_LOG_INFO("Sent UDP U38 alive packet [size = 38].");

    // debug
    for (std::vector<uint8_t>::iterator iter = pkt_data.begin(); iter != pkt_data.end(); iter++)
        printf("%02x ", *iter);
    printf("\n");
}

struct iphdr udp_dealer::get_ip_header(const char *source, const char *dest, uint16_t total_length) {
	struct iphdr ip_header;

    ip_header.version = IPVERSION;
	ip_header.ihl = sizeof(iphdr) / 4;
    ip_header.tos = 0;
    ip_header.tot_len = htons(total_length);
    ip_header.id = htons(ip_pkt_id);
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

void udp_dealer::generate_40_chksum(std::vector<uint8_t> &data_buf) {
    int16_t tmp = 0;
    uint16_t mid = 0;
    for (int i = 0; i < 20; i++) {
        memcpy(&tmp, &data_buf[2*i], 2);
        mid ^= tmp;
    }
    uint32_t result = uint32_t(mid)*711;
    memcpy(&data_buf[24], &result , 4);
}

void udp_dealer::generate_244_chksum(std::vector<uint8_t> &data_buf) {
    uint32_t drcom_protocol_param  = 20000711;
    memcpy(&data_buf[24], &drcom_protocol_param, 4);
    data_buf[28] = 126;

    uint16_t len = data_buf[2];
    uint32_t tmp = 0;
    uint32_t mid = 0;
    for (int i = 0; i < (len >> 2); i++) {
        memcpy(&tmp, &data_buf[4 * i], 4);
        mid ^= tmp;
    }

    data_buf[28] = 0;
    uint32_t result = mid * 19680126;
    memcpy(&data_buf[24], &result, 4);
}

//retrieve bit 8-11 from last 8 bytes response packet to fill the 20-23 bit of 244 bytes packet.
void udp_dealer::u244_retrieved_u8() {
}

//retrieve bit 16-19 from last 40 bytes response packet to fill the 16-19 bit of next 40 bytes alive packet.
void udp_dealer::u40_retrieved_last() {
}

//save the bits after calculation to std::vector<uint8_t> u38_reserved_byte in order to generate the u38 packet.
void udp_dealer::u38_retrieved_u244resp() {
    uint8_t source_bit = u38_reserved_byte[1];
    uint8_t tmp = source_bit << 1;
    if (source_bit >= 128)
        tmp |= 1;
    memcpy(&u38_reserved_byte[1], &tmp, 1);


    source_bit = u38_reserved_byte[2];
    tmp = source_bit >> 1;
    if (source_bit % 2 != 0)
        tmp |= 128;
    memcpy(&u38_reserved_byte[2], &tmp, 1);

}

udp_dealer::~udp_dealer() {
}