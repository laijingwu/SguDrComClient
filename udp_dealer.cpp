#include "udp_dealer.h"
#include "log.h"
#include "get_device_addr.h"
#include "utils.h"
#include "sgudrcom_exception.h"

udp_dealer::udp_dealer(
        vector<uint8_t> local_mac,
        string local_ip,
        string dst_ip,
        uint16_t port
    ) : sock(dst_ip, port, local_ip),
        local_mac(local_mac),
        port_to(port),
        local_ip(local_ip),
        dst_ip(dst_ip),
        udp_pkt_id(0u),
        u40_retrieved_byte(4, 0),
        u244_retrieved_byte(4, 0),
        u244_checksum(4, 0) {
}

bool udp_dealer::send_u8_pkt() {
    U8_LOG_INFO("Start to send." << endl);

    ////////////////////////////// Data set begin ////////////////////////////////
    vector<uint8_t> udp_data_set;
    udp_data_set.insert(udp_data_set.end(), { 0x07, 0x00, 0x08, 0x00, 0x01 } );
    udp_data_set.insert(udp_data_set.end(), 3, 0x00);
    /////////////////////////////// Data set end /////////////////////////////////

    vector<uint8_t> udp_packet_u8resp;
    string error;
    int retry_times = 0;
    bool ret;
    while (!(ret = sock.send_udp_pkt(udp_data_set, udp_packet_u8resp, error)) && retry_times < MAX_RETRY_TIME)
    {
        retry_times++;
        U8_LOG_ERR(error << ", retry times = " << retry_times << endl);
        U8_LOG_INFO("Try again after 2 seconds." << endl);
        sleep(2);
    }
    if (retry_times == MAX_RETRY_TIME)
    {
        U8_LOG_ERR("Send or Recv failed, stopped." << endl);
        return false;
    }
    U8_LOG_INFO("Sent UDP packet [size = 8]." << endl);
    if (!(u244_retrieved_u8(udp_packet_u8resp))) // save the bits for generating u244 packets.
        return send_u8_pkt();
    return ret;
}

bool udp_dealer::send_u244_pkt(string login_username, string hostname, string local_dns_1, string local_dns_2) {

    ////////////////////////////// Data set begin ////////////////////////////////
    vector<uint8_t> udp_data_set;
    uint16_t data_length = 244;

    /*************************** Packet info part *******************************/
    udp_data_set.push_back(0x07); // fixed
    udp_data_set.push_back(udp_id_counter()); // packet counter
    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[2], &data_length, 2); // data length
    udp_data_set.push_back(0x03); // fixed
    udp_data_set.push_back((uint8_t)login_username.length()); // username length

    /**************************** Address part **********************************/
    udp_data_set.insert(udp_data_set.end(), 6, 0x00);
    memcpy(&udp_data_set[6], &local_mac[0], 6); // local mac
    vector<uint8_t> vec_local_ip = str_ip_to_vec(local_ip);
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
    vector<uint8_t> vec_username = str_to_vec(login_username);
    udp_data_set.insert(udp_data_set.end(), 11, 0x00);
    memcpy(&udp_data_set[32], &vec_username[0], 11); // username

    vector<uint8_t> vec_hostname = str_to_vec(hostname);
    udp_data_set.insert(udp_data_set.end(), 15, 0x00); // fixed
    memcpy(&udp_data_set[43], &hostname[0], (hostname.size() >= 15 ? 15 : hostname.size()) );

    udp_data_set.insert(udp_data_set.end(), 17, 0x00);

    /****************************** DNS part ************************************/
    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    vector<uint8_t> vec_dns_1 = str_ip_to_vec(local_dns_1);
    memcpy(&udp_data_set[75], &vec_dns_1[0], 4); // local dns 1

    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // fixed

    vector<uint8_t> vec_dns_2 = str_ip_to_vec(local_dns_2);
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
    udp_data_set.insert(udp_data_set.end(), { 0x44, 0x72, 0x43, 0x4f, 0x4d } ); // string 'DrCom'
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


    vector<uint8_t> udp_packet_u244resp;
    string error;
    int retry_times = 0;
    bool ret;
    while (!(ret = sock.send_udp_pkt(udp_data_set, udp_packet_u244resp, error)) && retry_times < MAX_RETRY_TIME)
    {
        retry_times++;
        U244_LOG_ERR(error << ", retry times = " << retry_times << endl);
        U244_LOG_INFO("Try again after 2 seconds." << endl);
        sleep(2);
    }
    if (retry_times == MAX_RETRY_TIME)
    {
        U244_LOG_ERR("Send or Recv failed, stopped." << endl);
        return false;
    }
    U244_LOG_INFO("Sent UDP packet [size = 244]." << endl);
    if (!(u38_retrieved_u244resp(udp_packet_u244resp))) // save the bits for generating the checksum bits in u38 packets.
        return send_u244_pkt(login_username, hostname, local_dns_1, local_dns_2);
    return ret;
}

bool udp_dealer::sendalive_u40_1_pkt() {
    
    ////////////////////////////// Data set begin ////////////////////////////////
    vector<uint8_t> udp_data_set;
    uint16_t data_length = 40;

    udp_data_set.push_back(0x07); // fixed
    udp_data_set.push_back(udp_id_counter()); // packet counter
    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[2], &data_length, 2); // data length
    udp_data_set.push_back(0x0b); // fixed
    udp_data_set.push_back(0x01); // packet type
    udp_data_set.insert(udp_data_set.end(), { 0xdc, 0x02 }); // client version(uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    random_byte = xsrand();
    memcpy(&udp_data_set[8], &random_byte, 2); // generate 2 bit by the random function!

    udp_data_set.insert(udp_data_set.end(), 6, 0x00); // fixed

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[16], &u40_retrieved_byte[0], 4); // retrieved from last u40 packet(16-19bit)

    udp_data_set.insert(udp_data_set.end(), 8, 0x00); // fixed
    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // fixed, default ip addr:0.0.0.0
    udp_data_set.insert(udp_data_set.end(), 8, 0x00); // fixed
    /////////////////////////////// Data set end /////////////////////////////////

    vector<uint8_t> udp_packet_last;
    string error;
    int retry_times = 0;
    bool ret;
    while (!(ret = sock.send_udp_pkt(udp_data_set, udp_packet_last, error)) && retry_times < MAX_RETRY_TIME)
    {
        retry_times++;
        U40_1_LOG_ERR(error << ", retry times = " << retry_times << endl);
        U40_1_LOG_INFO("Try again after 2 seconds." << endl);
        sleep(2);
    }
    if (retry_times == MAX_RETRY_TIME)
    {
        U40_1_LOG_ERR("Send or Recv failed, stopped." << endl);
        return false;
    }
    U40_1_LOG_INFO("Sent UDP U40_1 alive packet [size = 40]." << endl);
    if (!(u40_retrieved_last(udp_packet_last))) // save the bits for generating the next u40 packets to send.
        return sendalive_u40_1_pkt();
    return ret;
}

bool udp_dealer::sendalive_u40_2_pkt() {
    uint16_t data_length = 40;

    ////////////////////////////// Data set begin ////////////////////////////////
    vector<uint8_t> udp_data_set;
    udp_data_set.push_back(0x07); // fixed
    udp_data_set.push_back(udp_id_counter()); // packet counter
    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[2], &data_length, 2); // data length
    udp_data_set.push_back(0x0b); // fixed
    udp_data_set.push_back(0x03); // packet type
    udp_data_set.insert(udp_data_set.end(), { 0xdc, 0x02 } ); // client version(uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[8], &random_byte, 2); // generate 2 bit by the random function!

    udp_data_set.insert(udp_data_set.end(), 6, 0x00); // fixed

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[16], &u40_retrieved_byte[0], 4); // retrieved from last u40 packet(16-19bit)

    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // fixed
    // udp_40_chksum, generate by function named generate_40_chksum.
    udp_data_set.insert(udp_data_set.end(), 4, 0x00); 

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    vector<uint8_t> vec_local_ip = str_ip_to_vec(local_ip);
    memcpy(&udp_data_set[28], &vec_local_ip[0], 4); // local ip

    udp_data_set.insert(udp_data_set.end(), 8, 0x00); // fixed
    /////////////////////////////// Data set end /////////////////////////////////

    generate_40_chksum(udp_data_set); //Fill in the 40 byte packet checksum;

    vector<uint8_t> udp_packet_last;
    string error;
    int retry_times = 0;
    bool ret;
    while (!(ret = sock.send_udp_pkt(udp_data_set, udp_packet_last, error)) && retry_times < MAX_RETRY_TIME)
    {
        retry_times++;
        U40_2_LOG_ERR(error << ", retry times = " << retry_times << endl);
        U40_2_LOG_INFO("Try again after 2 seconds." << endl);
        sleep(2);
    }
    if (retry_times == MAX_RETRY_TIME)
    {
        U40_2_LOG_ERR("Send or Recv failed, stopped." << endl);
        return false;
    }
    U40_2_LOG_INFO("Sent UDP U40_2 alive packet [size = 40]." << endl);
    return ret;
    // u40_retrieved_last(); //save the bits for generating the next u40 packets to send.
}

bool udp_dealer::sendalive_u38_pkt(vector<uint8_t> md5_challenge_value) {

    ////////////////////////////// Data set begin ////////////////////////////////
    vector<uint8_t> udp_data_set;
    udp_data_set.push_back(0xff); //fixed

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[1], &u244_checksum[0], 4); //fill in u244 checksum

    udp_data_set.insert(udp_data_set.end(), 12, 0x00);
    memcpy(&udp_data_set[5], &md5_challenge_value[16-12], 12); //fill in the last 12 bit data of md5 challenge

    udp_data_set.insert(udp_data_set.end(), 3, 0x00); //fixed
    udp_data_set.insert(udp_data_set.end(), { 0x44, 0x72, 0x63, 0x6f }); //fixed string "Drco"

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    vector<uint8_t> vec_server_ip = str_ip_to_vec(dst_ip);
    memcpy(&udp_data_set[24], &vec_server_ip[0], 4); // server ip

    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[28], &u38_reserved_byte[0], 2);


    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    vector<uint8_t> vec_local_ip = str_ip_to_vec(local_ip);
    memcpy(&udp_data_set[30], &vec_local_ip[0], 4); // local ip

    udp_data_set.push_back(0x01); //fixed

    udp_data_set.push_back(0x00);
    memcpy(&udp_data_set[35], &u38_reserved_byte[2], 1);


    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    time_t current_time = time(0);
    memcpy(&udp_data_set[36], &current_time, 2);  //last 2 bit of the unix time system
    /////////////////////////////// Data set end /////////////////////////////////

    vector<uint8_t> udp_packet_recv;
    string error;
    int retry_times = 0;
    bool ret;
    while (!(ret = sock.send_udp_pkt(udp_data_set, udp_packet_recv, error)) && retry_times < MAX_RETRY_TIME)
    {
        retry_times++;
        U38_LOG_ERR(error << ", retry times = " << retry_times << endl);
        U38_LOG_INFO("Try again after 2 seconds." << endl);
        sleep(2);
    }
    if (retry_times == MAX_RETRY_TIME)
    {
        U38_LOG_ERR("Send or Recv failed, stopped." << endl);
        return false;
    }
    U38_LOG_INFO("Sent UDP U38 alive packet [size = 38]." << endl);
    return ret;
}

bool udp_dealer::sendalive_u40_3_pkt() {
    uint16_t data_length = 40;

    ////////////////////////////// Data set begin ////////////////////////////////
    vector<uint8_t> udp_data_set;
    udp_data_set.push_back(0x07); // fixed
    udp_data_set.push_back(udp_id_counter()); // packet counter
    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    memcpy(&udp_data_set[2], &data_length, 2); // data length
    udp_data_set.push_back(0x0b); // fixed
    udp_data_set.push_back(0x01); // packet type
    udp_data_set.insert(udp_data_set.end(), { 0xdb, 0x02 } ); // client version(uncertain) 5.2.1X fixed { 0xdc , 0x02 }

    udp_data_set.insert(udp_data_set.end(), 2, 0x00);
    random_byte = xsrand();
    memcpy(&udp_data_set[8], &random_byte, 2); // generate 2 bit by the random function!

    udp_data_set.insert(udp_data_set.end(), 6, 0x00); // fixed

    udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    memcpy(&udp_data_set[16], &u40_retrieved_byte[0], 4); // retrieved from last u40 packet(16-19bit)

    udp_data_set.insert(udp_data_set.end(), 4, 0x00); // fixed
    // udp_40_chksum, generate by function named generate_40_chksum.
    udp_data_set.insert(udp_data_set.end(), 4, 0x00); 

    // udp_data_set.insert(udp_data_set.end(), 4, 0x00);
    // vector<uint8_t> vec_local_ip = str_ip_to_vec(local_ip);
    // memcpy(&udp_data_set[28], &vec_local_ip[0], 4); // local ip

    udp_data_set.insert(udp_data_set.end(), 12, 0x00); // fixed 8
    /////////////////////////////// Data set end /////////////////////////////////

    generate_40_chksum(udp_data_set); //Fill in the 40 byte packet checksum;

    vector<uint8_t> udp_packet_recv;
    string error;
    int retry_times = 0;
    bool ret;
    while (!(ret = sock.send_udp_pkt(udp_data_set, udp_packet_recv, error)) && retry_times < MAX_RETRY_TIME)
    {
        retry_times++;
        U40_3_LOG_ERR(error << ", retry times = " << retry_times << endl);
        U40_3_LOG_INFO("Try again after 2 seconds." << endl);
        sleep(2);
    }
    if (retry_times == MAX_RETRY_TIME)
    {
        U40_3_LOG_ERR("Send or Recv failed, stopped." << endl);
        return false;
    }
    U40_3_LOG_INFO("Sent UDP U40_3 alive packet [size = 40]." << endl);
    return ret;
}

uint8_t udp_dealer::udp_id_counter() {
    if (udp_pkt_id == 0xff)
        udp_pkt_id = 0;
    else
        udp_pkt_id++;
    return udp_pkt_id;
}

void udp_dealer::generate_40_chksum(vector<uint8_t> &data_buf) {
    int16_t tmp = 0;
    uint16_t mid = 0;
    for (int i = 0; i < 20; i++) {
        memcpy(&tmp, &data_buf[2*i], 2);
        mid ^= tmp;
    }
    uint32_t result = uint32_t(mid)*711;
    memcpy(&data_buf[24], &result , 4);
}

void udp_dealer::generate_244_chksum(vector<uint8_t> &data_buf) {
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

// retrieve bit 8-11 from last 8 bytes response packet to fill the 20-23 bit of 244 bytes packet.
bool udp_dealer::u244_retrieved_u8(vector<uint8_t> &udp_packet_u8resp) {
    if (udp_packet_u8resp[0] != 0x07) return false;
    udp_packet_u8resp.resize(32);
    memcpy(&u244_retrieved_byte[0], &udp_packet_u8resp[8], 4);
    return true;
}

// retrieve bit 16-19 from last 40 bytes response packet to fill the 16-19 bit of next 40 bytes alive packet.
bool udp_dealer::u40_retrieved_last(vector<uint8_t> &udp_packet_last) {
    if (udp_packet_last[0] == 0x07 && udp_packet_last[4] == 0x0b && udp_packet_last[5] == 0x02) {
        udp_packet_last.resize(40);
        memcpy(&u40_retrieved_byte[0], &udp_packet_last[16], 4);
        return true;
    } else
        return false;
}

// save the bits after calculation to vector<uint8_t> u38_reserved_byte in order to generate the u38 packet.
bool udp_dealer::u38_retrieved_u244resp(vector<uint8_t> &udp_packet_u244resp) {
    if (udp_packet_u244resp[0] != 0x07 && udp_packet_u244resp[4] != 0x04) return false;
    udp_packet_u244resp.resize(48);

    memcpy(&u38_reserved_byte[0], &udp_packet_u244resp[24], 2);
    memcpy(&u38_reserved_byte[2], &udp_packet_u244resp[31], 1);

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
    return true;
}

udp_dealer::~udp_dealer() {
}