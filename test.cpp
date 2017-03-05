#include <pcap.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include "def.h"
#include "eap_dealer.h"
#include "get_device_addr.h"
#include "udp_dealer.h"
using namespace std;

int main(int argc, char *argv[]) {
    std::string device = "ens33", username = "15115011018", password = "111111";
    std::string local_ip = "192.168.197.64";
    std::string authserver_ip = "192.168.127.129";
    uint16_t udp_alive_port = 61440;
    std::vector<uint8_t> local_mac= { 0xd4, 0x3d, 0x7e, 0x54, 0x95, 0x36 };
    std::vector<uint8_t> broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    std::vector<uint8_t> fujianst_mac = { 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 };
    std::vector<uint8_t> hangzhou_mac = { 0x58, 0x6a, 0xb1, 0x56, 0x78, 0x00 };

    //cout << "输出命令行参数" << endl;
    //for (int i = 1; i < argc; i++) {
        // if (!strcmp(argv[i], "-d") ||
        //     !strcmp(argv[i], "-u") ||
        //     !strcmp(argv[i], "-p")) {
        //     strcpy(device, argv[i + 1]);
        // } else if (!strcmp(argv[i], "-i")) {
        //     //
        // }
    //     cout << argv[i] << endl;
    // }

   //eap_dealer *dealer = new eap_dealer(device, local_mac, local_ip, username, password);
//    dealer->logoff(hangzhou_mac);
//    dealer->logoff(hangzhou_mac);
//    sleep(5);
//
//    if (dealer->start(broadcast_mac)) {
//        if (dealer->response_identity(hangzhou_mac)) {
//            if (dealer->response_md5_challenge(hangzhou_mac)) {
//                while (true) {
//                    dealer->alive_identity(broadcast_mac);
//                    sleep(300);
//                }
//            }
//        }
//    }
    udp_dealer *deal = new udp_dealer(device, local_mac, local_ip, hangzhou_mac, authserver_ip, udp_alive_port);
    deal->send_u244_pkt();

    printf("\n");

    return 0;
}
