#ifndef AUTH_H
#define AUTH_H

#include "dot11.h"

#pragma pack(push, 1)
struct AuthPacket{
    RadiotapHdr radiotapHdr;    // 8 bytes
    uint32_t radiotapData;      // 4 bytes
    Dot11Hdr dot11Hdr;          // 24 bytes
    uint8_t fixedParm[6];       // 6 bytes

    AuthPacket() {}
    AuthPacket(Mac ap, Mac station){
        radiotapHdr.revision = 0x00;
        radiotapHdr.pad = 0x00;
        radiotapHdr.len = 0x000c;
        radiotapHdr.present = 0x00008004;
        radiotapData = 0x00180002;

        dot11Hdr.version = 0x00;
        dot11Hdr.type = 0x00;
        dot11Hdr.subtype = 0x0b;
        dot11Hdr.flag = 0x00;
        dot11Hdr.duration = 0x0000;
        dot11Hdr.addr1 = ap;    // ra
        if(station.compare(Mac("00:00:00:00:00:00"))) // station이 NULL인 경우
            printf("Error : no station mac\n");
        else    // station이 특정되어 있는 경우
            dot11Hdr.addr2 = station;  //sa는 특정 station
        dot11Hdr.addr3 = ap;    // bssid
        dot11Hdr.seqControl = 0x0000;

        fixedParm[0] = 0x00;
        fixedParm[1] = 0x00;
        fixedParm[2] = 0x01;
        fixedParm[3] = 0x00;
        fixedParm[4] = 0x00;
        fixedParm[5] = 0x00;
    }
};
#pragma pack(pop)

#endif
