#ifndef BEACON_H
#define BEACON_H

#include "dot11.h"

struct BeaconHdr{
    RadiotapHdr radiotapHdr;    // 8 bytes
    Dot11Hdr dot11Hdr;      // 24 bytes

    void setDot11Hdr() {
        char* res = (char*)this;
        res += this->radiotapHdr.len;
        this->dot11Hdr = *(Dot11Hdr*)res;
    }

    Mac getBSSID(){
        return this->dot11Hdr.addr3;
    }
};

#endif

