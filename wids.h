#ifndef WIDS_H_INCLUDED
#define WIDS_H_INCLUDED

#include <stdint.h>

/* Radiotap Header v0 Template*/
static const uint8_t radiotapHeaderTemplate[]={
0x00, 0x00, /* Radiotap version */
0x0a, 0x00, /* Radiotap header length */

0x10,0x00,0x00,0x00, //IEEE80211_RADIOTAP_FLAGS, IEEE80211_RADIOTAP_TX_FLAGS
//0x0f,0x00,0x00,0x00, //IEEE80211_RADIOTAP_TX_FLAGS
//0x01, //IEEE80211_RADIOTAP_F_FCS
//0x40, //IEEE80211_RADIOTAP_F_BADFCS
0x08,0x00 //IEEE80211_RADIOTAP_F_TX_NOACK

};

/* IEEE 802.11 MAC Layer Header */
struct ieee80211macheader{
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
    uint8_t addr4[6];
} __attribute__((__packed__)) ;

/* Beacon Frame Header */
static const uint8_t beaconFrameHeader[] = {
    /* Frame control (2 bytes) */
    //Protocol version 00
    //Type 00 (Management)
    //Subtype 1000 (Beacon)
    //Bits of a byte in frame control field must be reversed so 0x04 becomes 0x80 (Confirmed on Wireshark!)
    0x80,
    //ToDS 0
    //FromDS 0
    //More fragments 0
    //Retry 0
    //Power management 0
    //More data 0
    //Protected frame 0
    //Order 0
    0x00,
    /* Duration/ID (2 bytes) */
    0x00,0x00,
    /* Address 1 (6 bytes) */
    0x01,0x23,0x45,0x67,0x89,0xab,
    /* Address 2 (6 bytes) */
    0x01,0x23,0x45,0x67,0x89,0xab,
    /* Address 3 (6 bytes) */
    0x01,0x23,0x45,0x67,0x89,0xab,
    /* Sequence control (2 bytes) */
    0x00,0x00
    /* Address 4 (Not always needed!) */
};

/* Beacon Frame Payload */
static const uint8_t beaconFramePayload[] = {
    /* Fixed parameters (12 bytes) */

    /* Timestamp (8 bytes) */
    0x00,0x00,0x00,0x77,0x77,0x77,0x77,0x77,
    /* Beacon interval (2 bytes) */
    0x64,0x00,
    /* Capabilities information (2 bytes) */
    //ESS, WEP, Short Slot Time
    0x11,0x04,

    /* Tagged parameters */

    /* Tag 1 SSID parameter set */
    //Tag number 0
    0x00,
    //Tag length 8
    0x08,
    //SSID
    0x54,0x54,0x54,0x54,0x54,0x54,0x54,0x54,

    /* Tag 2 Vendor specific */
    //Tag number 221
    0xdd,
    //Tag length 3
    0x08,
    //OUI
    0x54,0x54,0x54,
    //Type
    0x01,
    //Data
    0x55,0x55,0x55,0x55

};

#endif // WIDS_H_INCLUDED
