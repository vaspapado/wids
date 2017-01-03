#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <pcap.h>
#include <unistd.h>
#include "aes.h"

//#include <wids.h>

static const uint8_t radiotapHeader[]={
0x00, 0x00, /* Radiotap version */
0x0a, 0x00, /* Radiotap header length */

0x10,0x00,0x00,0x00, //IEEE80211_RADIOTAP_FLAGS, IEEE80211_RADIOTAP_TX_FLAGS
//0x0f,0x00,0x00,0x00, //IEEE80211_RADIOTAP_TX_FLAGS
//0x01, //IEEE80211_RADIOTAP_F_FCS
//0x40, //IEEE80211_RADIOTAP_F_BADFCS
0x08,0x00 //IEEE80211_RADIOTAP_F_TX_NOACK

};

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

static uint8_t beaconFramePayload[] = {
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

void printHelp();
int interfaceExists(char *dev);
void startBroadcast(char *dev,char *mode,char *ssid,char *psk);
uint8_t *getBeaconFramePayload(char *ssid,char *psk,int *length);
uint8_t *getTimestamp();
uint8_t *getBeaconInterval();
uint8_t *getCapabilities();
uint8_t *getIV();
uint8_t *getEncryptedData(char *psk,uint8_t *iv,uint8_t *data);

int main(int argc,char *argv[]){
    int i;
    char **options;
    char **optionValues;
    char *mode;
    char *ssid;
    char *pskfile;
    char *psk;
    if(argc==1){
        printHelp();
        exit(0);
    }
    else if(argc%2!=0){
        fprintf(stderr,"Wrong command usage!\n");
        printHelp();
        exit(1);
    }
    else{
        printf("Note: Run the program with administrator privileges\n");
        if(interfaceExists(argv[1])==1){
            printf("Interface %s found\n",argv[1]);
            options=(char**)malloc(((argc-2)/2)*sizeof(char*));
            optionValues=(char**)malloc(((argc-2)/2)*sizeof(char*));
            for(i=0; i<(argc-2)/2; i++){
                options[i]=argv[2+2*i];
                optionValues[i]=argv[3+2*i];
            }
            for(i=0; i<(argc-2)/2; i++){
                if(strcmp(options[i],"-mode")==0){
                    if(strcmp(optionValues[i],"beacon")==0){
                        mode=(char*)malloc(strlen(optionValues[i])+1);
                        memcpy(mode,optionValues[i],strlen(optionValues[i]));
                        memcpy(mode+strlen(optionValues[i]),"\0",1);
                    }
                    else{
                        fprintf(stderr,"Wrong command usage!\n");
                        fprintf(stderr,"Mode %s does not exist!\n",optionValues[i]);
                        exit(1);
                    }
                }
                else if(strcmp(options[i],"-ssid")==0){
                    if(strlen(optionValues[i])<33){
                        ssid=(char*)malloc(strlen(optionValues[i])+1);
                        memcpy(ssid,optionValues[i],strlen(optionValues[i]));
                        memcpy(ssid+strlen(optionValues[i]),"\0",1);
                    }
                    else{
                        fprintf(stderr,"Invalid SSID length!\n");
                        fprintf(stderr,"SSID cannot be more than 32 characters!\n");
                        exit(1);
                    }
                }
                else if(strcmp(options[i],"-pskfile")==0){
                    pskfile=(char*)malloc(strlen(optionValues[i])+1);
                    memcpy(pskfile,optionValues[i],strlen(optionValues[i]));
                    memcpy(pskfile+strlen(optionValues[i]),"\0",1);

                    FILE *file;
                    file=fopen(pskfile,"rb");
                    if(file!=NULL){
                        fseek(file,0,SEEK_END);
                        int fileSize=ftell(file);
                        if(fileSize==128){
                            rewind(file);
                            psk=(char*)malloc(128*sizeof(char));
                            fread(psk,1,fileSize,file);
                            fclose(file);
                        }
                        else{
                            fprintf(stderr,"Invalid key length!\n");
                            exit(1);
                        }
                    }
                    else{
                        fprintf(stderr,"Error reading key file!\n");
                        exit(1);
                    }
                }
                else{
                    fprintf(stderr,"Wrong command usage!\n");
                    fprintf(stderr,"Option %s does not exist!\n",options[i]);
                    exit(1);
                }
            }
            startBroadcast(argv[1],mode,ssid,psk);
        }
        else{
            fprintf(stderr,"Interface %s not found\n",argv[1]);
            exit(1);
        }
    }
    return 0;
}

void printHelp(){
    printf("Note: Run the program with administrator privileges");
    printf("Usage: broadcast [interface] options\n");
    printf("Options:\n");

    printf("\n");
}

int interfaceExists(char *dev){
    pcap_if_t *alldevs;
    pcap_if_t *currentdev;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs,errbuf)==-1){ // pcap_findalldevs may be obsolete
        fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
        exit(1);
    }
    for(currentdev=alldevs; currentdev!=NULL; currentdev=currentdev->next){
        if(strcmp(currentdev->name,dev)==0){
            //pcap_freealldevs(alldevs);
            return 1;
        }
    }
    //pcap_freealldevs(alldevs);
    return 0;
}

void startBroadcast(char *dev,char *mode,char *ssid,char *psk){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int datalinkNumber;
    char const *datalinkName;

    /* Open interface */
    handle=pcap_open_live(dev,BUFSIZ,1,0,errbuf); // 1: promiscuous, 0: no read timeout
    if(handle!=NULL){
         printf("Opened device %s\n",dev);
    }
    else{
        printf("Couldn't open device %s: %s\n",dev,errbuf);
        exit(1);
    }

    /* Datalink information*/
    datalinkNumber=pcap_datalink(handle);
    datalinkName=pcap_datalink_val_to_name(datalinkNumber);
    printf("%s: Link-layer header type: %s\n",dev,datalinkName);

    /* Prepare data for broadcasting */
    if(strcmp(mode,"beacon")==0){
        /* Prepare beacon frame payload */
        int payload_length;
        uint8_t *payload=getBeaconFramePayload(ssid,psk,&payload_length);
        /*
            Prepare buffer: Radiotap Header | Beacon Frame Header | Beacon Frame Payload
        */
        int buffer_size=sizeof(radiotapHeader)+sizeof(beaconFrameHeader)+payload_length;
        uint8_t *buffer;
        buffer=(uint8_t*)malloc(buffer_size);
        memcpy(buffer,radiotapHeader,sizeof(radiotapHeader));
        memcpy(buffer+sizeof(radiotapHeader),beaconFrameHeader,sizeof(beaconFrameHeader));
        memcpy(buffer+sizeof(radiotapHeader)+sizeof(beaconFrameHeader),payload,payload_length);
        /* Broadcast data */
        int i;
        for(i=0; i<5; i++){
            pcap_inject(handle,buffer,buffer_size);
        }
    }

}

uint8_t *getBeaconFramePayload(char *ssid,char *psk,int *length){
    int cnt=0;
    uint8_t *payload;
    payload=(uint8_t*)malloc((12+2+strlen(ssid)+2+3+16+128)*sizeof(uint8_t));
    *length=12+2+strlen(ssid)+2+3+16+128;
    /* Append fixed parameters */
    memcpy(payload+cnt,getTimestamp(),8); cnt+=8;
    memcpy(payload+cnt,getBeaconInterval(),2); cnt+=2;
    memcpy(payload+cnt,getCapabilities(),2); cnt+=2;
    /* Append SSID parameter */
    memset(payload+cnt,0,1); cnt++;
    memset(payload+cnt,strlen(ssid),1); cnt++;
    memcpy(payload+cnt,ssid,strlen(ssid)); cnt+=strlen(ssid);
    /* Append wids-related information */
    memset(payload+cnt,221,1); cnt++; // Tag number: Vendor Specific (221)
    memset(payload+cnt,147,1); cnt++; // Tag length (variable:5)
    memset(payload+cnt,170,1); cnt++; // OUI byte 1
    memset(payload+cnt,170,1); cnt++; // OUI byte 2
    memset(payload+cnt,170,1); cnt++; // OUI byte 3

    //memset(payload+cnt,170,1); cnt++; // Vendor Specific OUI Type
    //memset(payload+cnt,255,1); cnt++; // Vendor Specific Data

    uint8_t *iv;
    iv=getIV();
    memcpy(payload+cnt,iv,16); cnt+=16; //IV

    uint8_t *encrypted_data;
    encrypted_data=getEncryptedData(psk,iv,NULL);
    memcpy(payload+cnt,encrypted_data,128); cnt+=128; //Encrypted Data

    return payload;
}

uint8_t *getTimestamp(){
    uint8_t *timestamp;
    timestamp=(uint8_t*)malloc(8*sizeof(uint8_t));
    uint8_t ts[]={0x00,0x00,0x00,0x77,0x77,0x77,0x77,0x77};
    memcpy(timestamp,ts,8);
    return timestamp;
}

uint8_t *getBeaconInterval(){
    uint8_t *interval;
    interval=(uint8_t*)malloc(2*sizeof(uint8_t));
    uint8_t inter[]={0x64,0x00};
    memcpy(interval,inter,2);
    return interval;
}

uint8_t *getCapabilities(){
    uint8_t *capabilities;
    capabilities=(uint8_t*)malloc(2*sizeof(uint8_t));
    uint8_t cap[]={0x11,0x04}; // ESS, WEP, Short Slot Time
    memcpy(capabilities,cap,2);
    return capabilities;
}

uint8_t *getIV(){
    uint8_t *iv;
    iv=(uint8_t*)malloc(16*sizeof(uint8_t));
    memcpy(iv,"aaaaaaaaaaaaaaaa",16);
    return iv;
}

uint8_t *getEncryptedData(char *psk,uint8_t *iv,uint8_t *data){
    uint8_t *encrypted_data;
    encrypted_data=(uint8_t*)malloc(128*sizeof(uint8_t));

    //
    uint8_t *_data;
    _data=(uint8_t*)malloc(10*sizeof(uint8_t));
    memcpy(_data,"VASILIS",7);
    //

    AES128_CBC_encrypt_buffer(encrypted_data,_data,7,psk,iv);
    return encrypted_data;
}



