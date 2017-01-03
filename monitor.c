#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <pcap.h>
#include <unistd.h>

#define OPTION_MAX_LENGTH 100
#define OPTION_VALUE_MAX_LENGTH 1000

struct radiotapheader{
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct mac80211header{
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
    //uint8_t addr4[6];
} __attribute__((__packed__));

void printHelp();
int interfaceExists(char *dev);
void activateMonitorModeTerminal(char *dev);
void startMonitor(char *dev,char *mode,char *ssid,char *psk);
void gotPacketBeaconMode(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
int isBeaconFrame(uint16_t fc);
void scanParameters(const uint8_t *data,u_char *ssid,u_char *psk,int payload_length);

int main(int argc,char *argv[]){
    int i;
    char **options;
    char **optionValues;
    char *mode;
    char *ssid;
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
                else if(strcmp(options[i],"-psk")==0){
                    psk=(char*)malloc(strlen(optionValues[i])+1);
                    memcpy(psk,optionValues[i],strlen(optionValues[i]));
                    memcpy(psk+strlen(optionValues[i]),"\0",1);
                }
                else{
                    fprintf(stderr,"Wrong command usage!\n");
                    fprintf(stderr,"Option %s does not exist!\n",options[i]);
                    exit(1);
                }
            }
            //activateMonitorModeTerminal(argv[1]);
            startMonitor(argv[1],mode,ssid,psk);
        }
        else{
            fprintf(stderr,"Interface %s not found\n",argv[1]);
            exit(1);
        }
    }
    return 0;
}

void printHelp(){
    printf("Note: Run the program with administrator privileges\n");
    printf("Usage: monitor [interface] options\n");
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
            //pcap_freealldevs(alldevs); ???
            return 1;
        }
    }
    //pcap_freealldevs(alldevs); ???
    return 0;
}

void activateMonitorModeTerminal(char *dev){

    //We have to check if the device supports monitor mode

    /*
    We want to execute these commands for the given device
    sudo ifconfig <interface> down
    sudo iwconfig <interface> mode monitor
    sudo ifconfig <interface> up
    */

    char cmd[50];
    strcpy(cmd,"sudo ifconfig ");
    strcat(cmd,dev);
    strcat(cmd," down");
    system(cmd);
    printf("\t$%s\n",cmd);

    strcpy(cmd,"");
    strcpy(cmd,"sudo iwconfig ");
    strcat(cmd,dev);
    strcat(cmd," mode monitor");
    system(cmd);
    printf("\t$%s\n",cmd);

    strcpy(cmd,"");
    strcpy(cmd,"sudo ifconfig ");
    strcat(cmd,dev);
    strcat(cmd," up");
    system(cmd);
    printf("\t$%s\n",cmd);

    printf("%s: Monitor mode activated\n",dev);
}

void startMonitor(char *dev,char *mode,char *ssid,char *psk){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int datalinkNumber;
    char const *datalinkName;

    /* Open interface */
    handle=pcap_open_live(dev,1024,1,0,errbuf); // 1: promiscuous, 0: no read timeout
    if(handle!=NULL){
         printf("Opened interface %s\n",dev);
    }
    else{
        printf("Couldn't open interface %s: %s\n",dev,errbuf);
        exit(1);
    }

    /* Activate monitor mode */
    if(pcap_can_set_rfmon(handle)){
        pcap_set_rfmon(handle,1);
        printf("%s: Monitor mode activated\n",dev);
    }
    else{
        printf("%s: Monitor mode cannot be activated\n",dev);
        exit(1);
    }

    /* Datalink */
    datalinkNumber=pcap_datalink(handle);
    datalinkName=pcap_datalink_val_to_name(datalinkNumber);
    printf("%s: Link-layer header type: %s\n",dev,datalinkName);

    printf("%s: Interface ready\n",dev);

    /* Capture wids-related data */
    if(strcmp(mode,"beacon")==0){
        u_char *args;
        int *_args;
        _args=(int*)malloc(2*sizeof(int));
        _args[0]=ssid;
        _args[1]=psk;
        args=_args;
        pcap_loop(handle,1000,gotPacketBeaconMode,args);
        pcap_close(handle);
    }

}

void gotPacketBeaconMode(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
    int *args_array;
    args_array=args;
    u_char *ssid;
    u_char *psk;
    ssid=args_array[0];
    psk=args_array[1];

    /* Radiotap header */
    const struct radiotapheader *radiotap;
    radiotap=(struct radiotapheader*)(packet);

    /* IEEE 802.11 MAC Layer Header */
    const struct mac80211header *mac80211;
    mac80211=(struct mac80211header*)(packet+radiotap->it_len);

    /* IEEE 802.11 Frame Payload */
    const uint8_t *data;
    data=(uint8_t*)(packet+radiotap->it_len+24);

    /* Distinguish beacon frames */
    if(isBeaconFrame(mac80211->frame_control)==1){ /* subtype | type | protocol version */
        scanParameters(data,ssid,psk,header->len-radiotap->it_len-24);
    }

}

/*
    first byte:     1000 0000  subtype | type | protocol version
    second byte:    0000 0000   flags
    uint16_t:   0000 0000 1000 0000 -> 128
*/
int isBeaconFrame(uint16_t fc){
    uint16_t byte=fc;
    /* clear flags */
    byte=byte<<8;
    byte=byte>>8;
    if(byte==128){
        return 1;
    }
    return 0;
}

void scanParameters(const uint8_t *data,u_char *ssid,u_char *psk,int payload_length){
    /*
        First 12 bytes are fixed parameters
            -Timestamp (8 bytes)
            -Beacon Interval (2 bytes)
            -Capabilities Information (2 bytes)
    */
    int i=12;
    int tag_length;
    u_char *ssid_scanned;
    int repeat=1;
    int ssid_found=0;
    /* Scan for SSID parameter */
    while(i<=payload_length-4&&repeat==1){ /* Last 4 bytes are Frame Check Sequence (FCS) */
        if((uint8_t)data[i]==0){ /* SSID parameter set (0) */
            tag_length=(uint8_t)data[i+1];
            ssid_scanned=(u_char*)malloc(tag_length+1);
            memcpy(ssid_scanned,data+i+2,tag_length);
            memcpy(ssid_scanned+tag_length,"\0",1);
            if(strcmp(ssid,ssid_scanned)==0){
                ssid_found=1;
                repeat=0;
            }
            else{
                free(ssid_scanned);
                repeat=0;
            }
        }
        else{
            /* Ignore other tags */
        }
        i+=2+tag_length;
    }
    /* If valid SSID found, scan for wids-related information */
    if(ssid_found==1){
        i=12;
        repeat=1;
        u_char *vendor_specific;
        int data_type;
        uint8_t *iv;
        uint8_t *wids_data;
        while(i<=payload_length-4&&repeat==1){ /* Last 4 bytes are Frame Check Sequence (FCS) */
            if((uint8_t)data[i]==221){ /* Vendor Specific (221) */
                tag_length=(uint8_t)data[i+1];
                if(tag_length==3+16+128){
                    if((uint8_t)data[i+2]==170&&(uint8_t)data[i+3]==170&&(uint8_t)data[i+4]==170){ /* OUI: AA-AA-AA */
                        /* IV */
                        iv=(uint8_t*)malloc(16*sizeof(uint8_t));
                        memcpy(iv,data+i+2+3,16);
                        /* Encrypted data */
                        wids_data=(uint8_t*)malloc(128*sizeof(uint8_t));
                        memcpy(wids_data,data+i+2+3+16,128);
                        /* Save wids-related cpatured data */
                        printf("Found something\n");

                        ///
                        repeat=0;
                        free(ssid_scanned);
                        free(wids_data);
                    }
                    else{
                        /* Ignore other OUIs */
                    }
                }
                else{
                    /* Ignore invalid-length OUI tags */
                }
            }
            else{
                /* Ignore other tags */
            }
            i+=2+tag_length;
        }
    }
}
