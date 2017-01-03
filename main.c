#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <pcap.h>
#include <unistd.h>

#define BUFSIZE 1024 //beware RAM!!!

#define WLAN_FC_TYPE_DATA	2
#define WLAN_FC_SUBTYPE_DATA	0

const uint8_t dummy_mac[6] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab };

struct mac_header{
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
    //uint8_t addr4[6];
};

static const uint8_t u8aRadiotapHeader[] = {
    0x00, 0x00, // <-- radiotap version (ignore this)
    0x18, 0x00, // <-- number of bytes in our header (count the number of "0x"s)
    /**
    * The next field is a bitmap of which options we are including.
    * The full list of which field is which option is in ieee80211_radiotap.h,
    * but I've chosen to include:
    * 0x00 0x01: timestamp
    * 0x00 0x02: flags
    * 0x00 0x03: rate
    * 0x00 0x04: channel
    * 0x80 0x00: tx flags (seems silly to have this AND flags, but oh well)
    */
    0x0f, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
    /**
    * This is the first set of flags, and we've set the bit corresponding to
    * IEEE80211_RADIOTAP_F_FCS, meaning we want the card to add a FCS at the end
    * of our buffer for us.
    */
    0x10,
    0x00, // <-- rate
    0x00, 0x00, 0x00, 0x00, // <-- channel
    /**
    * This is the second set of flags, specifically related to transmissions. The
    * bit we've set is IEEE80211_RADIOTAP_F_TX_NOACK, which means the card won't
    * wait for an ACK for this frame, and that it won't retry if it doesn't get
    * one.
    */
    0x08, 0x00,
};

void *sniffFunction(char *vargp);
void *injectFunction(char *vargp);
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);

int main(int argc,uint8_t *argv[]){

    printf("%s\n",argv[1]);

    pthread_t sniffThread;
    pthread_t injectThread;
    //pthread_create(&sniffThread,NULL,(void*)sniffFunction,NULL);
    pthread_create(&injectThread,NULL,(void*)injectFunction,NULL);
    //pthread_join(sniffThread,NULL);
    pthread_join(injectThread,NULL);

    //Test mac header
    /*struct mac_header *hdr;
    uint8_t fcchunk[2]; /* 802.11 header frame control */
    /*fcchunk[0] = ((WLAN_FC_TYPE_DATA << 2) | (WLAN_FC_SUBTYPE_DATA << 4));
    fcchunk[1] = 0x02;
    memcpy(&hdr->frame_control, &fcchunk[0], 2*sizeof(uint8_t));
    hdr->duration_id = 0xffff;
    memcpy(&hdr->addr1[0], mac, 6*sizeof(uint8_t));
    memcpy(&hdr->addr2[0], mac, 6*sizeof(uint8_t));
    memcpy(&hdr->addr3[0], mac, 6*sizeof(uint8_t));
    hdr->seq_ctrl = 0;*/
    //hdr->addr4;



    return 0;
}

void *sniffFunction(char *vargp){
    int errorNo;
    char *dev="wlan0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    u_char *callback_args;

    //Use this if no dev is given
    /*dev=pcap_lookupdev(errbuf);
	if(dev== NULL){
		fprintf(stderr,"Couldn't find default device: %s\n",errbuf);
        return -1;
	}*/

	//system("sudo ifconfig wlan0 down");
	//system("sudo iwconfig wlan0 mode monitor");
	//system("sudo ifconfig wlan0 up");

    printf("Sniff device: %s\n",dev);

    handle=pcap_open_live(dev,BUFSIZE,1,1000,errbuf);
    if(pcap_can_set_rfmon(handle)){
        pcap_set_rfmon(handle,1);
        printf("Monitor mode activated\n");
    }
    else{
        printf("Monitor mode not supported\n");
    }

    if(pcap_set_datalink(handle,DLT_IEEE802_11_RADIO)==0){
        printf("Link-layer header type changed\n");
    }
    else{
        fprintf(stderr,"Couldn't change link-layer header type\n");
    }

    if(handle==NULL){
        fprintf(stderr,"Couldn't open device %s: %s\n",dev,errbuf);
        errorNo=-1;
        pthread_exit(&errorNo);
    }

    if(pcap_datalink(handle)!=DLT_IEEE802_11_RADIO){ //DLT_IEEE802_11 //DLT_EN10MB //DLT_IEEE802_11_RADIO
		fprintf(stderr,"Device %s doesn't provide Ethernet headers - not supported\n",dev);
		errorNo=-2;
		pthread_exit(&errorNo);
	}

    //Use this to read only one packet
	//packet=pcap_next(handle,&header);
    //printf("Jacked a packet with length of [%d]\n",header.len);
    //pcap_close(handle);

    //Use this to read packet in a loop
    pcap_loop(handle,100,got_packet,NULL);
    pcap_close(handle);
}

void *injectFunction(char *vargp){
    int errorNo;
    char *dev="wlan0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    //Use this if no dev is given
    /*dev=pcap_lookupdev(errbuf);
	if(dev== NULL){
		fprintf(stderr,"Couldn't find default device: %s\n",errbuf);
        return -1;
	}*/

	system("sudo ifconfig wlan0 down");
	system("sudo iwconfig wlan0 mode monitor");
	system("sudo ifconfig wlan0 up");

    printf("Inject device: %s\n",dev);

    handle=pcap_open_live(dev,BUFSIZE,1,1000,errbuf);
    if(pcap_can_set_rfmon(handle)){
        pcap_set_rfmon(handle,1);
        printf("Monitor mode activated\n");
    }
    else{
        printf("Monitor mode not supported\n");
    }

    if(pcap_set_datalink(handle,DLT_IEEE802_11_RADIO)==0){
        printf("Link-layer header type changed\n");
    }
    else{
        fprintf(stderr,"Couldn't change link-layer header type\n");
    }

    if(handle==NULL){
        fprintf(stderr,"Couldn't open device %s: %s\n",dev,errbuf);
        errorNo=-1;
        pthread_exit(&errorNo);
    }

    if(pcap_datalink(handle)!=DLT_IEEE802_11_RADIO){ //DLT_IEEE802_11 //DLT_EN10MB //DLT_IEEE802_11_RADIO
		fprintf(stderr,"Device %s doesn't provide Ethernet headers - not supported\n",dev);
		errorNo=-2;
		pthread_exit(&errorNo);
	}

    //read file
    int packets=1000;
    int i;
    long fileSize;
    char *buffer;
    char *bufferTest="MyData";
    FILE *file;
    file=fopen("packet.dat","rb");
    if(file!=NULL){
        fseek(file,0,SEEK_END);
        fileSize=ftell(file);
        rewind(file);
        buffer=(char*)malloc(sizeof(char)*fileSize);//(fileSize+1)
        fread(buffer,1,fileSize,file);
        fclose(file);
        for(i=0; i<packets; i++){
            printf("Packet Injected: %d bytes\n",pcap_inject(handle,buffer,fileSize));
            usleep(5000);
        }
        for(i=0; i<packets; i++){
            //printf("Packet Injected: %d bytes\n",pcap_inject(handle,bufferTest,fileSize));
        }
    }
    else{
        fprintf(stderr,"Error reading file \"packet.dat\"\n");
    }
}

void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet){
    static int x=0;
    printf("Packet ID: %d\n",x++);
    //printf("Packet capture length: %s\n",header->ts);
    printf("\tPacket capture length: %d\n",header->caplen);
    printf("\tPacket total length: %d\n",header->len);
    const struct mac_header *ethernet;
    ethernet=(struct mac_header*)(packet);
    printf("\tData: %d\n",ethernet->addr1[0]);
    printf("\tData: %d\n",ethernet->addr1[1]);
}
