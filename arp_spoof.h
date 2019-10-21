#pragma once
#include <stdint.h>
#include <pcap.h>
#include <sys/socket.h>
#include <map>


using namespace std;

#define ETHER_ADDR_LEN 6
#define IP_LEN 4

#define arp_hdr_len 28
#define eth_hdr_len 14

void arp_send_pkt_req(uint8_t* send_mac, uint8_t* send_ip, uint8_t* mymac, uint8_t* myip,pcap_t* handle);
void arp_send_pkt_spoof(uint8_t* target_ip, uint8_t* send_mac, uint8_t* send_ip, uint8_t* mymac, uint8_t* myip, pcap_t* handle);
int get_gatewayip(char *gatewayip, socklen_t size);

void print_len(uint8_t* s, int n);
void get_myIpaddr(uint32_t* IP_addr, char* interface);
void get_myMacaddr(uint8_t* mac, char* interface);
void convrt_mac(const char*data, char *cvrt_str, int sz);
void arp_spoof_on(int num_session, uint32_t gatewayip, uint32_t sender_target[][100], map<uint32_t, uint8_t*> iptomac, uint8_t* mymac, uint8_t* myip, pcap_t* handle);
struct ethernet_hdr{
	uint8_t dhost[ETHER_ADDR_LEN];
	uint8_t shost[ETHER_ADDR_LEN];
	uint16_t type;
};

struct arp_head{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t  hardware_addr_len;
	uint8_t  protocol_addr_len;
	uint16_t Opcode;
	uint8_t  source_hard_addr[ETHER_ADDR_LEN];
	uint8_t  source_protocol_addr[IP_LEN];
	uint8_t  dest_hard_addr[ETHER_ADDR_LEN];
	uint8_t  dest_protocol_addr[IP_LEN];
};
