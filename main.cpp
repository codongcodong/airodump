#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <map>
#include "analyzePacket.h"

void usage(void){
	puts("syntax : airodump <interface>");
	puts("sample : airodump mon0");
}

int main(int argc, char** argv){
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	struct pcap_pkthdr* header;
	const u_char* packet;
	int res;

	if (argc != 2) {
		usage();
		return -1;
	}

	dev = argv[1];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
		return -1;
	}

	map<std::string, apInfo> apMap;
	map<std::string, staInfo> staMap;

	while (true) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		if(analyzePkt(packet, &apMap, &staMap)){			//an update has occured
			system("clear");
			printf("  %-20s%-5s%-8s%-8s%-4s%s\n\n", "BSSID", "PWR", "Beacons", "#Data", "CH", "ESSID");
			for(auto ap : apMap){
				ap.second.printAPInfo();
			}
			puts("");
			printf("  %-20s%-20s%-8s%s\n\n", "BSSID", "STATION", "Frames", "Probes");
			for(auto sta : staMap){
				sta.second.printSTAInfo();
			}
		}
	}

	pcap_close(handle);
}
