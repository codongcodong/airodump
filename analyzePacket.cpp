#include <stdio.h>
#include <string.h>
#include <map>
#include "analyzePacket.h"

#define BEACONLEN 24

int getCH(uint16_t freq){

	if(freq < 3000){
		return (freq-2407)/5;
	}
	else if(freq > 5000 && freq <= 5865){
		return (freq-5000)/5;
	}
	else if(freq > 4000 && freq < 5000){
		return (freq-4000)/5;
	}
	else return -1;
}

string toString(uint8_t* mac_){
	char buf[32];
	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac_[0],
		mac_[1],
		mac_[2],
		mac_[3],
		mac_[4],
		mac_[5]);
	return std::string(buf);
}

void apInfo::updateAPInfo(const u_char* packet){		//update CH, PWR, essid
	ieee80211_radiotap_header* radiotap = (ieee80211_radiotap_header*)packet;
	bool isTSFT = ((radiotap->it_present & 1) != 0);
	bool isFlags = ((radiotap->it_present & 2) != 0);
	bool isRate = ((radiotap->it_present & 4) != 0);
	bool isChannel = ((radiotap->it_present & 8) != 0);
	bool isFHSS = ((radiotap->it_present & 16) != 0);
	bool isSignal = ((radiotap->it_present & 32) != 0);

	uint8_t* fields = ((uint8_t*)radiotap)+8;
	while( (fields[-1] & 0x80)!= 0){			//extended it_present bitmask is present
		fields+=4;
	}

	int offset;
	if(isChannel){
		offset = (isTSFT?1:0)*8 + (isFlags?1:0)*1 + (isRate?1:0)*1;
		uint16_t freq = *(uint16_t*)(fields+offset);
		this->ch = getCH(freq);
	}
	if(isSignal){
		offset += (isChannel?1:0)*4 + (isFHSS?1:0)*2;
		this->pwr = *(int8_t*)(fields+offset);
	}

	const u_char* taggedParams = packet + (radiotap->it_len) + BEACONLEN + 12;
	if(taggedParams[0] != 0){					//essid doesn't exist
		return;
	}

	int8_t essidLen = taggedParams[1];
	char essid[255];
	memcpy(essid, taggedParams+2, essidLen);
	essid[essidLen] = 0;
	this->essid = essid;
}

void staInfo::updateSTAInfo(string bssid, const u_char* packet){
	if(this->bssid == bssid){
		this->frameCnt++;
	}
	else{
		this->bssid = bssid;
		frameCnt = 1;
	}
	if(packet==nullptr){
		return;
	}

	const u_char* taggedParams = packet + (((ieee80211_radiotap_header*)packet)->it_len) + BEACONLEN;
	if(taggedParams[0] != 0){					//essid doesn't exist
		return;
	}

	int8_t essidLen = taggedParams[1];
	if(essidLen == 0){
		this->essid = "Wildcard (Broadcast)";
		return;
	}
	char essid[255];
	memcpy(essid, taggedParams+2, essidLen);
	essid[essidLen] = 0;
	this->essid = essid;
}

bool analyzePkt(const u_char* packet, map<string, apInfo> *apMap, map<string, staInfo> *staMap){

	ieee80211_radiotap_header* radiotap = (ieee80211_radiotap_header*)packet;
	ieee80211_frame_header* frameHeader = (ieee80211_frame_header*)(packet+radiotap->it_len);
	string bssid;
	string sta;

	uint8_t frameType = *(uint8_t*)frameHeader;

	if(frameType == 0x80){						//beacon frame
		bssid = toString(frameHeader->addr3);

		if(apMap->find(bssid)==apMap->end()){
			(*apMap)[bssid] = apInfo(bssid);
		}
		(*apMap)[bssid].updateAPInfo(packet);
		(*apMap)[bssid].incBeaconCnt();
	}
	else if((frameType & 0xF) == 0b1000){		//data frame
		u_int8_t flag = (*(((uint8_t*)frameHeader)+1));
		if(flag & 0b10){			//From DS
			bssid = toString(frameHeader->addr2);
			sta = toString(frameHeader->addr1);
		}
		else if(flag & 0b01){		//To DS
			bssid = toString(frameHeader->addr1);
			sta = toString(frameHeader->addr2);
		}
		else{
			puts("[EXCEPTION] IBSS PACKET DETECTED");
			return false; 
		}

		if(apMap->find(bssid)!=apMap->end()){
			(*apMap)[bssid].incDataCnt();
		}

		if(sta == "FF:FF:FF:FF:FF:FF"){
			return true;
		}
		if(staMap->find(sta)==staMap->end()){
			(*staMap)[sta] = staInfo(sta);
		}
		(*staMap)[sta].updateSTAInfo(bssid, nullptr);
	}
	else if(frameType == 0x40){				//probe request
		bssid = "(not associated)";
		sta = toString(frameHeader->addr2);

		if(staMap->find(sta)==staMap->end()){
			(*staMap)[sta] = staInfo(sta);
		}
		(*staMap)[sta].updateSTAInfo(bssid, packet);
	}
	else return false;

	return true;
}