#include <string>
#include <map>

using namespace::std;

struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct ieee80211_frame_header {
	u_int16_t   fc;     
	u_int16_t   duration;   
	u_int8_t	addr1[6];      
	u_int8_t	addr2[6];       
	u_int8_t	addr3[6];     
} __attribute__((__packed__));

class apInfo{
private:
	string bssid;
	int8_t pwr;
	int beaconCnt;
	int dataCnt;
	int ch;
	string essid;
public:
	apInfo(){
		apInfo("");
	}
	apInfo(string bssid){
		this->bssid = bssid;
		pwr 	= -1;
		beaconCnt = 0;
		dataCnt = 0;
		ch 		= -1;
		essid	= "";
	}
	
	void updateAPInfo(const u_char* packet);
	
	void incBeaconCnt(void){
		beaconCnt++;
	}
	void incDataCnt(void){
		dataCnt++;
	}
	void printAPInfo(void){
		printf("  %-20s%-5d%-8d%-8d%-4d%s\n", bssid.c_str(), pwr, beaconCnt, dataCnt, ch, essid.c_str());
	}
};

class staInfo{
private:
	string bssid;
	string sta;
	int frameCnt;
	string essid;
public:
	staInfo(){
		staInfo("");
	}
	staInfo(string sta){
		this->sta = sta;
		frameCnt = 0;
		bssid 	= "";
		essid	= "";
	}
	
	void updateSTAInfo(string bssid, const u_char* packet);

	void printSTAInfo(void){
		printf("  %-20s%-20s%-8d%s\n", bssid.c_str(), sta.c_str(), frameCnt, essid.c_str());
	}
};

bool analyzePkt(const u_char* packet, map<string, apInfo> *apMap, map<string, staInfo> *staMap);