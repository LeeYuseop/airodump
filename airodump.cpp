#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

struct BeaconTable{
	u_int8_t bssid[6];
	int pwr, beacons, dataNo, nps, ch;
	int essidLen;
	u_char *essid;
	struct BeaconTable *next;
};

struct StationTable{
	u_int8_t bssid[6], station[6];
	int pwr;
	struct StationTalbe *next;
};

struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct Radiotap{
	u_int8_t version;
	u_int8_t pad;
	u_int16_t len;
	u_int32_t present;

	u_int8_t flags, dataRate, FHSS;
	int8_t antennaSig;
	u_int16_t chFreq, chFlag;
	u_int32_t present2;
	u_int64_t TSFT;
};

struct Beacon{
	u_int8_t type;
	u_int8_t flags;
	u_int16_t duration;
	u_int8_t dst_addr[6], src_addr[6], bssid[6];
	u_int16_t number;
};

struct Tag{
	u_int8_t number, length;
	u_int8_t *data;
	struct Tag *next;
};

struct Wireless{
	u_int8_t fixed_parameters[12];
};

void usage();

void printMac(u_int8_t *mac, int len);
void printStr(u_int8_t *str, int len);
void printBeaconTable(struct BeaconTable *beaconTable);

struct BeaconTable *findBeacon(struct BeaconTable **beaconTable, u_int8_t *bssid);

struct Radiotap getRadiotap(const u_char *packet);

void BeaconFrame(struct pcap_pkthdr *header, const u_char *packet, struct BeaconTable **beaconTable, struct Radiotap radiotap);
void ProbeRequest(const u_char *packet);
void ProbeResponse(const u_char *packet);
void Acknowledgement(const u_char *packet);
void Authentication(const u_char *packet);
void Key(const u_char *packet);
void other(const u_char *packet);

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

    char *interface = argv[1];
    
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return -1;
	}

	struct BeaconTable *beaconTable=NULL;
	struct StationTable *stationTable=NULL;

    while(1){
		struct pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0) continue;
		if(res == -1 || res == -2){
			printf("pacap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

//		struct BeaconTable.show();

		struct radiotap_header *radiotapHdr = (radiotap_header *)packet;
//		printf("%d %d %d %d\n", radiotapHdr->it_version, radiotapHdr->it_pad, radiotapHdr->it_len, radiotapHdr->it_present);

		struct Radiotap radiotap = getRadiotap(packet);

		u_int8_t subtype = packet[radiotapHdr->it_len];
		if(subtype == 0x80) BeaconFrame(header, packet, &beaconTable, radiotap);
		else if(subtype == 0x40) ProbeRequest(packet);
		else if(subtype == 0x50) ProbeResponse(packet);
		else if(subtype == 0xd4) Acknowledgement(packet);
		else if(subtype == 0xb0) Authentication(packet);
		else if(subtype == 0x88) Key(packet);
		else{
//			printf("%02x\n", subtype);
			other(packet);
		}
    }

    return 0;
}

void usage()
{
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

void printMac(u_int8_t *mac, int len)
{
	for(int i=0; i<len; i++){
		if(i) printf(":");
		printf("%02X", mac[i]);
	}
}

void printStr(u_int8_t *str, int len)
{
	for(int i=0; i<len; i++){
		printf("%c", (char)str[i]);
	}
}

void printBeaconTable(struct BeaconTable *beaconTable)
{

	std::system("clear");
	printf("\n");
	printf("CH  1 ][ Elapsed: 6 mins ][ 2020-12-09 20:38 ][ WPA handshake: 64:E5:99:7A:E9:64\n");
	printf("\n");
	printf("BSSID \t\t\tPWR \tBeacons\tESSID\n");
	printf("\n");
	struct BeaconTable *ptr;
	for(ptr=beaconTable; ptr!=NULL; ptr=ptr->next){
		printMac(ptr->bssid, 6);
		printf("\t%d \t%d \t", ptr->pwr, ptr->beacons);
		printStr(ptr->essid, ptr->essidLen);
		printf("\n");
	}
	printf("\n");
}

struct BeaconTable *findBeacon(struct BeaconTable **beaconTable, u_int8_t *bssid)
{
	int len = 6;

	struct BeaconTable *ptr;
	for(ptr=*beaconTable; ptr!=NULL; ptr=ptr->next){
		int i;
		for(i=0; i<len; i++)
			if(ptr->bssid[i] != bssid[i])
				break;
		if(i == len) return ptr;
	}

	ptr = (struct BeaconTable *)malloc(sizeof(BeaconTable));
	for(int i=0; i<len; i++)
		ptr->bssid[i] = bssid[i];
	ptr->pwr = 0;
	ptr->beacons = 0;
	ptr->dataNo = 0;
	ptr->ch = 0;
	ptr->essid = NULL;
	ptr->essidLen = 0;
	ptr->next = *beaconTable;
	*beaconTable = ptr;

	return ptr;
}

struct Radiotap getRadiotap(const u_char *packet)
{
	struct Radiotap radiotap;

	radiotap.version = ((struct Radiotap *)packet)->version;
	radiotap.pad = ((struct Radiotap *)packet)->pad;
	radiotap.len = ((struct Radiotap *)packet)->len;
	radiotap.present = ((struct Radiotap *)packet)->present;
	packet = packet + 1 + 1 + 2 + 4;

	if(radiotap.present & 0x80000000){ radiotap.present2 = *((u_int32_t *)packet); packet = packet + 4; }
	if(radiotap.present & 0x00000001){ radiotap.TSFT = *((u_int64_t *)packet); packet = packet + 8; }
	if(radiotap.present & 0x00000002){ radiotap.flags = *((u_int8_t *)packet); packet = packet + 1; }
	if(radiotap.present & 0x00000004){ radiotap.dataRate = *((u_int8_t *)packet); packet = packet + 1; }
	if(radiotap.present & 0x00000008){ radiotap.chFreq = *((u_int16_t *)packet); packet = packet + 2;
						  radiotap.chFlag = *((u_int16_t *)packet); packet = packet + 2; }
	if(radiotap.present & 0x00000010){ radiotap.FHSS = *((u_int8_t *)packet); packet = packet + 1; }
	if(radiotap.present & 0x00000020){ radiotap.antennaSig = *((int8_t *)packet); packet = packet + 1; }

	return radiotap;
}

void BeaconFrame(struct pcap_pkthdr *header, const u_char *packet, struct BeaconTable **beaconTable, struct Radiotap radiotap)
{
//	printf("Beacon frame\n");

	struct radiotap_header *radiotapHdr = (struct radiotap_header *)packet;
	struct Beacon *beacon = (struct Beacon *)(packet + radiotapHdr->it_len);
	struct Wireless *wireless = (struct Wireless *)(beacon + 1);

	struct Tag *tags = NULL;
	u_int8_t *ptr = ((u_int8_t *)wireless) + 12;
	while(ptr < packet+header->caplen){
		struct Tag *curr = (struct Tag *)malloc(sizeof(Tag));
		curr->number = *ptr;
		curr->length = *(ptr+1);
		curr->data = ptr + 2;
		curr->next = tags;
		
		tags = curr;
		ptr = ptr + curr->length+2;
	}

	struct BeaconTable *curr = findBeacon(beaconTable, beacon->bssid);

	curr->beacons++;
	curr->pwr = radiotap.antennaSig;
	if(curr->essid == NULL){
		for(struct Tag *tag=tags; tag != NULL; tag=tag->next){
			if(tag->number == 0){
				curr->essid = (u_char *)malloc(sizeof(u_char) * tag->length);
				curr->essidLen = tag->length;
				for(int i=0; i<tag->length; i++)
					curr->essid[i] = tag->data[i];
			}
		}
	}

	printBeaconTable(*beaconTable);
}

void ProbeRequest(const u_char *packet)
{
//	printf("Probe Request\n");
}
void ProbeResponse(const u_char *packet)
{
//	printf("Probe Response\n");
}
void Acknowledgement(const u_char *packet)
{
//	printf("Acknowledgement\n");
}
void Authentication(const u_char *packet)
{
//	printf("Authentication\n");
}
void Key(const u_char *packet)
{
//	printf("Key\n");
}
void other(const u_char *packet)
{
//	printf("other\n");
}