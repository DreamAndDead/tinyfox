#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // getopt()
#include <pcap.h>

#include "EAP.h"
#include "EAPOL.h"
#include "Ethernet.h"
#include "authen.h"

/* 长度不知道为什么是 1518 ?? */
#define SNAP_LEN 1518

extern char * optarg;
extern int optind, opterr, optopt;

void Usage(void);
void Version(void);

void process_packet(u_char *args, const struct pcap_pkthdr *header,
				const u_char *packet);

int main(int argc, char ** argv) {
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int num_packets = -1; /* limitless */

	int opt;
	while ((opt = getopt(argc, argv, "u:p:n:lhv")) != -1) {
		switch (opt) {
		case 'u':
			username = optarg;
			break;
		case 'p':
			password = optarg;
			break;
		case 'n':
			dev = optarg;
			break;
		case 'l':
			ListDevs();
			return 0;
		case 'h':
			Usage();
			return 0;
		case 'v':
			Version();
			return 0;
		default:
			fprintf(stderr, "Usage: %s ", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	printf("device: %s, number of packets: %d, filter: %s \n",
		   dev, num_packets, filter_exp);
	
	/* 打开 */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* 检测是否是以太网设备 */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	} 

	/* 抓包循环 */
	pcap_loop(handle, num_packets, process_packet, (u_char *)handle); 

	/* 清理工作 */
	pcap_close(handle);
	return 0;
}

/* 这里有一个陷阱，即下面的代码是抓包之后执行的，如果完全没有联网，
 * 则不会运行，后期要修改逻辑 
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header,
				const u_char *packet) {
	pcap_t * handle = (pcap_t *)args;

	// 开始认证是一个特殊的情况
	if (State == START) {
		start(handle);
		State = REQUEST_ID;
		return;
	}

	/* eapol packet filter */
	const struct ethernet_struct *ethe;
	ethe = (struct ethernet_struct *)(packet);

	if (ethe->ethe_type != 0x8e88)
		return;

	/* receive packet, parse, change state */
	const struct eapol_struct *eapol;
	const struct eap_struct *eap;

	eapol = (struct eapol_struct *)(packet);
	eap = (struct eap_struct *)(&(eapol->eapol_packet_body));

	switch (eap->eap_code) {
	case CODE_REQUEST:
		switch (eap->eap_type) {
		case TYPE_IDENTITY:
			id = eap->eap_identifier;
			response_id(handle);
			break;
		case TYPE_MD5_CHALLENGE:
			id = eap->eap_identifier;
			memcpy(md5_value, (u_char *)&(eap->eap_type_data) + 1, 16);
			response_md5(handle);
			break;
		}
		break;
	case CODE_SUCCESS:
		success(eap);
		break;
	case CODE_FAILURE:
		failure();
		break;
	}
}

void Usage(void) {
	printf("Usage: Tinyfox [option [value]]\n");
	printf("\t options:\n");
	printf("\t\t -l \t List all the devs that can be detected\n");
	printf("\t\t -n DEV \t Set the authentication dev DEV\n");
	printf("\t\t -u USER \t Set the username USER\n");
	printf("\t\t -p PAWD \t Set the password PAWD\n");
	printf("\t\t -h \t Show this information");
	printf("\t\t -v \t Display this program's version number\n");
	printf("\n\n");
	printf("如果遇到什么问题，联系 favorofife@gmail.com");
} 

void Version(void) {
	
}
