#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // getopt()
#include <pcap.h>

#include "EAP.h"
#include "EAPOL.h"
#include "Ethernet.h"
#include "authen.h"

/* for debug */
#define debug printf 

/* 长度不知道为什么是 1518 ?? */
#define SNAP_LEN 1518

/* getopt() */
extern char * optarg;
extern int optind, opterr, optopt;

/* device */

void Usage(void);
void Version(void);

void process_packet(u_char *args, const struct pcap_pkthdr *header,
				const u_char *packet);

int main(int argc, char ** argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int num_packets = -1; /* limitless */

	int opt;
	while ((opt = getopt(argc, argv, "u:p:n:lhv")) != -1) {
		switch (opt) {
		case 'u':
			strcpy(username, optarg);
			break;
		case 'p':
			strcpy(password, optarg);
			break;
		case 'n':
			strcpy(dev, optarg);
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
			Usage();
			exit(EXIT_FAILURE);
		}
	}

	printf("Device: %s\n", dev);
	printf("Username: %s\n", username);
	printf("Password: %s\n", password);
	
	/* 打开 */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Error: Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* 检测是否是以太网设备 */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Error: %s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	} 

	/* 发送认证 */
	start(handle);
	/* 抓包循环 */
	pcap_loop(handle, num_packets, process_packet, (u_char *)handle); 

	/* 清理工作 */
	pcap_close(handle);
	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header,
				const u_char *packet) {
	pcap_t * handle = (pcap_t *)args;

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
			memcpy(dst_mac, eapol->mac_src, 0x06);
			id = eap->eap_identifier;
			printf("<<<< 请求验证身份...\n");
			response_id(handle);
			break;
		case TYPE_MD5_CHALLENGE:
			id = eap->eap_identifier;
			memcpy(md5_value, (u_char *)&(eap->eap_type_data) + 1, 16);
			printf("<<<< 请求MD5密码验证...\n");
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
	printf("Usage: tinyfox [option [value]]\n");
	printf("options:\n");
	printf("\t -l \t\t List all the devs that can be detected\n");
	printf("\t -n DEV \t Set the authentication dev DEV\n");
	printf("\t -u USER \t Set the username USER\n");
	printf("\t -p PAWD \t Set the password PAWD\n");
	printf("\t -h \t\t Show this information\n");
	printf("\t -v \t\t Display this program's version number\n");
	printf("\n");
	printf("example:\n");
	printf("\t ./tinyfox -l \t Show the devs that can be used\n");
	printf("\t ./tinyfox -n eth0 -u U201217798 -p mypassword \t Authenticate\n");
	printf("\n");
	printf("如果有什么问题，可以联系 favorofife@gmail.com，随时欢迎～\n");
} 

void Version(void) {
	
}
