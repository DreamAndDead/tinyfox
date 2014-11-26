#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h> // big <--> little endian convert
#include <sys/ioctl.h> // GetMac()
#include <net/if.h> 

#include "authen.h"

/*
 * libcrypto.so 动态链接库中，MD5 函数调用
 */
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);

char username[20];
char password[20];
u_char id;
char md5_value[16];

char dev[20];

const u_char broad_mac[6] = { 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 };
u_char dst_mac[6];
u_char local_mac[6];
/*
 * 列出所有本机的设备
 */
void ListDevs(void) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs, *pdev;
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		printf("%s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	int i = 0;
	for (pdev = alldevs; pdev; pdev = pdev->next) {
		printf("dev#%d: [%s] (%s)\n", ++i, pdev->name, pdev->description);
	}
}

/*
 * 获取本机 mac 地址，存储入 mac[6] 中
 */
void GetMac(char *dev, u_char mac[6]) {
	int sock_mac;
	struct ifreq ifr_mac;

	sock_mac = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_mac == -1) {
		fprintf(stderr, "Create socket error\n");
		exit(EXIT_FAILURE);
	}

	memset(&ifr_mac, 0, sizeof(ifr_mac));
	strncpy(ifr_mac.ifr_name, dev, sizeof(ifr_mac.ifr_name)-1);

	if ((ioctl(sock_mac, SIOCGIFHWADDR, &ifr_mac)) < 0) {
		fprintf(stderr, "Mac ictol error\n");
		exit(EXIT_FAILURE);
	}

	memcpy(mac, ifr_mac.ifr_hwaddr.sa_data, 6);
}

int ReadPacket(u_char *buffer, char *path) {
	FILE *input;
	if ((input = fopen(path, "rb")) == NULL) {
		fprintf(stderr, "path: %s, packet read error\n", path);
		exit(1);
	}

	int size;
	size = fread(buffer, sizeof(u_char), MAX_PACKET_LEN, input);
	if (size == 0) {
		fprintf(stderr, "path: %s, can't read anything");
		exit(1);
	}
	fclose(input);

	return size;
}

void start(pcap_t *p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "./packets/start.bin");

	GetMac(dev, local_mac);
	struct eapol_struct *eapol;
	eapol = (struct eapol_struct *)(packet);
	memcpy(eapol->mac_dst, broad_mac, 0x06);
	memcpy(eapol->mac_src, local_mac, 0x06);
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Error: Couldn't send start packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}

	printf(">>>> 开始认证...\n");
}

void response_id(pcap_t * p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "./packets/response_id.bin");

	packet[0x13] = id;
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}

	printf(">>>> 进行身份验证...\n");
}

// 算法： id + password + 16bit challenge bytes
// md5 extra data : 用户名
void response_md5(pcap_t * p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "./packets/response_md5.bin");

	packet[0x13] = id;

	u_char result[16];
	u_char data[32];

	data[0] = id;
	memcpy(data + 1, password, strlen(password));
	memcpy(data + 1 + strlen(password), md5_value, 0x10);
	MD5(data, 1 + strlen(password) + 0x10, result);

	memcpy(packet + 0x18, result, 0x10);

	u_short username_len = strlen(username);
	u_short eap_packet_len = 0x10 + username_len + 0x06;
	eap_packet_len = htons(eap_packet_len);
	packet[0x14] = packet[0x10] = eap_packet_len;

	memcpy(packet + 0x28, username, username_len);
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}

	printf(">>>> MD5密码验证...\n");
}

void logoff(pcap_t * p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "./packets/logoff.bin");
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}

	printf(">>>> 退出登录...\n");
}

/*
 * 输出认证后消息
 */
void success(const struct eap_struct * eap) {
	printf("<<<< 认证成功.\n");
	exit(0);
}

/*
 * 失败要如何处理
 */
void failure(void) {
	fprintf(stderr, "<<<< 认证失败.\n");
	exit(EXIT_FAILURE);
}
