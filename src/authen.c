#include <pcap.h>
#include <arpa/inet.h> // big <--> little endian convert
#include <sys/ioctl.h> // Getmac()
#include <net/if.h> 

#include "authen.h"

/*
 * libcrypto.so 动态链接库中，MD5 函数调用
 */
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);

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
	size = fread(buffer, sizeof(u_char), MAX_PACKET, input);
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
	size = ReadPacket(packet, "../packets/start.bin");
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}
}

void response_id(pcap_t * p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "../packets/response_id.bin");

	debug("size: %d\n", size);

	packet[0x13] = id;
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}
}

// 算法： id + password + 16bit challenge bytes
// md5 extra data : 用户名
void response_md5(pcap_t * p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "../packets/response_md5.bin");

	packet[0x13] = id;

	u_char result[16];
	u_char data[32];
	data[0] = id;
	memcpy(data + 1, password, strlen(password));
	memcpy(data + 1 + strlen(password), md5_value, 0x10);

	MD5(data, 1 + strlen(password) + 0x10, result);

	memcpy(packet + 0x18, result, 0x10);
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}
}

void logoff(pcap_t * p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "../packets/logoff.bin");
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}
}

/*
 * 输出认证后消息
 */
void success(const struct eap_struct * eap) {
	printf("认证成功\n");
}

/*
 * 失败要如何处理
 */
void failure(void) {
	fprintf(stderr, "认证失败....\n");
	exit(EXIT_FAILURE);
}
