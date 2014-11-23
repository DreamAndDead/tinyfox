#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h> // big little endian convert

#include "EAP.h"
#include "EAPOL.h"
#include "Ethernet.h"

/* 长度不知道为什么是 1518 ?? */
#define SNAP_LEN 1518
#define MAX_PACKET 600 // 实际传输的 eap 之类的包没有超过过 600

/* 状态
 * 这里的状态是有区别的
 * 本机根据状态发送包
 * 与
 * 服务器传送过来的状态
 *
 * 状态是由服务器的反馈驱动改变的
 */
#define START 0
#define RESPONSE_ID 1
#define RESPONSE_MD5 2
#define LOGOFF 3

#define REQUEST_ID 4
#define REQUEST_MD5 5
#define SUCCESS 6 
#define FAILURE 7

u_char State;

char username[20];
char password[20];
u_char Id;
char md5_value[16];

/* 广播数据包 MAC 01:d0:f8:00:00:03，源 MAC 本机 MAC
 * 这里偷懒下，直接使用，b4:8a:74:26:8a:5f
 * 后期可使用 struct ifreq 获得
 */
u_char broad_mac[6] = { 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 };
u_char dst_mac[6] = { };
u_char local_mac[6] = { 0xb4, 0x8a, 0x74, 0x26, 0x8a, 0x5f };

/*
 * 以太网帧，eapol 的 type 型别码
 */
const u_short eapol_eth_type = 0x8e88; // 网络序为大端，本机序为小端
const u_char eapol_version = 0x01;

int ReadPacket(u_char *buffer, char *path);

void start(pcap_t *);
void response_id(pcap_t *);
void response_md5(pcap_t *);
void logoff(pcap_t *);

void request_id();
void request_md5(const struct eap_struct *);
void success(const struct eap_struct *);
void failure();

void got_packet(u_char *args, const struct pcap_pkthdr *header,
				const u_char *packet);

int main(int argc, char ** argv) {
	char *dev = NULL;
	char *default_dev = "enp12s0"; /* 为了测试本机而存在 */
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	char *filter_exp = ""; // 还没有找到一个合适的表达式
	struct bpf_program fp;

	bpf_u_int32 mask;
	bpf_u_int32 net;
	int num_packets = 10; /* default 10 to capture */

	dev = default_dev;
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

	/* 编译并设置 过滤器 */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s",
				filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* 抓包循环
	 *
	 * 最后一个参数提供与回调函数
	 */
	pcap_loop(handle, num_packets, got_packet, (u_char *)handle); 

	/* 清理工作 */
	pcap_freecode(&fp);
	pcap_close(handle);
	
	printf("\nCapture complete.\n");

	return 0;
}

/* 这里有一个陷阱，即下面的代码是抓包之后执行的，如果完全没有联网，
 * 则不会运行，后期要修改逻辑 
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
				const u_char *packet) {
	pcap_t * handle = (pcap_t *)args;

	// 开始认证是一个特殊的情况
	if (State == START) {
		start();
		State = REQUEST_ID;
		return;
	}

	/* 0x888e filter */
	const struct ethernet_struct *ethe;
	ethe = (struct ethernet_struct *)(packet);
	if (ethe->ethe_type != 0x888e)
		return;

	/* receive packet, parse, change state */
	const struct eapol_struct *eapol;
	const struct eap_struct *eap;

	eapol = (struct eapol_struct *)(packet);
	eap = (struct eap_struct *)(&(eapol->eapol_packet_body));

	switch (eap->eap_code) {
	case CODE_REQUEST:
		switch (eap->eap_type) {
		case type_identify:
			// request_id();
			// 记录下来服务器 mac，与广播 mac 相区分
			// Id 对应 
			memcpy(dst_mac, eapol->mac_src, 6);
			Id = eap->eap_identifier;
			// response id
			response_id(handle);
			break;
		case type_md5_challenge:
			// request_md5();
			// Id 对应
			Id = eap->eap_identifier;
			// md5 值记录
			// 路过一个长度字节
			memcpy(md5_value, (u_char *)&(eap->eap_type_data) + 1, 16);
			// response md5
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

	return size;
}

void start(pcap_t *p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "../packet/start.bin");
	
	if (pcap_sendpacket(p, packet, size) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}
}

/*
 * 向服务器发送反馈包
 * 对应 Id
 * 发送自己的用户名
 *
 */

void response_id(pcap_t * p) {
	u_char packet[600];
	int size;
	size = ReadPacket(packet, "../packet/response_id.bin");
	
	struct eapol_struct *response_id_packet = (struct eapol_struct *)(packet);

	memcpy(response_id_packet->mac_dst, dst_mac, 6);
	memcpy(response_id_packet->mac_src, local_mac, 6);

	response_id_packet->ethe_type = eapol_eth_type;
	response_id_packet->eapol_version = eapol_version;
	response_id_packet->eapol_packet_type = EAP_PACKET;
	// big little endian 转换
	u_short len = strlen(username) + 5; // 5 代表着其它的字节长度
	len = htons(len);
	response_id_packet->eapol_packet_lenth = len;

	struct eap_struct *eap_part = (struct eap_struct *) &(response_id_packet->eapol_packet_body);
	eap_part->eap_code = CODE_RESPONSE;
	eap_part->eap_identifier = Id; // 由服务器传来的 Id
	eap_part->eap_lenth = len;
	eap_part->eap_type = TYPE_IDENTITY;

	memcpy((char *)&(eap_part->eap_type_data), username, strlen(username));
	
	// 553 的魔数源于，这是从抓包的实际数据中得到的大小 
	if (pcap_sendpacket(p, packet, 553) == -1) { 
		fprintf(stderr, "Couldn't send broad packet, error: %s",
				pcap_geterr(p));
		exit(EXIT_FAILURE);
	}
}

// 对应 Id
// 进行算法计算，加上自己的密码
// md5 extra data --> 用户名
void response_md5(pcap_t * p) {
	
}

void logoff(pcap_t * p) {
	
}

/*
 * 服务器请求身份验证
 *
 * 记录下来服务器的 mac 地址(与广播地址区分)
 * 
 */
void request_id(void) {
	
}

void request_md5(const struct eap_struct * eap) {
	
}

void success(const struct eap_struct * eap) {
	
}

void failure(void) {
	
}